package install

import (
	"encoding/binary"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	bootstrapKeyRefPrefix  = "bootstrap-key:v1:"
	maxOwnerIdentityLength = 512
)

// OwnerBinding binds bootstrap state to one machine and invoking OS
// principal without retaining either raw local identifier.
type OwnerBinding struct {
	machineDigest   Digest
	principalDigest Digest
}

// BindOwner hashes canonical machine and OS-principal identities using
// separate domain separators.
func BindOwner(machineIdentity, principalIdentity string) (OwnerBinding, error) {
	if !validOwnerIdentity(machineIdentity) {
		return OwnerBinding{}, newValidationError("machine_identity", "must be a bounded canonical local identity")
	}
	if !validOwnerIdentity(principalIdentity) {
		return OwnerBinding{}, newValidationError("principal_identity", "must be a bounded canonical local identity")
	}
	return OwnerBinding{
		machineDigest:   DigestBytes(append([]byte("agentmemory:machine:v1\x00"), machineIdentity...)),
		principalDigest: DigestBytes(append([]byte("agentmemory:principal:v1\x00"), principalIdentity...)),
	}, nil
}

// RestoreOwnerBinding restores already-hashed persisted owner identity.
func RestoreOwnerBinding(machineDigest, principalDigest string) (OwnerBinding, error) {
	machine, err := ParseDigest(machineDigest)
	if err != nil {
		return OwnerBinding{}, newIntegrityError("owner machine binding is invalid")
	}
	principal, err := ParseDigest(principalDigest)
	if err != nil {
		return OwnerBinding{}, newIntegrityError("owner principal binding is invalid")
	}
	return OwnerBinding{machineDigest: machine, principalDigest: principal}, nil
}

// MachineDigest returns the non-reversible machine identity digest.
func (b OwnerBinding) MachineDigest() Digest { return b.machineDigest }

// PrincipalDigest returns the non-reversible principal identity digest.
func (b OwnerBinding) PrincipalDigest() Digest { return b.principalDigest }

// Equal compares both bound identities.
func (b OwnerBinding) Equal(other OwnerBinding) bool {
	return b.machineDigest.Equal(other.machineDigest) && b.principalDigest.Equal(other.principalDigest)
}

// IsZero reports whether the binding is absent.
func (b OwnerBinding) IsZero() bool {
	return b.machineDigest.IsZero() || b.principalDigest.IsZero()
}

// Fingerprint returns a stable non-secret digest for map keys and HMAC input.
func (b OwnerBinding) Fingerprint() Digest {
	canonical := make([]byte, 0, 2*sha256DigestSize)
	canonical = append(canonical, b.machineDigest.value[:]...)
	canonical = append(canonical, b.principalDigest.value[:]...)
	return DigestBytes(canonical)
}

// BootstrapKeyRef is an opaque, non-secret reference to protected operation
// key material.
type BootstrapKeyRef struct {
	value string
}

// NewBootstrapKeyRef validates the fixed reference encoding.
func NewBootstrapKeyRef(value string) (BootstrapKeyRef, error) {
	if !strings.HasPrefix(value, bootstrapKeyRefPrefix) {
		return BootstrapKeyRef{}, newValidationError("bootstrap_key_ref", "has an unsupported format")
	}
	if _, err := ParseDigest(strings.TrimPrefix(value, bootstrapKeyRefPrefix)); err != nil {
		return BootstrapKeyRef{}, newValidationError("bootstrap_key_ref", "has an invalid digest")
	}
	return BootstrapKeyRef{value: value}, nil
}

// BootstrapKeyRefFromDigest creates a reference from a non-zero digest.
func BootstrapKeyRefFromDigest(digest Digest) (BootstrapKeyRef, error) {
	if digest.IsZero() {
		return BootstrapKeyRef{}, newValidationError("bootstrap_key_ref", "digest must not be zero")
	}
	return BootstrapKeyRef{value: bootstrapKeyRefPrefix + digest.String()}, nil
}

// String returns the persistable non-secret reference.
func (r BootstrapKeyRef) String() string { return r.value }

// IsZero reports whether no reference is present.
func (r BootstrapKeyRef) IsZero() bool { return r.value == "" }

// Equal compares opaque references.
func (r BootstrapKeyRef) Equal(other BootstrapKeyRef) bool { return r.value == other.value }

// RollbackAnchor binds a protected monotonic sequence to the exact journal
// digest, operation, machine, and principal.
type RollbackAnchor struct {
	operationID OperationID
	owner       OwnerBinding
	sequence    uint64
	stateDigest Digest
}

// NewRollbackAnchor validates a protected state anchor.
func NewRollbackAnchor(
	operationID OperationID,
	owner OwnerBinding,
	sequence uint64,
	stateDigest Digest,
) (RollbackAnchor, error) {
	if operationID.IsZero() {
		return RollbackAnchor{}, newValidationError("operation_id", "must not be empty")
	}
	if owner.IsZero() {
		return RollbackAnchor{}, newValidationError("owner_binding", "must not be empty")
	}
	if sequence == 0 {
		return RollbackAnchor{}, newValidationError("rollback_sequence", "must be positive")
	}
	if stateDigest.IsZero() {
		return RollbackAnchor{}, newValidationError("state_digest", "must not be zero")
	}
	return RollbackAnchor{operationID: operationID, owner: owner, sequence: sequence, stateDigest: stateDigest}, nil
}

// OperationID returns the anchored operation.
func (a RollbackAnchor) OperationID() OperationID { return a.operationID }

// Owner returns the bound machine/principal identity.
func (a RollbackAnchor) Owner() OwnerBinding { return a.owner }

// Sequence returns the strictly increasing sequence.
func (a RollbackAnchor) Sequence() uint64 { return a.sequence }

// StateDigest returns the exact authenticated state digest.
func (a RollbackAnchor) StateDigest() Digest { return a.stateDigest }

// CanonicalBytes returns an unambiguous, versioned HMAC input.
func (a RollbackAnchor) CanonicalBytes() []byte {
	operation := []byte(a.operationID.String())
	result := make([]byte, 0, 32+len(operation)+8+sha256DigestSize*3)
	result = append(result, "agentmemory:rollback-anchor:v1\x00"...)
	length := make([]byte, 4)
	//nolint:gosec // G115: OperationID validation caps operation to 128 bytes; owner=security expiry=2027-07-13.
	binary.BigEndian.PutUint32(length, uint32(len(operation)))
	result = append(result, length...)
	result = append(result, operation...)
	result = append(result, a.owner.machineDigest.value[:]...)
	result = append(result, a.owner.principalDigest.value[:]...)
	sequence := make([]byte, 8)
	binary.BigEndian.PutUint64(sequence, a.sequence)
	result = append(result, sequence...)
	result = append(result, a.stateDigest.value[:]...)
	return result
}

func validOwnerIdentity(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > maxOwnerIdentityLength || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

const sha256DigestSize = 32
