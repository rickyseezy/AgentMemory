// Package activerelease owns the fail-closed active-release pointer and its
// crash-resumable host/Core activation state.
package activerelease

import (
	"encoding/binary"
	"errors"
	"strings"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const (
	pointerSchemaVersion = uint16(1)
	maximumReleaseID     = 128
	maximumEndpoint      = 4096
)

// PointerInput is the complete ADR-017 active release tuple. Every digest is
// already verified by the owning install phase before construction.
type PointerInput struct {
	InstallationID           string
	ReleaseID                string
	GenerationID             string
	ManifestDigest           install.Digest
	ComposeDigest            install.Digest
	ReadinessReceiptDigest   install.Digest
	RuntimeEndpoint          string
	ReleaseSequence          uint64
	ResourceInventoryVersion uint64
	ResourceInventoryDigest  install.Digest
	SecurityEpoch            uint64
	ActivatedAt              time.Time
}

// PointerRecord is the versioned persistence representation. It contains no
// key material, credentials, host paths, or user content.
type PointerRecord struct {
	SchemaVersion            uint16
	InstallationID           string
	ReleaseID                string
	GenerationID             string
	ManifestDigest           string
	ComposeDigest            string
	ReadinessReceiptDigest   string
	RuntimeEndpoint          string
	ReleaseSequence          uint64
	ResourceInventoryVersion uint64
	ResourceInventoryDigest  string
	SecurityEpoch            uint64
	ActivatedAt              string
	PointerDigest            string
}

// Pointer is the immutable, authenticated active release value.
type Pointer struct {
	input  PointerInput
	digest install.Digest
}

// NewPointer validates and deterministically fingerprints a candidate active
// release. Remote daemon transports and noncanonical identifiers fail closed.
func NewPointer(input PointerInput) (Pointer, error) {
	input.ActivatedAt = input.ActivatedAt.UTC().Truncate(time.Microsecond)
	if !validUUIDv7(input.InstallationID) || !validReleaseID(input.ReleaseID) ||
		!validUUIDv7(input.GenerationID) || input.ManifestDigest.IsZero() || input.ComposeDigest.IsZero() ||
		input.ReadinessReceiptDigest.IsZero() || !validLocalEndpoint(input.RuntimeEndpoint) ||
		input.ReleaseSequence == 0 || input.ResourceInventoryVersion == 0 ||
		input.ResourceInventoryDigest.IsZero() || input.SecurityEpoch == 0 || input.ActivatedAt.IsZero() {
		return Pointer{}, errors.New("active release pointer is invalid")
	}
	pointer := Pointer{input: input}
	pointer.digest = install.DigestBytes(pointer.canonicalBytes())
	return pointer, nil
}

// RestorePointer strictly restores a versioned record and verifies its
// complete deterministic digest before returning domain state.
func RestorePointer(record PointerRecord) (Pointer, error) {
	if record.SchemaVersion != pointerSchemaVersion {
		return Pointer{}, errors.New("active release pointer schema is unsupported")
	}
	manifest, manifestError := install.ParseDigest(record.ManifestDigest)
	compose, composeError := install.ParseDigest(record.ComposeDigest)
	readiness, readinessError := install.ParseDigest(record.ReadinessReceiptDigest)
	inventory, inventoryError := install.ParseDigest(record.ResourceInventoryDigest)
	storedDigest, storedDigestError := install.ParseDigest(record.PointerDigest)
	activatedAt, timeError := time.Parse(time.RFC3339Nano, record.ActivatedAt)
	if manifestError != nil || composeError != nil || readinessError != nil || inventoryError != nil ||
		storedDigestError != nil || timeError != nil {
		return Pointer{}, errors.New("active release pointer record is invalid")
	}
	pointer, err := NewPointer(PointerInput{
		InstallationID:           record.InstallationID,
		ReleaseID:                record.ReleaseID,
		GenerationID:             record.GenerationID,
		ManifestDigest:           manifest,
		ComposeDigest:            compose,
		ReadinessReceiptDigest:   readiness,
		RuntimeEndpoint:          record.RuntimeEndpoint,
		ReleaseSequence:          record.ReleaseSequence,
		ResourceInventoryVersion: record.ResourceInventoryVersion,
		ResourceInventoryDigest:  inventory,
		SecurityEpoch:            record.SecurityEpoch,
		ActivatedAt:              activatedAt,
	})
	if err != nil || !pointer.digest.Equal(storedDigest) {
		return Pointer{}, errors.New("active release pointer integrity violation")
	}
	return pointer, nil
}

// Record returns a caller-owned versioned persistence value.
func (p Pointer) Record() PointerRecord {
	return PointerRecord{
		SchemaVersion:            pointerSchemaVersion,
		InstallationID:           p.input.InstallationID,
		ReleaseID:                p.input.ReleaseID,
		GenerationID:             p.input.GenerationID,
		ManifestDigest:           p.input.ManifestDigest.String(),
		ComposeDigest:            p.input.ComposeDigest.String(),
		ReadinessReceiptDigest:   p.input.ReadinessReceiptDigest.String(),
		RuntimeEndpoint:          p.input.RuntimeEndpoint,
		ReleaseSequence:          p.input.ReleaseSequence,
		ResourceInventoryVersion: p.input.ResourceInventoryVersion,
		ResourceInventoryDigest:  p.input.ResourceInventoryDigest.String(),
		SecurityEpoch:            p.input.SecurityEpoch,
		ActivatedAt:              p.input.ActivatedAt.Format(time.RFC3339Nano),
		PointerDigest:            p.digest.String(),
	}
}

// InstallationID returns the UUIDv7 installation owner.
func (p Pointer) InstallationID() string { return p.input.InstallationID }

// ReleaseID returns the signed release identity.
func (p Pointer) ReleaseID() string { return p.input.ReleaseID }

// GenerationID returns the active UUIDv7 data generation.
func (p Pointer) GenerationID() string { return p.input.GenerationID }

// ManifestDigest returns the verified release manifest binding.
func (p Pointer) ManifestDigest() install.Digest { return p.input.ManifestDigest }

// ComposeDigest returns the exact rendered Compose binding.
func (p Pointer) ComposeDigest() install.Digest { return p.input.ComposeDigest }

// ReadinessReceiptDigest returns the sole readiness authorization proof.
func (p Pointer) ReadinessReceiptDigest() install.Digest { return p.input.ReadinessReceiptDigest }

// RuntimeEndpoint returns the exact explicitly local Engine endpoint.
func (p Pointer) RuntimeEndpoint() string { return p.input.RuntimeEndpoint }

// ReleaseSequence returns the signed anti-rollback release sequence.
func (p Pointer) ReleaseSequence() uint64 { return p.input.ReleaseSequence }

// ResourceInventoryVersion returns the exact owned-resource revision.
func (p Pointer) ResourceInventoryVersion() uint64 { return p.input.ResourceInventoryVersion }

// ResourceInventoryDigest returns the complete inventory binding.
func (p Pointer) ResourceInventoryDigest() install.Digest { return p.input.ResourceInventoryDigest }

// SecurityEpoch returns the monotonic credential/policy epoch.
func (p Pointer) SecurityEpoch() uint64 { return p.input.SecurityEpoch }

// ActivatedAt returns the normalized activation decision time.
func (p Pointer) ActivatedAt() time.Time { return p.input.ActivatedAt }

// Digest returns the complete deterministic pointer binding.
func (p Pointer) Digest() install.Digest { return p.digest }

// IsZero reports whether this is not a valid pointer.
func (p Pointer) IsZero() bool { return p.digest.IsZero() }

func (p Pointer) canonicalBytes() []byte {
	output := appendField(nil, "agentmemory.active-release.v1")
	output = appendField(output, p.input.InstallationID)
	output = appendField(output, p.input.ReleaseID)
	output = appendField(output, p.input.GenerationID)
	output = appendField(output, p.input.ManifestDigest.String())
	output = appendField(output, p.input.ComposeDigest.String())
	output = appendField(output, p.input.ReadinessReceiptDigest.String())
	output = appendField(output, p.input.RuntimeEndpoint)
	output = appendUint64(output, p.input.ReleaseSequence)
	output = appendUint64(output, p.input.ResourceInventoryVersion)
	output = appendField(output, p.input.ResourceInventoryDigest.String())
	output = appendUint64(output, p.input.SecurityEpoch)
	return appendUint64(output, uint64(p.input.ActivatedAt.UnixMicro()))
}

func appendField(output []byte, value string) []byte {
	output = appendUint64(output, uint64(len(value)))
	return append(output, value...)
}

func appendUint64(output []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(output, encoded[:]...)
}

func validReleaseID(value string) bool {
	if value == "" || len(value) > maximumReleaseID || value != strings.TrimSpace(value) {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			(index > 0 && (character == '-' || character == '_' || character == '.')) {
			continue
		}
		return false
	}
	return true
}

func validUUIDv7(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' ||
		value[14] != '7' || !strings.ContainsRune("89ab", rune(value[19])) {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validLocalEndpoint(value string) bool {
	if value == "" || len(value) > maximumEndpoint || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	if strings.HasPrefix(value, "unix:///") {
		path := strings.TrimPrefix(value, "unix://")
		if !strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") || strings.Contains(path, "//") {
			return false
		}
		for _, segment := range strings.Split(path, "/") {
			if segment == "." || segment == ".." {
				return false
			}
		}
		return true
	}
	if strings.HasPrefix(value, "npipe:////./pipe/") {
		name := strings.TrimPrefix(value, "npipe:////./pipe/")
		return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, `/\\`)
	}
	return false
}

// ReplacementDecision is the closed anti-rollback pointer decision.
type ReplacementDecision uint8

const (
	// DecisionConflict rejects rollback, cross-install, or same-sequence equivocation.
	DecisionConflict ReplacementDecision = iota
	// DecisionActivate permits a compare-and-swap to the target pointer.
	DecisionActivate
	// DecisionAlreadyActive means the exact target digest is already durable.
	DecisionAlreadyActive
)

// DecideReplacement enforces monotonic signed release, inventory, and
// security state before the application may stage a Core activation.
func DecideReplacement(current Pointer, target Pointer) ReplacementDecision {
	if target.IsZero() {
		return DecisionConflict
	}
	if current.IsZero() {
		return DecisionActivate
	}
	if current.Digest().Equal(target.Digest()) {
		return DecisionAlreadyActive
	}
	if current.InstallationID() != target.InstallationID() ||
		target.ReleaseSequence() < current.ReleaseSequence() ||
		target.ResourceInventoryVersion() < current.ResourceInventoryVersion() ||
		target.SecurityEpoch() < current.SecurityEpoch() {
		return DecisionConflict
	}
	if target.ReleaseSequence() == current.ReleaseSequence() &&
		(target.ReleaseID() != current.ReleaseID() || !target.ManifestDigest().Equal(current.ManifestDigest()) ||
			!target.ComposeDigest().Equal(current.ComposeDigest())) {
		return DecisionConflict
	}
	return DecisionActivate
}
