package install

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode/utf8"
)

const (
	digestHexLength    = sha256.Size * 2
	maxOperationIDSize = 128
	maxActionSize      = 128
)

// Digest is an immutable SHA-256 digest of canonical bytes.
type Digest struct {
	value [sha256.Size]byte
}

// DigestBytes hashes canonical bytes. The caller owns canonicalization.
func DigestBytes(canonical []byte) Digest {
	return Digest{value: sha256.Sum256(canonical)}
}

// ParseDigest parses a lowercase or uppercase hexadecimal SHA-256 digest.
func ParseDigest(encoded string) (Digest, error) {
	if len(encoded) != digestHexLength {
		return Digest{}, newValidationError("digest", "must contain exactly 64 hexadecimal characters")
	}

	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		return Digest{}, newValidationError("digest", "must be hexadecimal")
	}

	var value [sha256.Size]byte
	copy(value[:], decoded)
	result := Digest{value: value}
	if result.IsZero() {
		return Digest{}, newValidationError("digest", "zero digest is not valid evidence")
	}
	return result, nil
}

func (d Digest) String() string {
	return hex.EncodeToString(d.value[:])
}

// IsZero reports whether no digest was supplied.
func (d Digest) IsZero() bool {
	return d == Digest{}
}

// Equal compares digest values without exposing mutable bytes.
func (d Digest) Equal(other Digest) bool {
	return d == other
}

// PlanDigest binds an operation and all of its evidence to one immutable,
// canonical installation plan.
type PlanDigest struct {
	digest Digest
}

// BindPlan hashes a non-empty canonical installation plan.
func BindPlan(canonicalPlan []byte) (PlanDigest, error) {
	if len(canonicalPlan) == 0 {
		return PlanDigest{}, newValidationError("canonical_plan", "must not be empty")
	}
	return PlanDigest{digest: DigestBytes(canonicalPlan)}, nil
}

// ParsePlanDigest parses a persisted hexadecimal SHA-256 plan binding.
func ParsePlanDigest(encoded string) (PlanDigest, error) {
	digest, err := ParseDigest(encoded)
	if err != nil {
		return PlanDigest{}, err
	}
	return PlanDigest{digest: digest}, nil
}

func (d PlanDigest) String() string {
	return d.digest.String()
}

// IsZero reports whether no plan binding was supplied.
func (d PlanDigest) IsZero() bool {
	return d.digest.IsZero()
}

// Equal compares immutable plan bindings.
func (d PlanDigest) Equal(other PlanDigest) bool {
	return d.digest.Equal(other.digest)
}

// OperationID is the safe, opaque identifier of one bootstrap operation.
type OperationID struct {
	value string
}

// NewOperationID validates a bounded opaque operation identifier. It is not a
// filesystem path component; adapters must use a fixed digest/encoding when
// selecting per-operation storage.
func NewOperationID(value string) (OperationID, error) {
	if value == "" {
		return OperationID{}, newValidationError("operation_id", "must not be empty")
	}
	if value != strings.TrimSpace(value) || len(value) > maxOperationIDSize || !utf8.ValidString(value) {
		return OperationID{}, newValidationError("operation_id", "must be valid, unpadded UTF-8 within 128 bytes")
	}
	for _, character := range value {
		if !isIdentifierCharacter(character) {
			return OperationID{}, newValidationError("operation_id", "contains a forbidden character")
		}
	}
	return OperationID{value: value}, nil
}

func (id OperationID) String() string {
	return id.value
}

// IsZero reports whether no operation ID was supplied.
func (id OperationID) IsZero() bool {
	return id.value == ""
}

// SafeAction is a localization/message key for the next safe action. It is a
// key rather than display text so evidence cannot accidentally persist raw
// process errors, paths, commands, or credentials.
type SafeAction struct {
	key string
}

// NewSafeAction validates a localization key for a plain-language safe action.
func NewSafeAction(key string) (SafeAction, error) {
	if key == "" || len(key) > maxActionSize || key != strings.TrimSpace(key) {
		return SafeAction{}, newValidationError("next_safe_action", "must be a non-empty message key within 128 bytes")
	}
	for _, character := range key {
		if !isActionCharacter(character) {
			return SafeAction{}, newValidationError("next_safe_action", "must contain only lowercase message-key characters")
		}
	}
	return SafeAction{key: key}, nil
}

func (a SafeAction) String() string {
	return a.key
}

func (a SafeAction) valid() bool {
	if a.key == "" || len(a.key) > maxActionSize {
		return false
	}
	for _, character := range a.key {
		if !isActionCharacter(character) {
			return false
		}
	}
	return true
}

func isIdentifierCharacter(character rune) bool {
	return character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9' ||
		character == '-' || character == '_' || character == '.'
}

func isActionCharacter(character rune) bool {
	return character >= 'a' && character <= 'z' ||
		character >= '0' && character <= '9' ||
		character == '-' || character == '_' || character == '.'
}
