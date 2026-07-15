// Package rebootcontinuation models the non-secret, one-use PF-001 login
// continuation. It contains no platform persistence or process behavior.
package rebootcontinuation

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

// MaximumLifetime is the closed PF-001 continuation lifetime.
const MaximumLifetime = 24 * time.Hour

var errInvalidRecord = errors.New("reboot continuation binding is invalid")

// Nonce is a random, non-secret one-use value. Its fixed width prevents
// ambiguous persistence and comparison encodings.
type Nonce [32]byte

// NonceBytes is intended for deterministic fixtures and adapter validation.
// Production entropy adapters must pass random bytes to NewNonce.
func NonceBytes(value []byte) Nonce {
	payload := append([]byte("agentmemory:reboot-continuation-nonce:v1\x00"), value...)
	return sha256.Sum256(payload)
}

// NewNonce validates exactly 32 bytes supplied by an entropy port.
func NewNonce(value []byte) (Nonce, error) {
	if len(value) != sha256.Size {
		return Nonce{}, errInvalidRecord
	}
	var nonce Nonce
	copy(nonce[:], value)
	if nonce.IsZero() {
		return Nonce{}, errInvalidRecord
	}
	return nonce, nil
}

// IsZero reports an absent nonce.
func (n Nonce) IsZero() bool { return n == Nonce{} }

// Bytes returns a caller-owned copy for persistence adapters.
func (n Nonce) Bytes() []byte { return append([]byte(nil), n[:]...) }

// TokenFor returns the fixed safe identifier used only by the native login
// command and record filename. It does not reveal the opaque operation ID.
func TokenFor(operationID install.OperationID) (string, error) {
	if operationID.IsZero() {
		return "", errInvalidRecord
	}
	canonical := append([]byte("agentmemory:reboot-continuation-path:v1\x00"), operationID.String()...)
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

// RecordInput is the complete allowed continuation payload. No credentials,
// provider material, runtime tokens, or Brain content can be represented.
type RecordInput struct {
	LauncherPath   string
	LauncherDigest install.Digest
	OperationID    install.OperationID
	JournalPath    string
	JournalDigest  install.Digest
	ExpiresAt      time.Time
	Nonce          Nonce
}

// Record is immutable once validated.
type Record struct {
	launcherPath   string
	launcherDigest install.Digest
	operationID    install.OperationID
	journalPath    string
	journalDigest  install.Digest
	expiresAt      time.Time
	nonce          Nonce
}

// NewRecord validates the exact payload and enforces the maximum lifetime.
func NewRecord(input RecordInput, now time.Time) (Record, error) {
	if now.IsZero() || now.Location() != time.UTC || input.ExpiresAt.IsZero() ||
		input.ExpiresAt.Location() != time.UTC || !input.ExpiresAt.After(now) ||
		input.ExpiresAt.After(now.Add(MaximumLifetime)) ||
		!validNativeAbsolutePath(input.LauncherPath) || !validNativeAbsolutePath(input.JournalPath) ||
		input.LauncherPath == input.JournalPath || input.LauncherDigest.IsZero() ||
		input.OperationID.IsZero() || input.JournalDigest.IsZero() || input.Nonce.IsZero() {
		return Record{}, errInvalidRecord
	}
	return Record{
		launcherPath: input.LauncherPath, launcherDigest: input.LauncherDigest,
		operationID: input.OperationID, journalPath: input.JournalPath,
		journalDigest: input.JournalDigest, expiresAt: input.ExpiresAt, nonce: input.Nonce,
	}, nil
}

// LauncherPath returns the exact verified native executable path.
func (r Record) LauncherPath() string { return r.launcherPath }

// LauncherDigest returns the exact executable content binding.
func (r Record) LauncherDigest() install.Digest { return r.launcherDigest }

// OperationID returns the sole installation operation allowed to resume.
func (r Record) OperationID() install.OperationID { return r.operationID }

// JournalPath returns the exact protected install-journal path.
func (r Record) JournalPath() string { return r.journalPath }

// JournalDigest returns the exact durable journal content binding.
func (r Record) JournalDigest() install.Digest { return r.journalDigest }

// ExpiresAt returns the closed UTC expiry boundary.
func (r Record) ExpiresAt() time.Time { return r.expiresAt }

// Nonce returns the random non-secret one-use value.
func (r Record) Nonce() Nonce { return r.nonce }

// Expired treats the exact expiry instant as expired.
func (r Record) Expired(now time.Time) bool {
	return now.IsZero() || !now.Before(r.expiresAt)
}

// Verification is freshly resolved from protected native objects at consume
// time. It is intentionally not caller-controlled command data.
type Verification struct {
	OperationID    install.OperationID
	LauncherPath   string
	LauncherDigest install.Digest
	JournalPath    string
	JournalDigest  install.Digest
}

// Verify rejects expiry and any executable, journal, or operation substitution.
func (r Record) Verify(actual Verification, now time.Time) error {
	if r.Expired(now) || actual.OperationID != r.operationID ||
		actual.LauncherPath != r.launcherPath || !actual.LauncherDigest.Equal(r.launcherDigest) ||
		actual.JournalPath != r.journalPath || !actual.JournalDigest.Equal(r.journalDigest) {
		return errInvalidRecord
	}
	return nil
}

func validNativeAbsolutePath(value string) bool {
	if value == "" || strings.TrimSpace(value) != value || strings.IndexByte(value, 0) >= 0 {
		return false
	}
	absolute := strings.HasPrefix(value, "/") || strings.HasPrefix(value, `\\`)
	if len(value) >= 3 && ((value[0] >= 'a' && value[0] <= 'z') || (value[0] >= 'A' && value[0] <= 'Z')) &&
		value[1] == ':' && (value[2] == '\\' || value[2] == '/') {
		absolute = true
	}
	if !absolute {
		return false
	}
	segments := strings.FieldsFunc(value, func(character rune) bool { return character == '/' || character == '\\' })
	for _, segment := range segments {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}
