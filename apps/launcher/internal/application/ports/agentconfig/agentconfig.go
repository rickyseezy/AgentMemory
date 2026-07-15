// Package agentconfig defines the portable boundary for one host agent's
// owner-scoped MCP configuration. Platform filesystem semantics stay behind
// Store; parsing and merge policy stay in the domain package.
package agentconfig

import (
	"context"
	"errors"
	"fmt"
	"strings"

	domain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
)

var (
	// ErrInvalidArgument rejects malformed port values.
	ErrInvalidArgument = errors.New("invalid agent configuration argument")
	// ErrNotFound reports an absent configuration file.
	ErrNotFound = errors.New("agent configuration not found")
	// ErrConflict reports compare-and-swap drift and preserves external edits.
	ErrConflict = errors.New("agent configuration conflict")
	// ErrIntegrity reports backup or receipt hash mismatch.
	ErrIntegrity = errors.New("agent configuration integrity violation")
	// ErrUnsafePath reports a symlink, ownership, type, or permission violation.
	ErrUnsafePath = errors.New("unsafe agent configuration path")
	// ErrDurabilityAmbiguous means replacement happened but durable sync could
	// not be proved. Replaying the same receipt is the safe recovery operation.
	ErrDurabilityAmbiguous = errors.New("agent configuration durability is ambiguous")
	// ErrIO sanitizes an otherwise unclassified filesystem failure.
	ErrIO = errors.New("agent configuration IO failure")
	// ErrUnsupportedPlatform reports that no certified adapter is composed.
	ErrUnsupportedPlatform = errors.New("agent configuration platform is unsupported")
)

// ConfigLocation is an explicitly addressed host configuration file or the
// AgentMemory-owned binding locator for path-neutral custom registration.
// Concrete filesystem adapters perform platform-specific path validation;
// custom registration never passes its binding locator to a filesystem store.
type ConfigLocation struct{ value string }

// NewConfigLocation validates transport-neutral path safety.
func NewConfigLocation(value string) (ConfigLocation, error) {
	if value == "" || len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
		return ConfigLocation{}, ErrInvalidArgument
	}
	return ConfigLocation{value: value}, nil
}

// String returns the exact explicitly configured path.
func (l ConfigLocation) String() string { return l.value }

// Detection is the side-effect-free presence result.
type Detection struct{ exists bool }

// NewDetection creates a detection result.
func NewDetection(exists bool) Detection { return Detection{exists: exists} }

// Exists reports whether the file was present.
func (d Detection) Exists() bool { return d.exists }

// Snapshot is an immutable exact-byte observation.
type Snapshot struct {
	exists  bool
	content []byte
	digest  domain.Digest
}

// NewSnapshot validates and copy-owns an exact observation.
func NewSnapshot(exists bool, content []byte) (Snapshot, error) {
	if !exists {
		if len(content) != 0 {
			return Snapshot{}, ErrInvalidArgument
		}
		return Snapshot{}, nil
	}
	if len(content) > domain.MaxDocumentBytes {
		return Snapshot{}, ErrInvalidArgument
	}
	return Snapshot{exists: true, content: append([]byte(nil), content...), digest: domain.DigestBytes(content)}, nil
}

// Exists reports whether the observed file existed.
func (s Snapshot) Exists() bool { return s.exists }

// Content returns a caller-owned copy of exact bytes.
func (s Snapshot) Content() []byte { return append([]byte(nil), s.content...) }

// Digest returns the exact-byte digest, or zero for absence.
func (s Snapshot) Digest() domain.Digest { return s.digest }

// ApplyReceipt binds backup and replacement evidence for safe compensation.
type ApplyReceipt struct {
	valid              bool
	changed            bool
	originalExisted    bool
	beforeDigest       domain.Digest
	afterDigest        domain.Digest
	managedEntryDigest domain.Digest
	backupLocation     string
	backupDigest       domain.Digest
}

// NewApplyReceipt validates mutation evidence.
func NewApplyReceipt(
	changed bool,
	originalExisted bool,
	beforeDigest domain.Digest,
	afterDigest domain.Digest,
	managedEntryDigest domain.Digest,
	backupLocation string,
	backupDigest domain.Digest,
) (ApplyReceipt, error) {
	if !changed || afterDigest.IsZero() || managedEntryDigest.IsZero() {
		return ApplyReceipt{}, ErrInvalidArgument
	}
	if originalExisted {
		if beforeDigest.IsZero() || backupLocation == "" || !backupDigest.Equal(beforeDigest) ||
			len(backupLocation) > 4096 || strings.ContainsAny(backupLocation, "\x00\r\n") {
			return ApplyReceipt{}, ErrInvalidArgument
		}
	} else if !beforeDigest.IsZero() || backupLocation != "" || !backupDigest.IsZero() {
		return ApplyReceipt{}, ErrInvalidArgument
	}
	return ApplyReceipt{
		valid:              true,
		changed:            true,
		originalExisted:    originalExisted,
		beforeDigest:       beforeDigest,
		afterDigest:        afterDigest,
		managedEntryDigest: managedEntryDigest,
		backupLocation:     backupLocation,
		backupDigest:       backupDigest,
	}, nil
}

// Valid reports whether a constructor created this receipt.
func (r ApplyReceipt) Valid() bool { return r.valid }

// Changed reports that one effective mutation occurred.
func (r ApplyReceipt) Changed() bool { return r.changed }

// OriginalExisted reports the pre-mutation file state.
func (r ApplyReceipt) OriginalExisted() bool { return r.originalExisted }

// BeforeDigest returns the exact pre-mutation hash.
func (r ApplyReceipt) BeforeDigest() domain.Digest { return r.beforeDigest }

// AfterDigest returns the exact post-mutation hash.
func (r ApplyReceipt) AfterDigest() domain.Digest { return r.afterDigest }

// ManagedEntryDigest returns the canonical owned-entry hash.
func (r ApplyReceipt) ManagedEntryDigest() domain.Digest { return r.managedEntryDigest }

// BackupLocation returns the owner-only content-addressed backup path.
func (r ApplyReceipt) BackupLocation() string { return r.backupLocation }

// BackupDigest returns the exact backup hash.
func (r ApplyReceipt) BackupDigest() domain.Digest { return r.backupDigest }

// RestoreReceipt proves the final restored state.
type RestoreReceipt struct {
	valid  bool
	exists bool
	digest domain.Digest
}

// NewRestoreReceipt validates restored-state evidence.
func NewRestoreReceipt(exists bool, digest domain.Digest) (RestoreReceipt, error) {
	if exists == digest.IsZero() {
		return RestoreReceipt{}, ErrInvalidArgument
	}
	return RestoreReceipt{valid: true, exists: exists, digest: digest}, nil
}

// Valid reports whether a constructor created this receipt.
func (r RestoreReceipt) Valid() bool { return r.valid }

// Exists reports whether restore produced a file.
func (r RestoreReceipt) Exists() bool { return r.exists }

// Digest returns the restored exact-byte hash, or zero for absence.
func (r RestoreReceipt) Digest() domain.Digest { return r.digest }

// Store owns concrete filesystem detection, reads, compare-and-swap atomic
// replacement, backup durability, and conflict-safe restoration.
type Store interface {
	Detect(context.Context, ConfigLocation) (Detection, error)
	Read(context.Context, ConfigLocation) (Snapshot, error)
	ApplyAtomic(context.Context, ConfigLocation, domain.MergePlan) (ApplyReceipt, error)
	RestoreBackup(context.Context, ConfigLocation, ApplyReceipt) (RestoreReceipt, error)
}

// DocumentPolicy is one pure host-format syntax adapter. Format libraries stay
// outside the domain and filesystem mutation remains exclusively in Store.
type DocumentPolicy interface {
	Supports(domain.AgentHost) bool
	Validate([]byte) error
	PlanMerge([]byte, bool, domain.Target, domain.Digest) (domain.MergePlan, error)
	VerifyManagedEntry([]byte, domain.Target) error
}

// InvocationVerifier proves the configured signed launcher can execute the
// generic MCP handshake without a shell.
type InvocationVerifier interface {
	Verify(context.Context, domain.Target) error
}

// Adapter is the complete PF-001 host configuration contract.
type Adapter interface {
	Detect(context.Context, ConfigLocation) (Detection, error)
	Read(context.Context, ConfigLocation) (Snapshot, error)
	Validate([]byte) error
	PlanMerge([]byte, bool, domain.Target, domain.Digest) (domain.MergePlan, error)
	ApplyAtomic(context.Context, ConfigLocation, domain.MergePlan) (ApplyReceipt, error)
	VerifyInvocation(context.Context, ConfigLocation, domain.Target) error
	RestoreBackup(context.Context, ConfigLocation, ApplyReceipt) (RestoreReceipt, error)
}

// Wrap annotates a stable category without exposing path or content.
func Wrap(category error, operation string) error {
	return fmt.Errorf("%s: %w", operation, category)
}
