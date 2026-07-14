package activereleaseapp

import (
	"context"
	"errors"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/activerelease"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/readiness"
)

var (
	// ErrReadinessReceiptNotFound means no durable proof exists at the digest.
	ErrReadinessReceiptNotFound = errors.New("readiness receipt not found")
	// ErrReadinessReceiptIntegrity means persisted proof cannot be authenticated.
	ErrReadinessReceiptIntegrity = errors.New("readiness receipt integrity violation")
	// ErrActivationNotFound means no activation saga exists for the operation.
	ErrActivationNotFound = errors.New("active release activation not found")
	// ErrActivationConflict means an optimistic activation save lost its CAS.
	ErrActivationConflict = errors.New("active release activation conflict")
	// ErrActivationIntegrity means the saved activation cannot be authenticated.
	ErrActivationIntegrity = errors.New("active release activation integrity violation")
	// ErrPointerNotFound means this installation has no active pointer yet.
	ErrPointerNotFound = errors.New("active release pointer not found")
	// ErrPointerConflict means host state no longer equals the CAS predecessor.
	ErrPointerConflict = errors.New("active release pointer conflict")
	// ErrPointerIntegrity means host pointer state cannot be authenticated.
	ErrPointerIntegrity = errors.New("active release pointer integrity violation")
)

// Clock supplies activation time without ambient time access inward.
type Clock interface {
	Now() time.Time
}

// ReadinessReceiptRepository resolves only authenticated persisted receipts.
type ReadinessReceiptRepository interface {
	LoadReadinessReceipt(context.Context, install.Digest) (readiness.Receipt, error)
}

// ActivationRepository persists the crash-recovery aggregate with optimistic
// versioning and full authentication.
type ActivationRepository interface {
	Load(context.Context, install.OperationID) (*activerelease.Activation, error)
	Save(context.Context, activerelease.ActivationSnapshot) error
}

// HostPointerRepository owns the fsync-safe authenticated host pointer. CAS
// accepts zero expected digest only when no pointer exists.
type HostPointerRepository interface {
	Load(context.Context, string) (activerelease.Pointer, error)
	CompareAndSwap(context.Context, install.Digest, activerelease.Pointer) error
	ConfirmDurable(context.Context, activerelease.Pointer) error
}

// CorePointerPort is the narrow governed Core activation transaction. Stage
// and Commit are idempotent for operation+pointer and expose no generic SQL.
type CorePointerPort interface {
	Stage(context.Context, install.OperationID, activerelease.Pointer, readiness.Receipt) (install.Digest, error)
	Commit(context.Context, install.OperationID, install.Digest, activerelease.Pointer) (install.Digest, error)
	Matches(context.Context, activerelease.Pointer) (bool, error)
}
