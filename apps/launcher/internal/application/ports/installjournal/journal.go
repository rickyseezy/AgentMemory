// Package installjournal defines the persistence boundary for resumable host
// installation state. Implementations must durably commit a whole snapshot
// before Append returns successfully.
package installjournal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Snapshot is an opaque, versioned application-state checkpoint. Payload is
// deliberately contract-neutral so the filesystem adapter does not depend on
// install-domain entities.
type Snapshot struct {
	OperationID string
	Revision    uint64
	CapturedAt  time.Time
	Payload     json.RawMessage
}

// Journal is the single-writer persistence port used by the install saga.
// expectedPreviousRevision is zero for the first snapshot. Implementations
// must reject a stale expected revision instead of losing a checkpoint.
type Journal interface {
	Append(ctx context.Context, expectedPreviousRevision uint64, snapshot Snapshot) error
	LoadLatest(ctx context.Context) (Snapshot, error)
	// ConfirmDurable re-authenticates the named current revision and does not
	// return until both its file contents and parent-directory entry have been
	// synchronized. It resolves the ambiguous crash window where atomic rename
	// succeeded but the caller did not receive a durability acknowledgement.
	ConfirmDurable(ctx context.Context, operationID string, revision uint64) error
}

// ErrorCode is stable across adapters and inbound error translations.
type ErrorCode string

const (
	// ErrorNotFound means no durable journal exists yet.
	ErrorNotFound ErrorCode = "not_found"
	// ErrorCorrupt means stored bytes failed structural or authentication checks.
	ErrorCorrupt ErrorCode = "corrupt"
	// ErrorConflict means the caller attempted a stale or cross-operation write.
	ErrorConflict ErrorCode = "conflict"
	// ErrorUnsafePermission means a filesystem object violates owner-only policy.
	ErrorUnsafePermission ErrorCode = "unsafe_permission"
	// ErrorInvalidSnapshot means the supplied checkpoint violates port invariants.
	ErrorInvalidSnapshot ErrorCode = "invalid_snapshot"
	// ErrorIO means a host persistence operation did not complete as required.
	ErrorIO ErrorCode = "io"
)

// Error is an adapter-neutral, typed journal failure.
type Error struct {
	Code  ErrorCode
	Op    string
	Cause error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Cause == nil {
		return fmt.Sprintf("install journal %s: %s", e.Op, e.Code)
	}
	return fmt.Sprintf("install journal %s: %s: %v", e.Op, e.Code, e.Cause)
}

func (e *Error) Unwrap() error { return e.Cause }

// Is lets callers use errors.Is with the sentinel values below while retaining
// the operation and underlying platform failure.
func (e *Error) Is(target error) bool {
	var other *Error
	return errors.As(target, &other) && e.Code == other.Code
}

var (
	// ErrNotFound is the errors.Is target for a missing journal.
	ErrNotFound = &Error{Code: ErrorNotFound}
	// ErrCorrupt is the errors.Is target for malformed or unauthenticated state.
	ErrCorrupt = &Error{Code: ErrorCorrupt}
	// ErrConflict is the errors.Is target for optimistic-write conflicts.
	ErrConflict = &Error{Code: ErrorConflict}
	// ErrUnsafePermission is the errors.Is target for unsafe filesystem objects.
	ErrUnsafePermission = &Error{Code: ErrorUnsafePermission}
	// ErrInvalidSnapshot is the errors.Is target for invalid checkpoint input.
	ErrInvalidSnapshot = &Error{Code: ErrorInvalidSnapshot}
	// ErrIO is the errors.Is target for incomplete host persistence operations.
	ErrIO = &Error{Code: ErrorIO}
)

// NewError is intended for port implementations translating infrastructure
// failures. Application code should normally inspect errors with errors.Is.
func NewError(code ErrorCode, operation string, cause error) error {
	return &Error{Code: code, Op: operation, Cause: cause}
}
