// Package installbootstrap defines narrow security capabilities required
// before the AgentMemory core and installation credential exist.
package installbootstrap

import (
	"context"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

var (
	// ErrNotFound means protected bootstrap state does not exist.
	ErrNotFound = errors.New("protected bootstrap state not found")
	// ErrConflict means a monotonic compare-and-swap or identity binding lost.
	ErrConflict = errors.New("protected bootstrap state conflict")
	// ErrIntegrity means protected state, owner binding, or key reference cannot
	// be authenticated. Callers must not recreate or overwrite it implicitly.
	ErrIntegrity = errors.New("protected bootstrap state integrity violation")
)

// OwnerBindingSource resolves the current machine and invoking OS principal.
type OwnerBindingSource interface {
	Current(context.Context) (install.OwnerBinding, error)
}

// OperationKeyConsumer may use key bytes only during the callback. It must not
// retain, log, serialize, or expose the supplied slice.
type OperationKeyConsumer func([]byte) error

// OperationKeySource provisions and resolves a 256-bit operation HMAC key by
// non-secret reference. Implementations bind every access to the operation,
// machine, and OS principal.
type OperationKeySource interface {
	Ensure(
		context.Context,
		install.OperationID,
		install.OwnerBinding,
	) (install.BootstrapKeyRef, error)
	UseHMACKey(
		context.Context,
		install.BootstrapKeyRef,
		install.OperationID,
		install.OwnerBinding,
		OperationKeyConsumer,
	) error
}

// OperationIDGenerator generates canonical UUIDv7 operation identities.
type OperationIDGenerator interface {
	NewOperationID(context.Context) (install.OperationID, error)
}

// RollbackAnchorStore protects a monotonic journal sequence with the operation
// key. expectedSequence is zero only when creating the first anchor. The
// installer's cross-process operation lock remains required around Advance.
type RollbackAnchorStore interface {
	Load(
		context.Context,
		install.BootstrapKeyRef,
		install.OperationID,
		install.OwnerBinding,
	) (install.RollbackAnchor, error)
	Advance(
		context.Context,
		install.BootstrapKeyRef,
		uint64,
		install.RollbackAnchor,
	) error
	// ConfirmDurable re-authenticates the exact anchor and synchronizes any
	// persistent file and parent-directory entry needed to survive power loss.
	// It resolves an ambiguous post-replace error without weakening CAS.
	ConfirmDurable(
		context.Context,
		install.BootstrapKeyRef,
		install.RollbackAnchor,
	) error
}
