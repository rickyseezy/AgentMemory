// Package resourceapp orchestrates crash-safe PF-001 Docker resource creation
// through an authenticated CAS inventory and a constrained engine port.
package resourceapp

import (
	"context"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/resourceinventory"
)

var (
	// ErrInventoryNotFound means no authenticated inventory exists yet.
	ErrInventoryNotFound = errors.New("resource inventory not found")
	// ErrInventoryIntegrity means authentication, strict decoding, rollback
	// protection, or domain restoration failed.
	ErrInventoryIntegrity = errors.New("resource inventory integrity failure")
	// ErrInventoryConflict means the repository CAS predecessor changed.
	ErrInventoryConflict = errors.New("resource inventory compare-and-swap conflict")
	// ErrInventoryPersistence means durable persistence could not complete.
	ErrInventoryPersistence = errors.New("resource inventory persistence failure")
)

// Repository stores the complete HMAC-authenticated inventory. Load must
// authenticate and rollback-check before returning. Save must durably CAS on
// expectedVersion; the initial zero-version snapshot is idempotent only when
// byte-equivalent and bound to the same installation.
type Repository interface {
	Load(context.Context, string) (resourceinventory.Snapshot, error)
	Save(context.Context, uint64, resourceinventory.Snapshot) error
}
