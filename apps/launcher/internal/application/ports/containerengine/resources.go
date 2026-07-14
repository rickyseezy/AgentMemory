package containerengine

import (
	"context"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/resourceinventory"
)

var (
	// ErrManagedResourceNotFound is returned only after a successful exact-name
	// engine listing proves no such object exists.
	ErrManagedResourceNotFound = errors.New("managed Docker resource not found")
	// ErrManagedResourceOperation means the addressed Docker command failed.
	ErrManagedResourceOperation = errors.New("managed Docker resource operation failed")
	// ErrManagedResourceResponse means bounded machine output was malformed,
	// ambiguous, truncated, or contradicted the closed resource policy.
	ErrManagedResourceResponse = errors.New("invalid managed Docker resource response")
	// ErrManagedResourceCollision means an exact name belongs to another object
	// or does not carry the exact authenticated inventory labels.
	ErrManagedResourceCollision = errors.New("managed Docker resource collision")
)

// ManagedResourcePort is the narrow argv-only Docker resource boundary. Remove
// accepts only a token minted by the authenticated domain inventory.
type ManagedResourcePort interface {
	Inspect(context.Context, Endpoint, resourceinventory.Spec) (resourceinventory.Observed, error)
	Create(context.Context, Endpoint, resourceinventory.Spec) (resourceinventory.Observed, error)
	Remove(context.Context, Endpoint, resourceinventory.RemovalAuthorization) error
}
