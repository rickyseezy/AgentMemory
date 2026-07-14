//go:build windows

package filesystem

import (
	"context"
	"errors"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const operationStateMutexPrefix = "agentmemory:pf001:operation-state-fence:v1:"

// NativeOperationStateFence uses a protected owner-only Windows kernel mutex
// while retaining the verified operation-directory handle for the transaction.
type NativeOperationStateFence struct {
	locator *bootstrapadapter.OperationLocator
}

// NewNativeOperationStateFence binds the fence to the secured bootstrap root.
func NewNativeOperationStateFence(locator *bootstrapadapter.OperationLocator) (*NativeOperationStateFence, error) {
	if locator == nil {
		return nil, errors.New("operation state fence locator is required")
	}
	return &NativeOperationStateFence{locator: locator}, nil
}

// WithExclusive holds the named mutex only for one journal transaction.
func (f *NativeOperationStateFence) WithExclusive(
	ctx context.Context,
	operationID install.OperationID,
	action func() error,
) error {
	if ctx == nil || operationID.IsZero() || action == nil || f == nil || f.locator == nil {
		return errors.New("operation state fence binding is invalid")
	}
	directory, err := f.locator.OperationDirectory(operationID)
	if err != nil {
		return err
	}
	name, err := windowssecurity.OwnerMutexName(operationStateMutexPrefix + operationID.String())
	if err != nil {
		return err
	}
	return windowssecurity.WithOperationDirectory(ctx, f.locator.Root(), directory, true, func() error {
		return windowssecurity.WithOwnerMutex(ctx, name, action)
	})
}
