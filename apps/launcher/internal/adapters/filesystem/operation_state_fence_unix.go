//go:build darwin || linux

package filesystem

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const operationStateLockLeaf = "operation-state.lock"

// NativeOperationStateFence is a short owner-only descriptor-anchored flock,
// separate from the machine mutation lock.
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

// WithExclusive holds the cross-process fence only for one journal transaction.
func (f *NativeOperationStateFence) WithExclusive(
	ctx context.Context,
	operationID install.OperationID,
	action func() error,
) (result error) {
	if ctx == nil || operationID.IsZero() || action == nil || f == nil || f.locator == nil {
		return errors.New("operation state fence binding is invalid")
	}
	directory, err := f.locator.OperationDirectory(operationID)
	if err != nil {
		return err
	}
	if err := ensureOperationStateFenceDirectory(ctx, f.locator.Root(), directory); err != nil {
		return err
	}
	directoryInfo, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, root.Close()) }()
	openedDirectoryInfo, err := root.Stat(".")
	if err != nil || !os.SameFile(directoryInfo, openedDirectoryInfo) {
		return errors.New("operation state fence directory changed while opening")
	}
	file, err := root.OpenFile(operationStateLockLeaf, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("operation state fence file is not owner-only and regular")
	}
	if err := verifyOpenedProtectedObject(ctx, file, info, "operation_state_fence"); err != nil {
		return err
	}

	delay := cancellationPollMinimum
	for {
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			break
		} else if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return err
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
		if delay < cancellationPollMaximum {
			delay *= 2
			if delay > cancellationPollMaximum {
				delay = cancellationPollMaximum
			}
		}
	}
	defer func() { result = errors.Join(result, syscall.Flock(int(file.Fd()), syscall.LOCK_UN)) }()
	currentDirectory, err := os.Lstat(directory)
	if err != nil || !os.SameFile(directoryInfo, currentDirectory) {
		return errors.New("operation state fence directory changed while locked")
	}
	openedAgain, err := root.Open(filepath.Base(operationStateLockLeaf))
	if err != nil {
		return err
	}
	reopenedInfo, statError := openedAgain.Stat()
	closeError := openedAgain.Close()
	if statError != nil || closeError != nil || !os.SameFile(info, reopenedInfo) {
		return errors.New("operation state fence path changed while locked")
	}
	return action()
}
