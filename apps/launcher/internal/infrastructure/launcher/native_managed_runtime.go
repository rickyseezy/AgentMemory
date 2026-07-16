package launcher

import (
	"context"
	"errors"
	"sync"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installphase"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeinstallapp"
)

// managedNativeRuntimeApplication owns every short-lived native runtime
// resource for both Linux and desktop compositions.
type managedNativeRuntimeApplication struct {
	application installphase.RuntimeEnsurer
	closers     []nativeRuntimeResourceCloser
	closeOnce   sync.Once
	closeError  error
}

func (a *managedNativeRuntimeApplication) Ensure(
	ctx context.Context,
	command runtimeinstallapp.Command,
) (runtimeinstallapp.Result, error) {
	if a == nil || nilAny(a.application) {
		return runtimeinstallapp.Result{}, errNativeInstallerIntegrity
	}
	result, ensureError := a.application.Ensure(ctx, command)
	closeError := a.Close(context.WithoutCancel(ctx))
	if closeError != nil {
		return result, errors.Join(ensureError, errNativeInstallerUnavailable)
	}
	return result, ensureError
}

func (a *managedNativeRuntimeApplication) Cancel(
	ctx context.Context,
	command runtimeinstallapp.Command,
) (runtimeinstallapp.Result, error) {
	if a == nil || nilAny(a.application) {
		return runtimeinstallapp.Result{}, errNativeInstallerIntegrity
	}
	result, cancellationError := a.application.Cancel(ctx, command)
	closeError := a.Close(context.WithoutCancel(ctx))
	if closeError != nil {
		return result, errors.Join(cancellationError, errNativeInstallerUnavailable)
	}
	return result, cancellationError
}

func (a *managedNativeRuntimeApplication) Close(ctx context.Context) error {
	if a == nil {
		return nil
	}
	a.closeOnce.Do(func() { a.closeError = closeNativeRuntimeResources(ctx, a.closers) })
	return a.closeError
}

func closeNativeRuntimeResources(ctx context.Context, closers []nativeRuntimeResourceCloser) error {
	var closeErrors []error
	for index := len(closers) - 1; index >= 0; index-- {
		if !nilAny(closers[index]) {
			if err := closers[index].Close(ctx); err != nil {
				closeErrors = append(closeErrors, err)
			}
		}
	}
	return errors.Join(closeErrors...)
}

var _ installphase.RuntimeEnsurer = (*managedNativeRuntimeApplication)(nil)
