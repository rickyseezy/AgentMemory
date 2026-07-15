// Package portablebootstrap keeps one MCP bootstrap session alive while the
// signed host package installs the native AgentMemory product, then adopts the
// authenticated native bootstrap surface without proxying stdio.
package portablebootstrap

import (
	"context"
	"errors"
	"math"
	"reflect"
	"sync"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/mcpbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpbootstrapapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/setupprogressapp"
)

const (
	portableInstallationID = "agentmemory-native-package"
	portableOperationID    = "native-package-install"
)

var (
	errPortableIntegrity   = errors.New("AM_SETUP_INTEGRITY")
	errPortableUnavailable = errors.New("AM_SETUP_UNAVAILABLE")
	errPortableConflict    = errors.New("AM_SETUP_CONFLICT")
)

// Installer installs and proves the exact publication-selected native
// package. It must settle only after installed-file postconditions pass.
type Installer interface {
	InstallNativePackage(context.Context) error
}

// Lifecycle owns every resource created with an adopted native surface.
type Lifecycle interface {
	Close(context.Context) error
}

// Surface is the transport-free native bootstrap unit adopted after package
// installation. Every capability is mandatory.
type Surface struct {
	Application mcpbootstrap.BootstrapApplication
	Ready       mcpbootstrap.ReadySurfaceProvider
	Lifecycle   Lifecycle
}

func (s Surface) valid() bool {
	return !nilCapability(s.Application) && !nilCapability(s.Ready) && !nilCapability(s.Lifecycle)
}

// SurfaceFactory builds the installed product's authenticated first-start
// surface from fixed package-manager-owned paths.
type SurfaceFactory interface {
	BuildInstalledSurface(context.Context) (Surface, error)
}

// Bridge is both the temporary bootstrap application and eventual Ready
// provider. It owns one background native package transaction.
type Bridge struct {
	ctx       context.Context
	cancel    context.CancelFunc
	installer Installer
	factory   SurfaceFactory
	done      chan struct{}

	mu      sync.RWMutex
	updated chan struct{}
	status  mcpbootstrapapp.InstallationStatus
	surface *Surface
	offset  uint64

	closeOnce sync.Once
	closeErr  error
}

// New starts exactly one background transaction after validating every
// capability. MCP construction can proceed immediately on the returned
// bridge.
func New(parent context.Context, installer Installer, factory SurfaceFactory) (*Bridge, error) {
	if parent == nil || nilCapability(installer) || nilCapability(factory) {
		return nil, errPortableIntegrity
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	bridge := &Bridge{
		ctx: ctx, cancel: cancel, installer: installer, factory: factory,
		done: make(chan struct{}), updated: make(chan struct{}), status: initialStatus(),
	}
	go bridge.run(ctx)
	return bridge, nil
}

func initialStatus() mcpbootstrapapp.InstallationStatus {
	return mcpbootstrapapp.InstallationStatus{
		ContractVersion:  setupprogressapp.ContractVersion,
		Sequence:         1,
		InstallationID:   portableInstallationID,
		OperationID:      portableOperationID,
		State:            string(setupprogressapp.StateRunning),
		Phase:            string(setupprogressapp.PhaseVerifyRelease),
		TotalStages:      1,
		MessageKey:       string(setupprogressapp.MessageVerifying),
		MessageArguments: make([]mcpbootstrapapp.MessageArgument, 0),
		Interaction:      mcpbootstrapapp.InteractionNone,
		Cancellable:      true,
	}
}

func (b *Bridge) run(ctx context.Context) {
	defer close(b.done)
	if err := b.installer.InstallNativePackage(ctx); err != nil {
		b.publishTerminal(err)
		return
	}
	if err := ctx.Err(); err != nil {
		b.publishTerminal(err)
		return
	}
	surface, err := b.factory.BuildInstalledSurface(ctx)
	if err != nil || !surface.valid() {
		if surface.valid() {
			_ = surface.Lifecycle.Close(context.WithoutCancel(ctx))
		}
		b.publishTerminal(errPortableUnavailable)
		return
	}
	if err := ctx.Err(); err != nil {
		_ = surface.Lifecycle.Close(context.WithoutCancel(ctx))
		b.publishTerminal(err)
		return
	}
	b.mu.Lock()
	b.offset = b.status.Sequence
	b.surface = &surface
	b.notifyLocked()
	b.mu.Unlock()
}

func (b *Bridge) publishTerminal(cause error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.surface != nil || b.status.State == string(setupprogressapp.StateCancelled) {
		return
	}
	b.status.Sequence++
	b.status.Cancellable = false
	b.status.CompletedStages = 0
	b.status.ReadyHandoffPending = false
	if errors.Is(cause, context.Canceled) {
		b.status.State = string(setupprogressapp.StateCancelled)
		b.status.MessageKey = string(setupprogressapp.MessageCancelled)
		b.status.Error = nil
	} else {
		b.status.State = string(setupprogressapp.StateFailed)
		b.status.MessageKey = string(setupprogressapp.MessageRetryableFailure)
		b.status.Error = &mcpbootstrapapp.StatusError{Code: "AM_DEPENDENCY_UNAVAILABLE", Retryable: true}
	}
	b.notifyLocked()
}

func (b *Bridge) notifyLocked() {
	close(b.updated)
	b.updated = make(chan struct{})
}

// Status returns only stable progress or the adopted native projection.
func (b *Bridge) Status(ctx context.Context) (mcpbootstrapapp.InstallationStatus, error) {
	if b == nil || ctx == nil {
		return mcpbootstrapapp.InstallationStatus{}, errPortableIntegrity
	}
	if err := ctx.Err(); err != nil {
		return mcpbootstrapapp.InstallationStatus{}, err
	}
	b.mu.RLock()
	surface, offset, local := b.surface, b.offset, b.status
	b.mu.RUnlock()
	if surface == nil {
		return local, nil
	}
	status, err := surface.Application.Status(ctx)
	return mapStatus(status, offset, err)
}

// WaitAfter preserves a single monotonic sequence namespace across the
// temporary and adopted applications.
func (b *Bridge) WaitAfter(
	ctx context.Context,
	after uint64,
) (mcpbootstrapapp.InstallationStatus, error) {
	if b == nil || ctx == nil {
		return mcpbootstrapapp.InstallationStatus{}, errPortableIntegrity
	}
	for {
		if err := ctx.Err(); err != nil {
			return mcpbootstrapapp.InstallationStatus{}, err
		}
		b.mu.RLock()
		surface, offset, local, updated := b.surface, b.offset, b.status, b.updated
		b.mu.RUnlock()
		if surface != nil {
			if after <= offset {
				status, err := surface.Application.Status(ctx)
				return mapStatus(status, offset, err)
			}
			status, err := surface.Application.WaitAfter(ctx, after-offset)
			return mapStatus(status, offset, err)
		}
		if local.Sequence > after {
			return local, nil
		}
		select {
		case <-updated:
		case <-ctx.Done():
			return mcpbootstrapapp.InstallationStatus{}, ctx.Err()
		}
	}
}

// OpenSetup delegates only after the installed setup controller exists. The
// native package manager itself owns any earlier OS prompt.
func (b *Bridge) OpenSetup(ctx context.Context) (mcpbootstrapapp.OpenSetupResult, error) {
	if b == nil || ctx == nil {
		return mcpbootstrapapp.OpenSetupResult{}, errPortableIntegrity
	}
	if err := ctx.Err(); err != nil {
		return mcpbootstrapapp.OpenSetupResult{}, err
	}
	b.mu.RLock()
	surface := b.surface
	b.mu.RUnlock()
	if surface == nil {
		return mcpbootstrapapp.OpenSetupResult{}, errPortableUnavailable
	}
	return surface.Application.OpenSetup(ctx)
}

// Cancel cancels the package transaction before adoption or delegates to the
// durable native installation cancellation authority afterward.
func (b *Bridge) Cancel(ctx context.Context) (mcpbootstrapapp.CancelResult, error) {
	if b == nil || ctx == nil {
		return mcpbootstrapapp.CancelResult{}, errPortableIntegrity
	}
	if err := ctx.Err(); err != nil {
		return mcpbootstrapapp.CancelResult{}, err
	}
	b.mu.RLock()
	surface, offset, state := b.surface, b.offset, b.status.State
	b.mu.RUnlock()
	if surface != nil {
		result, err := surface.Application.Cancel(ctx)
		if err != nil {
			return mcpbootstrapapp.CancelResult{}, err
		}
		mapped, err := mapStatus(result.Status, offset, nil)
		if err != nil {
			return mcpbootstrapapp.CancelResult{}, err
		}
		result.Status = mapped
		return result, nil
	}
	if state != string(setupprogressapp.StateRunning) {
		return mcpbootstrapapp.CancelResult{}, errPortableConflict
	}
	b.cancel()
	b.publishTerminal(context.Canceled)
	status, err := b.Status(ctx)
	if err != nil {
		return mcpbootstrapapp.CancelResult{}, err
	}
	return mcpbootstrapapp.CancelResult{
		ContractVersion: setupprogressapp.ContractVersion,
		InstallationID:  portableInstallationID, OperationID: portableOperationID,
		CancellationRequested: true, Status: status,
	}, nil
}

// ReadySurface delegates only to the adopted authenticated native provider.
func (b *Bridge) ReadySurface(ctx context.Context) (mcpbootstrap.ReadySurface, error) {
	if b == nil || ctx == nil {
		return mcpbootstrap.ReadySurface{}, errPortableIntegrity
	}
	for {
		if err := ctx.Err(); err != nil {
			return mcpbootstrap.ReadySurface{}, err
		}
		b.mu.RLock()
		surface, state, updated := b.surface, b.status.State, b.updated
		b.mu.RUnlock()
		if surface != nil {
			return surface.Ready.ReadySurface(ctx)
		}
		if state == string(setupprogressapp.StateFailed) || state == string(setupprogressapp.StateCancelled) {
			return mcpbootstrap.ReadySurface{}, errPortableUnavailable
		}
		select {
		case <-updated:
		case <-ctx.Done():
			return mcpbootstrap.ReadySurface{}, ctx.Err()
		}
	}
}

// Close settles the package task and then closes exactly one adopted native
// lifecycle. It is safe to call repeatedly.
func (b *Bridge) Close(ctx context.Context) error {
	if b == nil || ctx == nil {
		return errPortableIntegrity
	}
	b.closeOnce.Do(func() {
		b.cancel()
		select {
		case <-b.done:
		case <-ctx.Done():
			b.closeErr = ctx.Err()
			return
		}
		b.mu.RLock()
		surface := b.surface
		b.mu.RUnlock()
		if surface != nil {
			if err := surface.Lifecycle.Close(ctx); err != nil {
				b.closeErr = errPortableUnavailable
			}
		}
	})
	return b.closeErr
}

func mapStatus(
	status mcpbootstrapapp.InstallationStatus,
	offset uint64,
	err error,
) (mcpbootstrapapp.InstallationStatus, error) {
	if err != nil {
		return mcpbootstrapapp.InstallationStatus{}, err
	}
	if status.Sequence == 0 || status.Sequence > math.MaxUint64-offset {
		return mcpbootstrapapp.InstallationStatus{}, errPortableIntegrity
	}
	status.Sequence += offset
	return status, nil
}

func nilCapability(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Every non-nilable concrete kind is a valid capability.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid:
		return true
	default:
		return false
	}
}

var (
	_ mcpbootstrap.BootstrapApplication = (*Bridge)(nil)
	_ mcpbootstrap.ReadySurfaceProvider = (*Bridge)(nil)
	_ Lifecycle                         = (*Bridge)(nil)
)
