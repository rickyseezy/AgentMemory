// Package activereleaseapp coordinates the fail-closed PF-001 host/Core
// active-pointer transaction after the complete readiness receipt is durable.
package activereleaseapp

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/activerelease"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/readiness"
)

const (
	maximumReceiptAge  = 5 * time.Minute
	persistenceTimeout = 5 * time.Second
)

// Dependencies is the complete active-release composition contract.
type Dependencies struct {
	Clock             Clock
	ReadinessReceipts ReadinessReceiptRepository
	Activations       ActivationRepository
	HostPointers      HostPointerRepository
	CorePointers      CorePointerPort
}

// Application coordinates the journaled host/Core activation transaction.
type Application struct {
	clock             Clock
	readinessReceipts ReadinessReceiptRepository
	activations       ActivationRepository
	hostPointers      HostPointerRepository
	corePointers      CorePointerPort
}

// New rejects missing and typed-nil capabilities so no partial production
// composition can report an active release.
func New(dependencies Dependencies) (*Application, error) {
	required := []struct {
		name  string
		value any
	}{
		{name: "clock", value: dependencies.Clock},
		{name: "readiness receipt repository", value: dependencies.ReadinessReceipts},
		{name: "activation repository", value: dependencies.Activations},
		{name: "host pointer repository", value: dependencies.HostPointers},
		{name: "Core pointer port", value: dependencies.CorePointers},
	}
	for _, dependency := range required {
		if nilDependency(dependency.value) {
			return nil, fmt.Errorf("active release dependency %q is required", dependency.name)
		}
	}
	return &Application{
		clock:             dependencies.Clock,
		readinessReceipts: dependencies.ReadinessReceipts,
		activations:       dependencies.Activations,
		hostPointers:      dependencies.HostPointers,
		corePointers:      dependencies.CorePointers,
	}, nil
}

// Commit resumes the activation saga until the authenticated host pointer and
// Core mirror both match. It never treats container health as authorization.
func (a *Application) Commit(ctx context.Context, command Command) (Result, error) {
	if ctx == nil {
		return Result{}, applicationError(ErrorCodeInvalidArgument, false)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, applicationError(ErrorCodeDeadlineExceeded, true)
	}
	now := a.clock.Now().UTC().Truncate(time.Microsecond)
	if now.IsZero() || command.OperationID.IsZero() || command.PlanDigest.IsZero() ||
		command.ReadinessReceiptDigest.IsZero() {
		return Result{}, applicationError(ErrorCodeInvalidArgument, false)
	}
	receipt, err := a.readinessReceipts.LoadReadinessReceipt(ctx, command.ReadinessReceiptDigest)
	if err != nil {
		return Result{}, mapReceiptError(err)
	}
	if !receiptMatches(command, receipt, now) {
		return Result{}, applicationError(ErrorCodeReadinessRequired, false)
	}

	activation, loaded, err := a.loadOrCreate(ctx, command, receipt, now)
	if err != nil {
		return Result{}, err
	}
	alreadyCommitted := loaded && activation.State() == activerelease.StateCommitted

	for activation.State() != activerelease.StateCommitted {
		if err := ctx.Err(); err != nil {
			return Result{}, applicationError(ErrorCodeDeadlineExceeded, true)
		}
		switch activation.State() {
		case activerelease.StateCreated:
			stageDigest, stageError := a.corePointers.Stage(ctx, command.OperationID, activation.Pointer(), receipt)
			if stageError != nil {
				return Result{}, mapDependencyError(stageError)
			}
			if transitionError := activation.RecordCorePrepared(stageDigest); transitionError != nil {
				return Result{}, applicationError(ErrorCodeInternal, false)
			}
			if saveError := a.saveFresh(ctx, activation); saveError != nil {
				return Result{}, saveError
			}
		case activerelease.StateCorePrepared:
			if hostError := a.commitHost(ctx, activation); hostError != nil {
				return Result{}, hostError
			}
			if transitionError := activation.RecordHostCommitted(activation.Pointer().Digest()); transitionError != nil {
				return Result{}, applicationError(ErrorCodeInternal, false)
			}
			if saveError := a.saveFresh(ctx, activation); saveError != nil {
				return Result{}, saveError
			}
		case activerelease.StateHostCommitted:
			pointerDigest, commitError := a.corePointers.Commit(
				ctx,
				command.OperationID,
				activation.CoreStageDigest(),
				activation.Pointer(),
			)
			if commitError != nil {
				return Result{}, mapDependencyError(commitError)
			}
			if transitionError := activation.RecordCoreCommitted(activation.CoreStageDigest(), pointerDigest); transitionError != nil {
				return Result{}, applicationError(ErrorCodeIntegrityViolation, false)
			}
			if saveError := a.saveFresh(ctx, activation); saveError != nil {
				return Result{}, saveError
			}
		case activerelease.StateUnknown, activerelease.StateCommitted:
			return Result{}, applicationError(ErrorCodeInternal, false)
		}
	}

	if err := a.verifyAgreement(ctx, activation.Pointer()); err != nil {
		return Result{}, err
	}
	return Result{
		Status:        StatusCommitted,
		AlreadyActive: alreadyCommitted,
		PointerDigest: activation.Pointer().Digest(),
	}, nil
}

func (a *Application) loadOrCreate(
	ctx context.Context,
	command Command,
	receipt readiness.Receipt,
	now time.Time,
) (*activerelease.Activation, bool, error) {
	activation, err := a.activations.Load(ctx, command.OperationID)
	if err == nil {
		if activation == nil {
			return nil, false, applicationError(ErrorCodeIntegrityViolation, false)
		}
		if !activation.PlanDigest().Equal(command.PlanDigest) || !pointerMatchesCommand(activation.Pointer(), command) {
			return nil, false, applicationError(ErrorCodeConflict, false)
		}
		return activation, true, nil
	}
	if !errors.Is(err, ErrActivationNotFound) {
		return nil, false, mapActivationRepositoryError(err)
	}

	target, pointerError := activerelease.NewPointer(activerelease.PointerInput{
		InstallationID:           command.InstallationID,
		ReleaseID:                command.ReleaseID,
		GenerationID:             command.GenerationID,
		ManifestDigest:           command.ManifestDigest,
		ComposeDigest:            command.ComposeDigest,
		ReadinessReceiptDigest:   receipt.Digest(),
		RuntimeEndpoint:          command.RuntimeEndpoint,
		ReleaseSequence:          command.ReleaseSequence,
		ResourceInventoryVersion: command.ResourceInventoryVersion,
		ResourceInventoryDigest:  command.ResourceInventoryDigest,
		SecurityEpoch:            command.SecurityEpoch,
		ActivatedAt:              now,
	})
	if pointerError != nil {
		return nil, false, applicationError(ErrorCodeInvalidArgument, false)
	}
	current, loadError := a.hostPointers.Load(ctx, command.InstallationID)
	if loadError != nil && !errors.Is(loadError, ErrPointerNotFound) {
		return nil, false, mapPointerError(loadError)
	}
	if decision := activerelease.DecideReplacement(current, target); decision == activerelease.DecisionConflict {
		return nil, false, applicationError(ErrorCodeConflict, false)
	}
	expected := install.Digest{}
	if !current.IsZero() {
		expected = current.Digest()
	}
	activation, activationError := activerelease.NewActivation(command.OperationID, command.PlanDigest, expected, target)
	if activationError != nil {
		return nil, false, applicationError(ErrorCodeInvalidArgument, false)
	}
	if saveError := a.saveFresh(ctx, activation); saveError != nil {
		return nil, false, saveError
	}
	return activation, false, nil
}

func (a *Application) commitHost(ctx context.Context, activation *activerelease.Activation) error {
	current, err := a.hostPointers.Load(ctx, activation.Pointer().InstallationID())
	switch {
	case errors.Is(err, ErrPointerNotFound):
		if !activation.ExpectedHostDigest().IsZero() {
			return applicationError(ErrorCodeConflict, false)
		}
		if casError := a.hostPointers.CompareAndSwap(ctx, install.Digest{}, activation.Pointer()); casError != nil {
			return mapPointerError(casError)
		}
	case err != nil:
		return mapPointerError(err)
	case current.Digest().Equal(activation.Pointer().Digest()):
		// Reconcile a crash after the successful host CAS but before saga save.
	case current.Digest().Equal(activation.ExpectedHostDigest()):
		if casError := a.hostPointers.CompareAndSwap(ctx, activation.ExpectedHostDigest(), activation.Pointer()); casError != nil {
			return mapPointerError(casError)
		}
	default:
		return applicationError(ErrorCodeConflict, false)
	}
	if confirmError := a.hostPointers.ConfirmDurable(ctx, activation.Pointer()); confirmError != nil {
		return mapPointerError(confirmError)
	}
	return nil
}

func (a *Application) verifyAgreement(ctx context.Context, target activerelease.Pointer) error {
	current, err := a.hostPointers.Load(ctx, target.InstallationID())
	if err != nil {
		return mapPointerError(err)
	}
	if !current.Digest().Equal(target.Digest()) {
		return applicationError(ErrorCodeIntegrityViolation, false)
	}
	matches, err := a.corePointers.Matches(ctx, target)
	if err != nil {
		return mapDependencyError(err)
	}
	if !matches {
		return applicationError(ErrorCodeIntegrityViolation, false)
	}
	return nil
}

func (a *Application) saveFresh(parent context.Context, activation *activerelease.Activation) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), persistenceTimeout)
	defer cancel()
	if err := a.activations.Save(ctx, activation.Snapshot()); err != nil {
		return mapActivationRepositoryError(err)
	}
	return nil
}

func receiptMatches(command Command, receipt readiness.Receipt, now time.Time) bool {
	return !receipt.IsZero() && receipt.Digest().Equal(command.ReadinessReceiptDigest) &&
		receipt.OperationID() == command.OperationID && receipt.PlanDigest().Equal(command.PlanDigest) &&
		receipt.ReleaseID() == command.ReleaseID && receipt.GenerationID() == command.GenerationID &&
		receipt.ManifestDigest().Equal(command.ManifestDigest) && receipt.ComposeDigest().Equal(command.ComposeDigest) &&
		!receipt.EvaluatedAt().After(now) && now.Sub(receipt.EvaluatedAt()) <= maximumReceiptAge
}

func pointerMatchesCommand(pointer activerelease.Pointer, command Command) bool {
	return pointer.InstallationID() == command.InstallationID && pointer.ReleaseID() == command.ReleaseID &&
		pointer.GenerationID() == command.GenerationID && pointer.ManifestDigest().Equal(command.ManifestDigest) &&
		pointer.ComposeDigest().Equal(command.ComposeDigest) &&
		pointer.ReadinessReceiptDigest().Equal(command.ReadinessReceiptDigest) &&
		pointer.RuntimeEndpoint() == command.RuntimeEndpoint && pointer.ReleaseSequence() == command.ReleaseSequence &&
		pointer.ResourceInventoryVersion() == command.ResourceInventoryVersion &&
		pointer.ResourceInventoryDigest().Equal(command.ResourceInventoryDigest) &&
		pointer.SecurityEpoch() == command.SecurityEpoch
}

func mapReceiptError(err error) *ApplicationError {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return applicationError(ErrorCodeDeadlineExceeded, true)
	case errors.Is(err, ErrReadinessReceiptNotFound):
		return applicationError(ErrorCodeReadinessRequired, false)
	case errors.Is(err, ErrReadinessReceiptIntegrity):
		return applicationError(ErrorCodeIntegrityViolation, false)
	default:
		return applicationError(ErrorCodePersistence, true)
	}
}

func mapActivationRepositoryError(err error) *ApplicationError {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return applicationError(ErrorCodeDeadlineExceeded, true)
	case errors.Is(err, ErrActivationConflict):
		return applicationError(ErrorCodeConflict, true)
	case errors.Is(err, ErrActivationIntegrity):
		return applicationError(ErrorCodeIntegrityViolation, false)
	default:
		return applicationError(ErrorCodePersistence, true)
	}
}

func mapPointerError(err error) *ApplicationError {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return applicationError(ErrorCodeDeadlineExceeded, true)
	case errors.Is(err, ErrPointerConflict):
		return applicationError(ErrorCodeConflict, false)
	case errors.Is(err, ErrPointerIntegrity), errors.Is(err, ErrPointerNotFound):
		return applicationError(ErrorCodeIntegrityViolation, false)
	default:
		return applicationError(ErrorCodePersistence, true)
	}
}

func mapDependencyError(err error) *ApplicationError {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return applicationError(ErrorCodeDeadlineExceeded, true)
	}
	return applicationError(ErrorCodeDependencyUnavailable, true)
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid,
		reflect.Bool,
		reflect.Int,
		reflect.Int8,
		reflect.Int16,
		reflect.Int32,
		reflect.Int64,
		reflect.Uint,
		reflect.Uint8,
		reflect.Uint16,
		reflect.Uint32,
		reflect.Uint64,
		reflect.Uintptr,
		reflect.Float32,
		reflect.Float64,
		reflect.Complex64,
		reflect.Complex128,
		reflect.Array,
		reflect.String,
		reflect.Struct,
		reflect.UnsafePointer:
		return false
	}
	return false
}
