package installapp

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const finalizationTimeout = 5 * time.Second

// Dependencies is the composition-root contract for InstallApplication. Every
// dependency is mandatory; the constructor rejects nil and typed-nil ports.
type Dependencies struct {
	Operations          OperationRepository
	CancellationIntents CancellationIntentPort
	InstallationLock    InstallationLockPort
	HostVerification    HostVerificationPort
	ContainerRuntime    ContainerRuntimePort
	ReleaseVerification ReleaseVerificationPort
	SpaceReservation    SpaceReservationPort
	Directories         DirectoryPort
	Keys                KeyProvisioningPort
	ComposeBundle       ComposeBundlePort
	NetworkAndVolumes   NetworkVolumePort
	Migrations          MigrationPort
	CoreAndGraph        CoreGraphPort
	BrainBootstrap      BrainBootstrapPort
	AgentConfiguration  AgentConfigurationPort
	Readiness           ReadinessPort
	ActiveRelease       ActiveReleasePort
}

// InstallApplication is the concrete PF-001 use case. Named fields preserve
// the one-capability-per-phase boundary; there is no generic step executor or
// service locator.
type InstallApplication struct {
	operations          OperationRepository
	cancellationIntents CancellationIntentPort
	installationLock    InstallationLockPort
	hostVerification    HostVerificationPort
	containerRuntime    ContainerRuntimePort
	releaseVerification ReleaseVerificationPort
	spaceReservation    SpaceReservationPort
	directories         DirectoryPort
	keys                KeyProvisioningPort
	composeBundle       ComposeBundlePort
	networkAndVolumes   NetworkVolumePort
	migrations          MigrationPort
	coreAndGraph        CoreGraphPort
	brainBootstrap      BrainBootstrapPort
	agentConfiguration  AgentConfigurationPort
	readiness           ReadinessPort
	activeRelease       ActiveReleasePort
}

// NewInstallApplication creates a production-valid use case. Construction is
// impossible while any phase capability, lock, or repository is absent.
func NewInstallApplication(dependencies Dependencies) (*InstallApplication, error) {
	required := []struct {
		name  string
		value any
	}{
		{name: "operations", value: dependencies.Operations},
		{name: "cancellation intents", value: dependencies.CancellationIntents},
		{name: "installation lock", value: dependencies.InstallationLock},
		{name: "host verification", value: dependencies.HostVerification},
		{name: "container runtime", value: dependencies.ContainerRuntime},
		{name: "release verification", value: dependencies.ReleaseVerification},
		{name: "space reservation", value: dependencies.SpaceReservation},
		{name: "directories", value: dependencies.Directories},
		{name: "keys", value: dependencies.Keys},
		{name: "compose bundle", value: dependencies.ComposeBundle},
		{name: "network and volumes", value: dependencies.NetworkAndVolumes},
		{name: "migrations", value: dependencies.Migrations},
		{name: "core and graph", value: dependencies.CoreAndGraph},
		{name: "brain bootstrap", value: dependencies.BrainBootstrap},
		{name: "agent configuration", value: dependencies.AgentConfiguration},
		{name: "readiness", value: dependencies.Readiness},
		{name: "active release", value: dependencies.ActiveRelease},
	}
	for _, dependency := range required {
		if isNil(dependency.value) {
			return nil, fmt.Errorf("install application dependency %q is required", dependency.name)
		}
	}
	if !sameDependencyIdentity(dependencies.Operations, dependencies.CancellationIntents) {
		return nil, errors.New("operation repository and cancellation intents must share one atomic authority")
	}

	return &InstallApplication{
		operations:          dependencies.Operations,
		cancellationIntents: dependencies.CancellationIntents,
		installationLock:    dependencies.InstallationLock,
		hostVerification:    dependencies.HostVerification,
		containerRuntime:    dependencies.ContainerRuntime,
		releaseVerification: dependencies.ReleaseVerification,
		spaceReservation:    dependencies.SpaceReservation,
		directories:         dependencies.Directories,
		keys:                dependencies.Keys,
		composeBundle:       dependencies.ComposeBundle,
		networkAndVolumes:   dependencies.NetworkAndVolumes,
		migrations:          dependencies.Migrations,
		coreAndGraph:        dependencies.CoreAndGraph,
		brainBootstrap:      dependencies.BrainBootstrap,
		agentConfiguration:  dependencies.AgentConfiguration,
		readiness:           dependencies.Readiness,
		activeRelease:       dependencies.ActiveRelease,
	}, nil
}

func sameDependencyIdentity(left, right any) bool {
	leftValue := reflect.ValueOf(left)
	rightValue := reflect.ValueOf(right)
	return leftValue.IsValid() && rightValue.IsValid() && leftValue.Type() == rightValue.Type() &&
		leftValue.Kind() == reflect.Pointer && leftValue.Pointer() == rightValue.Pointer()
}

func isNil(value any) bool {
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

// Install starts or resumes PF-001 and runs until Ready or a durable pause or
// terminal outcome is reached.
func (a *InstallApplication) Install(
	ctx context.Context,
	command InstallCommand,
) (result InstallResult, returnedError error) {
	canonicalPlan := append([]byte(nil), command.CanonicalPlan...)
	command.CanonicalPlan = canonicalPlan
	if command.ResumeReceipt != nil {
		resumeReceipt := *command.ResumeReceipt
		command.ResumeReceipt = &resumeReceipt
	}
	operationID, planDigest, validationError := validateCommand(command)
	if validationError != nil {
		return InstallResult{}, validationError
	}

	lock, err := a.installationLock.Acquire(ctx)
	if err != nil {
		return InstallResult{OperationID: operationID.String()}, mapExternalBoundaryError(
			err, "installation lock could not be acquired",
		)
	}
	if isNil(lock) {
		return InstallResult{OperationID: operationID.String()}, internalError()
	}
	defer func() {
		releaseContext, cancelRelease := freshFinalizationContext(ctx)
		releaseError := lock.Release(releaseContext)
		cancelRelease()
		if releaseError != nil && returnedError == nil {
			returnedError = mapExternalBoundaryError(releaseError, "installation lock could not be released")
		}
	}()

	operation, err := a.operations.Load(ctx, operationID)
	loadedExisting := false
	switch {
	case err == nil && operation == nil:
		return InstallResult{OperationID: operationID.String()}, internalError()
	case err == nil:
		loadedExisting = true
	case errors.Is(err, ErrOperationIntegrity),
		errors.Is(err, ErrOperationConflict),
		isDeadlineBoundary(err):
		return InstallResult{OperationID: operationID.String()}, mapRepositoryError(
			err, "installation state could not be loaded",
		)
	case errors.Is(err, ErrOperationNotFound):
		operation, err = install.NewOperation(operationID, planDigest)
		if err != nil {
			return InstallResult{OperationID: operationID.String()}, mapDomainError(err)
		}
		if saveError := a.save(ctx, operation); saveError != nil {
			if reconciled, handled, reconciliationError := a.reconcileConcurrentCancellation(
				ctx, operation, canonicalPlan, saveError,
			); handled {
				return reconciled, reconciliationError
			}
			return resultFrom(operation, PhaseOutcomeUnknown, install.ResumeActionUnknown), saveError
		}
	default:
		return InstallResult{OperationID: operationID.String()}, mapRepositoryError(
			err, "installation state could not be loaded",
		)
	}
	var runtimeResumeReceipt *install.Digest
	if loadedExisting {
		if bindingError := operation.VerifyPlanBinding(planDigest); bindingError != nil {
			return resultFrom(operation, PhaseOutcomeUnknown, install.ResumeActionUnknown), mapDomainError(bindingError)
		}
		if terminalResult, releaseReason, terminal := replayableTerminalResult(operation); terminal {
			intent, hasIntent, intentError := a.observeCancellation(ctx, operation)
			if intentError != nil {
				terminalResult.ErrorCode = intentError.Code()
				return terminalResult, intentError
			}
			if hasIntent && operation.State() != install.StateCancelled {
				terminalResult.ErrorCode = ErrorCodeIntegrityViolation
				return terminalResult, cancellationIntegrityError()
			}
			if releaseReason != ReservationReleaseUnknown && reservationMayExist(operation) {
				if releaseError := a.releaseSpace(ctx, operation, canonicalPlan, releaseReason); releaseError != nil {
					terminalResult.ErrorCode = releaseError.Code()
					return terminalResult, releaseError
				}
			}
			if hasIntent {
				acknowledged, acknowledgeError := a.acknowledgeCancellation(ctx, operation, intent)
				if acknowledgeError != nil {
					terminalResult.ErrorCode = acknowledgeError.Code()
					return terminalResult, acknowledgeError
				}
				terminalResult.CancellationRequested = true
				terminalResult.CancellationSettled = acknowledged.Status == CancellationIntentAcknowledged
			}
			return terminalResult, nil
		}
		// Cancellation outranks resume gating. In particular, a reboot-pending
		// operation must be able to settle without requiring the continuation
		// receipt whose only purpose is to resume runtime provisioning.
		if cancellationResult, handled, cancellationError := a.cancelIfRequested(
			ctx, operation, canonicalPlan,
		); handled || cancellationError != nil {
			return cancellationResult, cancellationError
		}
		resumingRuntimeReboot := operation.State() == install.StateRebootPending && command.ResumeReceipt != nil
		resumeAction, resumeError := a.prepareExisting(ctx, operation, planDigest, command.ResumeReceipt)
		if resumeError != nil {
			return resultFrom(operation, PhaseOutcomeUnknown, resumeAction), resumeError
		}
		if resumingRuntimeReboot {
			receipt := *command.ResumeReceipt
			runtimeResumeReceipt = &receipt
		}
		switch resumeAction {
		case install.ResumeActionAlreadyReady:
			return resultFrom(operation, PhaseOutcomeCompleted, resumeAction), nil
		case install.ResumeActionAwaitVerification:
			paused := pausedResult(operation, PhaseOutcomeRebootRequired, ErrorCodeRebootRequired)
			paused.ResumeAction = resumeAction
			return paused, nil
		case install.ResumeActionUnknown,
			install.ResumeActionAlreadyRunning,
			install.ResumeActionCurrentPhase:
		}
	}

	for operation.State() == install.StateRunning {
		if cancellationResult, handled, cancellationError := a.cancelIfRequested(
			ctx, operation, canonicalPlan,
		); handled || cancellationError != nil {
			return cancellationResult, cancellationError
		}
		// The unchanged cursor is durably recorded immediately before every
		// side-effect boundary. An interrupted adapter can therefore only be
		// retried at the same first-unverified phase.
		if saveError := a.save(ctx, operation); saveError != nil {
			if reconciled, handled, reconciliationError := a.reconcileConcurrentCancellation(
				ctx, operation, canonicalPlan, saveError,
			); handled {
				return reconciled, reconciliationError
			}
			return resultFrom(operation, PhaseOutcomeUnknown, install.ResumeActionUnknown), saveError
		}
		if cancellationResult, handled, cancellationError := a.cancelIfRequested(
			ctx, operation, canonicalPlan,
		); handled || cancellationError != nil {
			return cancellationResult, cancellationError
		}

		phase := operation.CurrentPhase()
		request := newPhaseRequest(operation, canonicalPlan)
		if phase == install.PhaseEnsureContainerRuntime && runtimeResumeReceipt != nil {
			request = newRuntimeResumePhaseRequest(operation, canonicalPlan, *runtimeResumeReceipt)
		}
		output, watchedIntent, phaseError := a.dispatchWatchingCancellation(ctx, phase, request)
		if watchedIntent != nil {
			return a.settleCancellation(ctx, operation, canonicalPlan, *watchedIntent)
		}
		if phaseError != nil {
			var applicationBoundaryError *ApplicationError
			if errors.As(phaseError, &applicationBoundaryError) {
				result := resultFrom(operation, PhaseOutcomeUnknown, install.ResumeActionUnknown)
				result.ErrorCode = applicationBoundaryError.Code()
				return result, applicationBoundaryError
			}
			if isDeadlineBoundary(phaseError) {
				return a.failDeadline(ctx, operation, planDigest)
			}
			return a.failUnexpected(ctx, operation, planDigest)
		}
		if !output.validFor(phase) {
			return a.failInternal(ctx, operation, planDigest)
		}
		if cancellationResult, handled, cancellationError := a.cancelIfRequested(
			ctx, operation, canonicalPlan,
		); handled || cancellationError != nil {
			return cancellationResult, cancellationError
		}

		outcomeResult, continueInstall, outcomeError := a.applyOutput(operation, output)
		if outcomeError != nil {
			if failClosedDomainError(outcomeError) {
				return resultFrom(operation, output.outcome, install.ResumeActionUnknown), mapDomainError(outcomeError)
			}
			return a.failInternal(ctx, operation, planDigest)
		}
		if saveError := a.saveAfterTransition(ctx, operation); saveError != nil {
			if reconciled, handled, reconciliationError := a.reconcileConcurrentCancellation(
				ctx, operation, canonicalPlan, saveError,
			); handled {
				return reconciled, reconciliationError
			}
			return resultFrom(operation, output.outcome, install.ResumeActionUnknown), saveError
		}
		if !continueInstall {
			if releaseReason, required := terminalReservationRelease(operation, output.outcome); required {
				if releaseError := a.releaseSpace(ctx, operation, canonicalPlan, releaseReason); releaseError != nil {
					outcomeResult.ErrorCode = releaseError.Code()
					return outcomeResult, releaseError
				}
			}
			if operation.State() == install.StateCancelled {
				intent, hasIntent, intentError := a.observeCancellation(ctx, operation)
				if intentError != nil {
					outcomeResult.ErrorCode = intentError.Code()
					return outcomeResult, intentError
				}
				if hasIntent {
					acknowledged, acknowledgeError := a.acknowledgeCancellation(ctx, operation, intent)
					if acknowledgeError != nil {
						outcomeResult.ErrorCode = acknowledgeError.Code()
						return outcomeResult, acknowledgeError
					}
					outcomeResult.CancellationRequested = true
					outcomeResult.CancellationSettled = acknowledged.Status == CancellationIntentAcknowledged
				}
			}
			return outcomeResult, nil
		}
	}

	return resultFrom(operation, PhaseOutcomeCompleted, install.ResumeActionUnknown), nil
}

// Cancel records a durable plan-bound cancellation request without acquiring
// the machine mutation lock. The active Install invocation owns terminal
// transition, compensation, and acknowledgement; this method never reports
// settlement merely because a request was accepted.
func (a *InstallApplication) Cancel(
	ctx context.Context,
	command CancelCommand,
) (InstallResult, error) {
	if ctx == nil {
		return InstallResult{}, applicationError(ErrorCodeValidation, false, "installation cancellation request is invalid")
	}
	canonicalPlan := append([]byte(nil), command.CanonicalPlan...)
	operationID, planDigest, validationError := validateCommand(InstallCommand{
		OperationID: command.OperationID, CanonicalPlan: canonicalPlan,
	})
	if validationError != nil {
		return InstallResult{}, validationError
	}

	operation, err := a.operations.Load(ctx, operationID)
	if err != nil {
		return InstallResult{OperationID: operationID.String()}, mapRepositoryError(
			err, "installation state could not be loaded",
		)
	}
	if operation == nil {
		return InstallResult{OperationID: operationID.String()}, internalError()
	}
	if err := operation.VerifyPlanBinding(planDigest); err != nil {
		return resultFrom(operation, PhaseOutcomeUnknown, install.ResumeActionUnknown), mapDomainError(err)
	}
	if operation.State().Terminal() && operation.State() != install.StateCancelled {
		if err := operation.Cancel(planDigest); err != nil {
			return resultFrom(operation, PhaseOutcomeUnknown, install.ResumeActionUnknown), mapDomainError(err)
		}
	}

	if operation.State() == install.StateCancelled {
		intent, observeError := a.cancellationIntents.Observe(ctx, operationID, planDigest)
		switch {
		case observeError == nil:
			if !intent.ValidFor(operationID, planDigest) {
				return resultFrom(operation, PhaseOutcomeCancelled, install.ResumeActionUnknown), cancellationIntegrityError()
			}
			result := cancellationResult(operation, intent)
			return result, nil
		case errors.Is(observeError, ErrCancellationIntentNotFound):
			// A phase capability can independently return cancelled. That durable
			// state is truthful, but no request lifecycle is fabricated.
			return resultFrom(operation, PhaseOutcomeCancelled, install.ResumeActionUnknown), nil
		default:
			return resultFrom(operation, PhaseOutcomeCancelled, install.ResumeActionUnknown), mapCancellationIntentError(observeError)
		}
	}

	intent, requestError := a.cancellationIntents.Request(ctx, CancellationRequest{
		OperationID:              operationID,
		PlanDigest:               planDigest,
		ObservedAggregateVersion: operation.AggregateVersion(),
	})
	if requestError != nil {
		return resultFrom(operation, PhaseOutcomeUnknown, install.ResumeActionUnknown), mapCancellationIntentError(requestError)
	}
	if !intent.ValidFor(operationID, planDigest) {
		return resultFrom(operation, PhaseOutcomeUnknown, install.ResumeActionUnknown), cancellationIntegrityError()
	}
	return cancellationResult(operation, intent), nil
}

func terminalReservationRelease(
	operation *install.Operation,
	outcome PhaseOutcome,
) (ReservationReleaseReason, bool) {
	if !reservationMayExist(operation) {
		return ReservationReleaseUnknown, false
	}
	switch outcome {
	case PhaseOutcomeCompleted:
		if operation.State() == install.StateReady {
			return ReservationReleaseCompleted, true
		}
		return ReservationReleaseUnknown, false
	case PhaseOutcomeCancelled:
		return ReservationReleaseCancelled, true
	case PhaseOutcomeUnsupportedHost, PhaseOutcomeRuntimeConflict:
		return ReservationReleaseRollback, true
	case PhaseOutcomeUnknown, PhaseOutcomeFailedRecoverable,
		PhaseOutcomeAdministratorRequired, PhaseOutcomeRebootRequired:
		return ReservationReleaseUnknown, false
	}
	return ReservationReleaseUnknown, false
}

func replayableTerminalResult(
	operation *install.Operation,
) (InstallResult, ReservationReleaseReason, bool) {
	if operation == nil {
		return InstallResult{}, ReservationReleaseUnknown, false
	}
	switch operation.State() {
	case install.StateReady:
		return resultFrom(
			operation, PhaseOutcomeCompleted, install.ResumeActionAlreadyReady,
		), ReservationReleaseCompleted, true
	case install.StateCancelled:
		return resultFrom(
			operation, PhaseOutcomeCancelled, install.ResumeActionUnknown,
		), ReservationReleaseCancelled, true
	case install.StateUnsupportedHost:
		return pausedResult(
			operation, PhaseOutcomeUnsupportedHost, ErrorCodeUnsupportedHost,
		), ReservationReleaseRollback, true
	case install.StateRuntimeConflict:
		return pausedResult(
			operation, PhaseOutcomeRuntimeConflict, ErrorCodeRuntimeConflict,
		), ReservationReleaseRollback, true
	case install.StateUnknown, install.StateRunning, install.StateFailedRecoverable,
		install.StatePausedForAdministrator, install.StateRebootPending, install.StateResumeVerified:
		return InstallResult{}, ReservationReleaseUnknown, false
	}
	return InstallResult{}, ReservationReleaseUnknown, false
}

func reservationMayExist(operation *install.Operation) bool {
	return operation != nil && operation.CurrentPhase() >= install.PhaseReserveSpace
}

func (a *InstallApplication) releaseSpace(
	ctx context.Context,
	operation *install.Operation,
	canonicalPlan []byte,
	reason ReservationReleaseReason,
) *ApplicationError {
	cleanupContext, cancelCleanup := freshFinalizationContext(ctx)
	defer cancelCleanup()
	if err := a.spaceReservation.ReleaseSpace(
		cleanupContext, newPhaseRequest(operation, canonicalPlan), reason,
	); err != nil {
		return mapExternalBoundaryError(err, "installation reservation could not be released")
	}
	return nil
}

func validateCommand(command InstallCommand) (install.OperationID, install.PlanDigest, *ApplicationError) {
	operationID, err := install.NewOperationID(command.OperationID)
	if err != nil {
		return install.OperationID{}, install.PlanDigest{}, mapDomainError(err)
	}
	planDigest, err := install.BindPlan(command.CanonicalPlan)
	if err != nil {
		return install.OperationID{}, install.PlanDigest{}, mapDomainError(err)
	}
	if command.ResumeReceipt != nil && command.ResumeReceipt.IsZero() {
		return install.OperationID{}, install.PlanDigest{}, applicationError(
			ErrorCodeValidation, false, "installation request is invalid",
		)
	}
	return operationID, planDigest, nil
}

func (a *InstallApplication) prepareExisting(
	ctx context.Context,
	operation *install.Operation,
	planDigest install.PlanDigest,
	resumeReceipt *install.Digest,
) (install.ResumeAction, error) {
	if operation.State() == install.StateRebootPending && resumeReceipt != nil {
		if err := operation.VerifyResume(planDigest, *resumeReceipt); err != nil {
			return install.ResumeActionUnknown, mapDomainError(err)
		}
		if err := a.saveAfterTransition(ctx, operation); err != nil {
			return install.ResumeActionUnknown, err
		}
	}

	resumeAction, err := operation.Resume(planDigest)
	if err != nil {
		return resumeAction, mapDomainError(err)
	}
	if resumeAction == install.ResumeActionCurrentPhase {
		if err := a.saveAfterTransition(ctx, operation); err != nil {
			return resumeAction, err
		}
	}
	return resumeAction, nil
}

func (a *InstallApplication) dispatch(
	ctx context.Context,
	phase install.Phase,
	request PhaseRequest,
) (PhaseOutput, error) {
	switch phase {
	case install.PhaseUnknown:
		return PhaseOutput{}, applicationError(ErrorCodeIntegrityViolation, false, "installation phase is invalid")
	case install.PhaseVerifyHost:
		return a.hostVerification.VerifyHost(ctx, request)
	case install.PhaseEnsureContainerRuntime:
		return a.containerRuntime.EnsureContainerRuntime(ctx, request)
	case install.PhaseVerifyRelease:
		return a.releaseVerification.VerifyRelease(ctx, request)
	case install.PhaseReserveSpace:
		return a.spaceReservation.ReserveSpace(ctx, request)
	case install.PhaseEnsureDirectories:
		return a.directories.EnsureDirectories(ctx, request)
	case install.PhaseEnsureKeys:
		return a.keys.EnsureKeys(ctx, request)
	case install.PhaseEnsureComposeBundle:
		return a.composeBundle.EnsureComposeBundle(ctx, request)
	case install.PhaseEnsureNetworkAndVolumes:
		return a.networkAndVolumes.EnsureNetworkAndVolumes(ctx, request)
	case install.PhaseRunMigrations:
		return a.migrations.RunMigrations(ctx, request)
	case install.PhaseEnsureCoreAndGraph:
		return a.coreAndGraph.EnsureCoreAndGraph(ctx, request)
	case install.PhaseBootstrapLocalBrain:
		return a.brainBootstrap.BootstrapLocalBrain(ctx, request)
	case install.PhaseMergeAgentConfiguration:
		return a.agentConfiguration.MergeAgentConfiguration(ctx, request)
	case install.PhaseVerifyReadiness:
		return a.readiness.VerifyReadiness(ctx, request)
	case install.PhaseCommitActiveRelease:
		return a.activeRelease.CommitActiveRelease(ctx, request)
	}
	return PhaseOutput{}, applicationError(ErrorCodeIntegrityViolation, false, "installation phase is invalid")
}

type cancellationWatchResult struct {
	intent CancellationIntent
	err    error
}

// dispatchWatchingCancellation owns exactly one watcher and joins it before
// return. Wait is required to honor context cancellation, so no polling
// goroutine can survive its phase invocation.
func (a *InstallApplication) dispatchWatchingCancellation(
	ctx context.Context,
	phase install.Phase,
	request PhaseRequest,
) (PhaseOutput, *CancellationIntent, error) {
	phaseContext, cancelPhase := context.WithCancel(ctx)
	watchContext, stopWatch := context.WithCancel(ctx)
	watchResult := make(chan cancellationWatchResult, 1)
	go func() {
		intent, err := a.cancellationIntents.Wait(
			watchContext, request.OperationID(), request.PlanDigest(),
		)
		switch {
		case err == nil && !intent.ValidFor(request.OperationID(), request.PlanDigest()):
			err = ErrCancellationIntentIntegrity
		case err == nil && intent.Status == CancellationIntentRequested:
			cancelPhase()
		case err == nil:
			err = ErrCancellationIntentIntegrity
			cancelPhase()
		case !isDeadlineBoundary(err):
			cancelPhase()
		}
		watchResult <- cancellationWatchResult{intent: intent, err: err}
	}()

	output, phaseError := a.dispatch(phaseContext, phase, request)
	stopWatch()
	watched := <-watchResult
	cancelPhase()

	if watched.err == nil {
		intent := watched.intent
		return PhaseOutput{}, &intent, nil
	}
	if !isDeadlineBoundary(watched.err) {
		return PhaseOutput{}, nil, mapCancellationIntentError(watched.err)
	}
	if ctx.Err() != nil {
		return output, nil, phaseError
	}
	// The watcher is normally stopped after the phase returns. A final durable
	// observation closes the boundary between phase completion and transition.
	intent, observeError := a.cancellationIntents.Observe(
		ctx, request.OperationID(), request.PlanDigest(),
	)
	switch {
	case observeError == nil:
		if !intent.ValidFor(request.OperationID(), request.PlanDigest()) ||
			intent.Status != CancellationIntentRequested {
			return PhaseOutput{}, nil, cancellationIntegrityError()
		}
		return PhaseOutput{}, &intent, nil
	case errors.Is(observeError, ErrCancellationIntentNotFound):
		return output, nil, phaseError
	default:
		return PhaseOutput{}, nil, mapCancellationIntentError(observeError)
	}
}

func (a *InstallApplication) observeCancellation(
	ctx context.Context,
	operation *install.Operation,
) (CancellationIntent, bool, *ApplicationError) {
	intent, err := a.cancellationIntents.Observe(ctx, operation.ID(), operation.PlanDigest())
	switch {
	case err == nil:
		if !intent.ValidFor(operation.ID(), operation.PlanDigest()) {
			return CancellationIntent{}, false, cancellationIntegrityError()
		}
		if intent.Status == CancellationIntentAcknowledged && operation.State() != install.StateCancelled {
			return CancellationIntent{}, false, cancellationIntegrityError()
		}
		return intent, true, nil
	case errors.Is(err, ErrCancellationIntentNotFound):
		return CancellationIntent{}, false, nil
	default:
		return CancellationIntent{}, false, mapCancellationIntentError(err)
	}
}

func (a *InstallApplication) cancelIfRequested(
	ctx context.Context,
	operation *install.Operation,
	canonicalPlan []byte,
) (InstallResult, bool, error) {
	intent, found, err := a.observeCancellation(ctx, operation)
	if err != nil {
		result := resultFrom(operation, PhaseOutcomeUnknown, install.ResumeActionUnknown)
		result.ErrorCode = err.Code()
		return result, false, err
	}
	if !found {
		return InstallResult{}, false, nil
	}
	if intent.Status != CancellationIntentRequested {
		err := cancellationIntegrityError()
		result := resultFrom(operation, PhaseOutcomeUnknown, install.ResumeActionUnknown)
		result.ErrorCode = err.Code()
		return result, false, err
	}
	result, settleError := a.settleCancellation(ctx, operation, canonicalPlan, intent)
	return result, true, settleError
}

func (a *InstallApplication) settleCancellation(
	ctx context.Context,
	operation *install.Operation,
	canonicalPlan []byte,
	intent CancellationIntent,
) (InstallResult, error) {
	if !intent.ValidFor(operation.ID(), operation.PlanDigest()) ||
		intent.Status != CancellationIntentRequested {
		return resultFrom(operation, PhaseOutcomeUnknown, install.ResumeActionUnknown), cancellationIntegrityError()
	}
	if !aggregateContainsRequestedIntent(operation, intent) {
		refreshed, loadError := a.operations.Load(ctx, operation.ID())
		if loadError != nil {
			return resultFrom(operation, PhaseOutcomeUnknown, install.ResumeActionUnknown), mapRepositoryError(
				loadError, "installation state could not be refreshed for cancellation",
			)
		}
		if refreshed == nil || refreshed.VerifyPlanBinding(operation.PlanDigest()) != nil {
			return resultFrom(operation, PhaseOutcomeUnknown, install.ResumeActionUnknown), cancellationIntegrityError()
		}
		if !aggregateContainsRequestedIntent(refreshed, intent) {
			return resultFrom(refreshed, PhaseOutcomeUnknown, install.ResumeActionUnknown), cancellationIntegrityError()
		}
		operation = refreshed
	}
	if err := operation.Cancel(operation.PlanDigest()); err != nil {
		return resultFrom(operation, PhaseOutcomeUnknown, install.ResumeActionUnknown), mapDomainError(err)
	}
	result := resultFrom(operation, PhaseOutcomeCancelled, install.ResumeActionUnknown)
	result.CancellationRequested = true
	if err := a.saveAfterTransition(ctx, operation); err != nil {
		var applicationBoundaryError *ApplicationError
		if errors.As(err, &applicationBoundaryError) {
			result.ErrorCode = applicationBoundaryError.Code()
		}
		return result, err
	}
	if reservationMayExist(operation) {
		if releaseError := a.releaseSpace(ctx, operation, canonicalPlan, ReservationReleaseCancelled); releaseError != nil {
			result.ErrorCode = releaseError.Code()
			return result, releaseError
		}
	}
	acknowledged, acknowledgeError := a.acknowledgeCancellation(ctx, operation, intent)
	if acknowledgeError != nil {
		result.ErrorCode = acknowledgeError.Code()
		return result, acknowledgeError
	}
	result.CancellationSettled = acknowledged.Status == CancellationIntentAcknowledged
	return result, nil
}

func aggregateContainsRequestedIntent(operation *install.Operation, intent CancellationIntent) bool {
	if operation == nil || !intent.ValidFor(intent.OperationID, intent.PlanDigest) ||
		intent.Status != CancellationIntentRequested || operation.ID() != intent.OperationID ||
		!operation.PlanDigest().Equal(intent.PlanDigest) {
		return false
	}
	persisted, ok := operation.CancellationIntent()
	return ok && persisted.Status() == install.CancellationRequested &&
		persisted.RequestedAtVersion() == intent.Revision
}

func (a *InstallApplication) reconcileConcurrentCancellation(
	ctx context.Context,
	stale *install.Operation,
	canonicalPlan []byte,
	saveError error,
) (InstallResult, bool, error) {
	var applicationBoundaryError *ApplicationError
	if !errors.As(saveError, &applicationBoundaryError) || applicationBoundaryError.Code() != ErrorCodeConflict {
		return InstallResult{}, false, nil
	}
	current, loadError := a.operations.Load(ctx, stale.ID())
	if loadError != nil {
		if errors.Is(loadError, ErrOperationNotFound) {
			return InstallResult{}, false, nil
		}
		return resultFrom(stale, PhaseOutcomeUnknown, install.ResumeActionUnknown), true, mapRepositoryError(
			loadError, "installation state could not be reconciled",
		)
	}
	if current == nil || current.VerifyPlanBinding(stale.PlanDigest()) != nil {
		return resultFrom(stale, PhaseOutcomeUnknown, install.ResumeActionUnknown), true, cancellationIntegrityError()
	}
	intent, found, intentError := a.observeCancellation(ctx, current)
	if intentError != nil {
		return resultFrom(current, PhaseOutcomeUnknown, install.ResumeActionUnknown), true, intentError
	}
	if !found || intent.Status != CancellationIntentRequested {
		return InstallResult{}, false, nil
	}
	result, settleError := a.settleCancellation(ctx, current, canonicalPlan, intent)
	return result, true, settleError
}

func (a *InstallApplication) acknowledgeCancellation(
	ctx context.Context,
	operation *install.Operation,
	intent CancellationIntent,
) (CancellationIntent, *ApplicationError) {
	if operation.State() != install.StateCancelled ||
		!intent.ValidFor(operation.ID(), operation.PlanDigest()) {
		return CancellationIntent{}, cancellationIntegrityError()
	}
	if intent.Status == CancellationIntentAcknowledged {
		return intent, nil
	}
	finalizationContext, cancelFinalization := freshFinalizationContext(ctx)
	defer cancelFinalization()
	acknowledged, err := a.cancellationIntents.Acknowledge(
		finalizationContext, intent, install.StateCancelled,
	)
	if err != nil {
		return CancellationIntent{}, mapCancellationIntentError(err)
	}
	if !acknowledged.ValidFor(operation.ID(), operation.PlanDigest()) ||
		acknowledged.Status != CancellationIntentAcknowledged {
		return CancellationIntent{}, cancellationIntegrityError()
	}
	return acknowledged, nil
}

func cancellationResult(operation *install.Operation, intent CancellationIntent) InstallResult {
	result := resultFrom(operation, PhaseOutcomeUnknown, install.ResumeActionUnknown)
	result.CancellationRequested = intent.Status == CancellationIntentRequested ||
		intent.Status == CancellationIntentAcknowledged
	result.CancellationSettled = intent.Status == CancellationIntentAcknowledged &&
		operation.State() == install.StateCancelled
	if operation.State() == install.StateCancelled {
		result.Outcome = PhaseOutcomeCancelled
	}
	return result
}

func (a *InstallApplication) applyOutput(
	operation *install.Operation,
	output PhaseOutput,
) (InstallResult, bool, error) {
	planDigest := operation.PlanDigest()
	switch output.outcome {
	case PhaseOutcomeUnknown:
		return InstallResult{}, false, fmt.Errorf("unknown phase outcome")
	case PhaseOutcomeCompleted:
		evidence, err := install.NewStepEvidence(install.StepEvidenceInput{
			Phase:                  operation.CurrentPhase(),
			Attempt:                operation.Attempt(),
			PlanDigest:             planDigest,
			InputDigest:            output.completion.InputDigest,
			OutputDigest:           output.completion.OutputDigest,
			VerifiedArtifactDigest: output.completion.VerifiedArtifactDigest,
			Facts:                  output.completion.Facts,
			RuntimeOwnership:       output.completion.RuntimeOwnership,
			CompensationBoundary:   output.completion.CompensationBoundary,
			NextSafeAction:         output.completion.NextSafeAction,
		})
		if err != nil {
			return InstallResult{}, false, err
		}
		if err := operation.CompleteStep(evidence); err != nil {
			return InstallResult{}, false, err
		}
		return resultFrom(operation, output.outcome, install.ResumeActionUnknown), operation.State() == install.StateRunning, nil
	case PhaseOutcomeFailedRecoverable:
		if err := operation.FailRecoverable(planDigest); err != nil {
			return InstallResult{}, false, err
		}
		return pausedResultWithAction(operation, output, ErrorCodeDependencyUnavailable), false, nil
	case PhaseOutcomeAdministratorRequired:
		if err := operation.PauseForAdministrator(planDigest); err != nil {
			return InstallResult{}, false, err
		}
		return pausedResultWithAction(operation, output, ErrorCodeSetupAdminRequired), false, nil
	case PhaseOutcomeCancelled:
		if err := operation.Cancel(planDigest); err != nil {
			return InstallResult{}, false, err
		}
		return pausedResultWithAction(operation, output, ""), false, nil
	case PhaseOutcomeUnsupportedHost:
		if err := operation.MarkUnsupportedHost(planDigest); err != nil {
			return InstallResult{}, false, err
		}
		return pausedResultWithAction(operation, output, ErrorCodeUnsupportedHost), false, nil
	case PhaseOutcomeRuntimeConflict:
		if err := operation.MarkRuntimeConflict(planDigest); err != nil {
			return InstallResult{}, false, err
		}
		return pausedResultWithAction(operation, output, ErrorCodeRuntimeConflict), false, nil
	case PhaseOutcomeRebootRequired:
		checkpoint, err := install.NewRebootCheckpoint(
			planDigest,
			operation.CurrentPhase(),
			operation.Attempt(),
			output.resumeReceipt,
			output.nextAction,
		)
		if err != nil {
			return InstallResult{}, false, err
		}
		if err := operation.MarkRebootPending(planDigest, checkpoint); err != nil {
			return InstallResult{}, false, err
		}
		return pausedResultWithAction(operation, output, ErrorCodeRebootRequired), false, nil
	}
	return InstallResult{}, false, fmt.Errorf("unknown phase outcome")
}

func (a *InstallApplication) failUnexpected(
	ctx context.Context,
	operation *install.Operation,
	planDigest install.PlanDigest,
) (InstallResult, error) {
	return a.failInternal(ctx, operation, planDigest)
}

func (a *InstallApplication) failDeadline(
	ctx context.Context,
	operation *install.Operation,
	planDigest install.PlanDigest,
) (InstallResult, error) {
	return a.failRecoverable(ctx, operation, planDigest, PhaseOutcomeFailedRecoverable, deadlineError())
}

func (a *InstallApplication) failInternal(
	ctx context.Context,
	operation *install.Operation,
	planDigest install.PlanDigest,
) (InstallResult, error) {
	return a.failRecoverable(ctx, operation, planDigest, PhaseOutcomeFailedRecoverable, internalError())
}

func (a *InstallApplication) failRecoverable(
	ctx context.Context,
	operation *install.Operation,
	planDigest install.PlanDigest,
	outcome PhaseOutcome,
	publicError *ApplicationError,
) (InstallResult, error) {
	if err := operation.FailRecoverable(planDigest); err != nil {
		return resultFrom(operation, PhaseOutcomeUnknown, install.ResumeActionUnknown), mapDomainError(err)
	}
	if err := a.saveAfterTransition(ctx, operation); err != nil {
		return resultFrom(operation, outcome, install.ResumeActionUnknown), err
	}
	return pausedResult(operation, outcome, publicError.Code()), publicError
}

func (a *InstallApplication) save(ctx context.Context, operation *install.Operation) error {
	if err := a.operations.Save(ctx, operation.Snapshot()); err != nil {
		return mapRepositoryError(err, "installation state could not be saved")
	}
	return nil
}

func (a *InstallApplication) saveAfterTransition(ctx context.Context, operation *install.Operation) error {
	finalizationContext, cancelFinalization := freshFinalizationContext(ctx)
	defer cancelFinalization()
	return a.save(finalizationContext, operation)
}

func freshFinalizationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), finalizationTimeout)
}

func resultFrom(operation *install.Operation, outcome PhaseOutcome, resumeAction install.ResumeAction) InstallResult {
	return InstallResult{
		OperationID:    operation.ID().String(),
		State:          operation.State(),
		CurrentPhase:   operation.CurrentPhase(),
		CompletedSteps: len(operation.CompletedEvidence()),
		ResumeAction:   resumeAction,
		Outcome:        outcome,
	}
}

func pausedResult(operation *install.Operation, outcome PhaseOutcome, code ErrorCode) InstallResult {
	result := resultFrom(operation, outcome, install.ResumeActionUnknown)
	result.ErrorCode = code
	if checkpoint, ok := operation.Snapshot().RebootCheckpoint(); ok {
		result.NextSafeAction = checkpoint.NextSafeAction().String()
	}
	return result
}

func pausedResultWithAction(operation *install.Operation, output PhaseOutput, code ErrorCode) InstallResult {
	result := pausedResult(operation, output.outcome, code)
	result.NextSafeAction = output.nextAction.String()
	return result
}
