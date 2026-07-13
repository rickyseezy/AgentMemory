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

	return &InstallApplication{
		operations:          dependencies.Operations,
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
			return resultFrom(operation, PhaseOutcomeUnknown, install.ResumeActionUnknown), saveError
		}
	default:
		return InstallResult{OperationID: operationID.String()}, mapRepositoryError(
			err, "installation state could not be loaded",
		)
	}
	if loadedExisting {
		resumeAction, resumeError := a.prepareExisting(ctx, operation, planDigest, command.ResumeReceipt)
		if resumeError != nil {
			return resultFrom(operation, PhaseOutcomeUnknown, resumeAction), resumeError
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
		// The unchanged cursor is durably recorded immediately before every
		// side-effect boundary. An interrupted adapter can therefore only be
		// retried at the same first-unverified phase.
		if saveError := a.save(ctx, operation); saveError != nil {
			return resultFrom(operation, PhaseOutcomeUnknown, install.ResumeActionUnknown), saveError
		}

		phase := operation.CurrentPhase()
		output, phaseError := a.dispatch(ctx, phase, newPhaseRequest(operation, canonicalPlan))
		if phaseError != nil {
			if isDeadlineBoundary(phaseError) {
				return a.failDeadline(ctx, operation, planDigest)
			}
			return a.failUnexpected(ctx, operation, planDigest)
		}
		if !output.validFor(phase) {
			return a.failInternal(ctx, operation, planDigest)
		}

		outcomeResult, continueInstall, outcomeError := a.applyOutput(operation, output)
		if outcomeError != nil {
			if failClosedDomainError(outcomeError) {
				return resultFrom(operation, output.outcome, install.ResumeActionUnknown), mapDomainError(outcomeError)
			}
			return a.failInternal(ctx, operation, planDigest)
		}
		if saveError := a.saveAfterTransition(ctx, operation); saveError != nil {
			return resultFrom(operation, output.outcome, install.ResumeActionUnknown), saveError
		}
		if !continueInstall {
			return outcomeResult, nil
		}
	}

	return resultFrom(operation, PhaseOutcomeCompleted, install.ResumeActionUnknown), nil
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
