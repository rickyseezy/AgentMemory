package runtimeinstallapp

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const persistenceTimeout = 5 * time.Second

// Dependencies are explicit so no runtime phase can be accidentally omitted
// from the production composition root.
type Dependencies struct {
	Operations           OperationRepository
	OwnershipAuthorities RuntimeOwnershipAuthorityResolver
	OwnershipRecords     RuntimeOwnershipRepository
	Compensation         RuntimeCompensator
	Host                 HostCapabilityProbe
	Detector             ContainerRuntimeDetector
	Catalog              RuntimeReleaseCatalog
	Consent              RuntimeConsentPort
	Fetcher              RuntimeArtifactFetcher
	Verifier             RuntimeArtifactVerifier
	Prerequisites        RuntimePrerequisiteInstaller
	Installer            ContainerRuntimeInstaller
	Terms                ThirdPartyTermsPort
	Controller           ContainerRuntimeController
	Capabilities         RuntimeCapabilityProbe
}

// Application is the resumable PF-006 runtime provisioning use case consumed
// by PF-001's EnsureContainerRuntime adapter.
type Application struct {
	operations           OperationRepository
	ownershipAuthorities RuntimeOwnershipAuthorityResolver
	ownershipRecords     RuntimeOwnershipRepository
	compensation         RuntimeCompensator
	host                 HostCapabilityProbe
	detector             ContainerRuntimeDetector
	catalog              RuntimeReleaseCatalog
	consent              RuntimeConsentPort
	fetcher              RuntimeArtifactFetcher
	verifier             RuntimeArtifactVerifier
	prerequisites        RuntimePrerequisiteInstaller
	installer            ContainerRuntimeInstaller
	terms                ThirdPartyTermsPort
	controller           ContainerRuntimeController
	capabilities         RuntimeCapabilityProbe
}

// New constructs a runtime installer only when every capability exists.
func New(dependencies Dependencies) (*Application, error) {
	values := []any{
		dependencies.Operations,
		dependencies.OwnershipAuthorities,
		dependencies.OwnershipRecords,
		dependencies.Compensation,
		dependencies.Host,
		dependencies.Detector,
		dependencies.Catalog,
		dependencies.Consent,
		dependencies.Fetcher,
		dependencies.Verifier,
		dependencies.Prerequisites,
		dependencies.Installer,
		dependencies.Terms,
		dependencies.Controller,
		dependencies.Capabilities,
	}
	for _, value := range values {
		if nilInterface(value) {
			return nil, errors.New("every runtime installation dependency is required")
		}
	}
	return &Application{
		operations:           dependencies.Operations,
		ownershipAuthorities: dependencies.OwnershipAuthorities,
		ownershipRecords:     dependencies.OwnershipRecords,
		compensation:         dependencies.Compensation,
		host:                 dependencies.Host,
		detector:             dependencies.Detector,
		catalog:              dependencies.Catalog,
		consent:              dependencies.Consent,
		fetcher:              dependencies.Fetcher,
		verifier:             dependencies.Verifier,
		prerequisites:        dependencies.Prerequisites,
		installer:            dependencies.Installer,
		terms:                dependencies.Terms,
		controller:           dependencies.Controller,
		capabilities:         dependencies.Capabilities,
	}, nil
}

func nilInterface(value any) bool {
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

// Ensure executes until Ready or a durable pause/terminal result.
func (a *Application) Ensure(ctx context.Context, command Command) (Result, error) {
	decodedPlan, decodeError := runtimeinstall.DecodePlanV1(command.CanonicalPlan)
	if decodeError != nil {
		return Result{}, applicationError(ErrorCodeInvalidArgument, false)
	}
	plan := decodedPlan.CanonicalBytes()
	planDigest := runtimeinstall.Sum(plan)
	operation, err := a.operations.Load(ctx, command.OperationID)
	switch {
	case err == nil && operation == nil:
		return Result{OperationID: command.OperationID}, applicationError(ErrorCodeInternal, false)
	case err == nil:
		if operation.PlanDigest() != planDigest {
			return resultFrom(operation, OutcomeUnknown, ErrorCodeConflict), applicationError(ErrorCodeConflict, false)
		}
	case errors.Is(err, ErrOperationNotFound):
		operation, err = runtimeinstall.NewOperation(command.OperationID, planDigest)
		if err != nil {
			return Result{OperationID: command.OperationID}, applicationError(ErrorCodeInvalidArgument, false)
		}
		if saveError := a.save(ctx, operation); saveError != nil {
			return resultFrom(operation, OutcomeUnknown, errorCode(saveError)), saveError
		}
	case errors.Is(err, ErrOperationConflict), errors.Is(err, ErrOperationIntegrity):
		mapped := mapRepositoryError(err)
		return Result{OperationID: command.OperationID, ErrorCode: errorCode(mapped)}, mapped
	default:
		mapped := mapBoundaryError(err)
		return Result{OperationID: command.OperationID, ErrorCode: errorCode(mapped)}, mapped
	}

	if operation.State() == runtimeinstall.OperationStateReady {
		ownership, recorded, ownershipError := a.recordRuntimeOwnership(ctx, operation, plan)
		if ownershipError != nil {
			return resultFrom(operation, OutcomeUnknown, errorCode(ownershipError)), ownershipError
		}
		if !recorded {
			return resultFrom(operation, OutcomeUnknown, ErrorCodeIntegrityViolation),
				applicationError(ErrorCodeIntegrityViolation, false)
		}
		return completedResult(operation, ownership)
	}
	if operation.State() == runtimeinstall.OperationStateCancelled {
		return a.finishCancellation(ctx, operation, plan)
	}
	if operation.State() == runtimeinstall.OperationStateRebootPending {
		if _, _, ownershipError := a.recordRuntimeOwnership(ctx, operation, plan); ownershipError != nil {
			return resultFrom(operation, OutcomeUnknown, errorCode(ownershipError)), ownershipError
		}
		if command.ResumeReceipt == nil {
			return resultFrom(operation, OutcomeRebootRequired, ErrorCodeRebootRequired), nil
		}
		if err := operation.ResumeAfterReboot(*command.ResumeReceipt); err != nil {
			return resultFrom(operation, OutcomeUnknown, ErrorCodeIntegrityViolation), applicationError(ErrorCodeIntegrityViolation, false)
		}
		if saveError := a.saveFresh(ctx, operation); saveError != nil {
			return resultFrom(operation, OutcomeUnknown, errorCode(saveError)), saveError
		}
		if _, _, ownershipError := a.recordRuntimeOwnership(ctx, operation, plan); ownershipError != nil {
			return resultFrom(operation, OutcomeUnknown, errorCode(ownershipError)), ownershipError
		}
	}
	if operation.State() == runtimeinstall.OperationStateFailedRecoverable ||
		operation.State() == runtimeinstall.OperationStatePausedForAdministrator {
		if err := operation.Resume(); err != nil {
			return resultFrom(operation, OutcomeUnknown, ErrorCodeInternal), applicationError(ErrorCodeInternal, false)
		}
		if saveError := a.save(ctx, operation); saveError != nil {
			return resultFrom(operation, OutcomeUnknown, errorCode(saveError)), saveError
		}
	}
	if operation.State() != runtimeinstall.OperationStateRunning {
		return resultFrom(operation, outcomeForState(operation.State()), codeForState(operation.State())), nil
	}

	for operation.State() == runtimeinstall.OperationStateRunning {
		if saveError := a.save(ctx, operation); saveError != nil {
			return resultFrom(operation, OutcomeUnknown, errorCode(saveError)), saveError
		}
		if _, _, ownershipError := a.recordRuntimeOwnership(ctx, operation, plan); ownershipError != nil {
			return resultFrom(operation, OutcomeUnknown, errorCode(ownershipError)), ownershipError
		}
		phase := operation.CurrentPhase()
		output, dispatchError := a.dispatch(ctx, phase, newRequest(operation, plan))
		if dispatchError != nil {
			return a.failRecoverable(ctx, operation, dispatchError)
		}
		if !output.validFor(phase) {
			return a.failInternal(ctx, operation)
		}

		switch output.outcome {
		case OutcomeCompleted:
			evidence, evidenceError := runtimeinstall.NewTransitionEvidence(
				phase,
				operation.Attempt(),
				operation.PlanDigest(),
				output.completion.InputDigest,
				output.completion.OutputDigest,
				output.completion.ArtifactDigest,
				output.completion.Ownership,
			)
			if evidenceError != nil || operation.Complete(phase, evidence) != nil {
				return a.failInternal(ctx, operation)
			}
		case OutcomeRebootRequired:
			if operation.RequireReboot(output.resumeReceipt) != nil {
				return a.failInternal(ctx, operation)
			}
		case OutcomeFailedRecoverable,
			OutcomeAdministratorRequired,
			OutcomeCancelled,
			OutcomeUnsupportedHost,
			OutcomeRuntimeConflict:
			state := stateForOutcome(output.outcome)
			if operation.Pause(state) != nil {
				return a.failInternal(ctx, operation)
			}
		case OutcomeUnknown:
			return a.failInternal(ctx, operation)
		}

		if saveError := a.saveFresh(ctx, operation); saveError != nil {
			return resultFrom(operation, output.outcome, errorCode(saveError)), saveError
		}
		ownership, recorded, ownershipError := a.recordRuntimeOwnership(ctx, operation, plan)
		if ownershipError != nil {
			return resultFrom(operation, output.outcome, errorCode(ownershipError)), ownershipError
		}
		if operation.State() == runtimeinstall.OperationStateReady {
			if !recorded {
				return resultFrom(operation, OutcomeUnknown, ErrorCodeIntegrityViolation),
					applicationError(ErrorCodeIntegrityViolation, false)
			}
			return completedResult(operation, ownership)
		}
		if operation.State() == runtimeinstall.OperationStateCancelled {
			return a.finishCancellation(ctx, operation, plan)
		}
		if output.outcome != OutcomeCompleted {
			return resultFrom(operation, output.outcome, codeForState(operation.State())), nil
		}
	}
	return resultFrom(operation, OutcomeUnknown, ErrorCodeInternal), applicationError(ErrorCodeInternal, false)
}

// Cancel durably cancels the PF-006 child and completes only exact
// ownership-authorized cleanup. A missing child is a proven no-op because no
// runtime phase could have acquired or mutated state without creating it.
func (a *Application) Cancel(ctx context.Context, command Command) (Result, error) {
	plan, err := runtimeinstall.DecodePlanV1(command.CanonicalPlan)
	if err != nil || command.OperationID == "" {
		return Result{}, applicationError(ErrorCodeInvalidArgument, false)
	}
	operation, err := a.operations.Load(ctx, command.OperationID)
	switch {
	case errors.Is(err, ErrOperationNotFound):
		return Result{
			OperationID: command.OperationID, State: runtimeinstall.OperationStateCancelled,
			Outcome: OutcomeCancelled, planDigest: plan.Digest(), CompensationSettled: true,
		}, nil
	case err != nil:
		mapped := mapRepositoryError(err)
		return Result{OperationID: command.OperationID, ErrorCode: errorCode(mapped)}, mapped
	case operation == nil || operation.PlanDigest() != plan.Digest():
		return Result{OperationID: command.OperationID}, applicationError(ErrorCodeIntegrityViolation, false)
	}
	if operation.State() == runtimeinstall.OperationStateReady {
		ownership, recorded, ownershipError := a.recordRuntimeOwnership(ctx, operation, plan.CanonicalBytes())
		if ownershipError != nil || !recorded {
			if ownershipError == nil {
				ownershipError = applicationError(ErrorCodeIntegrityViolation, false)
			}
			return resultFrom(operation, OutcomeUnknown, errorCode(ownershipError)), ownershipError
		}
		result, completionError := completedResult(operation, ownership)
		result.CompensationSettled = completionError == nil
		return result, completionError
	}
	if operation.State() != runtimeinstall.OperationStateCancelled {
		if err := operation.Cancel(); err != nil {
			return resultFrom(operation, outcomeForState(operation.State()), ErrorCodeConflict),
				applicationError(ErrorCodeConflict, false)
		}
		if saveError := a.saveFresh(ctx, operation); saveError != nil {
			return resultFrom(operation, OutcomeUnknown, errorCode(saveError)), saveError
		}
	}
	return a.finishCancellation(ctx, operation, plan.CanonicalBytes())
}

func (a *Application) finishCancellation(
	ctx context.Context,
	operation *runtimeinstall.Operation,
	canonicalPlan []byte,
) (Result, error) {
	if operation == nil || operation.State() != runtimeinstall.OperationStateCancelled {
		return Result{}, applicationError(ErrorCodeIntegrityViolation, false)
	}
	if operation.CompensationSettled() {
		return resultFrom(operation, OutcomeCancelled, ErrorCodeCancelled), nil
	}
	if operation.CompensationStatus() != runtimeinstall.CompensationStatusPending {
		return resultFrom(operation, OutcomeUnknown, ErrorCodeIntegrityViolation),
			applicationError(ErrorCodeIntegrityViolation, false)
	}
	cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), persistenceTimeout)
	defer cancel()
	ownership, recorded, ownershipError := a.recordRuntimeOwnership(cleanupContext, operation, canonicalPlan)
	if ownershipError != nil || !recorded {
		if ownershipError == nil {
			ownershipError = applicationError(ErrorCodeIntegrityViolation, false)
		}
		result := resultFrom(operation, OutcomeCancelled, errorCode(ownershipError))
		result.CompensationSettled = false
		return result, ownershipError
	}
	request, err := newRuntimeCompensationRequest(canonicalPlan, ownership)
	if err != nil {
		return resultFrom(operation, OutcomeUnknown, ErrorCodeIntegrityViolation),
			applicationError(ErrorCodeIntegrityViolation, false)
	}
	receipt, compensateError := a.compensation.CompensateRuntime(cleanupContext, request)
	if compensateError != nil {
		mapped := mapBoundaryError(compensateError)
		result := resultFrom(operation, OutcomeCancelled, errorCode(mapped))
		result.CompensationSettled = false
		return result, mapped
	}
	if !receipt.ValidFor(request) || operation.CompleteCompensation(receipt.Digest()) != nil {
		return resultFrom(operation, OutcomeUnknown, ErrorCodeIntegrityViolation),
			applicationError(ErrorCodeIntegrityViolation, false)
	}
	if saveError := a.saveFresh(cleanupContext, operation); saveError != nil {
		result := resultFrom(operation, OutcomeCancelled, errorCode(saveError))
		result.CompensationSettled = false
		return result, saveError
	}
	if _, recorded, ownershipError = a.recordRuntimeOwnership(cleanupContext, operation, canonicalPlan); ownershipError != nil || !recorded {
		if ownershipError == nil {
			ownershipError = applicationError(ErrorCodeIntegrityViolation, false)
		}
		result := resultFrom(operation, OutcomeCancelled, errorCode(ownershipError))
		result.CompensationSettled = false
		return result, ownershipError
	}
	return resultFrom(operation, OutcomeCancelled, ErrorCodeCancelled), nil
}

func (a *Application) recordRuntimeOwnership(
	ctx context.Context,
	operation *runtimeinstall.Operation,
	canonicalPlan []byte,
) (runtimeinstall.RuntimeOwnershipRecord, bool, error) {
	if operation == nil || !runtimeinstall.RuntimeOwnershipRequired(operation.Snapshot()) {
		return runtimeinstall.RuntimeOwnershipRecord{}, false, nil
	}
	plan, err := runtimeinstall.DecodePlanV1(canonicalPlan)
	if err != nil || plan.Digest() != operation.PlanDigest() {
		return runtimeinstall.RuntimeOwnershipRecord{}, false, applicationError(ErrorCodeIntegrityViolation, false)
	}
	authority, err := a.ownershipAuthorities.ResolveRuntimeOwnershipAuthority(ctx, canonicalPlan)
	if err != nil {
		return runtimeinstall.RuntimeOwnershipRecord{}, false, mapOwnershipError(err)
	}
	var previous *runtimeinstall.RuntimeOwnershipRecord
	loaded, loadError := a.ownershipRecords.LoadRuntimeOwnership(ctx, operation.ID())
	switch {
	case loadError == nil:
		previous = &loaded
	case errors.Is(loadError, ErrOwnershipNotFound):
	default:
		return runtimeinstall.RuntimeOwnershipRecord{}, false, mapOwnershipError(loadError)
	}
	record, err := runtimeinstall.NewRuntimeOwnershipRecord(plan, operation.Snapshot(), authority, previous)
	if err != nil {
		return runtimeinstall.RuntimeOwnershipRecord{}, false, applicationError(ErrorCodeIntegrityViolation, false)
	}
	if err := mapOwnershipError(a.ownershipRecords.SaveRuntimeOwnership(ctx, record)); err != nil {
		return runtimeinstall.RuntimeOwnershipRecord{}, false, err
	}
	return record, true, nil
}

func mapOwnershipError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrOwnershipConflict):
		return applicationError(ErrorCodeConflict, true)
	case errors.Is(err, ErrOwnershipIntegrity):
		return applicationError(ErrorCodeIntegrityViolation, false)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return applicationError(ErrorCodeDeadlineExceeded, true)
	default:
		return applicationError(ErrorCodeInternal, true)
	}
}

func (a *Application) dispatch(ctx context.Context, phase runtimeinstall.Phase, request Request) (Output, error) {
	switch phase {
	case runtimeinstall.PhaseDetectHost:
		return a.host.DetectHost(ctx, request)
	case runtimeinstall.PhaseDetectRuntime:
		return a.detector.DetectRuntime(ctx, request)
	case runtimeinstall.PhasePlanRuntime:
		return a.catalog.PlanRuntime(ctx, request)
	case runtimeinstall.PhaseAwaitRuntimeConsent:
		return a.consent.AwaitRuntimeConsent(ctx, request)
	case runtimeinstall.PhaseAcquireRuntime:
		return a.fetcher.AcquireRuntime(ctx, request)
	case runtimeinstall.PhaseVerifyRuntimeArtifact:
		return a.verifier.VerifyRuntimeArtifact(ctx, request)
	case runtimeinstall.PhaseInstallPrerequisites:
		return a.prerequisites.InstallPrerequisites(ctx, request)
	case runtimeinstall.PhaseInstallRuntime:
		return a.installer.InstallRuntime(ctx, request)
	case runtimeinstall.PhaseAwaitThirdPartyTerms:
		return a.terms.AwaitThirdPartyTerms(ctx, request)
	case runtimeinstall.PhaseStartRuntime:
		return a.controller.StartRuntime(ctx, request)
	case runtimeinstall.PhaseVerifyRuntimeCapabilities:
		return a.capabilities.VerifyRuntimeCapabilities(ctx, request)
	case runtimeinstall.PhaseUnknown:
	}
	return Output{}, errors.New("runtime phase is invalid")
}

func (a *Application) failRecoverable(
	ctx context.Context,
	operation *runtimeinstall.Operation,
	boundaryError error,
) (Result, error) {
	if operation.Pause(runtimeinstall.OperationStateFailedRecoverable) != nil {
		return resultFrom(operation, OutcomeUnknown, ErrorCodeInternal), applicationError(ErrorCodeInternal, false)
	}
	if saveError := a.saveFresh(ctx, operation); saveError != nil {
		return resultFrom(operation, OutcomeFailedRecoverable, errorCode(saveError)), saveError
	}
	mapped := mapBoundaryError(boundaryError)
	return resultFrom(operation, OutcomeFailedRecoverable, errorCode(mapped)), mapped
}

func (a *Application) failInternal(ctx context.Context, operation *runtimeinstall.Operation) (Result, error) {
	if operation.State() == runtimeinstall.OperationStateRunning {
		_ = operation.Pause(runtimeinstall.OperationStateFailedRecoverable)
		if saveError := a.saveFresh(ctx, operation); saveError != nil {
			return resultFrom(operation, OutcomeFailedRecoverable, errorCode(saveError)), saveError
		}
	}
	return resultFrom(operation, OutcomeFailedRecoverable, ErrorCodeInternal), applicationError(ErrorCodeInternal, false)
}

func (a *Application) save(ctx context.Context, operation *runtimeinstall.Operation) error {
	return mapRepositoryError(a.operations.Save(ctx, operation.Snapshot()))
}

func (a *Application) saveFresh(parent context.Context, operation *runtimeinstall.Operation) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), persistenceTimeout)
	defer cancel()
	return a.save(ctx, operation)
}

func mapRepositoryError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrOperationConflict):
		return applicationError(ErrorCodeConflict, true)
	case errors.Is(err, ErrOperationIntegrity):
		return applicationError(ErrorCodeIntegrityViolation, false)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return applicationError(ErrorCodeDeadlineExceeded, true)
	default:
		return applicationError(ErrorCodeInternal, false)
	}
}

func mapBoundaryError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return applicationError(ErrorCodeDeadlineExceeded, true)
	}
	return applicationError(ErrorCodeInternal, true)
}

func errorCode(err error) ErrorCode {
	var typed *ApplicationError
	if errors.As(err, &typed) {
		return typed.Code()
	}
	return ErrorCodeInternal
}

func resultFrom(operation *runtimeinstall.Operation, outcome Outcome, code ErrorCode) Result {
	result := Result{
		OperationID:         operation.ID(),
		State:               operation.State(),
		CurrentPhase:        operation.CurrentPhase(),
		Attempt:             operation.Attempt(),
		Version:             operation.Version(),
		Outcome:             outcome,
		ErrorCode:           code,
		planDigest:          operation.PlanDigest(),
		CompensationSettled: operation.CompensationSettled(),
	}
	if operation.State() == runtimeinstall.OperationStateRebootPending {
		result.rebootReceipt = operation.Snapshot().RebootReceipt
	}
	return result
}

func stateForOutcome(outcome Outcome) runtimeinstall.OperationState {
	switch outcome {
	case OutcomeFailedRecoverable:
		return runtimeinstall.OperationStateFailedRecoverable
	case OutcomeAdministratorRequired:
		return runtimeinstall.OperationStatePausedForAdministrator
	case OutcomeCancelled:
		return runtimeinstall.OperationStateCancelled
	case OutcomeUnsupportedHost:
		return runtimeinstall.OperationStateUnsupportedHost
	case OutcomeRuntimeConflict:
		return runtimeinstall.OperationStateRuntimeConflict
	case OutcomeUnknown, OutcomeCompleted, OutcomeRebootRequired:
	}
	return runtimeinstall.OperationStateUnknown
}

func outcomeForState(state runtimeinstall.OperationState) Outcome {
	switch state {
	case runtimeinstall.OperationStateReady:
		return OutcomeCompleted
	case runtimeinstall.OperationStateRebootPending:
		return OutcomeRebootRequired
	case runtimeinstall.OperationStateFailedRecoverable:
		return OutcomeFailedRecoverable
	case runtimeinstall.OperationStatePausedForAdministrator:
		return OutcomeAdministratorRequired
	case runtimeinstall.OperationStateCancelled:
		return OutcomeCancelled
	case runtimeinstall.OperationStateUnsupportedHost:
		return OutcomeUnsupportedHost
	case runtimeinstall.OperationStateRuntimeConflict:
		return OutcomeRuntimeConflict
	case runtimeinstall.OperationStateUnknown, runtimeinstall.OperationStateRunning:
	}
	return OutcomeUnknown
}

func codeForState(state runtimeinstall.OperationState) ErrorCode {
	switch state {
	case runtimeinstall.OperationStateRebootPending:
		return ErrorCodeRebootRequired
	case runtimeinstall.OperationStatePausedForAdministrator:
		return ErrorCodeAdministratorRequired
	case runtimeinstall.OperationStateCancelled:
		return ErrorCodeCancelled
	case runtimeinstall.OperationStateUnsupportedHost:
		return ErrorCodeUnsupportedHost
	case runtimeinstall.OperationStateRuntimeConflict:
		return ErrorCodeRuntimeConflict
	case runtimeinstall.OperationStateFailedRecoverable:
		return ErrorCodeInternal
	case runtimeinstall.OperationStateUnknown,
		runtimeinstall.OperationStateRunning,
		runtimeinstall.OperationStateReady:
	}
	return ErrorCodeNone
}
