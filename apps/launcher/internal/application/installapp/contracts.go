package installapp

import (
	"fmt"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

// InstallCommand starts or idempotently resumes one plan-bound installation.
// OperationID must remain stable across retries. CanonicalPlan must contain the
// exact canonical bytes used by every retry. ResumeReceipt is supplied only
// after a reboot requested by EnsureContainerRuntime.
type InstallCommand struct {
	OperationID   string
	CanonicalPlan []byte
	ResumeReceipt *install.Digest
}

// CancelCommand terminates one exact plan-bound installation. The same
// command is replay-safe: cancellation intent is persisted before owned
// reservation capacity is released, and a later call retries only cleanup.
type CancelCommand struct {
	OperationID   string
	CanonicalPlan []byte
}

// CancellationIntentStatus is the closed durable lifecycle of one exact
// operation/plan cancellation request.
type CancellationIntentStatus uint8

const (
	// CancellationIntentUnknown is invalid.
	CancellationIntentUnknown CancellationIntentStatus = iota
	// CancellationIntentRequested means the installer must stop at the next
	// cancellation boundary and durably settle owned resources.
	CancellationIntentRequested
	// CancellationIntentAcknowledged means StateCancelled and all owned cleanup
	// were durable before the intent acknowledgement was committed.
	CancellationIntentAcknowledged
)

// CancellationRequest binds a durable intent to the exact aggregate revision
// validated by Cancel. The revision is audit evidence; cancellation remains
// operation-wide when the installer advances to a later non-terminal revision.
type CancellationRequest struct {
	OperationID              install.OperationID
	PlanDigest               install.PlanDigest
	ObservedAggregateVersion uint64
}

// CancellationIntent is an immutable-by-value authenticated adapter result.
// Its fields are exported only as read-only value objects; application code
// validates every binding before acting on it.
type CancellationIntent struct {
	OperationID              install.OperationID
	PlanDigest               install.PlanDigest
	ObservedAggregateVersion uint64
	Revision                 uint64
	Status                   CancellationIntentStatus
	SettledState             install.State
}

// NewRequestedCancellationIntentForAdapter constructs a validated durable
// adapter result. Infrastructure adapters must not return hand-built values.
func NewRequestedCancellationIntentForAdapter(
	request CancellationRequest,
	revision uint64,
) (CancellationIntent, error) {
	if request.OperationID.IsZero() || request.PlanDigest.IsZero() || revision == 0 {
		return CancellationIntent{}, fmt.Errorf("cancellation intent binding is invalid")
	}
	return CancellationIntent{
		OperationID:              request.OperationID,
		PlanDigest:               request.PlanDigest,
		ObservedAggregateVersion: request.ObservedAggregateVersion,
		Revision:                 revision,
		Status:                   CancellationIntentRequested,
	}, nil
}

// NewAcknowledgedCancellationIntentForAdapter validates the only legal
// settlement transition. Acknowledgement before durable StateCancelled is
// deliberately unrepresentable.
func NewAcknowledgedCancellationIntentForAdapter(
	requested CancellationIntent,
	revision uint64,
	settledState install.State,
) (CancellationIntent, error) {
	if !requested.ValidFor(requested.OperationID, requested.PlanDigest) ||
		requested.Status != CancellationIntentRequested || revision <= requested.Revision ||
		settledState != install.StateCancelled {
		return CancellationIntent{}, fmt.Errorf("cancellation acknowledgement is invalid")
	}
	requested.Revision = revision
	requested.Status = CancellationIntentAcknowledged
	requested.SettledState = settledState
	return requested, nil
}

// ValidFor authenticates the application-level identity, plan, revision, and
// lifecycle invariants of an adapter result.
func (i CancellationIntent) ValidFor(operationID install.OperationID, plan install.PlanDigest) bool {
	if i.OperationID.IsZero() || i.PlanDigest.IsZero() || i.Revision == 0 ||
		i.OperationID != operationID || !i.PlanDigest.Equal(plan) {
		return false
	}
	switch i.Status {
	case CancellationIntentRequested:
		return i.SettledState == install.StateUnknown
	case CancellationIntentAcknowledged:
		return i.Revision >= 2 && i.SettledState == install.StateCancelled
	case CancellationIntentUnknown:
		return false
	}
	return false
}

// ReservationReleaseReason is the closed parent-saga cleanup vocabulary.
// Artifact-specific release authority remains inside the installphase adapter.
type ReservationReleaseReason uint8

const (
	// ReservationReleaseUnknown is invalid.
	ReservationReleaseUnknown ReservationReleaseReason = iota
	// ReservationReleaseCompleted settles capacity only after durable activation.
	ReservationReleaseCompleted
	// ReservationReleaseCancelled settles capacity after explicit user cancellation.
	ReservationReleaseCancelled
	// ReservationReleaseRollback settles capacity after a terminal safe rollback.
	ReservationReleaseRollback
)

// InstallResult is safe to expose at an inbound adapter. It contains only
// stable codes and domain identifiers; raw platform errors never enter it.
type InstallResult struct {
	OperationID    string
	State          install.State
	CurrentPhase   install.Phase
	CompletedSteps int
	ResumeAction   install.ResumeAction
	Outcome        PhaseOutcome
	ErrorCode      ErrorCode
	NextSafeAction string
	// CancellationRequested reports durable intent without claiming the
	// installer has stopped or released owned resources.
	CancellationRequested bool
	// CancellationSettled is true only after StateCancelled, cleanup, and
	// durable intent acknowledgement all completed in that order.
	CancellationSettled bool
}

// PhaseRequest is an immutable-by-copy request passed to exactly one named
// phase capability.
type PhaseRequest struct {
	operationID   install.OperationID
	planDigest    install.PlanDigest
	attempt       uint32
	canonicalPlan []byte
	resumeReceipt install.Digest
}

func newPhaseRequest(operation *install.Operation, canonicalPlan []byte) PhaseRequest {
	return PhaseRequest{
		operationID:   operation.ID(),
		planDigest:    operation.PlanDigest(),
		attempt:       operation.Attempt(),
		canonicalPlan: append([]byte(nil), canonicalPlan...),
	}
}

func newRuntimeResumePhaseRequest(
	operation *install.Operation,
	canonicalPlan []byte,
	resumeReceipt install.Digest,
) PhaseRequest {
	request := newPhaseRequest(operation, canonicalPlan)
	request.resumeReceipt = resumeReceipt
	return request
}

// NewPhaseRequestForIntegration constructs a phase request for an outer
// application orchestrator or contract test. Production phase dispatch uses
// the aggregate-backed private constructor above.
func NewPhaseRequestForIntegration(
	operationID install.OperationID,
	planDigest install.PlanDigest,
	attempt uint32,
	canonicalPlan []byte,
	resumeReceipt ...install.Digest,
) (PhaseRequest, error) {
	bound, err := install.BindPlan(canonicalPlan)
	if operationID.IsZero() || planDigest.IsZero() || attempt == 0 || err != nil ||
		!bound.Equal(planDigest) || len(resumeReceipt) > 1 ||
		(len(resumeReceipt) == 1 && resumeReceipt[0].IsZero()) {
		return PhaseRequest{}, fmt.Errorf("phase request binding is invalid")
	}
	request := PhaseRequest{
		operationID: operationID, planDigest: planDigest, attempt: attempt,
		canonicalPlan: append([]byte(nil), canonicalPlan...),
	}
	if len(resumeReceipt) == 1 {
		request.resumeReceipt = resumeReceipt[0]
	}
	return request, nil
}

// OperationID returns the stable operation identifier.
func (r PhaseRequest) OperationID() install.OperationID { return r.operationID }

// PlanDigest returns the immutable digest bound to the operation.
func (r PhaseRequest) PlanDigest() install.PlanDigest { return r.planDigest }

// Attempt returns the one-based attempt for the current phase.
func (r PhaseRequest) Attempt() uint32 { return r.attempt }

// CanonicalPlan returns a copy of the exact plan bytes bound by PlanDigest.
func (r PhaseRequest) CanonicalPlan() []byte {
	return append([]byte(nil), r.canonicalPlan...)
}

// ResumeReceipt returns the parent-verified, one-use runtime receipt only on
// re-entry after an EnsureContainerRuntime reboot pause.
func (r PhaseRequest) ResumeReceipt() (install.Digest, bool) {
	if r.resumeReceipt.IsZero() {
		return install.Digest{}, false
	}
	return r.resumeReceipt, true
}

// PhaseOutcome is the closed outcome vocabulary understood by the saga.
type PhaseOutcome uint8

const (
	// PhaseOutcomeUnknown is the invalid zero value.
	PhaseOutcomeUnknown PhaseOutcome = iota
	// PhaseOutcomeCompleted records verified evidence and advances the cursor.
	PhaseOutcomeCompleted
	// PhaseOutcomeFailedRecoverable pauses at the current phase for retry.
	PhaseOutcomeFailedRecoverable
	// PhaseOutcomeAdministratorRequired requires an administrator action.
	PhaseOutcomeAdministratorRequired
	// PhaseOutcomeCancelled terminates the operation at the user's request.
	PhaseOutcomeCancelled
	// PhaseOutcomeUnsupportedHost terminates on an unsupported platform.
	PhaseOutcomeUnsupportedHost
	// PhaseOutcomeRuntimeConflict terminates on an incompatible external runtime.
	PhaseOutcomeRuntimeConflict
	// PhaseOutcomeRebootRequired pauses runtime provisioning across a reboot.
	PhaseOutcomeRebootRequired
)

func (o PhaseOutcome) String() string {
	switch o {
	case PhaseOutcomeUnknown:
		return "unknown"
	case PhaseOutcomeCompleted:
		return "completed"
	case PhaseOutcomeFailedRecoverable:
		return "failed_recoverable"
	case PhaseOutcomeAdministratorRequired:
		return "administrator_required"
	case PhaseOutcomeCancelled:
		return "cancelled"
	case PhaseOutcomeUnsupportedHost:
		return "unsupported_host"
	case PhaseOutcomeRuntimeConflict:
		return "runtime_conflict"
	case PhaseOutcomeRebootRequired:
		return "reboot_required"
	}
	return "unknown"
}

// CompletionOutput contains adapter-verified evidence. Phase, plan, and
// attempt are intentionally absent: InstallApplication binds those values from
// the aggregate cursor, so an adapter cannot advance another phase or plan.
type CompletionOutput struct {
	InputDigest            install.Digest
	OutputDigest           install.Digest
	VerifiedArtifactDigest install.Digest
	Facts                  []install.NonSecretFact
	RuntimeOwnership       install.RuntimeOwnership
	CompensationBoundary   install.CompensationBoundary
	NextSafeAction         install.SafeAction
}

// PhaseOutput can only be made valid through one of its constructors. This
// keeps capability results inside the application's closed outcome vocabulary.
type PhaseOutput struct {
	valid         bool
	outcome       PhaseOutcome
	completion    CompletionOutput
	resumeReceipt install.Digest
	nextAction    install.SafeAction
}

// Outcome returns the closed phase result.
func (o PhaseOutput) Outcome() PhaseOutcome { return o.outcome }

// InputDigest returns the verified phase input binding when completed.
func (o PhaseOutput) InputDigest() install.Digest { return o.completion.InputDigest }

// OutputDigest returns the verified phase output binding when completed.
func (o PhaseOutput) OutputDigest() install.Digest { return o.completion.OutputDigest }

// VerifiedArtifactDigest returns the immutable executable/artifact binding
// required by trust-sensitive phases such as VerifyRelease.
func (o PhaseOutput) VerifiedArtifactDigest() install.Digest {
	return o.completion.VerifiedArtifactDigest
}

// RuntimeOwnership returns the verified ownership disposition on completion.
func (o PhaseOutput) RuntimeOwnership() install.RuntimeOwnership {
	return o.completion.RuntimeOwnership
}

// ResumeReceipt returns the one-use receipt only for reboot-required output.
func (o PhaseOutput) ResumeReceipt() (install.Digest, bool) {
	if o.outcome != PhaseOutcomeRebootRequired || o.resumeReceipt.IsZero() {
		return install.Digest{}, false
	}
	return o.resumeReceipt, true
}

// NextSafeAction returns the localization key without raw diagnostic data.
func (o PhaseOutput) NextSafeAction() string { return o.nextAction.String() }

// NewCompletedPhaseOutput validates and copies successful phase evidence.
func NewCompletedPhaseOutput(input CompletionOutput) (PhaseOutput, error) {
	if input.InputDigest.IsZero() || input.OutputDigest.IsZero() {
		return PhaseOutput{}, fmt.Errorf("input and output evidence digests are required")
	}
	if !input.RuntimeOwnership.Valid() {
		return PhaseOutput{}, fmt.Errorf("runtime ownership is invalid")
	}
	if input.CompensationBoundary.String() == "" {
		return PhaseOutput{}, fmt.Errorf("compensation boundary is required")
	}
	if input.NextSafeAction.String() == "" {
		return PhaseOutput{}, fmt.Errorf("next safe action is required")
	}

	input.Facts = append([]install.NonSecretFact(nil), input.Facts...)
	return PhaseOutput{
		valid:      true,
		outcome:    PhaseOutcomeCompleted,
		completion: input,
		nextAction: input.NextSafeAction,
	}, nil
}

// NewExpectedPhaseOutput constructs a non-success outcome that does not need a
// reboot receipt. Expected outcomes are state transitions, not Go errors.
func NewExpectedPhaseOutput(outcome PhaseOutcome, nextAction install.SafeAction) (PhaseOutput, error) {
	switch outcome {
	case PhaseOutcomeUnknown, PhaseOutcomeCompleted, PhaseOutcomeRebootRequired:
		return PhaseOutput{}, fmt.Errorf("outcome %s requires another constructor", outcome)
	case PhaseOutcomeFailedRecoverable,
		PhaseOutcomeAdministratorRequired,
		PhaseOutcomeCancelled,
		PhaseOutcomeUnsupportedHost,
		PhaseOutcomeRuntimeConflict:
	}
	if nextAction.String() == "" {
		return PhaseOutput{}, fmt.Errorf("next safe action is required")
	}
	return PhaseOutput{valid: true, outcome: outcome, nextAction: nextAction}, nil
}

// NewRebootRequiredPhaseOutput constructs a verified request to pause after
// runtime provisioning until the caller presents the same receipt digest.
func NewRebootRequiredPhaseOutput(receipt install.Digest, nextAction install.SafeAction) (PhaseOutput, error) {
	if receipt.IsZero() {
		return PhaseOutput{}, fmt.Errorf("resume receipt digest is required")
	}
	if nextAction.String() == "" {
		return PhaseOutput{}, fmt.Errorf("next safe action is required")
	}
	return PhaseOutput{
		valid:         true,
		outcome:       PhaseOutcomeRebootRequired,
		resumeReceipt: receipt,
		nextAction:    nextAction,
	}, nil
}

func (o PhaseOutput) validFor(phase install.Phase) bool {
	if !o.valid || o.outcome == PhaseOutcomeUnknown || o.nextAction.String() == "" {
		return false
	}
	if o.outcome == PhaseOutcomeRebootRequired {
		return phase == install.PhaseEnsureContainerRuntime && !o.resumeReceipt.IsZero()
	}
	if o.outcome == PhaseOutcomeCompleted {
		return !o.completion.InputDigest.IsZero() && !o.completion.OutputDigest.IsZero() &&
			o.completion.RuntimeOwnership.ValidForPhase(phase) &&
			(!install.PhaseRequiresVerifiedArtifact(phase) || !o.completion.VerifiedArtifactDigest.IsZero()) &&
			o.completion.CompensationBoundary.String() != ""
	}
	return true
}
