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
}

// PhaseRequest is an immutable-by-copy request passed to exactly one named
// phase capability.
type PhaseRequest struct {
	operationID   install.OperationID
	planDigest    install.PlanDigest
	attempt       uint32
	canonicalPlan []byte
}

func newPhaseRequest(operation *install.Operation, canonicalPlan []byte) PhaseRequest {
	return PhaseRequest{
		operationID:   operation.ID(),
		planDigest:    operation.PlanDigest(),
		attempt:       operation.Attempt(),
		canonicalPlan: append([]byte(nil), canonicalPlan...),
	}
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
