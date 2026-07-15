// Package runtimeinstallapp orchestrates the PF-001/PF-006 runtime sub-saga.
package runtimeinstallapp

import (
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

// Outcome is the closed result vocabulary accepted from runtime capabilities.
type Outcome uint8

const (
	// OutcomeUnknown is the invalid zero value.
	OutcomeUnknown Outcome = iota
	// OutcomeCompleted advances with verified evidence.
	OutcomeCompleted
	// OutcomeFailedRecoverable keeps the current phase retryable.
	OutcomeFailedRecoverable
	// OutcomeAdministratorRequired pauses for managed-device action.
	OutcomeAdministratorRequired
	// OutcomeCancelled records an explicit user decline.
	OutcomeCancelled
	// OutcomeUnsupportedHost records a certified incompatibility.
	OutcomeUnsupportedHost
	// OutcomeRuntimeConflict preserves incompatible external state.
	OutcomeRuntimeConflict
	// OutcomeRebootRequired creates a receipt-bound pause.
	OutcomeRebootRequired
)

// Command starts or resumes the runtime sub-saga for one parent installation.
type Command struct {
	OperationID   string
	CanonicalPlan []byte
	ResumeReceipt *runtimeinstall.Hash
}

// Request is an immutable-by-copy, plan-bound phase request.
type Request struct {
	operationID   string
	planDigest    runtimeinstall.Hash
	phase         runtimeinstall.Phase
	attempt       uint32
	canonicalPlan []byte
}

func newRequest(operation *runtimeinstall.Operation, plan []byte) Request {
	return Request{
		operationID:   operation.ID(),
		planDigest:    operation.PlanDigest(),
		phase:         operation.CurrentPhase(),
		attempt:       operation.Attempt(),
		canonicalPlan: append([]byte(nil), plan...),
	}
}

// OperationID returns the stable parent installation identifier.
func (r Request) OperationID() string { return r.operationID }

// PlanDigest returns the immutable canonical-plan binding.
func (r Request) PlanDigest() runtimeinstall.Hash { return r.planDigest }

// Phase returns the exact capability being invoked.
func (r Request) Phase() runtimeinstall.Phase { return r.phase }

// Attempt returns the one-based attempt for Phase.
func (r Request) Attempt() uint32 { return r.attempt }

// CanonicalPlan returns a caller-owned copy of the exact plan bytes.
func (r Request) CanonicalPlan() []byte { return append([]byte(nil), r.canonicalPlan...) }

// Completion contains only non-secret digests and runtime ownership evidence.
type Completion struct {
	InputDigest    runtimeinstall.Hash
	OutputDigest   runtimeinstall.Hash
	ArtifactDigest runtimeinstall.Hash
	Ownership      runtimeinstall.OwnershipDisposition
}

// Output can only be constructed through the validation functions below.
type Output struct {
	valid         bool
	outcome       Outcome
	completion    Completion
	resumeReceipt runtimeinstall.Hash
}

// NewCompletedOutput creates a verified completion result.
func NewCompletedOutput(completion Completion) (Output, error) {
	if completion.InputDigest.IsZero() || completion.OutputDigest.IsZero() {
		return Output{}, errors.New("runtime input and output digests are required")
	}
	return Output{valid: true, outcome: OutcomeCompleted, completion: completion}, nil
}

// NewExpectedOutput creates a typed non-success result.
func NewExpectedOutput(outcome Outcome) (Output, error) {
	switch outcome {
	case OutcomeFailedRecoverable,
		OutcomeAdministratorRequired,
		OutcomeCancelled,
		OutcomeUnsupportedHost,
		OutcomeRuntimeConflict:
		return Output{valid: true, outcome: outcome}, nil
	case OutcomeUnknown, OutcomeCompleted, OutcomeRebootRequired:
		return Output{}, errors.New("runtime outcome requires another constructor")
	}
	return Output{}, errors.New("runtime outcome is invalid")
}

// NewRebootOutput creates a receipt-bound reboot result.
func NewRebootOutput(receipt runtimeinstall.Hash) (Output, error) {
	if receipt.IsZero() {
		return Output{}, errors.New("runtime reboot receipt is required")
	}
	return Output{valid: true, outcome: OutcomeRebootRequired, resumeReceipt: receipt}, nil
}

func (o Output) validFor(phase runtimeinstall.Phase) bool {
	if !o.valid || o.outcome == OutcomeUnknown {
		return false
	}
	if o.outcome == OutcomeRebootRequired {
		return (phase == runtimeinstall.PhaseInstallPrerequisites || phase == runtimeinstall.PhaseInstallRuntime) &&
			!o.resumeReceipt.IsZero()
	}
	if o.outcome != OutcomeCompleted {
		return true
	}
	if o.completion.InputDigest.IsZero() || o.completion.OutputDigest.IsZero() {
		return false
	}
	if phase >= runtimeinstall.PhaseVerifyRuntimeArtifact && o.completion.ArtifactDigest.IsZero() {
		return false
	}
	return phase != runtimeinstall.PhaseVerifyRuntimeCapabilities ||
		o.completion.Ownership != runtimeinstall.OwnershipUnknown
}

// Result is privacy-safe and suitable for an inbound setup/status adapter.
type Result struct {
	OperationID       string
	State             runtimeinstall.OperationState
	CurrentPhase      runtimeinstall.Phase
	Attempt           uint32
	Version           uint64
	Outcome           Outcome
	ErrorCode         ErrorCode
	planDigest        runtimeinstall.Hash
	completionReceipt CompletionReceipt
	rebootReceipt     runtimeinstall.Hash
	// CompensationSettled is true only when cancellation required no owned
	// cleanup or the authenticated cleanup receipt is durably recorded.
	CompensationSettled bool
}

// PlanDigest returns the exact nested runtime plan bound to this result.
func (r Result) PlanDigest() runtimeinstall.Hash { return r.planDigest }

// CompletionReceipt returns aggregate-derived evidence only for a verified
// Ready operation. It never projects partial phase evidence as completion.
func (r Result) CompletionReceipt() (CompletionReceipt, bool) {
	if !r.completionReceipt.Valid() {
		return CompletionReceipt{}, false
	}
	return r.completionReceipt, true
}

// RebootReceipt returns the one-use receipt only while the aggregate is
// durably paused for a reboot.
func (r Result) RebootReceipt() (runtimeinstall.Hash, bool) {
	if r.State != runtimeinstall.OperationStateRebootPending || r.rebootReceipt.IsZero() {
		return runtimeinstall.Hash{}, false
	}
	return r.rebootReceipt, true
}

// ErrorCode is a stable public runtime-installation error taxonomy.
type ErrorCode string

const (
	// ErrorCodeNone indicates no failure or pause.
	ErrorCodeNone ErrorCode = ""
	// ErrorCodeInvalidArgument rejects malformed caller input.
	ErrorCodeInvalidArgument ErrorCode = "AM_INVALID_ARGUMENT"
	// ErrorCodeConflict rejects plan or optimistic-version drift.
	ErrorCodeConflict ErrorCode = "AM_CONFLICT"
	// ErrorCodeIntegrityViolation rejects unauthentic state or receipts.
	ErrorCodeIntegrityViolation ErrorCode = "AM_INTEGRITY_VIOLATION"
	// ErrorCodeDeadlineExceeded reports cancellation without terminal cancellation.
	ErrorCodeDeadlineExceeded ErrorCode = "AM_DEADLINE_EXCEEDED"
	// ErrorCodeAdministratorRequired reports a policy/elevation block.
	ErrorCodeAdministratorRequired ErrorCode = "AM_ADMINISTRATOR_ACTION_REQUIRED"
	// ErrorCodeCancelled records an explicit user decision.
	ErrorCodeCancelled ErrorCode = "AM_CANCELLED"
	// ErrorCodeUnsupportedHost reports an uncertified host.
	ErrorCodeUnsupportedHost ErrorCode = "AM_UNSUPPORTED_HOST"
	// ErrorCodeRuntimeConflict preserves incompatible runtime state.
	ErrorCodeRuntimeConflict ErrorCode = "AM_RUNTIME_CONFLICT"
	// ErrorCodeRebootRequired reports a durable reboot pause.
	ErrorCodeRebootRequired ErrorCode = "AM_REBOOT_REQUIRED"
	// ErrorCodeInternal sanitizes an unclassified invariant failure.
	ErrorCodeInternal ErrorCode = "AM_INTERNAL"
)

// ApplicationError prevents raw platform, Docker, path, or user data from
// crossing the launcher boundary.
type ApplicationError struct {
	code      ErrorCode
	retryable bool
}

func (e *ApplicationError) Error() string { return string(e.code) }

// Code returns the stable public taxonomy value.
func (e *ApplicationError) Code() ErrorCode { return e.code }

// Retryable reports whether re-entry may safely retry the current phase.
func (e *ApplicationError) Retryable() bool { return e.retryable }

func applicationError(code ErrorCode, retryable bool) *ApplicationError {
	return &ApplicationError{code: code, retryable: retryable}
}
