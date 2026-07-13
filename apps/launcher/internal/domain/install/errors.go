package install

import "fmt"

// ErrorCode is the stable boundary code exposed by an installation domain
// error. Adapters map these codes to MCP, HTTP, UI, and diagnostic contracts.
type ErrorCode string

const (
	// ErrorCodeValidation means input failed strict domain validation.
	ErrorCodeValidation ErrorCode = "AM_VALIDATION"
	// ErrorCodeConflict means the requested state transition is not currently valid.
	ErrorCodeConflict ErrorCode = "AM_CONFLICT"
	// ErrorCodeIdempotencyConflict means a request reused an operation with a different plan.
	ErrorCodeIdempotencyConflict ErrorCode = "AM_IDEMPOTENCY_CONFLICT"
	// ErrorCodeIntegrityViolation means durable evidence is contradictory or discontinuous.
	ErrorCodeIntegrityViolation ErrorCode = "AM_INTEGRITY_VIOLATION"
)

// CodedError is implemented by every error returned by this domain package.
type CodedError interface {
	error
	Code() ErrorCode
	Retryable() bool
}

// ValidationError reports malformed input before a state transition is tried.
type ValidationError struct {
	field  string
	reason string
}

func newValidationError(field, reason string) *ValidationError {
	return &ValidationError{field: field, reason: reason}
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("install validation failed for %s: %s", e.field, e.reason)
}

// Code returns AM_VALIDATION.
func (e *ValidationError) Code() ErrorCode { return ErrorCodeValidation }

// Retryable reports false because the invalid input must change.
func (e *ValidationError) Retryable() bool { return false }

// Field returns the safe field name whose validation failed.
func (e *ValidationError) Field() string { return e.field }

// PlanBindingError reports an attempt to mutate an operation with a different
// immutable install plan. Digests are available to trusted adapters but omitted
// from Error so raw diagnostics do not disclose operation metadata.
type PlanBindingError struct {
	expected PlanDigest
	actual   PlanDigest
}

func (e *PlanBindingError) Error() string {
	return "install operation is bound to a different plan digest"
}

// Code returns AM_IDEMPOTENCY_CONFLICT.
func (e *PlanBindingError) Code() ErrorCode { return ErrorCodeIdempotencyConflict }

// Retryable reports false because the original plan binding cannot change.
func (e *PlanBindingError) Retryable() bool { return false }

// Expected returns the operation's immutable plan digest.
func (e *PlanBindingError) Expected() PlanDigest { return e.expected }

// Actual returns the conflicting plan digest supplied by the caller.
func (e *PlanBindingError) Actual() PlanDigest { return e.actual }

// TransitionError reports a transition forbidden by the state machine.
type TransitionError struct {
	state     State
	phase     Phase
	operation string
}

func newTransitionError(state State, phase Phase, operation string) *TransitionError {
	return &TransitionError{state: state, phase: phase, operation: operation}
}

func (e *TransitionError) Error() string {
	return fmt.Sprintf("install transition %s is not allowed from %s at %s", e.operation, e.state, e.phase)
}

// Code returns AM_CONFLICT.
func (e *TransitionError) Code() ErrorCode { return ErrorCodeConflict }

// Retryable reports false until the caller refreshes operation state.
func (e *TransitionError) Retryable() bool { return false }

// State returns the state that rejected the transition.
func (e *TransitionError) State() State { return e.state }

// Phase returns the phase cursor that rejected the transition.
func (e *TransitionError) Phase() Phase { return e.phase }

// IntegrityError reports contradictory or non-contiguous durable evidence.
// Automatic retry is forbidden because continuing could mark an unverified
// installation Ready.
type IntegrityError struct {
	reason string
}

func newIntegrityError(reason string) *IntegrityError {
	return &IntegrityError{reason: reason}
}

func (e *IntegrityError) Error() string {
	return "install evidence integrity violation: " + e.reason
}

// Code returns AM_INTEGRITY_VIOLATION.
func (e *IntegrityError) Code() ErrorCode { return ErrorCodeIntegrityViolation }

// Retryable reports false because automatic recovery from contradictory
// evidence could incorrectly mark an unverified installation Ready.
func (e *IntegrityError) Retryable() bool { return false }
