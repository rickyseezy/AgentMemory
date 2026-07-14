package activereleaseapp

// ErrorCode is a stable privacy-safe activation failure reason.
type ErrorCode string

const (
	// ErrorCodeInvalidArgument rejects an incomplete activation command.
	ErrorCodeInvalidArgument ErrorCode = "invalid_argument"
	// ErrorCodeReadinessRequired rejects missing, stale, or cross-bound proof.
	ErrorCodeReadinessRequired ErrorCode = "readiness_required"
	// ErrorCodeIntegrityViolation rejects unauthenticated durable state.
	ErrorCodeIntegrityViolation ErrorCode = "integrity_violation"
	// ErrorCodeConflict rejects rollback, equivocation, or lost CAS.
	ErrorCodeConflict ErrorCode = "conflict"
	// ErrorCodePersistence reports a retryable activation-journal failure.
	ErrorCodePersistence ErrorCode = "persistence_unavailable"
	// ErrorCodeDependencyUnavailable reports a retryable Core boundary failure.
	ErrorCodeDependencyUnavailable ErrorCode = "dependency_unavailable"
	// ErrorCodeDeadlineExceeded reports cancellation or deadline expiry.
	ErrorCodeDeadlineExceeded ErrorCode = "deadline_exceeded"
	// ErrorCodeInternal is a fail-closed invariant failure.
	ErrorCodeInternal ErrorCode = "internal"
)

// ApplicationError never wraps a raw host, persistence, or Core diagnostic.
type ApplicationError struct {
	code      ErrorCode
	retryable bool
}

func applicationError(code ErrorCode, retryable bool) *ApplicationError {
	return &ApplicationError{code: code, retryable: retryable}
}

// Error returns only the stable public code.
func (e *ApplicationError) Error() string { return string(e.code) }

// Code returns the machine-readable public reason.
func (e *ApplicationError) Code() ErrorCode { return e.code }

// Retryable reports whether rerunning the same operation is safe.
func (e *ApplicationError) Retryable() bool { return e.retryable }
