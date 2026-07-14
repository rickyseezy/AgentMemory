package readinessapp

// ErrorCode is the stable public readiness error taxonomy.
type ErrorCode string

const (
	// ErrorCodeInvalidArgument rejects an invalid release binding.
	ErrorCodeInvalidArgument ErrorCode = "AM_INVALID_ARGUMENT"
	// ErrorCodeDeadlineExceeded reports caller cancellation/deadline.
	ErrorCodeDeadlineExceeded ErrorCode = "AM_DEADLINE_EXCEEDED"
	// ErrorCodeDependencyUnavailable reports a failed probe boundary.
	ErrorCodeDependencyUnavailable ErrorCode = "AM_DEPENDENCY_UNAVAILABLE"
	// ErrorCodeConflict reports a concurrent receipt decision.
	ErrorCodeConflict ErrorCode = "AM_CONFLICT"
	// ErrorCodeIntegrityViolation reports unauthentic persisted receipt state.
	ErrorCodeIntegrityViolation ErrorCode = "AM_INTEGRITY_VIOLATION"
	// ErrorCodeInternal sanitizes an unclassified failure.
	ErrorCodeInternal ErrorCode = "AM_INTERNAL"
)

// ApplicationError never exposes raw database, Docker, path, or provider data.
type ApplicationError struct {
	code      ErrorCode
	retryable bool
}

func (e *ApplicationError) Error() string { return string(e.code) }

// Code returns the stable public code.
func (e *ApplicationError) Code() ErrorCode { return e.code }

// Retryable reports whether the same bound operation may retry.
func (e *ApplicationError) Retryable() bool { return e.retryable }

func applicationError(code ErrorCode, retryable bool) *ApplicationError {
	return &ApplicationError{code: code, retryable: retryable}
}
