package installapp

import (
	"context"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

// ErrorCode is a stable public boundary code.
type ErrorCode string

const (
	// ErrorCodeValidation reports malformed inbound input.
	ErrorCodeValidation ErrorCode = "AM_VALIDATION"
	// ErrorCodeIdempotencyConflict reports an operation/plan digest mismatch.
	ErrorCodeIdempotencyConflict ErrorCode = "AM_IDEMPOTENCY_CONFLICT"
	// ErrorCodeIntegrityViolation reports contradictory durable state.
	ErrorCodeIntegrityViolation ErrorCode = "AM_INTEGRITY_VIOLATION"
	// ErrorCodeConflict reports a valid request rejected by current aggregate state.
	ErrorCodeConflict ErrorCode = "AM_CONFLICT"
	// ErrorCodeDependencyUnavailable reports an unavailable phase, lock, or persistence dependency.
	ErrorCodeDependencyUnavailable ErrorCode = "AM_DEPENDENCY_UNAVAILABLE"
	// ErrorCodeDeadlineExceeded reports cancellation or deadline expiry at an external boundary.
	ErrorCodeDeadlineExceeded ErrorCode = "AM_DEADLINE_EXCEEDED"
	// ErrorCodeInternal reports a sanitized, otherwise-unclassified internal contract failure.
	ErrorCodeInternal ErrorCode = "AM_INTERNAL"
	// ErrorCodeSetupAdminRequired reports a privileged local setup action.
	ErrorCodeSetupAdminRequired ErrorCode = "AM_SETUP_ADMIN_REQUIRED"
	// ErrorCodeUnsupportedHost reports a terminal platform decision.
	ErrorCodeUnsupportedHost ErrorCode = "AM_UNSUPPORTED_HOST"
	// ErrorCodeRuntimeConflict reports an incompatible pre-existing runtime.
	ErrorCodeRuntimeConflict ErrorCode = "AM_RUNTIME_CONFLICT"
	// ErrorCodeRebootRequired reports a receipt-bound reboot checkpoint.
	ErrorCodeRebootRequired ErrorCode = "AM_REBOOT_REQUIRED"
)

// ApplicationError deliberately does not retain or unwrap an infrastructure
// cause. Raw commands, paths, credentials, and process output therefore cannot
// cross an inbound adapter by formatting or errors.Unwrap.
type ApplicationError struct {
	code      ErrorCode
	retryable bool
	message   string
}

func (e *ApplicationError) Error() string { return e.message }

// Code returns the stable public error code.
func (e *ApplicationError) Code() ErrorCode { return e.code }

// Retryable reports whether repeating the same plan may make progress.
func (e *ApplicationError) Retryable() bool { return e.retryable }

func applicationError(code ErrorCode, retryable bool, message string) *ApplicationError {
	return &ApplicationError{code: code, retryable: retryable, message: message}
}

func deadlineError() *ApplicationError {
	return applicationError(ErrorCodeDeadlineExceeded, true, "installation deadline was exceeded")
}

func internalError() *ApplicationError {
	return applicationError(ErrorCodeInternal, false, "installation could not continue")
}

func mapExternalBoundaryError(err error, dependencyMessage string) *ApplicationError {
	if isDeadlineBoundary(err) {
		return deadlineError()
	}
	return applicationError(ErrorCodeDependencyUnavailable, true, dependencyMessage)
}

func mapRepositoryError(err error, dependencyMessage string) *ApplicationError {
	switch {
	case errors.Is(err, ErrOperationIntegrity):
		return applicationError(ErrorCodeIntegrityViolation, false, "installation state could not be verified")
	case errors.Is(err, ErrOperationConflict):
		return applicationError(ErrorCodeConflict, false, "installation state changed concurrently")
	default:
		return mapExternalBoundaryError(err, dependencyMessage)
	}
}

func isDeadlineBoundary(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func failClosedDomainError(err error) bool {
	var coded install.CodedError
	if !errors.As(err, &coded) {
		return false
	}
	switch coded.Code() {
	case install.ErrorCodeIdempotencyConflict,
		install.ErrorCodeIntegrityViolation,
		install.ErrorCodeConflict:
		return true
	case install.ErrorCodeValidation:
		return false
	}
	return true
}

func mapDomainError(err error) *ApplicationError {
	var coded install.CodedError
	if !errors.As(err, &coded) {
		return applicationError(ErrorCodeIntegrityViolation, false, "installation state could not be verified")
	}
	switch coded.Code() {
	case install.ErrorCodeIdempotencyConflict:
		return applicationError(ErrorCodeIdempotencyConflict, false, "installation operation is bound to a different plan")
	case install.ErrorCodeValidation:
		return applicationError(ErrorCodeValidation, false, "installation request is invalid")
	case install.ErrorCodeIntegrityViolation:
		return applicationError(ErrorCodeIntegrityViolation, false, "installation state could not be verified")
	case install.ErrorCodeConflict:
		return applicationError(ErrorCodeConflict, coded.Retryable(), "installation transition was rejected")
	}
	return applicationError(ErrorCodeIntegrityViolation, false, "installation state could not be verified")
}
