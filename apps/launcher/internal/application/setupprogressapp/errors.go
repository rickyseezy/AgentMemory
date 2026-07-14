package setupprogressapp

import "errors"

// ErrorCode is a safe transport-neutral setup error taxonomy.
type ErrorCode string

//nolint:revive // Closed codes are documented by ErrorCode and their classifier functions.
const (
	ErrorInvalidArgument ErrorCode = "AM_SETUP_INVALID_ARGUMENT"
	ErrorDeadline        ErrorCode = "AM_SETUP_DEADLINE"
	ErrorConflict        ErrorCode = "AM_SETUP_CONFLICT"
	ErrorIntegrity       ErrorCode = "AM_SETUP_INTEGRITY"
	ErrorUnavailable     ErrorCode = "AM_SETUP_UNAVAILABLE"
)

// ApplicationError contains no raw backend diagnostics, paths, or secrets.
type ApplicationError struct{ code ErrorCode }

func (e *ApplicationError) Error() string { return string(e.code) }

// Code returns the stable safe error classification.
func (e *ApplicationError) Code() ErrorCode { return e.code }

// IsInvalidArgument reports malformed caller input.
func IsInvalidArgument(err error) bool { return hasCode(err, ErrorInvalidArgument) }

// IsDeadlineError reports cancellation or deadline expiry.
func IsDeadlineError(err error) bool { return hasCode(err, ErrorDeadline) }

// IsConflictError reports a durable concurrent decision.
func IsConflictError(err error) bool { return hasCode(err, ErrorConflict) }

// IsIntegrityError reports a contradictory authority response.
func IsIntegrityError(err error) bool { return hasCode(err, ErrorIntegrity) }

func hasCode(err error, code ErrorCode) bool {
	var applicationError *ApplicationError
	ok := errors.As(err, &applicationError)
	return ok && applicationError.code == code
}

func newApplicationError(code ErrorCode) *ApplicationError { return &ApplicationError{code: code} }
