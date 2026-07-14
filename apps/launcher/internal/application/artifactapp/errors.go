package artifactapp

import (
	"errors"
	"fmt"
)

// ErrorCode is a stable privacy-safe artifact application outcome.
type ErrorCode string

const (
	// ErrorInvalidCommand rejects malformed or unsigned input.
	ErrorInvalidCommand ErrorCode = "invalid_command"
	// ErrorReservation reports unsupported or failed local reservation.
	ErrorReservation ErrorCode = "reservation_failure"
	// ErrorRepository reports authenticated persistence failure.
	ErrorRepository ErrorCode = "repository_failure"
	// ErrorSource reports bounded source unavailability.
	ErrorSource ErrorCode = "source_failure"
	// ErrorIntegrity reports any source/store/plan contradiction.
	ErrorIntegrity ErrorCode = "integrity_failure"
	// ErrorStore reports a local content-store operation failure.
	ErrorStore ErrorCode = "store_failure"
	// ErrorCompensation reports incomplete invalid-partial cleanup.
	ErrorCompensation ErrorCode = "compensation_incomplete"
)

// Error contains no raw URL, path, process output, or transport diagnostic.
type Error struct {
	Code ErrorCode
	Op   string
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("artifact acquisition %s: %s", e.Op, e.Code)
}

// Is compares stable application error codes.
func (e *Error) Is(target error) bool {
	var other *Error
	return errors.As(target, &other) && e.Code == other.Code
}

func appError(code ErrorCode, operation string) error { return &Error{Code: code, Op: operation} }
