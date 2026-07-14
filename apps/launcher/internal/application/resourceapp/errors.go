package resourceapp

import (
	"errors"
	"fmt"
)

// ErrorCode is a stable privacy-safe EnsureNetworkAndVolumes outcome.
type ErrorCode string

const (
	// ErrorInvalidCommand rejects malformed or cross-install input.
	ErrorInvalidCommand ErrorCode = "invalid_command"
	// ErrorInventory rejects unauthenticated, stale, or contradictory state.
	ErrorInventory ErrorCode = "inventory_failure"
	// ErrorEngine reports a bounded Docker boundary failure.
	ErrorEngine ErrorCode = "engine_failure"
	// ErrorOwnership reports a foreign object or ownership mismatch.
	ErrorOwnership ErrorCode = "ownership_failure"
	// ErrorCompensation reports that safe cleanup could not be completed.
	ErrorCompensation ErrorCode = "compensation_incomplete"
)

// Error exposes only a stable code and safe operation key. Raw Docker output,
// host paths, and external diagnostics are never retained.
type Error struct {
	Code ErrorCode
	Op   string
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("ensure managed resources %s: %s", e.Op, e.Code)
}

// Is compares stable application error codes.
func (e *Error) Is(target error) bool {
	var other *Error
	return errors.As(target, &other) && e.Code == other.Code
}

func applicationError(code ErrorCode, operation string) error {
	return &Error{Code: code, Op: operation}
}
