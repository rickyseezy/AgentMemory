package mcpbootstrapapp

import (
	"context"
	"errors"
	"reflect"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/setupprogressapp"
)

const maximumInstallationIDBytes = 128

// InteractionKind is the closed set of user interactions exposed before the
// product MCP session is ready.
type InteractionKind string

const (
	// InteractionNone means setup requires no user interaction.
	InteractionNone InteractionKind = "none"
	// InteractionTerms requires a terms decision in the setup surface.
	InteractionTerms InteractionKind = "terms"
	// InteractionElevation requires an OS-native elevation decision.
	InteractionElevation InteractionKind = "elevation"
	// InteractionRestart requires an OS restart.
	InteractionRestart InteractionKind = "restart"
	// InteractionAdministrator requires administrator remediation.
	InteractionAdministrator InteractionKind = "administrator"
)

// StatusError is a stable, privacy-safe installation error projection.
type StatusError struct {
	Code      string `json:"code"`
	Retryable bool   `json:"retryable"`
}

// InstallationStatus is the complete safe MCP status result. It deliberately
// contains no host path, executable, credential, URL, or raw backend error.
type InstallationStatus struct {
	ContractVersion     uint8             `json:"contract_version"`
	Sequence            uint64            `json:"sequence"`
	InstallationID      string            `json:"installation_id"`
	OperationID         string            `json:"operation_id"`
	State               string            `json:"state"`
	Phase               string            `json:"phase"`
	CompletedBytes      uint64            `json:"completed_bytes"`
	TotalBytes          uint64            `json:"total_bytes"`
	CompletedStages     uint64            `json:"completed_stages"`
	TotalStages         uint64            `json:"total_stages"`
	MessageKey          string            `json:"message_key"`
	MessageArguments    []MessageArgument `json:"message_arguments"`
	Interaction         InteractionKind   `json:"interaction"`
	AutomaticRetryAt    *string           `json:"automatic_retry_at"`
	Cancellable         bool              `json:"cancellable"`
	Error               *StatusError      `json:"error"`
	ReadyHandoffPending bool              `json:"ready_handoff_pending"`
}

// MessageArgument is a bounded localization substitution. PF-001 currently
// has no backend-authoritative substitutions, so status returns an empty list
// rather than inventing display text.
type MessageArgument struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// OpenSetupResult confirms only that a browser capability was opened. The
// capability and loopback origins are intentionally absent.
type OpenSetupResult struct {
	ContractVersion uint8  `json:"contract_version"`
	InstallationID  string `json:"installation_id"`
	OperationID     string `json:"operation_id"`
	Opened          bool   `json:"opened"`
}

// CancelResult distinguishes durable request acceptance from terminal
// settlement and includes the latest backend-authoritative status.
type CancelResult struct {
	ContractVersion       uint8              `json:"contract_version"`
	InstallationID        string             `json:"installation_id"`
	OperationID           string             `json:"operation_id"`
	CancellationRequested bool               `json:"cancellation_requested"`
	Status                InstallationStatus `json:"status"`
}

// ErrorCode is a closed, transport-neutral bootstrap failure taxonomy.
type ErrorCode string

const (
	// ErrorInvalidArgument reports an invalid bootstrap request.
	ErrorInvalidArgument ErrorCode = "AM_SETUP_INVALID_ARGUMENT"
	// ErrorDeadline reports cancellation or timeout.
	ErrorDeadline ErrorCode = "AM_SETUP_DEADLINE"
	// ErrorConflict reports a durable concurrent decision.
	ErrorConflict ErrorCode = "AM_SETUP_CONFLICT"
	// ErrorIntegrity reports contradictory authenticated state.
	ErrorIntegrity ErrorCode = "AM_SETUP_INTEGRITY"
	// ErrorUnavailable reports a temporarily unavailable dependency.
	ErrorUnavailable ErrorCode = "AM_SETUP_UNAVAILABLE"
)

// ApplicationError contains only a stable code. Infrastructure errors are
// never retained or unwrapped across the MCP boundary.
type ApplicationError struct{ code ErrorCode }

func (e *ApplicationError) Error() string { return string(e.code) }

// Code returns the stable safe error classification.
func (e *ApplicationError) Code() ErrorCode { return e.code }

func newApplicationError(code ErrorCode) *ApplicationError { return &ApplicationError{code: code} }

func validInstallationID(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > maximumInstallationIDBytes {
		return false
	}
	for _, character := range value {
		if character <= 0x20 || character == 0x7f || character == '/' || character == '\\' {
			return false
		}
	}
	return true
}

func nilCapability(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Every non-nilable concrete kind is a valid capability.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid:
		return true
	default:
		return false
	}
}

func mapProgressError(err error) *ApplicationError {
	switch {
	case setupprogressapp.IsInvalidArgument(err):
		return newApplicationError(ErrorInvalidArgument)
	case setupprogressapp.IsDeadlineError(err):
		return newApplicationError(ErrorDeadline)
	case setupprogressapp.IsConflictError(err):
		return newApplicationError(ErrorConflict)
	case setupprogressapp.IsIntegrityError(err):
		return newApplicationError(ErrorIntegrity)
	default:
		return newApplicationError(ErrorUnavailable)
	}
}

func mapPortError(err error) *ApplicationError {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return newApplicationError(ErrorDeadline)
	}
	return newApplicationError(ErrorUnavailable)
}
