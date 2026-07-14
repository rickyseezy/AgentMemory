package mcpbootstrapapp

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/setupprogressapp"
)

// Application exposes only the three operations available while PF-001 has
// not completed. Status always comes from the durable progress authority.
type Application struct {
	installationID string
	binding        setupprogressapp.Binding
	progress       *setupprogressapp.Application
	setup          SetupPort
	cancellation   CancellationPort
}

// New constructs the bootstrap use case from narrow inward ports.
func New(
	installationID string,
	progress *setupprogressapp.Application,
	setup SetupPort,
	cancellation CancellationPort,
) (*Application, error) {
	if !validInstallationID(installationID) || progress == nil || !progress.Binding().Valid() ||
		nilCapability(setup) || nilCapability(cancellation) {
		return nil, newApplicationError(ErrorInvalidArgument)
	}
	return &Application{
		installationID: installationID,
		binding:        progress.Binding(),
		progress:       progress,
		setup:          setup,
		cancellation:   cancellation,
	}, nil
}

// Identity returns the non-secret installation and operation identifiers used
// to correlate typed tool failures when no status snapshot can be loaded.
func (a *Application) Identity() (installationID, operationID string) {
	if a == nil || !a.binding.Valid() {
		return "", ""
	}
	return a.installationID, a.binding.OperationID().String()
}

// Status returns the latest backend-authoritative projection.
func (a *Application) Status(ctx context.Context) (InstallationStatus, error) {
	if err := a.validateCall(ctx); err != nil {
		return InstallationStatus{}, err
	}
	snapshot, err := a.progress.Current(ctx)
	if err != nil {
		return InstallationStatus{}, mapProgressError(err)
	}
	return a.project(snapshot)
}

// WaitAfter blocks behind the durable progress authority until a newer
// snapshot exists. It is used for Ready handoff without polling host paths.
func (a *Application) WaitAfter(ctx context.Context, sequence uint64) (InstallationStatus, error) {
	if err := a.validateCall(ctx); err != nil {
		return InstallationStatus{}, err
	}
	snapshot, err := a.progress.WaitAfter(ctx, sequence)
	if err != nil {
		return InstallationStatus{}, mapProgressError(err)
	}
	return a.project(snapshot)
}

// OpenSetup opens one fresh browser-only capability and returns no URL or
// credential material.
func (a *Application) OpenSetup(ctx context.Context) (OpenSetupResult, error) {
	if err := a.validateCall(ctx); err != nil {
		return OpenSetupResult{}, err
	}
	if err := a.setup.OpenSetup(ctx); err != nil {
		return OpenSetupResult{}, mapPortError(err)
	}
	return OpenSetupResult{
		ContractVersion: setupprogressapp.ContractVersion,
		InstallationID:  a.installationID,
		OperationID:     a.binding.OperationID().String(),
		Opened:          true,
	}, nil
}

// Cancel durably requests cancellation, then re-reads authoritative status.
// Request acceptance never implies terminal cancellation settlement.
func (a *Application) Cancel(ctx context.Context) (CancelResult, error) {
	if err := a.validateCall(ctx); err != nil {
		return CancelResult{}, err
	}
	if err := a.cancellation.RequestCancellation(ctx); err != nil {
		return CancelResult{}, mapPortError(err)
	}
	status, err := a.Status(ctx)
	if err != nil {
		return CancelResult{}, err
	}
	return CancelResult{
		ContractVersion:       setupprogressapp.ContractVersion,
		InstallationID:        a.installationID,
		OperationID:           a.binding.OperationID().String(),
		CancellationRequested: true,
		Status:                status,
	}, nil
}

func (a *Application) validateCall(ctx context.Context) error {
	if a == nil || ctx == nil || !validInstallationID(a.installationID) || !a.binding.Valid() ||
		a.progress == nil || nilCapability(a.setup) || nilCapability(a.cancellation) {
		return newApplicationError(ErrorInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return newApplicationError(ErrorDeadline)
	}
	return nil
}

func (a *Application) project(snapshot setupprogressapp.Snapshot) (InstallationStatus, error) {
	if snapshot.OperationID() != a.binding.OperationID() ||
		!snapshot.PlanDigest().Equal(a.binding.PlanDigest()) {
		return InstallationStatus{}, newApplicationError(ErrorIntegrity)
	}
	if _, err := snapshot.CanonicalJSON(); err != nil {
		return InstallationStatus{}, newApplicationError(ErrorIntegrity)
	}
	progress := snapshot.Progress()
	state := snapshot.State()
	return InstallationStatus{
		ContractVersion:     setupprogressapp.ContractVersion,
		Sequence:            snapshot.Sequence(),
		InstallationID:      a.installationID,
		OperationID:         snapshot.OperationID().String(),
		State:               string(state),
		Phase:               string(snapshot.Phase()),
		CompletedBytes:      progress.DownloadedBytes,
		TotalBytes:          progress.TotalBytes,
		CompletedStages:     progress.CompletedStages,
		TotalStages:         progress.TotalStages,
		MessageKey:          string(snapshot.MessageKey()),
		MessageArguments:    make([]MessageArgument, 0),
		Interaction:         interactionFor(snapshot),
		AutomaticRetryAt:    nil,
		Cancellable:         cancellable(snapshot),
		Error:               statusError(snapshot),
		ReadyHandoffPending: state == setupprogressapp.StateReady,
	}, nil
}

func interactionFor(snapshot setupprogressapp.Snapshot) InteractionKind {
	switch snapshot.State() {
	case setupprogressapp.StateAwaitingConsent:
		return InteractionTerms
	case setupprogressapp.StateRebootRequired:
		return InteractionRestart
	case setupprogressapp.StatePausedForAdministrator:
		if snapshot.SafeAction() == setupprogressapp.ActionOpenNativePrompt {
			return InteractionElevation
		}
		return InteractionAdministrator
	case setupprogressapp.StateConnecting, setupprogressapp.StateRunning,
		setupprogressapp.StateReady, setupprogressapp.StateFailed,
		setupprogressapp.StateCancelled:
		return InteractionNone
	default:
		return InteractionNone
	}
}

func cancellable(snapshot setupprogressapp.Snapshot) bool {
	switch snapshot.State() {
	case setupprogressapp.StateReady, setupprogressapp.StateCancelled:
		return false
	case setupprogressapp.StateFailed:
		return snapshot.SafeAction() == setupprogressapp.ActionRetry ||
			snapshot.SafeAction() == setupprogressapp.ActionCancel
	case setupprogressapp.StateConnecting, setupprogressapp.StateAwaitingConsent,
		setupprogressapp.StateRunning, setupprogressapp.StatePausedForAdministrator,
		setupprogressapp.StateRebootRequired:
		return true
	default:
		return false
	}
}

func statusError(snapshot setupprogressapp.Snapshot) *StatusError {
	switch snapshot.State() {
	case setupprogressapp.StateFailed:
		return &StatusError{
			Code:      "AM_DEPENDENCY_UNAVAILABLE",
			Retryable: snapshot.SafeAction() == setupprogressapp.ActionRetry,
		}
	case setupprogressapp.StatePausedForAdministrator:
		return &StatusError{Code: "AM_SETUP_ADMIN_REQUIRED", Retryable: true}
	case setupprogressapp.StateRebootRequired:
		return &StatusError{Code: "AM_REBOOT_REQUIRED", Retryable: true}
	case setupprogressapp.StateConnecting, setupprogressapp.StateAwaitingConsent,
		setupprogressapp.StateRunning, setupprogressapp.StateReady,
		setupprogressapp.StateCancelled:
		return nil
	default:
		return &StatusError{Code: "AM_SETUP_INTEGRITY", Retryable: false}
	}
}
