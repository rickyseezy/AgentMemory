package installapp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/rebootapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001InstallApplicationCompletesEveryPhaseInNormativeOrder(t *testing.T) {
	t.Parallel()

	repository := newMemoryOperationRepository()
	capabilities := newPhaseCapabilities()
	application := mustApplication(t, repository, capabilities)

	result, err := application.Install(context.Background(), command("pf001-complete", "plan-a"))
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if result.State != install.StateReady {
		t.Fatalf("Install() state = %s, want Ready", result.State)
	}
	if result.Outcome != PhaseOutcomeCompleted {
		t.Fatalf("Install() outcome = %s, want completed", result.Outcome)
	}
	if len(capabilities.releaseReasons) != 1 || capabilities.releaseReasons[0] != ReservationReleaseCompleted {
		t.Fatalf("activation settlement reasons = %v", capabilities.releaseReasons)
	}
	assertPhasesEqual(t, capabilities.calls, install.OrderedPhases())

	operation := repository.mustLoad(t, "pf001-complete")
	completed := operation.CompletedEvidence()
	if len(completed) != len(install.OrderedPhases()) {
		t.Fatalf("completed evidence = %d, want %d", len(completed), len(install.OrderedPhases()))
	}
	for index, evidence := range completed {
		if evidence.Phase() != install.OrderedPhases()[index] {
			t.Fatalf("evidence[%d].Phase() = %s, want %s", index, evidence.Phase(), install.OrderedPhases()[index])
		}
		if evidence.Attempt() != 1 {
			t.Fatalf("evidence[%d].Attempt() = %d, want 1", index, evidence.Attempt())
		}
	}

	// One save creates the operation. Each phase then has a durable checkpoint
	// before its side effect and another after its state transition.
	wantSaves := 1 + (2 * len(install.OrderedPhases()))
	if repository.saves != wantSaves {
		t.Fatalf("repository saves = %d, want %d", repository.saves, wantSaves)
	}
}

func TestPF001NonArtifactPhasePreservesAbsentArtifactDigest(t *testing.T) {
	t.Parallel()

	repository := newMemoryOperationRepository()
	capabilities := newPhaseCapabilities()
	application := mustApplication(t, repository, capabilities)

	if _, err := application.Install(context.Background(), command("pf001-no-host-artifact", "plan-a")); err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	evidence := repository.mustLoad(t, "pf001-no-host-artifact").CompletedEvidence()
	if evidence[0].Phase() != install.PhaseVerifyHost {
		t.Fatalf("first evidence phase = %s, want VerifyHost", evidence[0].Phase())
	}
	if !evidence[0].VerifiedArtifactDigest().IsZero() {
		t.Fatal("non-artifact VerifyHost phase fabricated an artifact digest")
	}
}

func TestPF001InstallApplicationRetriesTheFirstUnverifiedPhaseAfterEveryInterruption(t *testing.T) {
	t.Parallel()

	for failureIndex, failedPhase := range install.OrderedPhases() {
		failureIndex := failureIndex
		failedPhase := failedPhase
		t.Run(failedPhase.String(), func(t *testing.T) {
			t.Parallel()

			repository := newMemoryOperationRepository()
			capabilities := newPhaseCapabilities()
			capabilities.failOnceAt = failedPhase
			application := mustApplication(t, repository, capabilities)
			installCommand := command("interrupt-"+failedPhase.String(), "plan-a")

			firstResult, firstErr := application.Install(context.Background(), installCommand)
			assertApplicationErrorCode(t, firstErr, ErrorCodeInternal)
			if firstResult.State != install.StateFailedRecoverable {
				t.Fatalf("first state = %s, want FailedRecoverable", firstResult.State)
			}
			assertPhasesEqual(t, capabilities.calls, install.OrderedPhases()[:failureIndex+1])

			secondResult, secondErr := application.Install(context.Background(), installCommand)
			if secondErr != nil {
				t.Fatalf("retry Install() error = %v", secondErr)
			}
			if secondResult.State != install.StateReady {
				t.Fatalf("retry state = %s, want Ready", secondResult.State)
			}

			operation := repository.mustLoad(t, installCommand.OperationID)
			completed := operation.CompletedEvidence()
			if completed[failureIndex].Phase() != failedPhase {
				t.Fatalf("retry evidence phase = %s, want %s", completed[failureIndex].Phase(), failedPhase)
			}
			if completed[failureIndex].Attempt() != 2 {
				t.Fatalf("retry evidence attempt = %d, want 2", completed[failureIndex].Attempt())
			}
			for index := failureIndex + 1; index < len(completed); index++ {
				if completed[index].Attempt() != 1 {
					t.Fatalf("later phase %s attempt = %d, want 1", completed[index].Phase(), completed[index].Attempt())
				}
			}
		})
	}
}

func TestPF001InstallApplicationMapsExpectedCapabilityOutcomesDurably(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		outcome       PhaseOutcome
		wantState     install.State
		wantErrorCode ErrorCode
	}{
		{name: "recoverable", outcome: PhaseOutcomeFailedRecoverable, wantState: install.StateFailedRecoverable, wantErrorCode: ErrorCodeDependencyUnavailable},
		{name: "administrator", outcome: PhaseOutcomeAdministratorRequired, wantState: install.StatePausedForAdministrator, wantErrorCode: ErrorCodeSetupAdminRequired},
		{name: "cancelled", outcome: PhaseOutcomeCancelled, wantState: install.StateCancelled, wantErrorCode: ""},
		{name: "unsupported host", outcome: PhaseOutcomeUnsupportedHost, wantState: install.StateUnsupportedHost, wantErrorCode: ErrorCodeUnsupportedHost},
		{name: "runtime conflict", outcome: PhaseOutcomeRuntimeConflict, wantState: install.StateRuntimeConflict, wantErrorCode: ErrorCodeRuntimeConflict},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			repository := newMemoryOperationRepository()
			capabilities := newPhaseCapabilities()
			capabilities.outputs[install.PhaseVerifyHost] = mustExpectedOutput(t, test.outcome)
			application := mustApplication(t, repository, capabilities)

			result, err := application.Install(context.Background(), command("outcome-"+strings.ReplaceAll(test.name, " ", "-"), "plan-a"))
			if err != nil {
				t.Fatalf("Install() error = %v", err)
			}
			if result.State != test.wantState {
				t.Fatalf("state = %s, want %s", result.State, test.wantState)
			}
			if result.ErrorCode != test.wantErrorCode {
				t.Fatalf("error code = %s, want %s", result.ErrorCode, test.wantErrorCode)
			}
			assertPhasesEqual(t, capabilities.calls, []install.Phase{install.PhaseVerifyHost})
			if repository.mustLoad(t, result.OperationID).State() != test.wantState {
				t.Fatalf("durable state was not %s", test.wantState)
			}
		})
	}
}

func TestPF001CancelPersistsTerminalIntentBeforeRetryableReservationCleanup(t *testing.T) {
	t.Parallel()

	repository := newMemoryOperationRepository()
	capabilities := newPhaseCapabilities()
	capabilities.outputs[install.PhaseReserveSpace] = mustExpectedOutput(t, PhaseOutcomeFailedRecoverable)
	application := mustApplication(t, repository, capabilities)
	installCommand := command("cancel-after-reservation", "plan-a")

	paused, err := application.Install(context.Background(), installCommand)
	if err != nil || paused.State != install.StateFailedRecoverable || paused.CurrentPhase != install.PhaseReserveSpace {
		t.Fatalf("paused Install()=(%+v,%v)", paused, err)
	}
	phaseCalls := len(capabilities.calls)
	capabilities.releaseError = errors.New("private reservation cleanup failure")
	requested, err := application.Cancel(context.Background(), CancelCommand{
		OperationID: installCommand.OperationID, CanonicalPlan: installCommand.CanonicalPlan,
	})
	if err != nil || !requested.CancellationRequested || requested.CancellationSettled ||
		requested.State == install.StateCancelled {
		t.Fatalf("Cancel()=(%+v,%v), want durable request without false settlement", requested, err)
	}
	result, err := application.Install(context.Background(), installCommand)
	assertApplicationErrorCode(t, err, ErrorCodeDependencyUnavailable)
	if result.State != install.StateCancelled || repository.mustLoad(t, installCommand.OperationID).State() != install.StateCancelled {
		t.Fatalf("cancel state result/durable=%s/%s", result.State, repository.mustLoad(t, installCommand.OperationID).State())
	}
	if len(capabilities.releaseReasons) != 1 || capabilities.releaseReasons[0] != ReservationReleaseCancelled ||
		len(capabilities.calls) != phaseCalls {
		t.Fatalf("cleanup reasons/phase calls=%v/%v", capabilities.releaseReasons, capabilities.calls)
	}

	capabilities.releaseError = nil
	replayed, err := application.Install(context.Background(), installCommand)
	if err != nil || replayed.State != install.StateCancelled || !replayed.CancellationSettled ||
		len(capabilities.releaseReasons) != 2 {
		t.Fatalf("replayed Install()=(%+v,%v), releases=%v", replayed, err, capabilities.releaseReasons)
	}
}

func TestPF001TerminalOutcomeSettlesReservationButEarlyTerminationDoesNotInventOne(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name         string
		phase        install.Phase
		outcome      PhaseOutcome
		wantReleases int
		wantReason   ReservationReleaseReason
	}{
		{name: "early unsupported", phase: install.PhaseVerifyHost, outcome: PhaseOutcomeUnsupportedHost},
		{name: "cancel after reserve", phase: install.PhaseEnsureDirectories, outcome: PhaseOutcomeCancelled, wantReleases: 1, wantReason: ReservationReleaseCancelled},
		{name: "conflict after reserve", phase: install.PhaseEnsureDirectories, outcome: PhaseOutcomeRuntimeConflict, wantReleases: 1, wantReason: ReservationReleaseRollback},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			repository := newMemoryOperationRepository()
			capabilities := newPhaseCapabilities()
			if test.outcome != PhaseOutcomeCompleted {
				capabilities.outputs[test.phase] = mustExpectedOutput(t, test.outcome)
			}
			application := mustApplication(t, repository, capabilities)
			result, err := application.Install(context.Background(), command("settle-"+strings.ReplaceAll(test.name, " ", "-"), "plan-a"))
			if err != nil {
				t.Fatalf("Install() error=%v", err)
			}
			if len(capabilities.releaseReasons) != test.wantReleases {
				t.Fatalf("release reasons=%v, want count %d", capabilities.releaseReasons, test.wantReleases)
			}
			if test.wantReleases == 1 && capabilities.releaseReasons[0] != test.wantReason {
				t.Fatalf("release reason=%v, want %v", capabilities.releaseReasons[0], test.wantReason)
			}
			if result.State == install.StateReady {
				t.Fatal("terminal non-ready outcome reached Ready")
			}
		})
	}
}

func TestPF001TerminalReservationCleanupRetriesWithoutRepeatingInstallSideEffects(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		phase      install.Phase
		outcome    PhaseOutcome
		wantState  install.State
		wantReason ReservationReleaseReason
	}{
		{
			name: "ready", phase: install.PhaseCommitActiveRelease, outcome: PhaseOutcomeCompleted,
			wantState: install.StateReady, wantReason: ReservationReleaseCompleted,
		},
		{
			name: "runtime conflict", phase: install.PhaseEnsureDirectories, outcome: PhaseOutcomeRuntimeConflict,
			wantState: install.StateRuntimeConflict, wantReason: ReservationReleaseRollback,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			repository := newMemoryOperationRepository()
			capabilities := newPhaseCapabilities()
			if test.outcome != PhaseOutcomeCompleted {
				capabilities.outputs[test.phase] = mustExpectedOutput(t, test.outcome)
			}
			capabilities.releaseError = errors.New("private cleanup failure")
			application := mustApplication(t, repository, capabilities)
			installCommand := command("terminal-cleanup-"+strings.ReplaceAll(test.name, " ", "-"), "plan-a")

			first, firstError := application.Install(context.Background(), installCommand)
			assertApplicationErrorCode(t, firstError, ErrorCodeDependencyUnavailable)
			if first.State != test.wantState || repository.mustLoad(t, installCommand.OperationID).State() != test.wantState ||
				len(capabilities.releaseReasons) != 1 || capabilities.releaseReasons[0] != test.wantReason {
				t.Fatalf("first result/state/releases=%+v/%s/%v", first, repository.mustLoad(t, installCommand.OperationID).State(), capabilities.releaseReasons)
			}
			phaseCalls := len(capabilities.calls)
			capabilities.releaseError = nil
			replayed, replayError := application.Install(context.Background(), installCommand)
			if replayError != nil || replayed.State != test.wantState || len(capabilities.calls) != phaseCalls ||
				len(capabilities.releaseReasons) != 2 || capabilities.releaseReasons[1] != test.wantReason {
				t.Fatalf("replay result/error/calls/releases=%+v/%v/%d/%v", replayed, replayError, len(capabilities.calls), capabilities.releaseReasons)
			}

			foreign := installCommand
			foreign.CanonicalPlan = []byte("foreign-plan")
			if _, err := application.Install(context.Background(), foreign); err == nil || len(capabilities.releaseReasons) != 2 {
				t.Fatalf("foreign terminal replay error/releases=%v/%v", err, capabilities.releaseReasons)
			}
		})
	}
}

func TestPF001CancelRejectsReadyAndForeignPlanWithoutCleanup(t *testing.T) {
	t.Parallel()

	repository := newMemoryOperationRepository()
	capabilities := newPhaseCapabilities()
	application := mustApplication(t, repository, capabilities)
	installCommand := command("cancel-rejected", "plan-a")
	if _, err := application.Install(context.Background(), installCommand); err != nil {
		t.Fatalf("Install() error=%v", err)
	}
	settledBeforeRejectedCancel := len(capabilities.releaseReasons)
	for _, cancelCommand := range []CancelCommand{
		{OperationID: installCommand.OperationID, CanonicalPlan: []byte("plan-b")},
		{OperationID: installCommand.OperationID, CanonicalPlan: installCommand.CanonicalPlan},
	} {
		if _, err := application.Cancel(context.Background(), cancelCommand); err == nil {
			t.Fatal("Cancel() error=nil, want plan/terminal conflict")
		}
	}
	if len(capabilities.releaseReasons) != settledBeforeRejectedCancel {
		t.Fatalf("rejected cancellation released capacity: %v", capabilities.releaseReasons)
	}
}

func TestPF001InstallApplicationPersistsAndVerifiesRebootResume(t *testing.T) {
	t.Parallel()

	repository := newMemoryOperationRepository()
	capabilities := newPhaseCapabilities()
	receipt := install.DigestBytes([]byte("trusted-resume-receipt"))
	action := mustSafeAction(t, "restart.host.and.resume")
	capabilities.outputs[install.PhaseEnsureContainerRuntime] = mustRebootOutput(t, receipt, action)
	application := mustApplication(t, repository, capabilities)
	installCommand := command("reboot-resume", "plan-a")

	first, err := application.Install(context.Background(), installCommand)
	if err != nil {
		t.Fatalf("first Install() error = %v", err)
	}
	if first.State != install.StateRebootPending || first.ErrorCode != ErrorCodeRebootRequired {
		t.Fatalf("first result = state %s code %s, want RebootPending/%s", first.State, first.ErrorCode, ErrorCodeRebootRequired)
	}
	if len(capabilities.rebootRegistrations) != 1 {
		t.Fatal("reboot continuation was not registered after the pending journal became durable")
	}
	assertPhasesEqual(t, capabilities.calls, []install.Phase{install.PhaseVerifyHost, install.PhaseEnsureContainerRuntime})

	// A repeated request without a receipt reports the checkpoint without
	// invoking or persisting another side effect.
	callsBefore := len(capabilities.calls)
	savesBefore := repository.saves
	repeated, err := application.Install(context.Background(), installCommand)
	if err != nil {
		t.Fatalf("repeated Install() error = %v", err)
	}
	if repeated.State != install.StateRebootPending {
		t.Fatalf("repeated state = %s, want RebootPending", repeated.State)
	}
	if repeated.ResumeAction != install.ResumeActionAwaitVerification {
		t.Fatalf("repeated resume action = %d, want AwaitVerification", repeated.ResumeAction)
	}
	if len(capabilities.calls) != callsBefore || repository.saves != savesBefore {
		t.Fatal("receipt-free replay performed work")
	}
	if len(capabilities.rebootRegistrations) != 2 {
		t.Fatal("pending replay did not reconcile the native login registration")
	}

	delete(capabilities.outputs, install.PhaseEnsureContainerRuntime)
	installCommand.ResumeContinuation = true
	resumed, err := application.Install(context.Background(), installCommand)
	if err != nil {
		t.Fatalf("resumed Install() error = %v", err)
	}
	if resumed.State != install.StateReady {
		t.Fatalf("resumed state = %s, want Ready", resumed.State)
	}
	if len(capabilities.rebootConsumptions) != 1 || len(capabilities.rebootRemovals) == 0 {
		t.Fatal("native continuation was not consumed once and removed after resume")
	}

	operation := repository.mustLoad(t, installCommand.OperationID)
	evidence := operation.CompletedEvidence()
	if evidence[1].Phase() != install.PhaseEnsureContainerRuntime || evidence[1].Attempt() != 2 {
		t.Fatalf("runtime retry evidence = phase %s attempt %d", evidence[1].Phase(), evidence[1].Attempt())
	}
}

func TestPF001InstallApplicationRecoversWhenResumeVerificationSaveIsInterrupted(t *testing.T) {
	t.Parallel()

	repository := newMemoryOperationRepository()
	capabilities := newPhaseCapabilities()
	receipt := install.DigestBytes([]byte("trusted-resume-receipt"))
	action := mustSafeAction(t, "restart.host.and.resume")
	capabilities.outputs[install.PhaseEnsureContainerRuntime] = mustRebootOutput(t, receipt, action)
	application := mustApplication(t, repository, capabilities)
	installCommand := command("reboot-resume-save-interruption", "plan-a")
	if _, err := application.Install(context.Background(), installCommand); err != nil {
		t.Fatalf("initial Install() error = %v", err)
	}

	delete(capabilities.outputs, install.PhaseEnsureContainerRuntime)
	installCommand.ResumeContinuation = true
	repository.failSaveAt = repository.saves + 1
	if _, err := application.Install(context.Background(), installCommand); err == nil {
		t.Fatal("interrupted ResumeVerified save unexpectedly succeeded")
	}
	if durable := repository.mustLoad(t, installCommand.OperationID); durable.State() != install.StateRebootPending {
		t.Fatalf("failed save changed durable state to %s", durable.State())
	}
	if len(capabilities.rebootConsumptions) != 1 || len(capabilities.rebootRemovals) != 0 {
		t.Fatal("failed durable resume save removed the crash-recovery continuation")
	}

	repository.failSaveAt = 0
	resumed, err := application.Install(context.Background(), installCommand)
	if err != nil || resumed.State != install.StateReady {
		t.Fatalf("recovered Install() = (%+v, %v)", resumed, err)
	}
	if len(capabilities.rebootConsumptions) != 2 || len(capabilities.rebootRemovals) == 0 {
		t.Fatal("recovery did not idempotently re-claim and eventually remove the continuation")
	}
}

func TestPF001InstallApplicationAlreadyReadyReplayIsIdempotent(t *testing.T) {
	t.Parallel()

	repository := newMemoryOperationRepository()
	capabilities := newPhaseCapabilities()
	application := mustApplication(t, repository, capabilities)
	installCommand := command("already-ready", "plan-a")

	if _, err := application.Install(context.Background(), installCommand); err != nil {
		t.Fatalf("first Install() error = %v", err)
	}
	callsBefore := len(capabilities.calls)
	savesBefore := repository.saves

	result, err := application.Install(context.Background(), installCommand)
	if err != nil {
		t.Fatalf("replay Install() error = %v", err)
	}
	if result.State != install.StateReady || result.ResumeAction != install.ResumeActionAlreadyReady {
		t.Fatalf("replay state/action = %s/%d, want Ready/AlreadyReady", result.State, result.ResumeAction)
	}
	if len(capabilities.calls) != callsBefore || repository.saves != savesBefore {
		t.Fatal("AlreadyReady replay performed or persisted work")
	}
}

func TestPF001InstallApplicationRejectsPlanMismatchWithStableCode(t *testing.T) {
	t.Parallel()

	repository := newMemoryOperationRepository()
	capabilities := newPhaseCapabilities()
	capabilities.failOnceAt = install.PhaseVerifyHost
	application := mustApplication(t, repository, capabilities)

	if _, err := application.Install(context.Background(), command("plan-bound", "plan-a")); err == nil {
		t.Fatal("first Install() error = nil, want injected interruption")
	}
	callsBefore := len(capabilities.calls)
	savesBefore := repository.saves

	_, err := application.Install(context.Background(), command("plan-bound", "plan-b"))
	assertApplicationErrorCode(t, err, ErrorCodeIdempotencyConflict)
	if len(capabilities.calls) != callsBefore || repository.saves != savesBefore {
		t.Fatal("plan mismatch performed or persisted work")
	}
}

func TestPF001InstallApplicationSanitizesUnexpectedCapabilityFailures(t *testing.T) {
	t.Parallel()

	repository := newMemoryOperationRepository()
	capabilities := newPhaseCapabilities()
	secretFailure := strings.Join([]string{"exec /private/path --", "token", " redacted-value failed"}, "")
	capabilities.errors[install.PhaseVerifyHost] = errors.New(secretFailure)
	application := mustApplication(t, repository, capabilities)

	result, err := application.Install(context.Background(), command("sanitized", "plan-a"))
	assertApplicationErrorCode(t, err, ErrorCodeInternal)
	assertApplicationErrorRetryable(t, err, false)
	if strings.Contains(err.Error(), secretFailure) || strings.Contains(err.Error(), "redacted-value") {
		t.Fatalf("public error exposed adapter internals: %q", err)
	}
	if result.State != install.StateFailedRecoverable {
		t.Fatalf("state = %s, want FailedRecoverable", result.State)
	}
	if repository.mustLoad(t, result.OperationID).State() != install.StateFailedRecoverable {
		t.Fatal("unexpected failure was not durably recoverable")
	}
}

func TestPF001InstallApplicationDoesNotInvokeSideEffectWhenPreBoundarySaveFails(t *testing.T) {
	t.Parallel()

	repository := newMemoryOperationRepository()
	// Save one creates the operation; save two is the boundary immediately
	// before VerifyHost.
	repository.failSaveAt = 2
	capabilities := newPhaseCapabilities()
	application := mustApplication(t, repository, capabilities)

	_, err := application.Install(context.Background(), command("pre-boundary", "plan-a"))
	assertApplicationErrorCode(t, err, ErrorCodeDependencyUnavailable)
	if len(capabilities.calls) != 0 {
		t.Fatalf("side effects = %v, want none", capabilities.calls)
	}
}

func TestPF001InstallApplicationMapsContextCancellationToDurableResumableState(t *testing.T) {
	t.Parallel()

	repository := newMemoryOperationRepository()
	capabilities := newPhaseCapabilities()
	capabilities.errors[install.PhaseVerifyHost] = context.Canceled
	application := mustApplication(t, repository, capabilities)

	result, err := application.Install(context.Background(), command("cancelled-context", "plan-a"))
	assertApplicationErrorCode(t, err, ErrorCodeDeadlineExceeded)
	if result.State != install.StateFailedRecoverable || result.ErrorCode != ErrorCodeDeadlineExceeded {
		t.Fatalf(
			"state/code = %s/%s, want FailedRecoverable/%s",
			result.State,
			result.ErrorCode,
			ErrorCodeDeadlineExceeded,
		)
	}
	if repository.mustLoad(t, result.OperationID).State() != install.StateFailedRecoverable {
		t.Fatal("deadline state was not durably resumable")
	}
}

func TestPF001NewInstallApplicationRejectsEveryMissingProductionDependency(t *testing.T) {
	t.Parallel()

	repository := newMemoryOperationRepository()
	capabilities := newPhaseCapabilities()
	valid := dependencies(repository, capabilities)

	tests := []struct {
		name   string
		remove func(*Dependencies)
	}{
		{name: "operation repository", remove: func(d *Dependencies) { d.Operations = nil }},
		{name: "cancellation intents", remove: func(d *Dependencies) { d.CancellationIntents = nil }},
		{name: "installation lock", remove: func(d *Dependencies) { d.InstallationLock = nil }},
		{name: "reboot coordinator", remove: func(d *Dependencies) { d.RebootCoordinator = nil }},
		{name: "verify host", remove: func(d *Dependencies) { d.HostVerification = nil }},
		{name: "ensure container runtime", remove: func(d *Dependencies) { d.ContainerRuntime = nil }},
		{name: "verify release", remove: func(d *Dependencies) { d.ReleaseVerification = nil }},
		{name: "reserve space", remove: func(d *Dependencies) { d.SpaceReservation = nil }},
		{name: "ensure directories", remove: func(d *Dependencies) { d.Directories = nil }},
		{name: "ensure keys", remove: func(d *Dependencies) { d.Keys = nil }},
		{name: "ensure compose bundle", remove: func(d *Dependencies) { d.ComposeBundle = nil }},
		{name: "ensure network and volumes", remove: func(d *Dependencies) { d.NetworkAndVolumes = nil }},
		{name: "run migrations", remove: func(d *Dependencies) { d.Migrations = nil }},
		{name: "ensure core and graph", remove: func(d *Dependencies) { d.CoreAndGraph = nil }},
		{name: "bootstrap local brain", remove: func(d *Dependencies) { d.BrainBootstrap = nil }},
		{name: "merge agent configuration", remove: func(d *Dependencies) { d.AgentConfiguration = nil }},
		{name: "verify readiness", remove: func(d *Dependencies) { d.Readiness = nil }},
		{name: "commit active release", remove: func(d *Dependencies) { d.ActiveRelease = nil }},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := valid
			test.remove(&candidate)
			if application, err := NewInstallApplication(candidate); err == nil || application != nil {
				t.Fatalf("NewInstallApplication() = (%v, %v), want nil/error", application, err)
			}
		})
	}
}

func TestPF001PhaseOutputConstructorsRejectUnverifiedData(t *testing.T) {
	t.Parallel()

	boundary := mustBoundary(t, "rollback.current.phase")
	action := mustSafeAction(t, "retry.current.phase")
	validDigest := install.DigestBytes([]byte("valid"))

	if _, err := NewCompletedPhaseOutput(CompletionOutput{
		InputDigest:            install.Digest{},
		OutputDigest:           validDigest,
		VerifiedArtifactDigest: validDigest,
		RuntimeOwnership:       install.RuntimeOwnershipNotApplicable,
		CompensationBoundary:   boundary,
		NextSafeAction:         action,
	}); err == nil {
		t.Fatal("NewCompletedPhaseOutput() accepted a zero input digest")
	}
	if _, err := NewExpectedPhaseOutput(PhaseOutcomeCompleted, action); err == nil {
		t.Fatal("NewExpectedPhaseOutput() accepted completed without evidence")
	}
	if _, err := NewExpectedPhaseOutput(PhaseOutcomeRebootRequired, action); err == nil {
		t.Fatal("NewExpectedPhaseOutput() accepted reboot without receipt")
	}
	if _, err := NewRebootRequiredPhaseOutput(install.Digest{}, action); err == nil {
		t.Fatal("NewRebootRequiredPhaseOutput() accepted a zero receipt")
	}
}

type memoryOperationRepository struct {
	mu         sync.Mutex
	operations map[string]install.OperationSnapshot
	saves      int
	failSaveAt int
	saveError  error
	loadError  error
	returnNil  bool
}

func newMemoryOperationRepository() *memoryOperationRepository {
	return &memoryOperationRepository{operations: make(map[string]install.OperationSnapshot)}
}

func (r *memoryOperationRepository) Load(_ context.Context, id install.OperationID) (*install.Operation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.loadError != nil {
		return nil, r.loadError
	}
	if r.returnNil {
		return nil, nil
	}
	snapshot, found := r.operations[id.String()]
	if !found {
		return nil, ErrOperationNotFound
	}
	return restoreSnapshot(snapshot)
}

func (r *memoryOperationRepository) Save(_ context.Context, snapshot install.OperationSnapshot) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.saves++
	if r.failSaveAt != 0 && r.saves == r.failSaveAt {
		if r.saveError != nil {
			return r.saveError
		}
		return errors.New("injected repository failure /private/journal")
	}
	r.operations[snapshot.OperationID().String()] = snapshot
	return nil
}

func (r *memoryOperationRepository) mustLoad(t *testing.T, id string) *install.Operation {
	t.Helper()
	operationID, err := install.NewOperationID(id)
	if err != nil {
		t.Fatalf("NewOperationID() error = %v", err)
	}
	operation, err := r.Load(context.Background(), operationID)
	if err != nil {
		t.Fatalf("repository.Load() error = %v", err)
	}
	return operation
}

func restoreSnapshot(snapshot install.OperationSnapshot) (*install.Operation, error) {
	checkpoint, hasCheckpoint := snapshot.RebootCheckpoint()
	var checkpointPointer *install.RebootCheckpoint
	if hasCheckpoint {
		checkpointPointer = &checkpoint
	}
	restoreInput := install.RestoreInput{
		OperationID:      snapshot.OperationID(),
		PlanDigest:       snapshot.PlanDigest(),
		AggregateVersion: snapshot.AggregateVersion(),
		State:            snapshot.State(),
		CurrentPhase:     snapshot.CurrentPhase(),
		Attempt:          snapshot.Attempt(),
		Completed:        snapshot.CompletedEvidence(),
		RebootCheckpoint: checkpointPointer,
	}
	if cancellation, ok := snapshot.CancellationIntent(); ok {
		restoreInput.CancellationIntent = &install.CancellationRestoreInput{
			RequestedAtVersion:    cancellation.RequestedAtVersion(),
			AcknowledgedAtVersion: cancellation.AcknowledgedAtVersion(),
		}
	}
	return install.RestoreOperation(restoreInput)
}

type memoryLockPort struct {
	acquisitions int
}

func (p *memoryLockPort) Acquire(context.Context) (InstallationLock, error) {
	p.acquisitions++
	return noopInstallationLock{}, nil
}

type noopInstallationLock struct{}

func (noopInstallationLock) Release(context.Context) error { return nil }

type phaseCapabilities struct {
	calls               []install.Phase
	outputs             map[install.Phase]PhaseOutput
	errors              map[install.Phase]error
	failOnceAt          install.Phase
	failed              bool
	releaseReasons      []ReservationReleaseReason
	releaseError        error
	runtimeCancelCalls  int
	runtimeCancelError  error
	rebootRegistrations []rebootapp.Binding
	rebootConsumptions  []rebootapp.Binding
	rebootRemovals      []install.OperationID
	rebootError         error
}

func newPhaseCapabilities() *phaseCapabilities {
	return &phaseCapabilities{
		outputs: make(map[install.Phase]PhaseOutput),
		errors:  make(map[install.Phase]error),
	}
}

func (p *phaseCapabilities) execute(phase install.Phase) (PhaseOutput, error) {
	p.calls = append(p.calls, phase)
	if phase == p.failOnceAt && !p.failed {
		p.failed = true
		return PhaseOutput{}, errors.New("simulated machine interruption")
	}
	if err := p.errors[phase]; err != nil {
		return PhaseOutput{}, err
	}
	if output, found := p.outputs[phase]; found {
		return output, nil
	}
	return completedOutputForPhase(phase), nil
}

func (p *phaseCapabilities) VerifyHost(context.Context, PhaseRequest) (PhaseOutput, error) {
	return p.execute(install.PhaseVerifyHost)
}
func (p *phaseCapabilities) EnsureContainerRuntime(context.Context, PhaseRequest) (PhaseOutput, error) {
	return p.execute(install.PhaseEnsureContainerRuntime)
}
func (p *phaseCapabilities) CancelContainerRuntime(context.Context, PhaseRequest) error {
	p.runtimeCancelCalls++
	return p.runtimeCancelError
}
func (p *phaseCapabilities) VerifyRelease(context.Context, PhaseRequest) (PhaseOutput, error) {
	return p.execute(install.PhaseVerifyRelease)
}
func (p *phaseCapabilities) ReserveSpace(context.Context, PhaseRequest) (PhaseOutput, error) {
	return p.execute(install.PhaseReserveSpace)
}
func (p *phaseCapabilities) ReleaseSpace(
	_ context.Context,
	_ PhaseRequest,
	reason ReservationReleaseReason,
) error {
	p.releaseReasons = append(p.releaseReasons, reason)
	return p.releaseError
}
func (p *phaseCapabilities) EnsureDirectories(context.Context, PhaseRequest) (PhaseOutput, error) {
	return p.execute(install.PhaseEnsureDirectories)
}
func (p *phaseCapabilities) EnsureKeys(context.Context, PhaseRequest) (PhaseOutput, error) {
	return p.execute(install.PhaseEnsureKeys)
}
func (p *phaseCapabilities) EnsureComposeBundle(context.Context, PhaseRequest) (PhaseOutput, error) {
	return p.execute(install.PhaseEnsureComposeBundle)
}
func (p *phaseCapabilities) EnsureNetworkAndVolumes(context.Context, PhaseRequest) (PhaseOutput, error) {
	return p.execute(install.PhaseEnsureNetworkAndVolumes)
}
func (p *phaseCapabilities) RunMigrations(context.Context, PhaseRequest) (PhaseOutput, error) {
	return p.execute(install.PhaseRunMigrations)
}
func (p *phaseCapabilities) EnsureCoreAndGraph(context.Context, PhaseRequest) (PhaseOutput, error) {
	return p.execute(install.PhaseEnsureCoreAndGraph)
}
func (p *phaseCapabilities) BootstrapLocalBrain(context.Context, PhaseRequest) (PhaseOutput, error) {
	return p.execute(install.PhaseBootstrapLocalBrain)
}
func (p *phaseCapabilities) MergeAgentConfiguration(context.Context, PhaseRequest) (PhaseOutput, error) {
	return p.execute(install.PhaseMergeAgentConfiguration)
}
func (p *phaseCapabilities) VerifyReadiness(context.Context, PhaseRequest) (PhaseOutput, error) {
	return p.execute(install.PhaseVerifyReadiness)
}
func (p *phaseCapabilities) CommitActiveRelease(context.Context, PhaseRequest) (PhaseOutput, error) {
	return p.execute(install.PhaseCommitActiveRelease)
}

func (p *phaseCapabilities) Register(_ context.Context, binding rebootapp.Binding) error {
	p.rebootRegistrations = append(p.rebootRegistrations, binding)
	return p.rebootError
}

func (p *phaseCapabilities) Consume(_ context.Context, binding rebootapp.Binding) error {
	p.rebootConsumptions = append(p.rebootConsumptions, binding)
	return p.rebootError
}

func (p *phaseCapabilities) Remove(_ context.Context, operationID install.OperationID) error {
	p.rebootRemovals = append(p.rebootRemovals, operationID)
	return p.rebootError
}

func completedOutputForPhase(phase install.Phase) PhaseOutput {
	boundary, _ := install.NewCompensationBoundary("rollback." + strings.ToLower(phase.String()))
	action, _ := install.NewSafeAction("continue." + strings.ToLower(phase.String()))
	fact, _ := install.NewNonSecretFact("verified_phase", phase.String())
	var verifiedArtifactDigest install.Digest
	if install.PhaseRequiresVerifiedArtifact(phase) {
		verifiedArtifactDigest = install.DigestBytes([]byte("artifact:" + phase.String()))
	}
	runtimeOwnership := install.RuntimeOwnershipUndetermined
	if phase != install.PhaseVerifyHost {
		runtimeOwnership = install.RuntimeOwnershipReusedExternal
	}
	output, err := NewCompletedPhaseOutput(CompletionOutput{
		InputDigest:            install.DigestBytes([]byte("input:" + phase.String())),
		OutputDigest:           install.DigestBytes([]byte("output:" + phase.String())),
		VerifiedArtifactDigest: verifiedArtifactDigest,
		Facts:                  []install.NonSecretFact{fact},
		RuntimeOwnership:       runtimeOwnership,
		CompensationBoundary:   boundary,
		NextSafeAction:         action,
	})
	if err != nil {
		panic(fmt.Sprintf("valid test output: %v", err))
	}
	return output
}

func command(operationID, plan string) InstallCommand {
	return InstallCommand{OperationID: operationID, CanonicalPlan: []byte(plan)}
}

func dependencies(repository OperationRepository, capabilities *phaseCapabilities) Dependencies {
	authority := newMemoryOperationAuthority(repository)
	return Dependencies{
		Operations:          authority,
		CancellationIntents: authority,
		InstallationLock:    &memoryLockPort{},
		RebootCoordinator:   capabilities,
		HostVerification:    capabilities,
		ContainerRuntime:    capabilities,
		ReleaseVerification: capabilities,
		SpaceReservation:    capabilities,
		Directories:         capabilities,
		Keys:                capabilities,
		ComposeBundle:       capabilities,
		NetworkAndVolumes:   capabilities,
		Migrations:          capabilities,
		CoreAndGraph:        capabilities,
		BrainBootstrap:      capabilities,
		AgentConfiguration:  capabilities,
		Readiness:           capabilities,
		ActiveRelease:       capabilities,
	}
}

type memoryOperationAuthority struct {
	OperationRepository
	*memoryCancellationIntentPort
}

func newMemoryOperationAuthority(repository OperationRepository) *memoryOperationAuthority {
	return &memoryOperationAuthority{
		OperationRepository:          repository,
		memoryCancellationIntentPort: newMemoryCancellationIntentPort(repository),
	}
}

func mustApplication(t *testing.T, repository OperationRepository, capabilities *phaseCapabilities) *InstallApplication {
	t.Helper()
	application, err := NewInstallApplication(dependencies(repository, capabilities))
	if err != nil {
		t.Fatalf("NewInstallApplication() error = %v", err)
	}
	return application
}

func mustExpectedOutput(t *testing.T, outcome PhaseOutcome) PhaseOutput {
	t.Helper()
	output, err := NewExpectedPhaseOutput(outcome, mustSafeAction(t, "follow.expected.action"))
	if err != nil {
		t.Fatalf("NewExpectedPhaseOutput() error = %v", err)
	}
	return output
}

func mustRebootOutput(t *testing.T, receipt install.Digest, action install.SafeAction) PhaseOutput {
	t.Helper()
	output, err := NewRebootRequiredPhaseOutput(receipt, action)
	if err != nil {
		t.Fatalf("NewRebootRequiredPhaseOutput() error = %v", err)
	}
	return output
}

func mustSafeAction(t *testing.T, key string) install.SafeAction {
	t.Helper()
	action, err := install.NewSafeAction(key)
	if err != nil {
		t.Fatalf("NewSafeAction() error = %v", err)
	}
	return action
}

func mustBoundary(t *testing.T, key string) install.CompensationBoundary {
	t.Helper()
	boundary, err := install.NewCompensationBoundary(key)
	if err != nil {
		t.Fatalf("NewCompensationBoundary() error = %v", err)
	}
	return boundary
}

func assertPhasesEqual(t *testing.T, actual, expected []install.Phase) {
	t.Helper()
	if len(actual) != len(expected) {
		t.Fatalf("phase call count = %d (%v), want %d (%v)", len(actual), actual, len(expected), expected)
	}
	for index := range expected {
		if actual[index] != expected[index] {
			t.Fatalf("phase[%d] = %s, want %s", index, actual[index], expected[index])
		}
	}
}

func assertApplicationErrorCode(t *testing.T, err error, expected ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want %s", expected)
	}
	var applicationError *ApplicationError
	if !errors.As(err, &applicationError) {
		t.Fatalf("error type = %T, want *ApplicationError", err)
	}
	if applicationError.Code() != expected {
		t.Fatalf("error code = %s, want %s", applicationError.Code(), expected)
	}
}
