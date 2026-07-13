package installapp

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001InstallationLockContractIsMachineGlobal(t *testing.T) {
	t.Parallel()

	lockPort := &globalLockPortSpy{}
	capabilities := newPhaseCapabilities()
	dependencies := dependencies(newMemoryOperationRepository(), capabilities)
	dependencies.InstallationLock = lockPort
	application, err := NewInstallApplication(dependencies)
	if err != nil {
		t.Fatalf("NewInstallApplication() error = %v", err)
	}

	for _, operationID := range []string{"global-lock-a", "global-lock-b"} {
		if _, err := application.Install(context.Background(), command(operationID, "plan")); err != nil {
			t.Fatalf("Install(%q) error = %v", operationID, err)
		}
	}
	if lockPort.acquisitions != 2 {
		t.Fatalf("global lock acquisitions = %d, want 2", lockPort.acquisitions)
	}
}

func TestPF001ExternalDeadlineErrorsRemainDurablyResumable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{name: "cancellation", err: context.Canceled},
		{name: "deadline", err: context.DeadlineExceeded},
		{name: "wrapped cancellation", err: errors.Join(errors.New("private adapter detail"), context.Canceled)},
		{name: "wrapped deadline", err: errors.Join(errors.New("private adapter detail"), context.DeadlineExceeded)},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			repository := newMemoryOperationRepository()
			capabilities := newPhaseCapabilities()
			capabilities.errors[install.PhaseVerifyHost] = test.err
			application := mustApplication(t, repository, capabilities)

			result, err := application.Install(
				context.Background(),
				command(testOperationID("deadline-"+test.name), "plan"),
			)
			assertApplicationErrorCode(t, err, ErrorCodeDeadlineExceeded)
			assertApplicationErrorRetryable(t, err, true)
			if result.State != install.StateFailedRecoverable || result.ErrorCode != ErrorCodeDeadlineExceeded {
				t.Fatalf(
					"state/code = %s/%s, want FailedRecoverable/%s",
					result.State,
					result.ErrorCode,
					ErrorCodeDeadlineExceeded,
				)
			}
			if repository.mustLoad(t, result.OperationID).State() != install.StateFailedRecoverable {
				t.Fatal("deadline transition was not durable")
			}
			if err != nil && errors.Is(err, test.err) {
				t.Fatal("application error exposed the external cause")
			}

			delete(capabilities.errors, install.PhaseVerifyHost)
			resumed, resumeError := application.Install(
				context.Background(),
				command(testOperationID("deadline-"+test.name), "plan"),
			)
			if resumeError != nil {
				t.Fatalf("resumed Install() error = %v", resumeError)
			}
			if resumed.State != install.StateReady {
				t.Fatalf("resumed state = %s, want Ready", resumed.State)
			}
		})
	}
}

func TestPF001ExplicitCancellationOutcomeRemainsTerminal(t *testing.T) {
	t.Parallel()

	repository := newMemoryOperationRepository()
	capabilities := newPhaseCapabilities()
	capabilities.outputs[install.PhaseVerifyHost] = mustExpectedOutput(t, PhaseOutcomeCancelled)
	application := mustApplication(t, repository, capabilities)

	result, err := application.Install(context.Background(), command("explicit-cancel", "plan"))
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if result.State != install.StateCancelled || result.Outcome != PhaseOutcomeCancelled || result.ErrorCode != "" {
		t.Fatalf("result = %#v, want terminal explicit cancellation", result)
	}
}

func TestPF001RuntimeOwnershipDriftRemainsFailClosed(t *testing.T) {
	t.Parallel()

	repository := newMemoryOperationRepository()
	capabilities := newPhaseCapabilities()
	drift := completedOutputForPhase(install.PhaseVerifyRelease)
	drift.completion.RuntimeOwnership = install.RuntimeOwnershipProvisionedByAgentMemory
	capabilities.outputs[install.PhaseVerifyRelease] = drift
	application := mustApplication(t, repository, capabilities)

	result, err := application.Install(context.Background(), command("ownership-drift", "plan"))
	assertApplicationErrorCode(t, err, ErrorCodeIntegrityViolation)
	assertApplicationErrorRetryable(t, err, false)
	if result.State != install.StateRunning || result.CurrentPhase != install.PhaseVerifyRelease {
		t.Fatalf("result cursor = %s/%s, want Running/VerifyRelease", result.State, result.CurrentPhase)
	}
	restored := repository.mustLoad(t, result.OperationID)
	if restored.State() != install.StateRunning || restored.CurrentPhase() != install.PhaseVerifyRelease {
		t.Fatalf("durable cursor = %s/%s, want Running/VerifyRelease", restored.State(), restored.CurrentPhase())
	}
}

func TestPF001InstallSnapshotsCallerOwnedPlanAndResumeReceiptAtEntry(t *testing.T) {
	t.Parallel()

	operationID, err := install.NewOperationID("entry-snapshot")
	if err != nil {
		t.Fatal(err)
	}
	canonicalPlan := []byte("canonical-plan-a")
	planDigest, err := install.BindPlan(canonicalPlan)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := install.NewOperation(operationID, planDigest)
	if err != nil {
		t.Fatal(err)
	}
	hostOutput := completedOutputForPhase(install.PhaseVerifyHost)
	hostEvidence, err := install.NewStepEvidence(install.StepEvidenceInput{
		Phase:                install.PhaseVerifyHost,
		Attempt:              operation.Attempt(),
		PlanDigest:           planDigest,
		InputDigest:          hostOutput.completion.InputDigest,
		OutputDigest:         hostOutput.completion.OutputDigest,
		Facts:                hostOutput.completion.Facts,
		RuntimeOwnership:     hostOutput.completion.RuntimeOwnership,
		CompensationBoundary: hostOutput.completion.CompensationBoundary,
		NextSafeAction:       hostOutput.completion.NextSafeAction,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := operation.CompleteStep(hostEvidence); err != nil {
		t.Fatal(err)
	}
	resumeReceipt := install.DigestBytes([]byte("correct-resume-receipt"))
	checkpoint, err := install.NewRebootCheckpoint(
		planDigest,
		install.PhaseEnsureContainerRuntime,
		operation.Attempt(),
		resumeReceipt,
		mustSafeAction(t, "resume.after_restart"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := operation.MarkRebootPending(planDigest, checkpoint); err != nil {
		t.Fatal(err)
	}

	repository := newMemoryOperationRepository()
	if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}
	lockPort := &entrySnapshotLockPort{
		entered: make(chan struct{}),
		proceed: make(chan struct{}),
	}
	capabilities := newPhaseCapabilities()
	runtimeCapture := &capturingRuntimePort{delegate: capabilities}
	dependencies := dependencies(repository, capabilities)
	dependencies.InstallationLock = lockPort
	dependencies.ContainerRuntime = runtimeCapture
	application, err := NewInstallApplication(dependencies)
	if err != nil {
		t.Fatal(err)
	}

	type installOutcome struct {
		result InstallResult
		err    error
	}
	completed := make(chan installOutcome, 1)
	go func() {
		result, installError := application.Install(context.Background(), InstallCommand{
			OperationID:   operationID.String(),
			CanonicalPlan: canonicalPlan,
			ResumeReceipt: &resumeReceipt,
		})
		completed <- installOutcome{result: result, err: installError}
	}()
	<-lockPort.entered
	copy(canonicalPlan, []byte("mutated-plan----"))
	resumeReceipt = install.DigestBytes([]byte("wrong-resume-receipt"))
	close(lockPort.proceed)

	outcome := <-completed
	if outcome.err != nil {
		t.Fatalf("Install() error = %v", outcome.err)
	}
	if outcome.result.State != install.StateReady {
		t.Fatalf("state = %s, want Ready", outcome.result.State)
	}
	wantPlan := []byte("canonical-plan-a")
	if !bytes.Equal(runtimeCapture.request.CanonicalPlan(), wantPlan) {
		t.Fatalf("phase plan = %q, want %q", runtimeCapture.request.CanonicalPlan(), wantPlan)
	}
	wantDigest, err := install.BindPlan(wantPlan)
	if err != nil {
		t.Fatal(err)
	}
	if !runtimeCapture.request.PlanDigest().Equal(wantDigest) {
		t.Fatalf("phase plan digest = %s, want %s", runtimeCapture.request.PlanDigest().String(), wantDigest.String())
	}
}

func TestPF001RepositorySaveSentinelsMapAtEveryPersistenceBoundary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		failSaveAt int
		sentinel   error
		wantCode   ErrorCode
		retryable  bool
	}{
		{name: "initial integrity", failSaveAt: 1, sentinel: ErrOperationIntegrity, wantCode: ErrorCodeIntegrityViolation},
		{name: "pre-boundary integrity", failSaveAt: 2, sentinel: ErrOperationIntegrity, wantCode: ErrorCodeIntegrityViolation},
		{name: "post-transition integrity", failSaveAt: 3, sentinel: ErrOperationIntegrity, wantCode: ErrorCodeIntegrityViolation},
		{name: "initial conflict", failSaveAt: 1, sentinel: ErrOperationConflict, wantCode: ErrorCodeConflict},
		{name: "pre-boundary conflict", failSaveAt: 2, sentinel: ErrOperationConflict, wantCode: ErrorCodeConflict},
		{name: "post-transition conflict", failSaveAt: 3, sentinel: ErrOperationConflict, wantCode: ErrorCodeConflict},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			repository := newMemoryOperationRepository()
			repository.failSaveAt = test.failSaveAt
			repository.saveError = errors.Join(test.sentinel, errors.New("private journal detail"))
			capabilities := newPhaseCapabilities()
			application := mustApplication(t, repository, capabilities)

			_, err := application.Install(
				context.Background(),
				command(testOperationID("save-"+test.name), "plan"),
			)
			assertApplicationErrorCode(t, err, test.wantCode)
			assertApplicationErrorRetryable(t, err, test.retryable)
			if err != nil && errors.Is(err, test.sentinel) {
				t.Fatal("public application error retained the repository cause")
			}
		})
	}
}

func TestPF001RepositoryLoadSentinelsUseFailClosedPrecedence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		err       error
		wantCode  ErrorCode
		retryable bool
	}{
		{name: "integrity", err: ErrOperationIntegrity, wantCode: ErrorCodeIntegrityViolation},
		{name: "conflict", err: ErrOperationConflict, wantCode: ErrorCodeConflict},
		{
			name:      "integrity dominates not found",
			err:       errors.Join(ErrOperationNotFound, ErrOperationIntegrity, errors.New("private journal detail")),
			wantCode:  ErrorCodeIntegrityViolation,
			retryable: false,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			repository := newMemoryOperationRepository()
			repository.loadError = test.err
			application := mustApplication(t, repository, newPhaseCapabilities())

			_, err := application.Install(
				context.Background(),
				command(testOperationID("load-"+test.name), "plan"),
			)
			assertApplicationErrorCode(t, err, test.wantCode)
			assertApplicationErrorRetryable(t, err, test.retryable)
			if repository.saves != 0 {
				t.Fatalf("repository saves = %d, want 0 after fail-closed load", repository.saves)
			}
		})
	}
}

func TestPF001RepositoryAndLockDeadlineErrorsUseDeadlineTaxonomy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prepare func(*Dependencies, *memoryOperationRepository)
	}{
		{
			name: "lock acquisition",
			prepare: func(dependencies *Dependencies, _ *memoryOperationRepository) {
				dependencies.InstallationLock = failingLockPort{acquireError: context.DeadlineExceeded}
			},
		},
		{
			name: "repository load",
			prepare: func(_ *Dependencies, repository *memoryOperationRepository) {
				repository.loadError = context.Canceled
			},
		},
		{
			name: "repository save",
			prepare: func(_ *Dependencies, repository *memoryOperationRepository) {
				repository.failSaveAt = 1
				repository.saveError = context.DeadlineExceeded
			},
		},
		{
			name: "lock release",
			prepare: func(dependencies *Dependencies, _ *memoryOperationRepository) {
				dependencies.InstallationLock = failingLockPort{releaseError: context.DeadlineExceeded}
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			repository := newMemoryOperationRepository()
			capabilities := newPhaseCapabilities()
			dependencies := dependencies(repository, capabilities)
			test.prepare(&dependencies, repository)
			application, err := NewInstallApplication(dependencies)
			if err != nil {
				t.Fatalf("NewInstallApplication() error = %v", err)
			}

			_, err = application.Install(
				context.Background(),
				command(testOperationID("boundary-"+test.name), "plan"),
			)
			assertApplicationErrorCode(t, err, ErrorCodeDeadlineExceeded)
			assertApplicationErrorRetryable(t, err, true)
		})
	}
}

func TestPF001FinalizationUsesFreshBoundedContexts(t *testing.T) {
	t.Parallel()

	parent, cancel := context.WithCancel(context.Background())
	cancel()
	repository := &finalizationContextRepository{memoryOperationRepository: newMemoryOperationRepository()}
	lockPort := &finalizationContextLockPort{}
	capabilities := newPhaseCapabilities()
	capabilities.errors[install.PhaseVerifyHost] = context.Canceled
	dependencies := dependencies(repository, capabilities)
	dependencies.InstallationLock = lockPort
	application, err := NewInstallApplication(dependencies)
	if err != nil {
		t.Fatalf("NewInstallApplication() error = %v", err)
	}

	_, err = application.Install(parent, command("bounded-finalization", "plan"))
	assertApplicationErrorCode(t, err, ErrorCodeDeadlineExceeded)
	assertFreshBoundedContextObservation(t, repository.transitionSave)
	assertFreshBoundedContextObservation(t, lockPort.release)
}

func TestPF001InternalContractFailuresUseInternalTaxonomy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		output PhaseOutput
	}{
		{name: "invalid output", output: PhaseOutput{}},
		{name: "invalid completion evidence", output: invalidCompletionOutput(t)},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			repository := newMemoryOperationRepository()
			capabilities := newPhaseCapabilities()
			capabilities.outputs[install.PhaseVerifyHost] = test.output
			application := mustApplication(t, repository, capabilities)

			result, err := application.Install(
				context.Background(),
				command(testOperationID("internal-"+test.name), "plan"),
			)
			assertApplicationErrorCode(t, err, ErrorCodeInternal)
			assertApplicationErrorRetryable(t, err, false)
			if result.State != install.StateFailedRecoverable || result.ErrorCode != ErrorCodeInternal {
				t.Fatalf("state/code = %s/%s, want FailedRecoverable/%s", result.State, result.ErrorCode, ErrorCodeInternal)
			}
		})
	}
}

type globalLockPortSpy struct {
	acquisitions int
}

func (p *globalLockPortSpy) Acquire(context.Context) (InstallationLock, error) {
	p.acquisitions++
	return noopInstallationLock{}, nil
}

type contextObservation struct {
	called      bool
	errAtCall   error
	hadDeadline bool
	remaining   time.Duration
}

func observeContext(ctx context.Context) contextObservation {
	deadline, hasDeadline := ctx.Deadline()
	return contextObservation{
		called:      true,
		errAtCall:   ctx.Err(),
		hadDeadline: hasDeadline,
		remaining:   time.Until(deadline),
	}
}

type finalizationContextRepository struct {
	*memoryOperationRepository
	transitionSave contextObservation
}

func (r *finalizationContextRepository) Save(ctx context.Context, snapshot install.OperationSnapshot) error {
	if r.saves == 2 {
		r.transitionSave = observeContext(ctx)
	}
	return r.memoryOperationRepository.Save(ctx, snapshot)
}

type finalizationContextLockPort struct {
	release contextObservation
}

func (p *finalizationContextLockPort) Acquire(context.Context) (InstallationLock, error) {
	return finalizationContextLock{observation: &p.release}, nil
}

type finalizationContextLock struct {
	observation *contextObservation
}

type entrySnapshotLockPort struct {
	entered chan struct{}
	proceed chan struct{}
}

func (p *entrySnapshotLockPort) Acquire(ctx context.Context) (InstallationLock, error) {
	close(p.entered)
	select {
	case <-p.proceed:
		return noopInstallationLock{}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type capturingRuntimePort struct {
	delegate *phaseCapabilities
	request  PhaseRequest
}

func (p *capturingRuntimePort) EnsureContainerRuntime(
	_ context.Context,
	request PhaseRequest,
) (PhaseOutput, error) {
	p.request = request
	return p.delegate.execute(install.PhaseEnsureContainerRuntime)
}

func (l finalizationContextLock) Release(ctx context.Context) error {
	*l.observation = observeContext(ctx)
	return nil
}

func assertFreshBoundedContextObservation(t *testing.T, observation contextObservation) {
	t.Helper()
	if !observation.called {
		t.Fatal("finalization boundary was not called")
	}
	if observation.errAtCall != nil {
		t.Fatalf("fresh finalization context error at call = %v", observation.errAtCall)
	}
	if !observation.hadDeadline {
		t.Fatal("finalization context had no deadline")
	}
	if observation.remaining <= 0 || observation.remaining > finalizationTimeout {
		t.Fatalf("finalization deadline remaining = %s, want (0, %s]", observation.remaining, finalizationTimeout)
	}
}

func assertApplicationErrorRetryable(t *testing.T, err error, expected bool) {
	t.Helper()
	var publicError *ApplicationError
	if !errors.As(err, &publicError) {
		t.Fatalf("error type = %T, want *ApplicationError", err)
	}
	if publicError.Retryable() != expected {
		t.Fatalf("Retryable() = %t, want %t", publicError.Retryable(), expected)
	}
}

func invalidCompletionOutput(t *testing.T) PhaseOutput {
	t.Helper()
	output := completedOutputForPhase(install.PhaseVerifyHost)
	output.completion.Facts = []install.NonSecretFact{{}}
	return output
}
