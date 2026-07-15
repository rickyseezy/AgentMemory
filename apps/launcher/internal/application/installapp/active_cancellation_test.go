package installapp

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001CancelRequestsIntentWithoutWaitingForMachineMutationLock(t *testing.T) {
	t.Parallel()

	repository := newMemoryOperationRepository()
	capabilities := newPhaseCapabilities()
	intents := newMemoryCancellationIntentPort(repository)
	blocking := &cancellableHostPhase{started: make(chan struct{})}
	lock := newSerialInstallationLockPort()
	deps := dependencies(repository, capabilities)
	authority := &memoryOperationAuthority{OperationRepository: repository, memoryCancellationIntentPort: intents}
	deps.Operations = authority
	deps.CancellationIntents = authority
	deps.InstallationLock = lock
	deps.HostVerification = blocking
	application, err := NewInstallApplication(deps)
	if err != nil {
		t.Fatalf("NewInstallApplication() error = %v", err)
	}

	command := command("active-cancel", "plan-a")
	installDone := make(chan struct {
		result InstallResult
		err    error
	}, 1)
	go func() {
		result, installError := application.Install(context.Background(), command)
		installDone <- struct {
			result InstallResult
			err    error
		}{result: result, err: installError}
	}()

	select {
	case <-blocking.started:
	case <-time.After(time.Second):
		t.Fatal("blocking phase did not start")
	}

	cancelDone := make(chan struct {
		result InstallResult
		err    error
	}, 1)
	go func() {
		result, cancelError := application.Cancel(context.Background(), CancelCommand{
			OperationID: command.OperationID, CanonicalPlan: command.CanonicalPlan,
		})
		cancelDone <- struct {
			result InstallResult
			err    error
		}{result: result, err: cancelError}
	}()

	select {
	case requested := <-cancelDone:
		if requested.err != nil || !requested.result.CancellationRequested || requested.result.CancellationSettled {
			t.Fatalf("Cancel() = (%+v, %v), want requested/non-terminal", requested.result, requested.err)
		}
		if requested.result.State == install.StateCancelled {
			t.Fatal("Cancel() falsely reported terminal settlement")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Cancel() waited for the machine mutation lock")
	}

	select {
	case completed := <-installDone:
		if completed.err != nil || completed.result.State != install.StateCancelled || !completed.result.CancellationSettled {
			t.Fatalf("Install() after intent = (%+v, %v)", completed.result, completed.err)
		}
	case <-time.After(time.Second):
		t.Fatal("active phase was not cancelled promptly")
	}
	if !blocking.cancelled() || !intents.acknowledged(command.OperationID) {
		t.Fatal("phase context was not cancelled or durable intent was not acknowledged")
	}
}

func TestPF001CancellationRequestedBeforePhasePreventsSideEffect(t *testing.T) {
	t.Parallel()

	repository := newMemoryOperationRepository()
	operationID, _ := install.NewOperationID("cancel-before-phase")
	plan, _ := install.BindPlan([]byte("plan-a"))
	operation, _ := install.NewOperation(operationID, plan)
	if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatalf("seed operation: %v", err)
	}
	capabilities := newPhaseCapabilities()
	intents := newMemoryCancellationIntentPort(repository)
	deps := dependencies(repository, capabilities)
	authority := &memoryOperationAuthority{OperationRepository: repository, memoryCancellationIntentPort: intents}
	deps.Operations = authority
	deps.CancellationIntents = authority
	application, err := NewInstallApplication(deps)
	if err != nil {
		t.Fatalf("NewInstallApplication() error = %v", err)
	}

	requested, err := application.Cancel(context.Background(), CancelCommand{
		OperationID: operationID.String(), CanonicalPlan: []byte("plan-a"),
	})
	if err != nil || !requested.CancellationRequested || requested.CancellationSettled {
		t.Fatalf("Cancel() = (%+v, %v)", requested, err)
	}
	settled, err := application.Install(context.Background(), command(operationID.String(), "plan-a"))
	if err != nil || settled.State != install.StateCancelled || !settled.CancellationSettled {
		t.Fatalf("Install() = (%+v, %v)", settled, err)
	}
	if len(capabilities.calls) != 0 {
		t.Fatalf("phases ran after pre-existing cancellation intent: %v", capabilities.calls)
	}
}

func TestPF001CancellationAcknowledgementCrashReplaysOnlySettlement(t *testing.T) {
	t.Parallel()

	repository := newMemoryOperationRepository()
	operationID, _ := install.NewOperationID("cancel-ack-replay")
	plan, _ := install.BindPlan([]byte("plan-a"))
	operation, _ := install.NewOperation(operationID, plan)
	if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}
	capabilities := newPhaseCapabilities()
	intents := newMemoryCancellationIntentPort(repository)
	deps := dependencies(repository, capabilities)
	authority := &memoryOperationAuthority{OperationRepository: repository, memoryCancellationIntentPort: intents}
	deps.Operations = authority
	deps.CancellationIntents = authority
	application, err := NewInstallApplication(deps)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := application.Cancel(context.Background(), CancelCommand{
		OperationID: operationID.String(), CanonicalPlan: []byte("plan-a"),
	}); err != nil {
		t.Fatal(err)
	}
	intents.mu.Lock()
	intents.ackError = errors.New("injected acknowledgement crash")
	intents.mu.Unlock()
	first, err := application.Install(context.Background(), command(operationID.String(), "plan-a"))
	assertApplicationErrorCode(t, err, ErrorCodeDependencyUnavailable)
	if first.State != install.StateCancelled || first.CancellationSettled || len(capabilities.calls) != 0 {
		t.Fatalf("first settlement=(%+v,%v), calls=%v", first, err, capabilities.calls)
	}
	intents.mu.Lock()
	intents.ackError = nil
	intents.mu.Unlock()
	replayed, err := application.Install(context.Background(), command(operationID.String(), "plan-a"))
	if err != nil || !replayed.CancellationSettled || len(capabilities.calls) != 0 {
		t.Fatalf("replayed settlement=(%+v,%v), calls=%v", replayed, err, capabilities.calls)
	}
	idempotent, err := application.Cancel(context.Background(), CancelCommand{
		OperationID: operationID.String(), CanonicalPlan: []byte("plan-a"),
	})
	if err != nil || !idempotent.CancellationSettled {
		t.Fatalf("idempotent Cancel()=(%+v,%v)", idempotent, err)
	}
}

func TestPF001PendingRebootCancellationSettlesWithoutResumeReceipt(t *testing.T) {
	t.Parallel()

	operationID, _ := install.NewOperationID("cancel-reboot-pending")
	canonicalPlan := []byte("plan-a")
	plan, _ := install.BindPlan(canonicalPlan)
	operation, _ := install.NewOperation(operationID, plan)
	if err := operation.CompleteStep(testEvidenceForCancellation(t, operation, plan)); err != nil {
		t.Fatal(err)
	}
	checkpoint, err := install.NewRebootCheckpoint(
		plan,
		install.PhaseEnsureContainerRuntime,
		operation.Attempt(),
		install.DigestBytes([]byte("resume-receipt")),
		mustSafeAction(t, "resume.after_restart"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := operation.MarkRebootPending(plan, checkpoint); err != nil {
		t.Fatal(err)
	}

	repository := newMemoryOperationRepository()
	if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}
	capabilities := newPhaseCapabilities()
	application := mustApplication(t, repository, capabilities)
	if _, err := application.Cancel(context.Background(), CancelCommand{
		OperationID: operationID.String(), CanonicalPlan: canonicalPlan,
	}); err != nil {
		t.Fatal(err)
	}

	settled, err := application.Install(context.Background(), InstallCommand{
		OperationID: operationID.String(), CanonicalPlan: canonicalPlan,
	})
	if err != nil || settled.State != install.StateCancelled || !settled.CancellationSettled {
		t.Fatalf("Install() without resume receipt = (%+v, %v), want settled cancellation", settled, err)
	}
	if len(capabilities.calls) != 0 {
		t.Fatalf("phase ran while settling reboot cancellation: %v", capabilities.calls)
	}
	if capabilities.runtimeCancelCalls != 1 {
		t.Fatalf("runtime cancellation calls = %d, want 1", capabilities.runtimeCancelCalls)
	}
}

func TestPF001RuntimeCancellationFailureBlocksAcknowledgementAndRetries(t *testing.T) {
	t.Parallel()

	operationID, _ := install.NewOperationID("cancel-runtime-cleanup-retry")
	canonicalPlan := []byte("plan-a")
	plan, _ := install.BindPlan(canonicalPlan)
	operation, _ := install.NewOperation(operationID, plan)
	if err := operation.CompleteStep(testEvidenceForCancellation(t, operation, plan)); err != nil {
		t.Fatal(err)
	}
	repository := newMemoryOperationRepository()
	if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}
	capabilities := newPhaseCapabilities()
	capabilities.runtimeCancelError = errors.New("private runtime cleanup failure")
	application := mustApplication(t, repository, capabilities)
	if _, err := application.Cancel(context.Background(), CancelCommand{
		OperationID: operationID.String(), CanonicalPlan: canonicalPlan,
	}); err != nil {
		t.Fatal(err)
	}

	first, firstErr := application.Install(context.Background(), InstallCommand{
		OperationID: operationID.String(), CanonicalPlan: canonicalPlan,
	})
	assertApplicationErrorCode(t, firstErr, ErrorCodeDependencyUnavailable)
	if first.State != install.StateCancelled || first.CancellationSettled ||
		capabilities.runtimeCancelCalls != 1 {
		t.Fatalf("first settlement = (%+v, %v), runtime calls=%d", first, firstErr, capabilities.runtimeCancelCalls)
	}
	capabilities.runtimeCancelError = nil
	second, secondErr := application.Install(context.Background(), InstallCommand{
		OperationID: operationID.String(), CanonicalPlan: canonicalPlan,
	})
	if secondErr != nil || !second.CancellationSettled || capabilities.runtimeCancelCalls != 2 {
		t.Fatalf("retried settlement = (%+v, %v), runtime calls=%d", second, secondErr, capabilities.runtimeCancelCalls)
	}
}

func TestPF001CancellationWinningPreSideEffectSaveConflictSettlesInActiveInstall(t *testing.T) {
	t.Parallel()

	operationID, _ := install.NewOperationID("cancel-before-cursor-save")
	canonicalPlan := []byte("plan-a")
	plan, _ := install.BindPlan(canonicalPlan)
	operation, _ := install.NewOperation(operationID, plan)
	repository := newMemoryOperationRepository()
	if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}
	baseAuthority := newMemoryOperationAuthority(repository)
	authority := &requestOnFirstSaveAuthority{memoryOperationAuthority: baseAuthority}
	capabilities := newPhaseCapabilities()
	deps := dependencies(repository, capabilities)
	deps.Operations = authority
	deps.CancellationIntents = authority
	application, err := NewInstallApplication(deps)
	if err != nil {
		t.Fatal(err)
	}

	settled, err := application.Install(context.Background(), InstallCommand{
		OperationID: operationID.String(), CanonicalPlan: canonicalPlan,
	})
	if err != nil || settled.State != install.StateCancelled || !settled.CancellationSettled {
		t.Fatalf("Install() after request won cursor-save CAS = (%+v, %v)", settled, err)
	}
	if len(capabilities.calls) != 0 {
		t.Fatalf("phase ran after request won cursor-save CAS: %v", capabilities.calls)
	}
}

func TestPF001EqualVersionAggregateWithoutRequestCannotSettleCancellation(t *testing.T) {
	t.Parallel()

	operationID, _ := install.NewOperationID("equal-version-divergence")
	plan, _ := install.BindPlan([]byte("plan-a"))
	completed, _ := install.NewOperation(operationID, plan)
	if err := completed.CompleteStep(testEvidenceForCancellation(t, completed, plan)); err != nil {
		t.Fatal(err)
	}
	intent, err := NewRequestedCancellationIntentForAdapter(CancellationRequest{
		OperationID: operationID, PlanDigest: plan,
	}, completed.AggregateVersion())
	if err != nil {
		t.Fatal(err)
	}
	if aggregateContainsRequestedIntent(completed, intent) {
		t.Fatal("equal-version phase aggregate was mistaken for cancellation authority")
	}
	requested, _ := install.NewOperation(operationID, plan)
	if err := requested.RequestCancellation(plan); err != nil {
		t.Fatal(err)
	}
	if !aggregateContainsRequestedIntent(requested, intent) {
		t.Fatal("exact aggregate-owned request was not recognized")
	}
}

func testEvidenceForCancellation(
	t *testing.T,
	operation *install.Operation,
	plan install.PlanDigest,
) install.StepEvidence {
	t.Helper()
	fact, err := install.NewNonSecretFact("verified_phase", "VerifyHost")
	if err != nil {
		t.Fatal(err)
	}
	boundary := mustBoundary(t, "rollback.verify_host")
	action := mustSafeAction(t, "continue.verify_host")
	evidence, err := install.NewStepEvidence(install.StepEvidenceInput{
		Phase: operation.CurrentPhase(), Attempt: operation.Attempt(), PlanDigest: plan,
		InputDigest: install.DigestBytes([]byte("input")), OutputDigest: install.DigestBytes([]byte("output")),
		Facts: []install.NonSecretFact{fact}, RuntimeOwnership: install.RuntimeOwnershipUndetermined,
		CompensationBoundary: boundary, NextSafeAction: action,
	})
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

type cancellableHostPhase struct {
	started chan struct{}
	once    sync.Once
	mu      sync.Mutex
	wasDone bool
}

func (p *cancellableHostPhase) VerifyHost(ctx context.Context, _ PhaseRequest) (PhaseOutput, error) {
	p.once.Do(func() { close(p.started) })
	<-ctx.Done()
	p.mu.Lock()
	p.wasDone = true
	p.mu.Unlock()
	return PhaseOutput{}, ctx.Err()
}

func (p *cancellableHostPhase) cancelled() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.wasDone
}

type serialInstallationLockPort struct{ token chan struct{} }

func newSerialInstallationLockPort() *serialInstallationLockPort {
	token := make(chan struct{}, 1)
	token <- struct{}{}
	return &serialInstallationLockPort{token: token}
}

func (p *serialInstallationLockPort) Acquire(ctx context.Context) (InstallationLock, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.token:
		return &serialInstallationLock{token: p.token}, nil
	}
}

type serialInstallationLock struct {
	token chan struct{}
	once  sync.Once
}

func (l *serialInstallationLock) Release(context.Context) error {
	l.once.Do(func() { l.token <- struct{}{} })
	return nil
}

type memoryCancellationIntentPort struct {
	mu         sync.Mutex
	intents    map[string]CancellationIntent
	wake       chan struct{}
	ackError   error
	operations OperationRepository
}

type requestOnFirstSaveAuthority struct {
	*memoryOperationAuthority
	once     sync.Once
	injected bool
}

func (a *requestOnFirstSaveAuthority) Save(
	ctx context.Context,
	snapshot install.OperationSnapshot,
) error {
	var requestError error
	a.once.Do(func() {
		a.injected = true
		_, requestError = a.Request(ctx, CancellationRequest{
			OperationID: snapshot.OperationID(), PlanDigest: snapshot.PlanDigest(),
			ObservedAggregateVersion: snapshot.AggregateVersion(),
		})
	})
	if requestError != nil {
		return requestError
	}
	if a.injected {
		a.injected = false
		return ErrOperationConflict
	}
	return a.OperationRepository.Save(ctx, snapshot)
}

func newMemoryCancellationIntentPort(operations OperationRepository) *memoryCancellationIntentPort {
	return &memoryCancellationIntentPort{
		intents: make(map[string]CancellationIntent), wake: make(chan struct{}), operations: operations,
	}
}

func (p *memoryCancellationIntentPort) Request(
	ctx context.Context,
	request CancellationRequest,
) (CancellationIntent, error) {
	operation, err := p.operations.Load(ctx, request.OperationID)
	if err != nil {
		return CancellationIntent{}, err
	}
	if err := operation.RequestCancellation(request.PlanDigest); err != nil {
		return CancellationIntent{}, err
	}
	if err := p.operations.Save(ctx, operation.Snapshot()); err != nil {
		return CancellationIntent{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	key := request.OperationID.String()
	if current, ok := p.intents[key]; ok {
		if !current.PlanDigest.Equal(request.PlanDigest) {
			return CancellationIntent{}, ErrCancellationIntentIntegrity
		}
		return current, nil
	}
	intent, err := NewRequestedCancellationIntentForAdapter(request, operation.AggregateVersion())
	if err != nil {
		return CancellationIntent{}, err
	}
	p.intents[key] = intent
	close(p.wake)
	p.wake = make(chan struct{})
	return intent, nil
}

func (p *memoryCancellationIntentPort) Observe(
	_ context.Context,
	operationID install.OperationID,
	plan install.PlanDigest,
) (CancellationIntent, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	intent, ok := p.intents[operationID.String()]
	if !ok {
		return CancellationIntent{}, ErrCancellationIntentNotFound
	}
	if !intent.PlanDigest.Equal(plan) {
		return CancellationIntent{}, ErrCancellationIntentIntegrity
	}
	return intent, nil
}

func (p *memoryCancellationIntentPort) Wait(
	ctx context.Context,
	operationID install.OperationID,
	plan install.PlanDigest,
) (CancellationIntent, error) {
	for {
		intent, err := p.Observe(ctx, operationID, plan)
		if err == nil {
			return intent, nil
		}
		if !errors.Is(err, ErrCancellationIntentNotFound) {
			return CancellationIntent{}, err
		}
		p.mu.Lock()
		wake := p.wake
		p.mu.Unlock()
		select {
		case <-ctx.Done():
			return CancellationIntent{}, ctx.Err()
		case <-wake:
		}
	}
}

func (p *memoryCancellationIntentPort) Acknowledge(
	ctx context.Context,
	intent CancellationIntent,
	state install.State,
) (CancellationIntent, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ackError != nil {
		return CancellationIntent{}, p.ackError
	}
	current, ok := p.intents[intent.OperationID.String()]
	if !ok || current.Revision != intent.Revision || !current.PlanDigest.Equal(intent.PlanDigest) {
		return CancellationIntent{}, ErrCancellationIntentConflict
	}
	operation, err := p.operations.Load(ctx, intent.OperationID)
	if err != nil {
		return CancellationIntent{}, err
	}
	if err := operation.AcknowledgeCancellation(intent.PlanDigest); err != nil {
		return CancellationIntent{}, err
	}
	if err := p.operations.Save(ctx, operation.Snapshot()); err != nil {
		return CancellationIntent{}, err
	}
	acknowledged, err := NewAcknowledgedCancellationIntentForAdapter(current, operation.AggregateVersion(), state)
	if err != nil {
		return CancellationIntent{}, err
	}
	p.intents[intent.OperationID.String()] = acknowledged
	return acknowledged, nil
}

func (p *memoryCancellationIntentPort) acknowledged(operationID string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.intents[operationID].Status == CancellationIntentAcknowledged
}
