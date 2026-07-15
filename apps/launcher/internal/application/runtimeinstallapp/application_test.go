package runtimeinstallapp

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF001RuntimeApplicationExecutesEveryPhaseWithDurableBoundaries(t *testing.T) {
	t.Parallel()

	repository := newMemoryRepository()
	harness := &phaseHarness{repository: repository}
	application := newTestApplication(t, repository, harness)
	result, err := application.Ensure(context.Background(), testCommand())
	if err != nil {
		t.Fatal(err)
	}
	if result.State != runtimeinstall.OperationStateReady || result.Outcome != OutcomeCompleted {
		t.Fatalf("result = %+v", result)
	}
	want := runtimeinstall.OrderedPhases()
	if len(harness.calls) != len(want) {
		t.Fatalf("call count = %d, want %d", len(harness.calls), len(want))
	}
	for index := range want {
		if harness.calls[index] != want[index] {
			t.Fatalf("call %d = %s, want %s", index, harness.calls[index], want[index])
		}
	}
	// One initial save, one pre-side-effect save, and one post-transition save
	// are required for every phase. Extra saves are allowed only for resumes.
	wantSaves := 1 + 2*len(want)
	if repository.saveCalls != wantSaves {
		t.Fatalf("save count = %d, want %d", repository.saveCalls, wantSaves)
	}
	ownership := harness.ownership.snapshot
	if !harness.ownership.exists || ownership.Status() != runtimeinstall.OwnershipStatusFinalized ||
		ownership.OperationState() != runtimeinstall.OperationStateReady ||
		len(ownership.Mutations()) != 4 || ownership.CompatibilityDigest().IsZero() {
		t.Fatal("runtime ownership record was not finalized before completion")
	}
	if harness.ownership.firstPhase != runtimeinstall.PhaseAcquireRuntime {
		t.Fatalf("first ownership record phase = %s, want AcquireRuntime", harness.ownership.firstPhase)
	}
}

func TestPF001RuntimeApplicationBlocksFirstMutationUntilOwnershipIsDurable(t *testing.T) {
	t.Parallel()
	repository := newMemoryRepository()
	harness := &phaseHarness{repository: repository}
	harness.ownership = &memoryOwnershipRepository{saveError: errors.New("private ownership disk failure")}
	application := newTestApplication(t, repository, harness)
	result, err := application.Ensure(context.Background(), testCommand())
	if errorCode(err) != ErrorCodeInternal || result.CurrentPhase != runtimeinstall.PhaseAcquireRuntime ||
		countPhase(harness.calls, runtimeinstall.PhaseAcquireRuntime) != 0 {
		t.Fatalf("ownership failure result/error/calls = %+v/%v/%v", result, err, harness.calls)
	}
	harness.ownership.saveError = nil
	ready, err := application.Ensure(context.Background(), testCommand())
	if err != nil || ready.State != runtimeinstall.OperationStateReady ||
		countPhase(harness.calls, runtimeinstall.PhaseAcquireRuntime) != 1 {
		t.Fatalf("ownership retry result/error/calls = %+v/%v/%v", ready, err, harness.calls)
	}
}

func TestPF001RuntimeOwnershipTestProjectionMatchesApplicationEvidence(t *testing.T) {
	t.Parallel()
	plan, err := runtimeinstall.DecodePlanV1(testCanonicalRuntimePlan())
	if err != nil {
		t.Fatal(err)
	}
	operation, err := runtimeinstall.NewOperation(testCommand().OperationID, plan.Digest())
	if err != nil {
		t.Fatal(err)
	}
	for operation.CurrentPhase() <= runtimeinstall.PhaseAwaitRuntimeConsent {
		phase := operation.CurrentPhase()
		evidence, evidenceError := runtimeinstall.NewTransitionEvidence(
			phase, operation.Attempt(), plan.Digest(), runtimeinstall.Sum([]byte("input-"+phase.String())),
			runtimeinstall.Sum([]byte("output-"+phase.String())), runtimeinstall.Hash{}, runtimeinstall.OwnershipUnknown,
		)
		if evidenceError != nil || operation.Complete(phase, evidence) != nil {
			t.Fatalf("complete %s: %v", phase, evidenceError)
		}
	}
	harness := &phaseHarness{}
	authority, err := harness.ResolveRuntimeOwnershipAuthority(context.Background(), plan.CanonicalBytes())
	if err != nil {
		t.Fatal(err)
	}
	record, err := runtimeinstall.NewRuntimeOwnershipRecord(plan, operation.Snapshot(), authority, nil)
	if err != nil {
		t.Fatal(err)
	}
	repository := &memoryOwnershipRepository{}
	if err := repository.SaveRuntimeOwnership(context.Background(), record); err != nil {
		t.Fatal(err)
	}
}

func TestPF001RuntimeApplicationResumesFirstUnverifiedPhaseAfterEveryFailure(t *testing.T) {
	t.Parallel()

	for _, interruptedPhase := range runtimeinstall.OrderedPhases() {
		interruptedPhase := interruptedPhase
		t.Run(interruptedPhase.String(), func(t *testing.T) {
			t.Parallel()

			repository := newMemoryRepository()
			harness := &phaseHarness{repository: repository, failOnceAt: interruptedPhase}
			application := newTestApplication(t, repository, harness)
			first, firstErr := application.Ensure(context.Background(), testCommand())
			if firstErr == nil {
				t.Fatal("interrupted phase returned no error")
			}
			if first.State != runtimeinstall.OperationStateFailedRecoverable || first.CurrentPhase != interruptedPhase {
				t.Fatalf("interrupted result = %+v", first)
			}

			beforeResumeCalls := len(harness.calls)
			second, secondErr := application.Ensure(context.Background(), testCommand())
			if secondErr != nil {
				t.Fatal(secondErr)
			}
			if second.State != runtimeinstall.OperationStateReady {
				t.Fatalf("resumed result = %+v", second)
			}
			if harness.calls[beforeResumeCalls] != interruptedPhase {
				t.Fatalf("resume started at %s, want %s", harness.calls[beforeResumeCalls], interruptedPhase)
			}
			if got := countPhase(harness.calls, interruptedPhase); got != 2 {
				t.Fatalf("interrupted phase calls = %d, want 2", got)
			}
		})
	}
}

func TestPF001RuntimeApplicationPersistsAndVerifiesOneUseRebootResume(t *testing.T) {
	t.Parallel()

	for _, rebootPhase := range []runtimeinstall.Phase{
		runtimeinstall.PhaseInstallPrerequisites,
		runtimeinstall.PhaseInstallRuntime,
	} {
		rebootPhase := rebootPhase
		t.Run(rebootPhase.String(), func(t *testing.T) {
			t.Parallel()

			repository := newMemoryRepository()
			receipt := runtimeinstall.Sum([]byte("one-use-reboot-receipt"))
			harness := &phaseHarness{repository: repository, rebootOnceAt: rebootPhase, rebootReceipt: receipt}
			application := newTestApplication(t, repository, harness)

			first, err := application.Ensure(context.Background(), testCommand())
			if err != nil {
				t.Fatal(err)
			}
			if first.State != runtimeinstall.OperationStateRebootPending || first.ErrorCode != ErrorCodeRebootRequired {
				t.Fatalf("reboot result = %+v", first)
			}
			withoutReceipt, err := application.Ensure(context.Background(), testCommand())
			if err != nil || withoutReceipt.State != runtimeinstall.OperationStateRebootPending {
				t.Fatalf("unverified resume = %+v, %v", withoutReceipt, err)
			}

			wrong := runtimeinstall.Sum([]byte("wrong"))
			wrongCommand := testCommand()
			wrongCommand.ResumeReceipt = &wrong
			if _, err := application.Ensure(context.Background(), wrongCommand); errorCode(err) != ErrorCodeIntegrityViolation {
				t.Fatalf("wrong receipt error = %v", err)
			}

			resumeCommand := testCommand()
			resumeCommand.ResumeReceipt = &receipt
			ready, err := application.Ensure(context.Background(), resumeCommand)
			if err != nil {
				t.Fatal(err)
			}
			if ready.State != runtimeinstall.OperationStateReady {
				t.Fatalf("resumed result = %+v", ready)
			}
			if got := countPhase(harness.calls, rebootPhase); got != 2 {
				t.Fatalf("reboot phase calls = %d, want 2", got)
			}
		})
	}
}

func TestPF001RuntimeApplicationMapsEveryExpectedOutcomeWithoutAdvancing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		outcome Outcome
		state   runtimeinstall.OperationState
		code    ErrorCode
	}{
		{name: "recoverable", outcome: OutcomeFailedRecoverable, state: runtimeinstall.OperationStateFailedRecoverable, code: ErrorCodeInternal},
		{name: "administrator", outcome: OutcomeAdministratorRequired, state: runtimeinstall.OperationStatePausedForAdministrator, code: ErrorCodeAdministratorRequired},
		{name: "cancelled", outcome: OutcomeCancelled, state: runtimeinstall.OperationStateCancelled, code: ErrorCodeCancelled},
		{name: "unsupported", outcome: OutcomeUnsupportedHost, state: runtimeinstall.OperationStateUnsupportedHost, code: ErrorCodeUnsupportedHost},
		{name: "conflict", outcome: OutcomeRuntimeConflict, state: runtimeinstall.OperationStateRuntimeConflict, code: ErrorCodeRuntimeConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			repository := newMemoryRepository()
			harness := &phaseHarness{
				repository: repository,
				outcomeAt:  runtimeinstall.PhaseDetectRuntime,
				outcome:    test.outcome,
			}
			application := newTestApplication(t, repository, harness)
			result, err := application.Ensure(context.Background(), testCommand())
			if err != nil {
				t.Fatal(err)
			}
			if result.State != test.state || result.CurrentPhase != runtimeinstall.PhaseDetectRuntime || result.ErrorCode != test.code {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestPF001RuntimeApplicationAlreadyReadyIsIdempotent(t *testing.T) {
	t.Parallel()

	repository := newMemoryRepository()
	harness := &phaseHarness{repository: repository}
	application := newTestApplication(t, repository, harness)
	if _, err := application.Ensure(context.Background(), testCommand()); err != nil {
		t.Fatal(err)
	}
	callCount := len(harness.calls)
	saveCount := repository.saveCalls
	result, err := application.Ensure(context.Background(), testCommand())
	if err != nil {
		t.Fatal(err)
	}
	if result.State != runtimeinstall.OperationStateReady || len(harness.calls) != callCount || repository.saveCalls != saveCount {
		t.Fatalf("idempotent result/calls/saves = %+v/%d/%d", result, len(harness.calls), repository.saveCalls)
	}
}

func TestPF001RuntimeApplicationRejectsPlanDriftAndRepositoryIntegrity(t *testing.T) {
	t.Parallel()

	repository := newMemoryRepository()
	harness := &phaseHarness{repository: repository, outcomeAt: runtimeinstall.PhaseDetectRuntime, outcome: OutcomeCancelled}
	application := newTestApplication(t, repository, harness)
	if _, err := application.Ensure(context.Background(), testCommand()); err != nil {
		t.Fatal(err)
	}

	drifted := testCommand()
	drifted.CanonicalPlan = testCanonicalRuntimePlanFor("different signed catalog")
	if _, err := application.Ensure(context.Background(), drifted); errorCode(err) != ErrorCodeConflict {
		t.Fatalf("plan drift error = %v", err)
	}

	repository.loadError = ErrOperationIntegrity
	if _, err := application.Ensure(context.Background(), testCommand()); errorCode(err) != ErrorCodeIntegrityViolation {
		t.Fatalf("integrity error = %v", err)
	}
}

func TestPF001RuntimeApplicationCancellationStaysRecoverableAndPrivacySafe(t *testing.T) {
	t.Parallel()

	repository := newMemoryRepository()
	harness := &phaseHarness{repository: repository, failWith: context.Canceled, failOnceAt: runtimeinstall.PhaseAcquireRuntime}
	application := newTestApplication(t, repository, harness)
	result, err := application.Ensure(context.Background(), testCommand())
	if result.State != runtimeinstall.OperationStateFailedRecoverable || errorCode(err) != ErrorCodeDeadlineExceeded {
		t.Fatalf("result/error = %+v/%v", result, err)
	}
	if err.Error() != string(ErrorCodeDeadlineExceeded) {
		t.Fatalf("error leaked boundary details: %q", err)
	}
}

func TestPF001RuntimeApplicationSettlesOwnedCancellationBeforeReturning(t *testing.T) {
	t.Parallel()

	repository := newMemoryRepository()
	harness := &phaseHarness{
		repository: repository,
		outcomeAt:  runtimeinstall.PhaseVerifyRuntimeArtifact,
		outcome:    OutcomeCancelled,
	}
	application := newTestApplication(t, repository, harness)
	result, err := application.Ensure(context.Background(), testCommand())
	if err != nil {
		t.Fatal(err)
	}
	if result.State != runtimeinstall.OperationStateCancelled || !result.CompensationSettled ||
		harness.compensations != 1 {
		t.Fatalf("cancel result/compensations = %+v/%d", result, harness.compensations)
	}
	if repository.snapshot.CompensationStatus != runtimeinstall.CompensationStatusCompleted ||
		repository.snapshot.CompensationReceipt.IsZero() ||
		harness.ownership.snapshot.CompensationReceiptDigest() != repository.snapshot.CompensationReceipt {
		t.Fatal("compensation receipt was not durably bound to operation and ownership records")
	}
}

func TestPF001RuntimeApplicationRetriesPendingCompensationIdempotently(t *testing.T) {
	t.Parallel()

	repository := newMemoryRepository()
	harness := &phaseHarness{
		repository:    repository,
		outcomeAt:     runtimeinstall.PhaseVerifyRuntimeArtifact,
		outcome:       OutcomeCancelled,
		compensateErr: errors.New("private cleanup path"),
	}
	application := newTestApplication(t, repository, harness)
	first, firstErr := application.Ensure(context.Background(), testCommand())
	if errorCode(firstErr) != ErrorCodeInternal || first.State != runtimeinstall.OperationStateCancelled ||
		first.CompensationSettled || repository.snapshot.CompensationStatus != runtimeinstall.CompensationStatusPending {
		t.Fatalf("first cancellation = %+v/%v", first, firstErr)
	}
	if firstErr.Error() != string(ErrorCodeInternal) {
		t.Fatalf("compensation error leaked private detail: %q", firstErr)
	}
	harness.compensateErr = nil
	second, secondErr := application.Ensure(context.Background(), testCommand())
	if secondErr != nil || second.State != runtimeinstall.OperationStateCancelled ||
		!second.CompensationSettled || harness.compensations != 2 {
		t.Fatalf("retried cancellation = %+v/%v, calls %d", second, secondErr, harness.compensations)
	}
}

func TestPF001RuntimeApplicationCancelMissingChildIsProvenNoOp(t *testing.T) {
	t.Parallel()

	repository := newMemoryRepository()
	harness := &phaseHarness{repository: repository}
	application := newTestApplication(t, repository, harness)
	result, err := application.Cancel(context.Background(), testCommand())
	if err != nil || result.State != runtimeinstall.OperationStateCancelled ||
		!result.CompensationSettled || harness.compensations != 0 || repository.exists {
		t.Fatalf("missing child cancellation = %+v/%v", result, err)
	}
}

func TestPF001RuntimeApplicationCancelPreservesReadyRuntime(t *testing.T) {
	t.Parallel()

	repository := newMemoryRepository()
	harness := &phaseHarness{repository: repository}
	application := newTestApplication(t, repository, harness)
	ready, err := application.Ensure(context.Background(), testCommand())
	if err != nil || ready.State != runtimeinstall.OperationStateReady {
		t.Fatalf("ready result = %+v/%v", ready, err)
	}
	result, err := application.Cancel(context.Background(), testCommand())
	if err != nil || result.State != runtimeinstall.OperationStateReady || result.Outcome != OutcomeCompleted ||
		!result.CompensationSettled || harness.compensations != 0 {
		t.Fatalf("ready cancellation = %+v/%v", result, err)
	}
}

func TestPF001RuntimeApplicationConstructorRejectsNilAndTypedNil(t *testing.T) {
	t.Parallel()

	repository := newMemoryRepository()
	harness := &phaseHarness{repository: repository}
	dependencies := testDependencies(repository, harness)
	dependencies.Operations = nil
	if _, err := New(dependencies); err == nil {
		t.Fatal("nil dependency accepted")
	}
	var typedNil *memoryRepository
	dependencies = testDependencies(repository, harness)
	dependencies.Operations = typedNil
	if _, err := New(dependencies); err == nil {
		t.Fatal("typed nil dependency accepted")
	}
}

func TestPF001RuntimeApplicationRejectsMalformedOutputAndPersistsFailure(t *testing.T) {
	t.Parallel()

	repository := newMemoryRepository()
	harness := &phaseHarness{repository: repository, invalidAt: runtimeinstall.PhaseVerifyRuntimeArtifact}
	application := newTestApplication(t, repository, harness)
	result, err := application.Ensure(context.Background(), testCommand())
	if result.State != runtimeinstall.OperationStateFailedRecoverable || errorCode(err) != ErrorCodeInternal {
		t.Fatalf("result/error = %+v/%v", result, err)
	}
	loaded, loadErr := repository.Load(context.Background(), testCommand().OperationID)
	if loadErr != nil || loaded.State() != runtimeinstall.OperationStateFailedRecoverable ||
		loaded.CurrentPhase() != runtimeinstall.PhaseVerifyRuntimeArtifact {
		t.Fatalf("durable failure = %+v/%v", loaded, loadErr)
	}
}

func newTestApplication(t *testing.T, repository *memoryRepository, harness *phaseHarness) *Application {
	t.Helper()
	application, err := New(testDependencies(repository, harness))
	if err != nil {
		t.Fatal(err)
	}
	return application
}

func testDependencies(repository OperationRepository, harness *phaseHarness) Dependencies {
	if harness.ownership == nil {
		harness.ownership = &memoryOwnershipRepository{}
	}
	return Dependencies{
		Operations:           repository,
		OwnershipAuthorities: harness,
		OwnershipRecords:     harness.ownership,
		Compensation:         harness,
		Host:                 harness,
		Detector:             harness,
		Catalog:              harness,
		Consent:              harness,
		Fetcher:              harness,
		Verifier:             harness,
		Prerequisites:        harness,
		Installer:            harness,
		Terms:                harness,
		Controller:           harness,
		Capabilities:         harness,
	}
}

func testCommand() Command {
	return Command{
		OperationID:   "019f5f20-1234-7abc-8123-0123456789ab",
		CanonicalPlan: testCanonicalRuntimePlan(),
	}
}

func testCanonicalRuntimePlan() []byte {
	return testCanonicalRuntimePlanFor("catalog")
}

func testCanonicalRuntimePlanFor(catalogBinding string) []byte {
	host, err := runtimeinstall.NewHostCapabilities(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "6.8.0", true, true, true, true,
		8, 32*1024*1024*1024, 24*1024*1024*1024, 100*1024*1024*1024,
	)
	if err != nil {
		panic(err)
	}
	catalog, err := runtimeinstall.NewCertifiedRuntime(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "docker-engine", "28.0.0", "stable", 42,
		runtimeinstall.Sum([]byte(catalogBinding)), runtimeinstall.RuntimeTermsInput{
			ID: runtimeinstall.DockerEngineTermsID, Version: "apache-2.0", URL: "https://docs.docker.com/engine/",
			Digest: runtimeinstall.Sum([]byte("terms")), Presentation: runtimeinstall.TermsPresentationAgentMemory,
		}, 1024, 4096,
	)
	if err != nil {
		panic(err)
	}
	plan, err := runtimeinstall.NewPlanV1(host, runtimeinstall.NewAbsentRuntimeDiscovery(), catalog)
	if err != nil {
		panic(err)
	}
	return plan.CanonicalBytes()
}

type memoryRepository struct {
	mu        sync.Mutex
	exists    bool
	snapshot  runtimeinstall.OperationSnapshot
	saveCalls int
	loadError error
	saveError error
}

func newMemoryRepository() *memoryRepository { return &memoryRepository{} }

func (r *memoryRepository) Load(_ context.Context, operationID string) (*runtimeinstall.Operation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.loadError != nil {
		return nil, r.loadError
	}
	if !r.exists || r.snapshot.OperationID != operationID {
		return nil, ErrOperationNotFound
	}
	return runtimeinstall.RestoreOperation(r.snapshot)
}

func (r *memoryRepository) Save(_ context.Context, snapshot runtimeinstall.OperationSnapshot) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.saveError != nil {
		return r.saveError
	}
	if r.exists {
		if snapshot.OperationID != r.snapshot.OperationID {
			return ErrOperationConflict
		}
		if snapshot.Version < r.snapshot.Version || snapshot.Version > r.snapshot.Version+1 {
			return ErrOperationConflict
		}
	}
	if _, err := runtimeinstall.RestoreOperation(snapshot); err != nil {
		return errors.Join(ErrOperationIntegrity, err)
	}
	r.snapshot = snapshot
	r.snapshot.Evidence = append([]runtimeinstall.TransitionEvidence(nil), snapshot.Evidence...)
	r.exists = true
	r.saveCalls++
	return nil
}

func (r *memoryRepository) assertPreSideEffect(request Request) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.exists || r.snapshot.State != runtimeinstall.OperationStateRunning ||
		r.snapshot.CurrentPhase != request.Phase() || r.snapshot.Attempt != request.Attempt() {
		return errors.New("phase side effect was not preceded by its durable cursor")
	}
	return nil
}

type phaseHarness struct {
	mu            sync.Mutex
	repository    *memoryRepository
	calls         []runtimeinstall.Phase
	failOnceAt    runtimeinstall.Phase
	failWith      error
	failed        bool
	rebootOnceAt  runtimeinstall.Phase
	rebootReceipt runtimeinstall.Hash
	rebooted      bool
	outcomeAt     runtimeinstall.Phase
	outcome       Outcome
	invalidAt     runtimeinstall.Phase
	ownership     *memoryOwnershipRepository
	compensations int
	compensateErr error
}

func (h *phaseHarness) CompensateRuntime(
	_ context.Context,
	request RuntimeCompensationRequest,
) (RuntimeCompensationReceipt, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.compensations++
	if h.compensateErr != nil {
		return RuntimeCompensationReceipt{}, h.compensateErr
	}
	runtimeDigest := runtimeinstall.Sum([]byte("preserved-runtime-state"))
	return NewRuntimeCompensationReceipt(request, RuntimeCompensationReceiptInput{
		RuntimeBeforeDigest:   runtimeDigest,
		RuntimeAfterDigest:    runtimeDigest,
		ArtifactCleanupDigest: runtimeinstall.Sum([]byte("released-owned-artifact-state")),
		RemovedArtifactDigests: []runtimeinstall.Hash{
			request.OwnershipRecord().ArtifactDigest(),
		},
		RuntimePreserved: true,
	})
}

func (h *phaseHarness) ResolveRuntimeOwnershipAuthority(
	_ context.Context,
	canonical []byte,
) (runtimeinstall.RuntimeOwnershipAuthority, error) {
	plan, err := runtimeinstall.DecodePlanV1(canonical)
	if err != nil {
		return runtimeinstall.RuntimeOwnershipAuthority{}, err
	}
	return runtimeinstall.NewRuntimeOwnershipAuthority(runtimeinstall.RuntimeOwnershipAuthoritySnapshot{
		Vendor: plan.Product(), Version: plan.Version(), Channel: plan.Channel(),
		Endpoint: "unix:///run/user/1000/docker.sock", Context: "explicit-local-endpoint",
		Publisher: "docker-release-key-2026", PublisherDigest: runtimeinstall.Sum([]byte("publisher")),
		ArtifactDigest: runtimeinstall.Sum([]byte("verified-runtime-artifact")),
		Components:     []string{"compose@2.39.1", "engine@28.0.0"},
		Settings:       []string{"repository:docker-stable", "service:docker.service"},
	})
}

type memoryOwnershipRepository struct {
	mu         sync.Mutex
	exists     bool
	snapshot   runtimeinstall.RuntimeOwnershipRecord
	firstPhase runtimeinstall.Phase
	saveError  error
}

func (r *memoryOwnershipRepository) LoadRuntimeOwnership(
	_ context.Context,
	operationID string,
) (runtimeinstall.RuntimeOwnershipRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.exists || r.snapshot.OperationID() != operationID {
		return runtimeinstall.RuntimeOwnershipRecord{}, ErrOwnershipNotFound
	}
	return runtimeinstall.RestoreRuntimeOwnershipRecord(r.snapshot.Snapshot())
}

func (r *memoryOwnershipRepository) SaveRuntimeOwnership(
	_ context.Context,
	record runtimeinstall.RuntimeOwnershipRecord,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.saveError != nil {
		return r.saveError
	}
	if r.exists {
		if record.Revision() == r.snapshot.Revision() && record.Digest() == r.snapshot.Digest() {
			return nil
		}
		if !record.CanFollow(r.snapshot) {
			return ErrOwnershipConflict
		}
	} else {
		r.firstPhase = runtimeinstall.PhaseAcquireRuntime
	}
	restored, err := runtimeinstall.RestoreRuntimeOwnershipRecord(record.Snapshot())
	if err != nil {
		return errors.Join(ErrOwnershipIntegrity, err)
	}
	r.snapshot = restored
	r.exists = true
	return nil
}

func (h *phaseHarness) run(request Request) (Output, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.repository.assertPreSideEffect(request); err != nil {
		return Output{}, err
	}
	h.calls = append(h.calls, request.Phase())
	if request.PlanDigest() != runtimeinstall.Sum(request.CanonicalPlan()) {
		return Output{}, errors.New("request plan bytes were not digest-bound")
	}
	if h.failOnceAt == request.Phase() && !h.failed {
		h.failed = true
		if h.failWith != nil {
			return Output{}, h.failWith
		}
		return Output{}, errors.New("private platform failure /Users/private/runtime")
	}
	if h.rebootOnceAt == request.Phase() && !h.rebooted {
		h.rebooted = true
		return NewRebootOutput(h.rebootReceipt)
	}
	if h.outcomeAt == request.Phase() {
		return NewExpectedOutput(h.outcome)
	}
	if h.invalidAt == request.Phase() {
		return Output{valid: true, outcome: OutcomeCompleted}, nil
	}

	artifact := runtimeinstall.Hash{}
	if request.Phase() >= runtimeinstall.PhaseVerifyRuntimeArtifact {
		artifact = runtimeinstall.Sum([]byte("verified-runtime-artifact"))
	}
	ownership := runtimeinstall.OwnershipUnknown
	if request.Phase() == runtimeinstall.PhaseVerifyRuntimeCapabilities {
		ownership = runtimeinstall.OwnershipProvisionedByAgentMemory
	}
	return NewCompletedOutput(Completion{
		InputDigest:    runtimeinstall.Sum([]byte("input-" + request.Phase().String())),
		OutputDigest:   runtimeinstall.Sum([]byte("output-" + request.Phase().String())),
		ArtifactDigest: artifact,
		Ownership:      ownership,
	})
}

func (h *phaseHarness) DetectHost(_ context.Context, request Request) (Output, error) {
	return h.run(request)
}
func (h *phaseHarness) DetectRuntime(_ context.Context, request Request) (Output, error) {
	return h.run(request)
}
func (h *phaseHarness) PlanRuntime(_ context.Context, request Request) (Output, error) {
	return h.run(request)
}
func (h *phaseHarness) AwaitRuntimeConsent(_ context.Context, request Request) (Output, error) {
	return h.run(request)
}
func (h *phaseHarness) AcquireRuntime(_ context.Context, request Request) (Output, error) {
	return h.run(request)
}
func (h *phaseHarness) VerifyRuntimeArtifact(_ context.Context, request Request) (Output, error) {
	return h.run(request)
}
func (h *phaseHarness) InstallPrerequisites(_ context.Context, request Request) (Output, error) {
	return h.run(request)
}
func (h *phaseHarness) InstallRuntime(_ context.Context, request Request) (Output, error) {
	return h.run(request)
}
func (h *phaseHarness) AwaitThirdPartyTerms(_ context.Context, request Request) (Output, error) {
	return h.run(request)
}
func (h *phaseHarness) StartRuntime(_ context.Context, request Request) (Output, error) {
	return h.run(request)
}
func (h *phaseHarness) VerifyRuntimeCapabilities(_ context.Context, request Request) (Output, error) {
	return h.run(request)
}

func countPhase(phases []runtimeinstall.Phase, target runtimeinstall.Phase) int {
	count := 0
	for _, phase := range phases {
		if phase == target {
			count++
		}
	}
	return count
}
