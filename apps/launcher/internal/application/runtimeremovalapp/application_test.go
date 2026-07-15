package runtimeremovalapp

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeremoval"
)

func TestPF001ManagedRuntimeRemovalPersistsConsentAndIntentBeforeNativeEffect(t *testing.T) {
	t.Parallel()
	runtimePlan, ownership := managedOwnershipFixture(t)
	harness := newRemovalHarness(t, ownership)
	result, err := harness.application(t).Remove(context.Background(), removalCommand(runtimePlan))
	if err != nil || result.Outcome != OutcomeRemoved || harness.remover.calls != 1 || harness.scanner.calls != 3 {
		t.Fatalf("remove result = %+v/%v calls=%d scans=%d", result, err, harness.remover.calls, harness.scanner.calls)
	}
	wantStates := []runtimeremoval.State{
		runtimeremoval.StateAwaitingConsent,
		runtimeremoval.StateReadyToRemove,
		runtimeremoval.StateRemoving,
		runtimeremoval.StateRemoved,
	}
	if len(harness.operations.savedStates) != len(wantStates) {
		t.Fatalf("saved states = %v", harness.operations.savedStates)
	}
	for index, want := range wantStates {
		if harness.operations.savedStates[index] != want {
			t.Fatalf("saved state %d = %v, want %v", index, harness.operations.savedStates[index], want)
		}
	}
}

func TestPF001ManagedRuntimeRemovalPreparePersistsOnlySafePlanBeforeSecondConsent(t *testing.T) {
	t.Parallel()
	runtimePlan, ownership := managedOwnershipFixture(t)
	harness := newRemovalHarness(t, ownership)
	application := harness.application(t)
	command := removalCommand(runtimePlan)
	prepared, err := application.Prepare(t.Context(), command)
	if err != nil || !prepared.Valid() || prepared.OperationID() != command.OperationID ||
		prepared.SourceOperationID() != command.SourceOperationID || prepared.PlanDigest().IsZero() ||
		prepared.Impact() != runtimeremoval.ImpactPreserveLocalRuntimeData ||
		prepared.Product() != runtimePlan.Product() || prepared.Version() != runtimePlan.Version() ||
		prepared.Platform() != runtimeinstall.PlatformLinux || harness.scanner.calls != 1 ||
		harness.consent.calls != 0 || harness.remover.calls != 0 ||
		len(harness.operations.savedStates) != 1 ||
		harness.operations.savedStates[0] != runtimeremoval.StateAwaitingConsent {
		t.Fatalf("prepared=%+v scans=%d consent=%d remover=%d states=%v error=%v",
			prepared, harness.scanner.calls, harness.consent.calls, harness.remover.calls,
			harness.operations.savedStates, err)
	}
	replayed, err := application.Prepare(t.Context(), command)
	if err != nil || replayed.PlanDigest() != prepared.PlanDigest() || harness.scanner.calls != 1 ||
		len(harness.operations.savedStates) != 1 {
		t.Fatalf("replayed=%+v scans=%d states=%v error=%v", replayed, harness.scanner.calls,
			harness.operations.savedStates, err)
	}
}

func TestPF001ManagedRuntimeRemovalCrashRecoveryAcceptsOnlyExactAbsenceProof(t *testing.T) {
	t.Parallel()
	runtimePlan, ownership := managedOwnershipFixture(t)
	harness := newRemovalHarness(t, ownership)
	harness.remover.err = errors.New("interrupted after native invocation")
	command := removalCommand(runtimePlan)
	if _, err := harness.application(t).Remove(context.Background(), command); err == nil {
		t.Fatal("interrupted native removal succeeded")
	}
	if harness.operations.operation.State() != runtimeremoval.StateRemoving {
		t.Fatalf("state = %v", harness.operations.operation.State())
	}
	harness.remover.err = nil
	harness.presence.proofs = []PresenceProof{presenceProofFor(harness.operations.operation.Plan(), true, "replay-absence")}
	result, err := harness.application(t).Remove(context.Background(), command)
	if err != nil || result.Outcome != OutcomeRemoved || harness.remover.calls != 1 {
		t.Fatalf("replay = %+v/%v remover calls=%d", result, err, harness.remover.calls)
	}
}

func TestPF001ManagedRuntimeRemovalRefusesDependenciesBeforeConsentOrEffect(t *testing.T) {
	t.Parallel()
	runtimePlan, ownership := managedOwnershipFixture(t)
	harness := newRemovalHarness(t, ownership)
	harness.scanner.dependent = true
	_, err := harness.application(t).Remove(context.Background(), removalCommand(runtimePlan))
	if !errors.Is(err, ErrDependenciesExist) || harness.consent.calls != 0 || harness.remover.calls != 0 ||
		len(harness.operations.savedStates) != 0 {
		t.Fatalf("refusal = %v consent=%d remover=%d saves=%v", err, harness.consent.calls,
			harness.remover.calls, harness.operations.savedStates)
	}
}

func TestPF001ManagedRuntimeRemovalDeclineIsDurableAndHasNoNativeEffect(t *testing.T) {
	t.Parallel()
	runtimePlan, ownership := managedOwnershipFixture(t)
	harness := newRemovalHarness(t, ownership)
	harness.consent.approved = false
	result, err := harness.application(t).Remove(context.Background(), removalCommand(runtimePlan))
	if err != nil || result.Outcome != OutcomeDeclined || harness.remover.calls != 0 ||
		harness.operations.operation.State() != runtimeremoval.StateDeclined {
		t.Fatalf("decline = %+v/%v remover=%d", result, err, harness.remover.calls)
	}
	result, err = harness.application(t).Remove(context.Background(), removalCommand(runtimePlan))
	if err != nil || result.Outcome != OutcomeDeclined || harness.consent.calls != 1 {
		t.Fatalf("decline replay = %+v/%v consent calls=%d", result, err, harness.consent.calls)
	}
}

func TestPF001ManagedRuntimeRemovalRejectsIncompleteCompositionAndCommands(t *testing.T) {
	t.Parallel()
	_, ownership := managedOwnershipFixture(t)
	harness := newRemovalHarness(t, ownership)
	valid := Dependencies{
		Operations: harness.operations, Ownership: harness.ownership, Scanner: harness.scanner,
		Consent: harness.consent, Presence: harness.presence, Remover: harness.remover,
	}
	for name, mutate := range map[string]func(*Dependencies){
		"operations": func(dependencies *Dependencies) { dependencies.Operations = nil },
		"ownership":  func(dependencies *Dependencies) { dependencies.Ownership = nil },
		"scanner":    func(dependencies *Dependencies) { dependencies.Scanner = nil },
		"consent":    func(dependencies *Dependencies) { dependencies.Consent = nil },
		"presence":   func(dependencies *Dependencies) { dependencies.Presence = nil },
		"remover":    func(dependencies *Dependencies) { dependencies.Remover = nil },
	} {
		t.Run(name, func(t *testing.T) {
			dependencies := valid
			mutate(&dependencies)
			if application, err := New(dependencies); err == nil || application != nil {
				t.Fatal("incomplete application was accepted")
			}
		})
	}
	application := harness.application(t)
	for name, command := range map[string]Command{
		"operation": {OperationID: "invalid", SourceOperationID: "019f60a0-1111-7abc-8123-0123456789ab"},
		"source":    {OperationID: "019f60a0-0000-7abc-8123-0123456789ab", SourceOperationID: "invalid"},
		"same": {
			OperationID:       "019f60a0-0000-7abc-8123-0123456789ab",
			SourceOperationID: "019f60a0-0000-7abc-8123-0123456789ab",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := application.Remove(context.Background(), command); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("invalid command error = %v", err)
			}
		})
	}
}

func TestPF001ManagedRuntimeRemovalPropagatesFailClosedBoundaryErrors(t *testing.T) {
	t.Parallel()
	runtimePlan, ownership := managedOwnershipFixture(t)
	command := removalCommand(runtimePlan)
	boundaryError := errors.New("boundary unavailable")
	for name, configure := range map[string]func(*removalHarness){
		"load":         func(harness *removalHarness) { harness.operations.loadErr = boundaryError },
		"nil load":     func(harness *removalHarness) { harness.operations.returnNil = true },
		"ownership":    func(harness *removalHarness) { harness.ownership.err = boundaryError },
		"scanner":      func(harness *removalHarness) { harness.scanner.err = boundaryError },
		"consent":      func(harness *removalHarness) { harness.consent.err = boundaryError },
		"initial save": func(harness *removalHarness) { harness.operations.saveErr = boundaryError },
	} {
		t.Run(name, func(t *testing.T) {
			harness := newRemovalHarness(t, ownership)
			configure(harness)
			_, err := harness.application(t).Remove(context.Background(), command)
			if err == nil {
				t.Fatal("boundary failure succeeded")
			}
		})
	}
}

func TestPF001ManagedRuntimeRemovalRejectsConsentSubstitutionAndLateDependencies(t *testing.T) {
	t.Parallel()
	runtimePlan, ownership := managedOwnershipFixture(t)
	command := removalCommand(runtimePlan)
	harness := newRemovalHarness(t, ownership)
	harness.consent.decision = &ConsentDecision{
		Approved: true, Explicit: true, Impact: "substituted-impact",
		Receipt: runtimeinstall.Sum([]byte("receipt")),
	}
	if _, err := harness.application(t).Remove(context.Background(), command); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("substituted consent error = %v", err)
	}

	harness = newRemovalHarness(t, ownership)
	harness.scanner.dependentAt = 2
	if _, err := harness.application(t).Remove(context.Background(), command); !errors.Is(err, ErrDependenciesExist) ||
		harness.operations.operation.State() != runtimeremoval.StateReadyToRemove || harness.remover.calls != 0 {
		t.Fatalf("late dependency error/state/remover = %v/%v/%d", err,
			harness.operations.operation.State(), harness.remover.calls)
	}
}

func TestPF001ManagedRuntimeRemovalRejectsPresenceNativeAndReplayScanSubstitution(t *testing.T) {
	t.Parallel()
	runtimePlan, ownership := managedOwnershipFixture(t)
	command := removalCommand(runtimePlan)
	harness := newRemovalHarness(t, ownership)
	harness.presence.proofs = []PresenceProof{{}}
	if _, err := harness.application(t).Remove(context.Background(), command); !errors.Is(err, ErrScanUncertain) {
		t.Fatalf("invalid presence error = %v", err)
	}

	harness = newRemovalHarness(t, ownership)
	harness.remover.invalid = true
	if _, err := harness.application(t).Remove(context.Background(), command); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("invalid native receipt error = %v", err)
	}

	harness = newRemovalHarness(t, ownership)
	harness.remover.err = errors.New("native interruption")
	if _, err := harness.application(t).Remove(context.Background(), command); err == nil {
		t.Fatal("native interruption succeeded")
	}
	harness.remover.err = nil
	harness.scanner.salt = "changed"
	if _, err := harness.application(t).Remove(context.Background(), command); !errors.Is(err, ErrScanUncertain) ||
		harness.remover.calls != 1 {
		t.Fatalf("scan substitution error/calls = %v/%d", err, harness.remover.calls)
	}
}

type removalHarness struct {
	operations *removalOperationRepositoryStub
	ownership  *removalOwnershipRepositoryStub
	scanner    *removalScannerStub
	consent    *removalConsentStub
	presence   *removalPresenceStub
	remover    *removalNativeStub
}

func newRemovalHarness(t *testing.T, ownership runtimeinstall.RuntimeOwnershipRecord) *removalHarness {
	t.Helper()
	operations := &removalOperationRepositoryStub{}
	harness := &removalHarness{
		operations: operations,
		ownership:  &removalOwnershipRepositoryStub{record: ownership},
		scanner:    &removalScannerStub{},
		consent:    &removalConsentStub{approved: true},
		presence:   &removalPresenceStub{},
	}
	harness.remover = &removalNativeStub{operations: operations, presence: harness.presence}
	return harness
}

func (h *removalHarness) application(t *testing.T) *Application {
	t.Helper()
	application, err := New(Dependencies{
		Operations: h.operations, Ownership: h.ownership, Scanner: h.scanner,
		Consent: h.consent, Presence: h.presence, Remover: h.remover,
	})
	if err != nil {
		t.Fatal(err)
	}
	return application
}

type removalOperationRepositoryStub struct {
	operation   *runtimeremoval.Operation
	savedStates []runtimeremoval.State
	loadErr     error
	saveErr     error
	returnNil   bool
}

func (r *removalOperationRepositoryStub) Load(_ context.Context, _ string) (*runtimeremoval.Operation, error) {
	if r.loadErr != nil {
		return nil, r.loadErr
	}
	if r.returnNil {
		return nil, nil
	}
	if r.operation == nil {
		return nil, ErrOperationNotFound
	}
	return runtimeremoval.RestoreOperation(r.operation.Snapshot())
}

func (r *removalOperationRepositoryStub) Save(_ context.Context, snapshot runtimeremoval.OperationSnapshot) error {
	if r.saveErr != nil {
		return r.saveErr
	}
	operation, err := runtimeremoval.RestoreOperation(snapshot)
	if err != nil {
		return err
	}
	r.operation = operation
	r.savedStates = append(r.savedStates, operation.State())
	return nil
}

type removalOwnershipRepositoryStub struct {
	record runtimeinstall.RuntimeOwnershipRecord
	err    error
}

func (r *removalOwnershipRepositoryStub) LoadRuntimeOwnership(
	_ context.Context,
	_ string,
) (runtimeinstall.RuntimeOwnershipRecord, error) {
	return r.record, r.err
}

type removalScannerStub struct {
	calls       int
	dependent   bool
	dependentAt int
	err         error
	salt        string
}

func (s *removalScannerStub) ScanRuntimeDependencies(
	_ context.Context,
	request ScanRequest,
) (runtimeremoval.DependencyScan, error) {
	s.calls++
	if s.err != nil {
		return runtimeremoval.DependencyScan{}, s.err
	}
	proofs := make([]runtimeremoval.DependencyProofInput, 0, len(runtimeremoval.OrderedDependencyKinds()))
	for index, kind := range runtimeremoval.OrderedDependencyKinds() {
		count := uint64(0)
		if (s.dependent || s.calls == s.dependentAt) && index == 0 {
			count = 1
		}
		proofs = append(proofs, runtimeremoval.DependencyProofInput{
			Kind: kind, Count: count, Complete: true,
			EvidenceDigest: runtimeinstall.Sum([]byte("stable-empty-" + kind.String() + s.salt)),
		})
	}
	return runtimeremoval.NewDependencyScan(runtimeremoval.DependencyScanInput{
		OwnershipRecordDigest: request.Ownership.Digest(), Endpoint: request.Endpoint, Proofs: proofs,
	})
}

type removalConsentStub struct {
	calls    int
	approved bool
	err      error
	decision *ConsentDecision
}

func (s *removalConsentStub) AwaitManagedRuntimeRemovalConsent(
	_ context.Context,
	plan runtimeremoval.Plan,
) (ConsentDecision, error) {
	s.calls++
	if s.err != nil {
		return ConsentDecision{}, s.err
	}
	if s.decision != nil {
		return *s.decision, nil
	}
	decision := ConsentDecision{
		Approved: s.approved, PlanDigest: plan.Digest(), Impact: plan.ImpactConfirmation(),
	}
	if s.approved {
		decision.Explicit = true
		decision.Receipt = runtimeinstall.Sum([]byte("explicit-second-consent"))
	}
	return decision, nil
}

type removalPresenceStub struct {
	proofs []PresenceProof
	err    error
}

func (s *removalPresenceStub) InspectManagedRuntime(
	_ context.Context,
	plan runtimeremoval.Plan,
) (PresenceProof, error) {
	if s.err != nil {
		return PresenceProof{}, s.err
	}
	if len(s.proofs) == 0 {
		return presenceProofFor(plan, false, "present-before-removal"), nil
	}
	proof := s.proofs[0]
	s.proofs = s.proofs[1:]
	return proof, nil
}

type removalNativeStub struct {
	operations *removalOperationRepositoryStub
	presence   *removalPresenceStub
	calls      int
	err        error
	invalid    bool
}

func (s *removalNativeStub) RemoveManagedRuntime(
	_ context.Context,
	authorization RemovalAuthorization,
) (NativeRemovalResult, error) {
	if s.operations.operation == nil || s.operations.operation.State() != runtimeremoval.StateRemoving {
		return NativeRemovalResult{}, errors.New("removal intent was not durable")
	}
	if authorization.ConsentReceipt().IsZero() {
		return NativeRemovalResult{}, errors.New("second consent was not bound")
	}
	s.calls++
	if s.err != nil {
		return NativeRemovalResult{}, s.err
	}
	if s.invalid {
		return NativeRemovalResult{}, nil
	}
	s.presence.proofs = append(s.presence.proofs, presenceProofFor(authorization.Plan(), true, "absent-after-removal"))
	return NativeRemovalResult{
		PlanDigest: authorization.Plan().Digest(), OwnershipDigest: authorization.Ownership().Digest(),
		ExecutionScan: authorization.Scan().Digest(), BeforeDigest: runtimeinstall.Sum([]byte("before-native")),
		EffectDigest: runtimeinstall.Sum([]byte("native-effect")),
	}, nil
}

func presenceProofFor(plan runtimeremoval.Plan, absent bool, evidence string) PresenceProof {
	return PresenceProof{
		PlanDigest: plan.Digest(), OwnershipDigest: plan.OwnershipRecordDigest(),
		EvidenceDigest: runtimeinstall.Sum([]byte(evidence)), Absent: absent,
	}
}

func removalCommand(plan runtimeinstall.Plan) Command {
	return Command{
		OperationID:          "019f60a0-0000-7abc-8123-0123456789ab",
		SourceOperationID:    "019f60a0-1111-7abc-8123-0123456789ab",
		CanonicalRuntimePlan: plan.CanonicalBytes(),
	}
}

func managedOwnershipFixture(t *testing.T) (runtimeinstall.Plan, runtimeinstall.RuntimeOwnershipRecord) {
	t.Helper()
	host, err := runtimeinstall.NewHostCapabilities(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "24.04", true, true, true, true,
		8, 32<<30, 24<<30, 100<<30,
	)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := runtimeinstall.NewCertifiedRuntime(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "docker_engine", "29.6.1", "stable", 7,
		runtimeinstall.Sum([]byte("catalog")), runtimeinstall.RuntimeTermsInput{
			ID: runtimeinstall.DockerEngineTermsID, Version: "apache-2.0", URL: "https://docs.docker.com/engine/",
			Digest: runtimeinstall.Sum([]byte("terms")), Presentation: runtimeinstall.TermsPresentationAgentMemory,
		}, 1, 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := runtimeinstall.NewPlanV1(host, runtimeinstall.NewAbsentRuntimeDiscovery(), catalog)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := runtimeinstall.NewOperation(removalCommand(plan).SourceOperationID, plan.Digest())
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range runtimeinstall.OrderedPhases() {
		artifact := runtimeinstall.Hash{}
		if phase >= runtimeinstall.PhaseVerifyRuntimeArtifact {
			artifact = runtimeinstall.Sum([]byte("runtime-artifact"))
		}
		ownership := runtimeinstall.OwnershipUnknown
		if phase == runtimeinstall.PhaseVerifyRuntimeCapabilities {
			ownership = runtimeinstall.OwnershipProvisionedByAgentMemory
		}
		evidence, evidenceError := runtimeinstall.NewTransitionEvidence(
			phase, operation.Attempt(), plan.Digest(), runtimeinstall.Sum([]byte("before-"+phase.String())),
			runtimeinstall.Sum([]byte("after-"+phase.String())), artifact, ownership,
		)
		if evidenceError != nil || operation.Complete(phase, evidence) != nil {
			t.Fatalf("complete %s: %v", phase, evidenceError)
		}
	}
	authority, err := runtimeinstall.NewRuntimeOwnershipAuthority(runtimeinstall.RuntimeOwnershipAuthoritySnapshot{
		Vendor: plan.Product(), Version: plan.Version(), Channel: plan.Channel(),
		Endpoint: "unix:///run/user/1000/docker.sock", Context: "explicit-local-endpoint",
		Publisher: "docker-stable:key", PublisherDigest: runtimeinstall.Sum([]byte("publisher")),
		ArtifactDigest: runtimeinstall.Sum([]byte("runtime-artifact")),
		Components:     []string{"engine@29.6.1"}, Settings: []string{"service:docker.service"},
	})
	if err != nil {
		t.Fatal(err)
	}
	record, err := runtimeinstall.NewRuntimeOwnershipRecord(plan, operation.Snapshot(), authority, nil)
	if err != nil {
		t.Fatal(err)
	}
	return plan, record
}
