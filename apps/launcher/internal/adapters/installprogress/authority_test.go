package installprogress

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeinstallapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/setupprogressapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const decisionID = "019f5f2a-1234-7abc-8123-0123456789ab"

func TestPF001ProgressAuthorityProjectsAuthenticatedOperation(t *testing.T) {
	t.Parallel()
	fixture := newAuthorityFixture(t)
	snapshot, err := fixture.authority.CurrentSnapshot(context.Background(), fixture.binding)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.State() != setupprogressapp.StateRunning || snapshot.Phase() != setupprogressapp.PhaseVerifyHost ||
		snapshot.Sequence() != 1 || snapshot.SafeAction() != setupprogressapp.ActionCancel {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	waited, err := fixture.authority.WaitSnapshotAfter(context.Background(), fixture.binding, 0)
	if err != nil || waited.Sequence() != snapshot.Sequence() {
		t.Fatalf("WaitSnapshotAfter()=%+v, %v", waited, err)
	}
}

func TestPF001ProgressAuthorityPersistsIdempotentDecisionReceipt(t *testing.T) {
	t.Parallel()
	fixture := newAuthorityFixture(t)
	application, err := setupprogressapp.NewApplication(fixture.binding, fixture.authority, fixture.authority)
	if err != nil {
		t.Fatal(err)
	}
	input := setupprogressapp.DecisionInput{
		PlanDigest: fixture.binding.PlanDigest().String(), Decision: setupprogressapp.DecisionCancel,
		IdempotencyKey: decisionID,
	}
	first, err := application.Decide(context.Background(), input)
	if err != nil || first.State() != setupprogressapp.StateCancelled || fixture.effect.calls != 1 {
		t.Fatalf("Decide()=%+v, %v calls=%d", first, err, fixture.effect.calls)
	}
	second, err := application.Decide(context.Background(), input)
	if err != nil || second.State() != setupprogressapp.StateCancelled || fixture.effect.calls != 1 {
		t.Fatalf("replay=%+v, %v calls=%d", second, err, fixture.effect.calls)
	}
	if fixture.journal.snapshot.Revision != 1 || fixture.journal.confirms != 2 {
		t.Fatalf("journal revision=%d confirms=%d", fixture.journal.snapshot.Revision, fixture.journal.confirms)
	}
}

func TestPF001ProgressAuthorityWaitHonorsCancellation(t *testing.T) {
	t.Parallel()
	fixture := newAuthorityFixture(t)
	fixture.authority.pollInterval = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	_, err := fixture.authority.WaitSnapshotAfter(ctx, fixture.binding, 1)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitSnapshotAfter() error=%v", err)
	}
}

func TestPF001ProgressAuthorityRejectsInvalidCompositionAndSubstitution(t *testing.T) {
	t.Parallel()
	fixture := newAuthorityFixture(t)
	if _, err := NewAuthority(setupprogressapp.Binding{}, 0, nil, nil, nil, nil, nil, nil); !errors.Is(err, setupprogressapp.ErrAuthorityIntegrity) {
		t.Fatalf("NewAuthority() error=%v", err)
	}
	foreignID, _ := install.NewOperationID("019f5f2a-1234-7abc-8123-0123456789ac")
	foreign, _ := setupprogressapp.NewBinding(foreignID, fixture.binding.PlanDigest())
	if _, err := fixture.authority.CurrentSnapshot(context.Background(), foreign); !errors.Is(err, setupprogressapp.ErrAuthorityIntegrity) {
		t.Fatalf("foreign binding error=%v", err)
	}
	fixture.operations.err = errors.New("/private/secret")
	if _, err := fixture.authority.CurrentSnapshot(context.Background(), fixture.binding); err == nil || strings.Contains(err.Error(), "private") {
		t.Fatalf("unsanitized error=%v", err)
	}
	fixture.operations.err = context.Canceled
	if _, err := fixture.authority.CurrentSnapshot(context.Background(), fixture.binding); !errors.Is(err, context.Canceled) {
		t.Fatalf("context mapping error=%v", err)
	}
	fixture.operations.err = nil
	fixture.operations.operation = nil
	if _, err := fixture.authority.CurrentSnapshot(context.Background(), fixture.binding); !errors.Is(err, setupprogressapp.ErrAuthorityIntegrity) {
		t.Fatalf("nil operation error=%v", err)
	}
	if _, err := fixture.authority.WaitSnapshotAfter(context.Background(), fixture.binding, setupprogressapp.MaximumSafeInteger+1); !errors.Is(err, setupprogressapp.ErrAuthorityIntegrity) {
		t.Fatalf("unsafe cursor error=%v", err)
	}
	fixture = newAuthorityFixture(t)
	fixture.authority.decisions = staticDecisionProvider{err: errors.New("private journal failure")}
	application, err := setupprogressapp.NewApplication(fixture.binding, fixture.authority, fixture.authority)
	if err != nil {
		t.Fatal(err)
	}
	_, err = application.Decide(context.Background(), setupprogressapp.DecisionInput{
		PlanDigest: fixture.binding.PlanDigest().String(), Decision: setupprogressapp.DecisionCancel,
		IdempotencyKey: decisionID,
	})
	if err == nil || strings.Contains(err.Error(), "private") {
		t.Fatalf("decision journal error=%v", err)
	}
}

func TestPF001ProgressProjectsAuthenticatedRuntimeConsent(t *testing.T) {
	t.Parallel()
	fixture := newAuthorityFixture(t)
	advanceParentToRuntime(t, fixture.operations.operation)
	child, authority := runtimeConsentAuthority(t, fixture.operations.operation)
	fixture.runtime.operation = child
	fixture.runtime.err = nil
	fixture.runtimePlans.authority = authority
	fixture.runtimePlans.err = nil

	snapshot, err := fixture.authority.CurrentSnapshot(context.Background(), fixture.binding)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.State() != setupprogressapp.StateAwaitingConsent ||
		snapshot.Phase() != setupprogressapp.PhaseEnsureContainerRuntime ||
		snapshot.MessageKey() != setupprogressapp.MessageAwaitingConsent ||
		snapshot.SafeAction() != setupprogressapp.ActionNone || snapshot.Sequence() != 5 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	canonical, err := snapshot.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`"termsDigest":"` + authority.Plan().TermsDigest().String() + `"`,
		`"downloadBytes":700000000`, `"expandedBytes":2000000000`,
		`"requiresElevation":true`, `"mayRequireReboot":false`,
		`"changes":["Install the certified docker desktop 28.3.2","Confirm you are authorized and licensed to use Docker Desktop"]`,
	} {
		if !strings.Contains(string(canonical), required) {
			t.Fatalf("canonical consent %s missing %s", canonical, required)
		}
	}
}

func TestPF001ProgressRuntimeProjectionFailsClosed(t *testing.T) {
	t.Parallel()
	missing := newAuthorityFixture(t)
	advanceParentToRuntime(t, missing.operations.operation)
	advanceParentBeyondRuntime(t, missing.operations.operation)
	if _, err := missing.authority.CurrentSnapshot(context.Background(), missing.binding); !errors.Is(err, setupprogressapp.ErrAuthorityIntegrity) {
		t.Fatalf("missing completed runtime error=%v", err)
	}

	fixture := newAuthorityFixture(t)
	advanceParentToRuntime(t, fixture.operations.operation)
	child, authority := runtimeConsentAuthority(t, fixture.operations.operation)
	fixture.runtime.operation, fixture.runtime.err = child, nil
	fixture.runtimePlans.authority, fixture.runtimePlans.err = authority, nil

	fixture.runtimePlans.err = installplanapp.ErrRuntimePlanIntegrity
	if _, err := fixture.authority.CurrentSnapshot(context.Background(), fixture.binding); !errors.Is(err, setupprogressapp.ErrAuthorityIntegrity) {
		t.Fatalf("runtime plan integrity error=%v", err)
	}
	fixture.runtimePlans.err = nil
	fixture.runtimePlans.authority = installplanapp.RuntimePlanAuthority{}
	if _, err := fixture.authority.CurrentSnapshot(context.Background(), fixture.binding); !errors.Is(err, setupprogressapp.ErrAuthorityIntegrity) {
		t.Fatalf("substituted runtime plan error=%v", err)
	}
	fixture.runtime.err = context.Canceled
	if _, err := fixture.authority.CurrentSnapshot(context.Background(), fixture.binding); !errors.Is(err, context.Canceled) {
		t.Fatalf("runtime cancellation error=%v", err)
	}
}

func TestPF001ProgressProjectionCoversEveryClosedStatePhaseAndMessage(t *testing.T) {
	t.Parallel()
	states := []install.State{
		install.StateUnknown, install.StateRunning, install.StateRebootPending, install.StateResumeVerified,
		install.StateFailedRecoverable, install.StatePausedForAdministrator, install.StateCancelled,
		install.StateUnsupportedHost, install.StateRuntimeConflict, install.StateReady, install.State(255),
	}
	for _, state := range states {
		projected, action := setupState(state)
		if projected == "" || action == "" || setupMessage(state, install.PhaseVerifyHost) == "" {
			t.Fatalf("state %v has incomplete projection", state)
		}
	}
	for _, phase := range install.OrderedPhases() {
		projected, ok := setupPhase(phase)
		if !ok || projected == "" || setupMessage(install.StateRunning, phase) == "" {
			t.Fatalf("phase %v has incomplete projection", phase)
		}
	}
	if _, ok := setupPhase(install.PhaseUnknown); ok || setupMessage(install.StateRunning, install.PhaseUnknown) != setupprogressapp.MessageConnecting {
		t.Fatal("unknown phase did not fail closed")
	}
}

func TestPF001RuntimeProgressProjectionCoversEveryClosedStateAndFailure(t *testing.T) {
	t.Parallel()
	states := []runtimeinstall.OperationState{
		runtimeinstall.OperationStateUnknown,
		runtimeinstall.OperationStateRunning,
		runtimeinstall.OperationStateRebootPending,
		runtimeinstall.OperationStateReady,
		runtimeinstall.OperationStateCancelled,
		runtimeinstall.OperationStatePausedForAdministrator,
		runtimeinstall.OperationStateUnsupportedHost,
		runtimeinstall.OperationStateRuntimeConflict,
		runtimeinstall.OperationStateFailedRecoverable,
		runtimeinstall.OperationState(255),
	}
	for _, state := range states {
		projected, action := setupRuntimeState(state)
		if projected == "" || action == "" || runtimeMessage(projected) == "" {
			t.Fatalf("runtime state %v has incomplete projection", state)
		}
	}
	for _, state := range []setupprogressapp.State{
		setupprogressapp.StateAwaitingConsent,
		setupprogressapp.StateReady,
		setupprogressapp.State("unknown"),
	} {
		if runtimeMessage(state) == "" {
			t.Fatalf("runtime message missing for %q", state)
		}
	}
	for _, input := range []error{
		context.Canceled,
		context.DeadlineExceeded,
		runtimeinstallapp.ErrOperationIntegrity,
		installplanapp.ErrRuntimePlanIntegrity,
		installplanapp.ErrRuntimePlanConflict,
		errors.New("private path"),
	} {
		mapped := mapRuntimeProjectionError(input)
		if mapped == nil || strings.Contains(mapped.Error(), "private") {
			t.Fatalf("mapRuntimeProjectionError(%v)=%v", input, mapped)
		}
	}
	if _, _, _, ok := runtimeConsentChange(runtimeinstall.Plan{}); ok {
		t.Fatal("zero runtime plan produced consent")
	}
}

func TestPF001ProgressDecisionTransitionPolicyIsClosed(t *testing.T) {
	t.Parallel()
	fixture := newAuthorityFixture(t)
	makeSnapshot := func(state setupprogressapp.State, action setupprogressapp.SafeAction) setupprogressapp.Snapshot {
		snapshot, err := setupprogressapp.NewSnapshot(setupprogressapp.SnapshotInput{
			Sequence: 1, OperationID: fixture.binding.OperationID(), PlanDigest: fixture.binding.PlanDigest(),
			State: state, Phase: setupprogressapp.PhaseVerifyHost, MessageKey: messageForTestState(state),
			Progress: setupprogressapp.Progress{TotalStages: 14}, SafeAction: action,
			Consent: consentForTestState(state),
		})
		if err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	tests := []struct {
		state    setupprogressapp.State
		action   setupprogressapp.SafeAction
		decision setupprogressapp.Decision
		want     bool
		wantErr  bool
	}{
		{setupprogressapp.StateRunning, setupprogressapp.ActionCancel, setupprogressapp.DecisionCancel, true, false},
		{setupprogressapp.StateCancelled, setupprogressapp.ActionNone, setupprogressapp.DecisionCancel, false, false},
		{setupprogressapp.StateReady, setupprogressapp.ActionNone, setupprogressapp.DecisionCancel, false, true},
		{setupprogressapp.StateAwaitingConsent, setupprogressapp.ActionNone, setupprogressapp.DecisionAccept, true, false},
		{setupprogressapp.StateAwaitingConsent, setupprogressapp.ActionNone, setupprogressapp.DecisionDecline, true, false},
		{setupprogressapp.StateFailed, setupprogressapp.ActionRetry, setupprogressapp.DecisionRetry, true, false},
		{setupprogressapp.StateFailed, setupprogressapp.ActionNone, setupprogressapp.DecisionRetry, false, true},
		{setupprogressapp.StateRunning, setupprogressapp.ActionCancel, setupprogressapp.Decision("unknown"), false, true},
	}
	for _, test := range tests {
		needsEffect, err := validateDecisionTransition(makeSnapshot(test.state, test.action), test.decision)
		if needsEffect != test.want || (err != nil) != test.wantErr {
			t.Fatalf("state=%s decision=%s result=%v,%v", test.state, test.decision, needsEffect, err)
		}
	}
}

func TestPF001ProgressDecisionJournalRejectsTamperAndMapsFailures(t *testing.T) {
	t.Parallel()
	fixture := newAuthorityFixture(t)
	fixture.journal.loadErr = journalport.ErrIO
	if _, _, err := fixture.authority.loadDecisionState(context.Background(), fixture.journal); err == nil {
		t.Fatal("journal IO was accepted")
	}
	fixture.journal.loadErr = nil
	fixture.journal.snapshot = journalport.Snapshot{OperationID: fixture.binding.OperationID().String(), Revision: 1,
		CapturedAt: time.Now().UTC(), Payload: []byte(`{"schema_version":1}`)}
	if _, _, err := fixture.authority.loadDecisionState(context.Background(), fixture.journal); !errors.Is(err, setupprogressapp.ErrAuthorityIntegrity) {
		t.Fatalf("tamper error=%v", err)
	}
	for _, input := range []error{context.Canceled, context.DeadlineExceeded, journalport.ErrConflict,
		journalport.ErrCorrupt, journalport.ErrUnsafePermission, journalport.ErrInvalidSnapshot, journalport.ErrIO} {
		if mapJournalError(input) == nil {
			t.Fatalf("mapJournalError(%v)=nil", input)
		}
	}
	if !nilCapability(nil) || nilCapability(struct{}{}) {
		t.Fatal("nil capability classifier failed closed contract")
	}
}

func TestPF001ProgressDecisionExecutionFailsClosedAtEveryDurabilityBoundary(t *testing.T) {
	t.Parallel()
	seed := newAuthorityFixture(t)
	application, err := setupprogressapp.NewApplication(seed.binding, seed.authority, seed.authority)
	if err != nil {
		t.Fatal(err)
	}
	_, err = application.Decide(context.Background(), setupprogressapp.DecisionInput{
		PlanDigest: seed.binding.PlanDigest().String(), Decision: setupprogressapp.DecisionCancel,
		IdempotencyKey: decisionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	command := seed.effect.command
	if !command.Decision().Valid() {
		t.Fatal("decision command was not captured")
	}
	decide := func(f authorityFixture) error {
		_, err := f.authority.ApplyDecision(context.Background(), command)
		if err != nil {
			return err
		}
		return nil
	}
	tests := []struct {
		name   string
		mutate func(*authorityFixture)
		want   error
	}{
		{name: "nil journal", mutate: func(f *authorityFixture) {
			f.authority.decisions = staticDecisionProvider{}
		}},
		{name: "effect unavailable", mutate: func(f *authorityFixture) {
			f.effect.err = errors.New("private effect")
		}},
		{name: "effect cancelled", mutate: func(f *authorityFixture) {
			f.effect.err = context.Canceled
		}, want: context.Canceled},
		{name: "append corrupt", mutate: func(f *authorityFixture) {
			f.journal.appendErr = journalport.ErrCorrupt
		}, want: setupprogressapp.ErrAuthorityIntegrity},
		{name: "confirm conflict", mutate: func(f *authorityFixture) {
			f.journal.confirmErr = journalport.ErrConflict
		}, want: setupprogressapp.ErrAuthorityConflict},
		{name: "zero clock", mutate: func(f *authorityFixture) {
			f.authority.clock = zeroProgressClock{}
		}, want: setupprogressapp.ErrAuthorityIntegrity},
		{name: "CAS exhaustion", mutate: func(f *authorityFixture) {
			f.journal.appendErr = journalport.ErrConflict
		}, want: setupprogressapp.ErrAuthorityConflict},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newAuthorityFixture(t)
			test.mutate(&fixture)
			err := decide(fixture)
			if err == nil || (test.want != nil && !errors.Is(err, test.want)) || strings.Contains(err.Error(), "private") {
				t.Fatalf("ApplyDecision() error=%v, want=%v", err, test.want)
			}
		})
	}

	fixture := newAuthorityFixture(t)
	fixture.authority.operations = &memoryOperations{operation: fixture.operations.operation, err: installapp.ErrOperationIntegrity}
	if _, err := fixture.authority.CurrentSnapshot(context.Background(), fixture.binding); !errors.Is(err, setupprogressapp.ErrAuthorityIntegrity) {
		t.Fatalf("integrity mapping error=%v", err)
	}
}

func TestPF001ProgressSnapshotCanonicalDecoderRejectsNonCanonicalInput(t *testing.T) {
	t.Parallel()
	fixture := newAuthorityFixture(t)
	snapshot, err := fixture.authority.CurrentSnapshot(context.Background(), fixture.binding)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := snapshot.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeSnapshot(canonical)
	if err != nil || decoded.Sequence() != snapshot.Sequence() {
		t.Fatalf("decodeSnapshot()=%+v,%v", decoded, err)
	}
	for _, raw := range [][]byte{nil, append(append([]byte(nil), canonical...), '\n'), []byte(`{"contractVersion":2}`), []byte(`{} {}`)} {
		if _, err := decodeSnapshot(raw); !errors.Is(err, setupprogressapp.ErrAuthorityIntegrity) {
			t.Fatalf("decodeSnapshot(%q) error=%v", raw, err)
		}
	}
}

type authorityFixture struct {
	authority    *Authority
	binding      setupprogressapp.Binding
	operations   *memoryOperations
	runtime      *memoryRuntimeOperations
	runtimePlans *memoryRuntimePlans
	journal      *memoryDecisionJournal
	effect       *cancellingEffect
}

func newAuthorityFixture(t testing.TB) authorityFixture {
	t.Helper()
	operationID, err := install.NewOperationID("019f5f29-1234-7abc-8123-0123456789ab")
	if err != nil {
		t.Fatal(err)
	}
	planDigest, err := install.BindPlan([]byte("canonical installer plan"))
	if err != nil {
		t.Fatal(err)
	}
	operation, err := install.NewOperation(operationID, planDigest)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := setupprogressapp.NewBinding(operationID, planDigest)
	if err != nil {
		t.Fatal(err)
	}
	operations := &memoryOperations{operation: operation}
	runtimeOperations := &memoryRuntimeOperations{err: runtimeinstallapp.ErrOperationNotFound}
	runtimePlans := &memoryRuntimePlans{err: installplanapp.ErrRuntimePlanNotFound}
	journal := &memoryDecisionJournal{}
	effect := &cancellingEffect{operation: operation, plan: planDigest}
	authority, err := NewAuthority(
		binding, 1024, operations, runtimeOperations, runtimePlans,
		staticDecisionProvider{journal: journal}, effect, fixedProgressClock{},
	)
	if err != nil {
		t.Fatal(err)
	}
	return authorityFixture{
		authority: authority, binding: binding, operations: operations,
		runtime: runtimeOperations, runtimePlans: runtimePlans,
		journal: journal, effect: effect,
	}
}

func advanceParentToRuntime(t testing.TB, operation *install.Operation) {
	t.Helper()
	boundary, err := install.NewCompensationBoundary("verify-host")
	if err != nil {
		t.Fatal(err)
	}
	action, err := install.NewSafeAction("continue")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := install.NewStepEvidence(install.StepEvidenceInput{
		Phase: install.PhaseVerifyHost, Attempt: 1, PlanDigest: operation.PlanDigest(),
		InputDigest:          install.DigestBytes([]byte("host-input")),
		OutputDigest:         install.DigestBytes([]byte("host-output")),
		RuntimeOwnership:     install.RuntimeOwnershipUndetermined,
		CompensationBoundary: boundary, NextSafeAction: action,
	})
	if err != nil || operation.CompleteStep(evidence) != nil {
		t.Fatalf("advance parent: %v", err)
	}
}

func advanceParentBeyondRuntime(t testing.TB, operation *install.Operation) {
	t.Helper()
	boundary, err := install.NewCompensationBoundary("runtime")
	if err != nil {
		t.Fatal(err)
	}
	action, err := install.NewSafeAction("continue")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := install.NewStepEvidence(install.StepEvidenceInput{
		Phase: install.PhaseEnsureContainerRuntime, Attempt: 1, PlanDigest: operation.PlanDigest(),
		InputDigest:            install.DigestBytes([]byte("runtime-input")),
		OutputDigest:           install.DigestBytes([]byte("runtime-output")),
		VerifiedArtifactDigest: install.DigestBytes([]byte("runtime-artifact")),
		RuntimeOwnership:       install.RuntimeOwnershipProvisionedByAgentMemory,
		CompensationBoundary:   boundary, NextSafeAction: action,
	})
	if err != nil || operation.CompleteStep(evidence) != nil {
		t.Fatalf("advance parent beyond runtime: %v", err)
	}
}

func runtimeConsentAuthority(
	t testing.TB,
	parent *install.Operation,
) (*runtimeinstall.Operation, installplanapp.RuntimePlanAuthority) {
	t.Helper()
	host, err := runtimeinstall.NewHostCapabilities(
		runtimeinstall.PlatformDarwin, runtimeinstall.ArchitectureARM64, "15.5", true,
		true, true, true, 8, 16<<30, 12<<30, 80<<30,
	)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := runtimeinstall.NewCertifiedRuntime(
		runtimeinstall.PlatformDarwin, runtimeinstall.ArchitectureARM64,
		"docker_desktop", "28.3.2", "stable", 42,
		runtimeinstall.Sum([]byte("catalog")), runtimeinstall.Sum([]byte("terms")),
		700000000, 2000000000,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := runtimeinstall.NewPlanV1(host, runtimeinstall.NewAbsentRuntimeDiscovery(), catalog)
	if err != nil {
		t.Fatal(err)
	}
	child, err := runtimeinstall.NewOperation(parent.ID().String(), plan.Digest())
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []runtimeinstall.Phase{
		runtimeinstall.PhaseDetectHost,
		runtimeinstall.PhaseDetectRuntime,
		runtimeinstall.PhasePlanRuntime,
	} {
		evidence, evidenceErr := runtimeinstall.NewTransitionEvidence(
			phase, child.Attempt(), plan.Digest(),
			runtimeinstall.Sum([]byte("input-"+phase.String())),
			runtimeinstall.Sum([]byte("output-"+phase.String())),
			runtimeinstall.Hash{}, runtimeinstall.OwnershipUnknown,
		)
		if evidenceErr != nil || child.Complete(phase, evidence) != nil {
			t.Fatalf("advance runtime %s: %v", phase, evidenceErr)
		}
	}
	authority, err := installplanapp.NewRuntimePlanAuthority(
		parent.ID(), parent.PlanDigest(), plan,
		install.DigestBytes([]byte("host-evidence")),
		install.DigestBytes([]byte("discovery-evidence")),
		install.DigestBytes([]byte("catalog-resource-evidence")),
		install.DigestBytes([]byte("catalog")),
	)
	if err != nil {
		t.Fatal(err)
	}
	return child, authority
}

type memoryOperations struct {
	operation *install.Operation
	err       error
}

func (r *memoryOperations) Load(context.Context, install.OperationID) (*install.Operation, error) {
	return r.operation, r.err
}

type memoryRuntimeOperations struct {
	operation *runtimeinstall.Operation
	err       error
}

func (r *memoryRuntimeOperations) Load(context.Context, string) (*runtimeinstall.Operation, error) {
	return r.operation, r.err
}

type memoryRuntimePlans struct {
	authority installplanapp.RuntimePlanAuthority
	err       error
}

func (r *memoryRuntimePlans) LoadRuntimePlan(
	context.Context,
	install.OperationID,
	install.PlanDigest,
) (installplanapp.RuntimePlanAuthority, error) {
	return r.authority, r.err
}

type staticDecisionProvider struct {
	journal journalport.Journal
	err     error
}

func (p staticDecisionProvider) JournalFor(context.Context, install.OperationID) (journalport.Journal, error) {
	return p.journal, p.err
}

type memoryDecisionJournal struct {
	snapshot   journalport.Snapshot
	loadErr    error
	appendErr  error
	confirmErr error
	confirms   int
}

func (j *memoryDecisionJournal) Append(_ context.Context, expected uint64, snapshot journalport.Snapshot) error {
	if j.appendErr != nil {
		return j.appendErr
	}
	if expected != j.snapshot.Revision {
		return journalport.ErrConflict
	}
	snapshot.Payload = append([]byte(nil), snapshot.Payload...)
	j.snapshot = snapshot
	return nil
}

func (j *memoryDecisionJournal) LoadLatest(context.Context) (journalport.Snapshot, error) {
	if j.loadErr != nil {
		return journalport.Snapshot{}, j.loadErr
	}
	if j.snapshot.Revision == 0 {
		return journalport.Snapshot{}, journalport.ErrNotFound
	}
	result := j.snapshot
	result.Payload = append([]byte(nil), result.Payload...)
	return result, nil
}

func (j *memoryDecisionJournal) ConfirmDurable(_ context.Context, operationID string, revision uint64) error {
	if j.confirmErr != nil {
		return j.confirmErr
	}
	if operationID != j.snapshot.OperationID || revision != j.snapshot.Revision {
		return journalport.ErrConflict
	}
	j.confirms++
	return nil
}

type cancellingEffect struct {
	operation *install.Operation
	plan      install.PlanDigest
	calls     int
	err       error
	command   setupprogressapp.DecisionCommand
}

func (e *cancellingEffect) ApplySetupDecision(_ context.Context, command setupprogressapp.DecisionCommand) error {
	e.calls++
	e.command = command
	if e.err != nil {
		return e.err
	}
	if command.Decision() != setupprogressapp.DecisionCancel {
		return errors.New("unexpected decision")
	}
	return e.operation.Cancel(e.plan)
}

type zeroProgressClock struct{}

func (zeroProgressClock) Now() time.Time { return time.Time{} }

type fixedProgressClock struct{}

func (fixedProgressClock) Now() time.Time {
	return time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
}

func messageForTestState(state setupprogressapp.State) setupprogressapp.MessageKey {
	switch state {
	case setupprogressapp.StateConnecting, setupprogressapp.StateRunning,
		setupprogressapp.StatePausedForAdministrator, setupprogressapp.StateRebootRequired:
		return setupprogressapp.MessageVerifying
	case setupprogressapp.StateAwaitingConsent:
		return setupprogressapp.MessageAwaitingConsent
	case setupprogressapp.StateFailed:
		return setupprogressapp.MessageRetryableFailure
	case setupprogressapp.StateCancelled:
		return setupprogressapp.MessageCancelled
	case setupprogressapp.StateReady:
		return setupprogressapp.MessageReady
	default:
		return setupprogressapp.MessageVerifying
	}
}

func consentForTestState(state setupprogressapp.State) *setupprogressapp.ConsentInput {
	if state != setupprogressapp.StateAwaitingConsent {
		return nil
	}
	return &setupprogressapp.ConsentInput{
		TermsTitle: "Docker Desktop terms", TermsURL: "https://example.com/terms",
		TermsDigest: strings.Repeat("a", 64), Changes: []string{"Install local runtime"},
	}
}

func TestNilCapabilityAcceptsConcreteValue(t *testing.T) {
	t.Parallel()
	if nilCapability(1) {
		t.Fatal("nilCapability(1)=true")
	}
	if got := setupMessage(install.StateRunning, install.Phase(255)); got != setupprogressapp.MessageConnecting {
		t.Fatalf("setupMessage(invalid)=%q", got)
	}
}
