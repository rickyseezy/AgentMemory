package installprogress

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/setupprogressapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
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
	if _, err := NewAuthority(setupprogressapp.Binding{}, 0, nil, nil, nil, nil); !errors.Is(err, setupprogressapp.ErrAuthorityIntegrity) {
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
	authority  *Authority
	binding    setupprogressapp.Binding
	operations *memoryOperations
	journal    *memoryDecisionJournal
	effect     *cancellingEffect
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
	journal := &memoryDecisionJournal{}
	effect := &cancellingEffect{operation: operation, plan: planDigest}
	authority, err := NewAuthority(binding, 1024, operations, staticDecisionProvider{journal: journal}, effect, fixedProgressClock{})
	if err != nil {
		t.Fatal(err)
	}
	return authorityFixture{authority: authority, binding: binding, operations: operations, journal: journal, effect: effect}
}

type memoryOperations struct {
	operation *install.Operation
	err       error
}

func (r *memoryOperations) Load(context.Context, install.OperationID) (*install.Operation, error) {
	return r.operation, r.err
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
}

func (e *cancellingEffect) ApplySetupDecision(_ context.Context, command setupprogressapp.DecisionCommand) error {
	e.calls++
	if command.Decision() != setupprogressapp.DecisionCancel {
		return errors.New("unexpected decision")
	}
	return e.operation.Cancel(e.plan)
}

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
