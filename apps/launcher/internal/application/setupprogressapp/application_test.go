package setupprogressapp

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001SetupProgressApplicationProjectsOnlyBoundBackendSnapshots(t *testing.T) {
	t.Parallel()
	binding := testBinding(t)
	initial := testSnapshot(t, binding, 1, StateAwaitingConsent)
	authority := &progressAuthorityStub{current: initial, waited: testSnapshot(t, binding, 2, StateRunning)}
	application, err := NewApplication(binding, authority, authority)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := application.Current(context.Background()); err != nil || got.Sequence() != 1 {
		t.Fatalf("Current()=%+v,%v", got, err)
	}
	if got, err := application.WaitAfter(context.Background(), 1); err != nil || got.Sequence() != 2 {
		t.Fatalf("WaitAfter()=%+v,%v", got, err)
	}

	receipt, _ := NewDecisionReceipt(
		"018f47ab-9a77-7df0-8f4c-3e934c0a7d41",
		DecisionAccept,
		testSnapshot(t, binding, 3, StateRunning),
	)
	authority.receipt = receipt
	got, err := application.Decide(context.Background(), DecisionInput{
		PlanDigest: binding.PlanDigest().String(), Decision: DecisionAccept,
		IdempotencyKey: receipt.IdempotencyKey(),
	})
	if err != nil || got.Sequence() != 3 || authority.command.Binding() != binding ||
		authority.command.Decision() != DecisionAccept {
		t.Fatalf("Decide()=%+v,%v command=%+v", got, err, authority.command)
	}
}

func TestPF001SetupProgressApplicationRejectsBackendBindingAndSequenceContradictions(t *testing.T) {
	t.Parallel()
	binding := testBinding(t)
	foreignOperation, _ := install.NewOperationID("foreign-operation")
	foreignBinding, _ := NewBinding(foreignOperation, binding.PlanDigest())
	tests := []struct {
		name string
		run  func(*Application, *progressAuthorityStub) error
	}{
		{name: "foreign current binding", run: func(application *Application, authority *progressAuthorityStub) error {
			authority.current = testSnapshot(t, foreignBinding, 1, StateRunning)
			_, err := application.Current(context.Background())
			return err
		}},
		{name: "regressed wait", run: func(application *Application, authority *progressAuthorityStub) error {
			authority.current = testSnapshot(t, binding, 4, StateRunning)
			if _, err := application.Current(context.Background()); err != nil {
				return err
			}
			authority.waited = testSnapshot(t, binding, 3, StateRunning)
			_, err := application.WaitAfter(context.Background(), 4)
			return err
		}},
		{name: "equal sequence changed payload", run: func(application *Application, authority *progressAuthorityStub) error {
			authority.current = testSnapshot(t, binding, 5, StateRunning)
			if _, err := application.Current(context.Background()); err != nil {
				return err
			}
			authority.current = testSnapshotWithMessage(t, binding, 5, StateRunning, MessageCheckingBrain)
			_, err := application.Current(context.Background())
			return err
		}},
		{name: "receipt key substitution", run: func(application *Application, authority *progressAuthorityStub) error {
			authority.current = testSnapshot(t, binding, 1, StateAwaitingConsent)
			authority.receipt, _ = NewDecisionReceipt(
				"018f47ab-9a77-7df0-8f4c-3e934c0a7d42", DecisionAccept,
				testSnapshot(t, binding, 2, StateRunning),
			)
			_, err := application.Decide(context.Background(), DecisionInput{
				PlanDigest: binding.PlanDigest().String(), Decision: DecisionAccept,
				IdempotencyKey: "018f47ab-9a77-7df0-8f4c-3e934c0a7d41",
			})
			return err
		}},
		{name: "receipt decision substitution", run: func(application *Application, authority *progressAuthorityStub) error {
			authority.receipt, _ = NewDecisionReceipt(
				"018f47ab-9a77-7df0-8f4c-3e934c0a7d41", DecisionDecline,
				testSnapshot(t, binding, 2, StateCancelled),
			)
			_, err := application.Decide(context.Background(), DecisionInput{
				PlanDigest: binding.PlanDigest().String(), Decision: DecisionAccept,
				IdempotencyKey: "018f47ab-9a77-7df0-8f4c-3e934c0a7d41",
			})
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authority := &progressAuthorityStub{current: testSnapshot(t, binding, 1, StateAwaitingConsent)}
			application, err := NewApplication(binding, authority, authority)
			if err != nil {
				t.Fatal(err)
			}
			if err := test.run(application, authority); !IsIntegrityError(err) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestPF001SetupProgressApplicationValidatesCommandsAndSanitizesAuthorityErrors(t *testing.T) {
	t.Parallel()
	binding := testBinding(t)
	authority := &progressAuthorityStub{current: testSnapshot(t, binding, 1, StateAwaitingConsent)}
	application, err := NewApplication(binding, authority, authority)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []DecisionInput{
		{},
		{PlanDigest: strings.Repeat("b", 64), Decision: DecisionAccept, IdempotencyKey: "018f47ab-9a77-7df0-8f4c-3e934c0a7d41"},
		{PlanDigest: binding.PlanDigest().String(), Decision: "approve", IdempotencyKey: "018f47ab-9a77-7df0-8f4c-3e934c0a7d41"},
		{PlanDigest: binding.PlanDigest().String(), Decision: DecisionAccept, IdempotencyKey: "not-a-uuid"},
	} {
		if _, err := application.Decide(context.Background(), input); !IsInvalidArgument(err) {
			t.Fatalf("input=%+v error=%v", input, err)
		}
	}
	authority.err = errors.New("/private/path: database secret")
	if _, err := application.Current(context.Background()); err == nil ||
		strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsanitized error=%v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := application.Current(ctx); !IsDeadlineError(err) {
		t.Fatalf("cancelled error=%v", err)
	}
	//lint:ignore SA1012 Deliberate nil-context boundary test.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if _, err := application.Current(nil); !IsInvalidArgument(err) {
		t.Fatalf("nil-context error=%v", err)
	}
}

func TestPF001SetupProgressApplicationSerializesConcurrentDecisionsThroughDurablePort(t *testing.T) {
	t.Parallel()
	binding := testBinding(t)
	authority := newConcurrentDecisionAuthority(t, binding)
	application, err := NewApplication(binding, authority, authority)
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{
		"018f47ab-9a77-7df0-8f4c-3e934c0a7d41",
		"018f47ab-9a77-7df0-8f4c-3e934c0a7d42",
	}
	errorsSeen := make(chan error, len(keys))
	for _, key := range keys {
		go func(idempotencyKey string) {
			_, decideError := application.Decide(context.Background(), DecisionInput{
				PlanDigest: binding.PlanDigest().String(), Decision: DecisionAccept,
				IdempotencyKey: idempotencyKey,
			})
			errorsSeen <- decideError
		}(key)
	}
	successes, conflicts := 0, 0
	for range keys {
		switch err := <-errorsSeen; {
		case err == nil:
			successes++
		case IsConflictError(err):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent error=%v", err)
		}
	}
	if successes != 1 || conflicts != 1 || authority.accepted != 1 {
		t.Fatalf("success=%d conflict=%d accepted=%d", successes, conflicts, authority.accepted)
	}
}

type progressAuthorityStub struct {
	current Snapshot
	waited  Snapshot
	receipt DecisionReceipt
	command DecisionCommand
	err     error
}

func (s *progressAuthorityStub) CurrentSnapshot(context.Context, Binding) (Snapshot, error) {
	return s.current, s.err
}

func (s *progressAuthorityStub) WaitSnapshotAfter(context.Context, Binding, uint64) (Snapshot, error) {
	return s.waited, s.err
}

func (s *progressAuthorityStub) ApplyDecision(_ context.Context, command DecisionCommand) (DecisionReceipt, error) {
	s.command = command
	return s.receipt, s.err
}

type concurrentDecisionAuthority struct {
	t        *testing.T
	binding  Binding
	current  Snapshot
	mu       sync.Mutex
	accepted int
}

func newConcurrentDecisionAuthority(t *testing.T, binding Binding) *concurrentDecisionAuthority {
	t.Helper()
	return &concurrentDecisionAuthority{t: t, binding: binding, current: testSnapshot(t, binding, 1, StateAwaitingConsent)}
}

func (a *concurrentDecisionAuthority) CurrentSnapshot(context.Context, Binding) (Snapshot, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.current, nil
}

func (a *concurrentDecisionAuthority) WaitSnapshotAfter(context.Context, Binding, uint64) (Snapshot, error) {
	return Snapshot{}, context.DeadlineExceeded
}

func (a *concurrentDecisionAuthority) ApplyDecision(_ context.Context, command DecisionCommand) (DecisionReceipt, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.accepted != 0 {
		return DecisionReceipt{}, ErrAuthorityConflict
	}
	a.accepted++
	a.current = testSnapshot(a.t, a.binding, 2, StateRunning)
	return NewDecisionReceipt(command.IdempotencyKey(), command.Decision(), a.current)
}

func testBinding(t testing.TB) Binding {
	t.Helper()
	operation, err := install.NewOperationID("operation-1")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := install.ParsePlanDigest(strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := NewBinding(operation, plan)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func testSnapshot(t testing.TB, binding Binding, sequence uint64, state State) Snapshot {
	t.Helper()
	message := MessageAwaitingConsent
	action := ActionCancel
	consent := testConsentInput()
	if state == StateRunning {
		message, action, consent = MessagePreparingRuntime, ActionCancel, nil
	}
	if state == StateCancelled {
		message, action, consent = MessageCancelled, ActionNone, nil
	}
	return testSnapshotWith(t, binding, sequence, state, message, action, consent)
}

func testSnapshotWithMessage(
	t testing.TB,
	binding Binding,
	sequence uint64,
	state State,
	message MessageKey,
) Snapshot {
	t.Helper()
	return testSnapshotWith(t, binding, sequence, state, message, ActionCancel, nil)
}

func testSnapshotWith(
	t testing.TB,
	binding Binding,
	sequence uint64,
	state State,
	message MessageKey,
	action SafeAction,
	consent *ConsentInput,
) Snapshot {
	t.Helper()
	snapshot, err := NewSnapshot(SnapshotInput{
		Sequence: sequence, OperationID: binding.OperationID(), PlanDigest: binding.PlanDigest(),
		State: state, Phase: PhaseEnsureContainerRuntime, MessageKey: message,
		Progress:   Progress{CompletedStages: 1, TotalStages: 14, TotalBytes: 1024},
		SafeAction: action, Consent: consent,
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func testConsentInput() *ConsentInput {
	return &ConsentInput{
		TermsTitle:  "Docker Subscription Service Agreement",
		TermsURL:    "https://www.docker.com/legal/docker-subscription-service-agreement/",
		TermsDigest: strings.Repeat("b", 64), DownloadBytes: 1024, ExpandedBytes: 4096,
		Changes: []string{"Install the verified local runtime"},
	}
}
