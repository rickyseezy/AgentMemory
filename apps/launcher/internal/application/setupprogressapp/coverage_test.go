package setupprogressapp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001SetupProgressContractGetterAndTerminalCoverage(t *testing.T) {
	t.Parallel()
	binding := testBinding(t)
	states := []State{
		StateConnecting, StateAwaitingConsent, StateRunning, StatePausedForAdministrator,
		StateRebootRequired, StateReady, StateFailed, StateCancelled,
	}
	for index, state := range states {
		var consent *ConsentInput
		if state == StateAwaitingConsent {
			consent = testConsentInput()
		}
		snapshot := testSnapshotWith(
			t, binding, uint64(index+1), state, MessageConnecting, ActionNone, consent,
		)
		consentValue, consentPresent := snapshot.Consent()
		if snapshot.State() != state || snapshot.Phase() != PhaseEnsureContainerRuntime ||
			snapshot.MessageKey() != MessageConnecting || snapshot.Progress().TotalStages != 14 ||
			snapshot.SafeAction() != ActionNone || consentPresent != (consent != nil) {
			t.Fatalf("snapshot getters failed for %s", state)
		}
		if consentPresent && consentValue.termsTitle == "" {
			t.Fatal("consent getter returned zero value")
		}
		wantTerminal := state == StateReady || state == StateFailed || state == StateCancelled
		if snapshot.Terminal() != wantTerminal {
			t.Fatalf("Terminal(%s)=%t", state, snapshot.Terminal())
		}
	}
}

func TestPF001SetupProgressConstructorAndErrorEdgeCoverage(t *testing.T) {
	t.Parallel()
	if _, err := NewBinding(install.OperationID{}, install.PlanDigest{}); err == nil {
		t.Fatal("zero binding accepted")
	}
	binding := testBinding(t)
	var absentSnapshots *progressAuthorityStub
	if _, err := NewApplication(binding, absentSnapshots, absentSnapshots); err == nil {
		t.Fatal("typed-nil authority accepted")
	}
	var absentApplication *Application
	if absentApplication.Binding().Valid() {
		t.Fatal("nil application returned binding")
	}
	if (Snapshot{}).ContractVersion() != ContractVersion {
		t.Fatal("contract version is not stable")
	}
	if _, err := (Snapshot{}).CanonicalJSON(); err == nil {
		t.Fatal("zero snapshot encoded")
	}
	if _, err := NewDecisionReceipt(
		"018f47ab-9a77-7df0-8f4c-3e934c0a7d41", DecisionAccept, Snapshot{},
	); err == nil {
		t.Fatal("zero receipt snapshot accepted")
	}
	if newApplicationError(ErrorConflict).Code() != ErrorConflict {
		t.Fatal("error code getter failed")
	}
	for _, value := range []any{nil, (chan int)(nil), (func())(nil), (map[string]string)(nil), ([]byte)(nil), nilCapabilityFixture{}} {
		want := value == nil
		switch value.(type) {
		case chan int, func(), map[string]string, []byte:
			want = true
		}
		if got := nilCapability(value); got != want {
			t.Fatalf("nilCapability(%T)=%t want=%t", value, got, want)
		}
	}
}

func TestPF001SetupProgressMapsEveryAuthorityFailureAndInvalidCursor(t *testing.T) {
	t.Parallel()
	binding := testBinding(t)
	for _, test := range []struct {
		name string
		err  error
		want func(error) bool
	}{
		{name: "cancelled", err: context.Canceled, want: IsDeadlineError},
		{name: "deadline", err: context.DeadlineExceeded, want: IsDeadlineError},
		{name: "conflict", err: ErrAuthorityConflict, want: IsConflictError},
		{name: "integrity", err: ErrAuthorityIntegrity, want: IsIntegrityError},
		{name: "unavailable", err: errors.New("raw secret"), want: func(err error) bool {
			var applicationError *ApplicationError
			ok := errors.As(err, &applicationError)
			return ok && applicationError.Code() == ErrorUnavailable && !strings.Contains(err.Error(), "secret")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			authority := &progressAuthorityStub{current: testSnapshot(t, binding, 1, StateRunning), err: test.err}
			application, err := NewApplication(binding, authority, authority)
			if err != nil {
				t.Fatal(err)
			}
			_, gotError := application.Current(context.Background())
			if !test.want(gotError) {
				t.Fatalf("error=%v", gotError)
			}
		})
	}
	authority := &progressAuthorityStub{current: testSnapshot(t, binding, 1, StateRunning)}
	application, _ := NewApplication(binding, authority, authority)
	if _, err := application.WaitAfter(context.Background(), MaximumSafeInteger+1); !IsInvalidArgument(err) {
		t.Fatalf("cursor error=%v", err)
	}
}

func TestPF001SetupProgressRejectsUUIDAndConsentEncodingEdges(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"", "018f47ab9a77-7df0-8f4c-3e934c0a7d41", "018f47ab-9a77-0df0-8f4c-3e934c0a7d41",
		"018f47ab-9a77-7df0-7f4c-3e934c0a7d41", "018f47ab-9a77-7df0-8f4c-3e934c0a7d4z",
	} {
		if validUUID(value) {
			t.Fatalf("invalid UUID accepted %q", value)
		}
	}
	if validBoundedText("control\n", 20) || validBoundedText("", 20) ||
		validBoundedText(strings.Repeat("x", 21), 20) {
		t.Fatal("invalid bounded text accepted")
	}
	for _, value := range []string{
		"http://example.com", "https://user@example.com", "https://example", "https://.example.com",
		"https://example.com/#fragment", "https://example.com//double",
	} {
		if validHTTPSURL(value) {
			t.Fatalf("unsafe HTTPS URL accepted %q", value)
		}
	}
}

type nilCapabilityFixture struct{}
