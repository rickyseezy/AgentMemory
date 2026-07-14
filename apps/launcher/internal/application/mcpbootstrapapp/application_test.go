package mcpbootstrapapp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/setupprogressapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const testInstallationID = "019f5f20-1234-7abc-8123-0123456789ab"

func TestPF001MCPBootstrapProjectsCompletePrivacySafeStatus(t *testing.T) {
	t.Parallel()
	fixture := newApplicationFixture(t, snapshotSpec{
		state: setupprogressapp.StateRunning, action: setupprogressapp.ActionCancel,
		message: setupprogressapp.MessagePreparingRuntime, sequence: 3,
	})

	status, err := fixture.application.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.ContractVersion != setupprogressapp.ContractVersion || status.Sequence != 3 ||
		status.InstallationID != testInstallationID || status.OperationID != fixture.binding.OperationID().String() ||
		status.State != "running" || status.Phase != "ensure_container_runtime" ||
		status.CompletedBytes != 128 || status.TotalBytes != 1024 ||
		status.CompletedStages != 1 || status.TotalStages != 14 ||
		status.MessageKey != "setup.preparing_runtime" || len(status.MessageArguments) != 0 ||
		status.Interaction != InteractionNone || status.AutomaticRetryAt != nil || !status.Cancellable ||
		status.Error != nil || status.ReadyHandoffPending {
		t.Fatalf("unexpected status: %+v", status)
	}
	installationID, operationID := fixture.application.Identity()
	if installationID != testInstallationID || operationID != fixture.binding.OperationID().String() {
		t.Fatalf("identity = %q, %q", installationID, operationID)
	}
}

func TestPF001MCPBootstrapMapsEveryInteractionAndSafeError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		spec        snapshotSpec
		interaction InteractionKind
		cancellable bool
		errorCode   string
		pending     bool
	}{
		{name: "connecting", spec: snapshotSpec{state: setupprogressapp.StateConnecting, action: setupprogressapp.ActionCancel, message: setupprogressapp.MessageConnecting}, cancellable: true},
		{name: "terms", spec: snapshotSpec{state: setupprogressapp.StateAwaitingConsent, action: setupprogressapp.ActionCancel, message: setupprogressapp.MessageAwaitingConsent}, interaction: InteractionTerms, cancellable: true},
		{name: "elevation", spec: snapshotSpec{state: setupprogressapp.StatePausedForAdministrator, action: setupprogressapp.ActionOpenNativePrompt, message: setupprogressapp.MessageAdministratorRequired}, interaction: InteractionElevation, cancellable: true, errorCode: "AM_SETUP_ADMIN_REQUIRED"},
		{name: "administrator", spec: snapshotSpec{state: setupprogressapp.StatePausedForAdministrator, action: setupprogressapp.ActionCancel, message: setupprogressapp.MessageAdministratorRequired}, interaction: InteractionAdministrator, cancellable: true, errorCode: "AM_SETUP_ADMIN_REQUIRED"},
		{name: "restart", spec: snapshotSpec{state: setupprogressapp.StateRebootRequired, action: setupprogressapp.ActionReboot, message: setupprogressapp.MessageRebootRequired}, interaction: InteractionRestart, cancellable: true, errorCode: "AM_REBOOT_REQUIRED"},
		{name: "retryable failure", spec: snapshotSpec{state: setupprogressapp.StateFailed, action: setupprogressapp.ActionRetry, message: setupprogressapp.MessageRetryableFailure}, cancellable: true, errorCode: "AM_DEPENDENCY_UNAVAILABLE"},
		{name: "terminal failure", spec: snapshotSpec{state: setupprogressapp.StateFailed, action: setupprogressapp.ActionNone, message: setupprogressapp.MessageRetryableFailure}, errorCode: "AM_DEPENDENCY_UNAVAILABLE"},
		{name: "cancelled", spec: snapshotSpec{state: setupprogressapp.StateCancelled, action: setupprogressapp.ActionNone, message: setupprogressapp.MessageCancelled}},
		{name: "ready", spec: snapshotSpec{state: setupprogressapp.StateReady, action: setupprogressapp.ActionNone, message: setupprogressapp.MessageReady}, pending: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if test.interaction == "" {
				test.interaction = InteractionNone
			}
			if test.spec.sequence == 0 {
				test.spec.sequence = 1
			}
			fixture := newApplicationFixture(t, test.spec)
			status, err := fixture.application.Status(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if status.Interaction != test.interaction || status.Cancellable != test.cancellable ||
				status.ReadyHandoffPending != test.pending {
				t.Fatalf("status = %+v", status)
			}
			if test.errorCode == "" && status.Error != nil ||
				test.errorCode != "" && (status.Error == nil || status.Error.Code != test.errorCode) {
				t.Fatalf("status error = %+v, want %q", status.Error, test.errorCode)
			}
		})
	}
}

func TestPF001MCPBootstrapOpenCancelAndWaitUseBoundAuthorities(t *testing.T) {
	t.Parallel()
	fixture := newApplicationFixture(t, snapshotSpec{
		state: setupprogressapp.StateRunning, action: setupprogressapp.ActionCancel,
		message: setupprogressapp.MessagePreparingRuntime, sequence: 1,
	})
	opened, err := fixture.application.OpenSetup(context.Background())
	if err != nil || !opened.Opened || opened.InstallationID != testInstallationID ||
		opened.OperationID != fixture.binding.OperationID().String() || fixture.setup.calls != 1 {
		t.Fatalf("OpenSetup() = %+v, %v, calls=%d", opened, err, fixture.setup.calls)
	}

	cancelled := fixture.snapshot(snapshotSpec{
		state: setupprogressapp.StateCancelled, action: setupprogressapp.ActionNone,
		message: setupprogressapp.MessageCancelled, sequence: 2,
	})
	fixture.cancellation.after = cancelled
	result, err := fixture.application.Cancel(context.Background())
	if err != nil || !result.CancellationRequested || result.Status.State != "cancelled" ||
		result.Status.Cancellable || fixture.cancellation.calls != 1 {
		t.Fatalf("Cancel() = %+v, %v, calls=%d", result, err, fixture.cancellation.calls)
	}

	ready := fixture.snapshot(snapshotSpec{
		state: setupprogressapp.StateReady, action: setupprogressapp.ActionNone,
		message: setupprogressapp.MessageReady, sequence: 3,
	})
	fixture.snapshots.next = ready
	waited, err := fixture.application.WaitAfter(context.Background(), 2)
	if err != nil || !waited.ReadyHandoffPending || waited.Sequence != 3 {
		t.Fatalf("WaitAfter() = %+v, %v", waited, err)
	}
}

func TestPF001MCPBootstrapRejectsInvalidCompositionAndSanitizesFailures(t *testing.T) {
	t.Parallel()
	fixture := newApplicationFixture(t, snapshotSpec{
		state: setupprogressapp.StateRunning, action: setupprogressapp.ActionCancel,
		message: setupprogressapp.MessagePreparingRuntime, sequence: 1,
	})
	var nilSetup *setupStub
	var nilCancellation *cancellationStub
	for _, construct := range []func() (*Application, error){
		func() (*Application, error) { return New("", fixture.progress, fixture.setup, fixture.cancellation) },
		func() (*Application, error) { return New(testInstallationID, nil, fixture.setup, fixture.cancellation) },
		func() (*Application, error) {
			return New(testInstallationID, fixture.progress, nilSetup, fixture.cancellation)
		},
		func() (*Application, error) {
			return New(testInstallationID, fixture.progress, fixture.setup, nilCancellation)
		},
	} {
		if application, err := construct(); application != nil || errorCode(err) != ErrorInvalidArgument {
			t.Fatalf("invalid composition = %#v, %v", application, err)
		}
	}

	fixture.setup.err = errors.New("secret host path")
	if _, err := fixture.application.OpenSetup(context.Background()); errorCode(err) != ErrorUnavailable ||
		err.Error() != string(ErrorUnavailable) {
		t.Fatalf("OpenSetup error = %v", err)
	}
	fixture.cancellation.err = context.DeadlineExceeded
	if _, err := fixture.application.Cancel(context.Background()); errorCode(err) != ErrorDeadline {
		t.Fatalf("Cancel error = %v", err)
	}
	fixture.snapshots.err = setupprogressapp.ErrAuthorityIntegrity
	if _, err := fixture.application.Status(context.Background()); errorCode(err) != ErrorIntegrity {
		t.Fatalf("Status error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fixture.application.Status(cancelled); errorCode(err) != ErrorDeadline {
		t.Fatalf("cancelled Status error = %v", err)
	}
	var nilApplication *Application
	if installationID, operationID := nilApplication.Identity(); installationID != "" || operationID != "" {
		t.Fatalf("nil identity = %q, %q", installationID, operationID)
	}
	if _, err := nilApplication.Status(context.Background()); errorCode(err) != ErrorInvalidArgument {
		t.Fatalf("nil application error = %v", err)
	}
}

func TestPF001MCPBootstrapMapsAllProgressCodesAndRejectsInvalidCursorAndIdentity(t *testing.T) {
	t.Parallel()
	fixture := newApplicationFixture(t, snapshotSpec{
		state: setupprogressapp.StateRunning, action: setupprogressapp.ActionCancel,
		message: setupprogressapp.MessagePreparingRuntime, sequence: 1,
	})
	for name, test := range map[string]struct {
		authorityError error
		want           ErrorCode
	}{
		"deadline":    {authorityError: context.DeadlineExceeded, want: ErrorDeadline},
		"conflict":    {authorityError: setupprogressapp.ErrAuthorityConflict, want: ErrorConflict},
		"integrity":   {authorityError: setupprogressapp.ErrAuthorityIntegrity, want: ErrorIntegrity},
		"unavailable": {authorityError: errors.New("raw backend detail"), want: ErrorUnavailable},
	} {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			isolated := newApplicationFixture(t, snapshotSpec{
				state: setupprogressapp.StateRunning, action: setupprogressapp.ActionCancel,
				message: setupprogressapp.MessagePreparingRuntime, sequence: 1,
			})
			isolated.snapshots.err = test.authorityError
			if _, err := isolated.application.Status(context.Background()); errorCode(err) != test.want ||
				strings.Contains(err.Error(), "raw") {
				t.Fatalf("mapped error = %v, want %s", err, test.want)
			}
		})
	}
	if _, err := fixture.application.WaitAfter(context.Background(), setupprogressapp.MaximumSafeInteger+1); errorCode(err) != ErrorInvalidArgument {
		t.Fatalf("invalid cursor error = %v", err)
	}
	fixture.cancellation.after = fixture.snapshot(snapshotSpec{
		state: setupprogressapp.StateCancelled, action: setupprogressapp.ActionNone,
		message: setupprogressapp.MessageCancelled, sequence: 2,
	})
	fixture.snapshots.err = errors.New("status reload failed")
	if _, err := fixture.application.Cancel(context.Background()); errorCode(err) != ErrorUnavailable {
		t.Fatalf("post-cancel status error = %v", err)
	}
	//lint:ignore SA1012 Deliberate nil-context boundary test.
	//nolint:staticcheck // SA1012: inbound boundary fixture; owner=security expiry=2027-07-14.
	if _, err := fixture.application.OpenSetup(nil); errorCode(err) != ErrorInvalidArgument {
		t.Fatalf("nil OpenSetup error = %v", err)
	}

	for _, installationID := range []string{
		" padded ", "unsafe/path", "unsafe\\path", "control\n", strings.Repeat("a", maximumInstallationIDBytes+1),
	} {
		if application, err := New(installationID, fixture.progress, fixture.setup, fixture.cancellation); application != nil ||
			errorCode(err) != ErrorInvalidArgument {
			t.Fatalf("invalid installation ID %q = %#v, %v", installationID, application, err)
		}
	}
	if application, err := New(testInstallationID, fixture.progress, valueSetup{}, fixture.cancellation); application == nil || err != nil {
		t.Fatalf("value setup dependency = %#v, %v", application, err)
	}
}

type snapshotSpec struct {
	state    setupprogressapp.State
	action   setupprogressapp.SafeAction
	message  setupprogressapp.MessageKey
	sequence uint64
}

type applicationFixture struct {
	application  *Application
	progress     *setupprogressapp.Application
	binding      setupprogressapp.Binding
	snapshots    *snapshotAuthorityStub
	setup        *setupStub
	cancellation *cancellationStub
}

func newApplicationFixture(t testing.TB, spec snapshotSpec) *applicationFixture {
	t.Helper()
	operationID, err := install.NewOperationID("019f5f20-1234-7abc-8123-0123456789ac")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := install.BindPlan([]byte(`{"schema":1}`))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := setupprogressapp.NewBinding(operationID, plan)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &applicationFixture{binding: binding}
	fixture.snapshots = &snapshotAuthorityStub{}
	fixture.snapshots.current = fixture.snapshot(spec)
	fixture.snapshots.next = fixture.snapshots.current
	fixture.setup = &setupStub{}
	fixture.cancellation = &cancellationStub{snapshots: fixture.snapshots}
	fixture.progress, err = setupprogressapp.NewApplication(binding, fixture.snapshots, decisionAuthorityStub{})
	if err != nil {
		t.Fatal(err)
	}
	fixture.application, err = New(testInstallationID, fixture.progress, fixture.setup, fixture.cancellation)
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (f *applicationFixture) snapshot(spec snapshotSpec) setupprogressapp.Snapshot {
	input := setupprogressapp.SnapshotInput{
		Sequence: spec.sequence, OperationID: f.binding.OperationID(), PlanDigest: f.binding.PlanDigest(),
		State: spec.state, Phase: setupprogressapp.PhaseEnsureContainerRuntime,
		MessageKey: spec.message, SafeAction: spec.action,
		Progress: setupprogressapp.Progress{
			CompletedStages: 1, TotalStages: 14, DownloadedBytes: 128, TotalBytes: 1024,
		},
	}
	if spec.state == setupprogressapp.StateAwaitingConsent {
		input.Consent = &setupprogressapp.ConsentInput{
			TermsTitle: "Runtime terms", TermsURL: "https://example.com/terms",
			TermsDigest: f.binding.PlanDigest().String(), DownloadBytes: 1024,
			ExpandedBytes: 2048, Changes: []string{"Install the certified local runtime"},
		}
	}
	snapshot, err := setupprogressapp.NewSnapshot(input)
	if err != nil {
		panic(err)
	}
	return snapshot
}

type snapshotAuthorityStub struct {
	current setupprogressapp.Snapshot
	next    setupprogressapp.Snapshot
	err     error
}

func (s *snapshotAuthorityStub) CurrentSnapshot(context.Context, setupprogressapp.Binding) (setupprogressapp.Snapshot, error) {
	return s.current, s.err
}

func (s *snapshotAuthorityStub) WaitSnapshotAfter(context.Context, setupprogressapp.Binding, uint64) (setupprogressapp.Snapshot, error) {
	return s.next, s.err
}

type decisionAuthorityStub struct{}

func (decisionAuthorityStub) ApplyDecision(context.Context, setupprogressapp.DecisionCommand) (setupprogressapp.DecisionReceipt, error) {
	return setupprogressapp.DecisionReceipt{}, errors.New("unused")
}

type setupStub struct {
	calls int
	err   error
}

type valueSetup struct{}

func (valueSetup) OpenSetup(context.Context) error { return nil }

func (s *setupStub) OpenSetup(context.Context) error {
	s.calls++
	return s.err
}

type cancellationStub struct {
	snapshots *snapshotAuthorityStub
	after     setupprogressapp.Snapshot
	calls     int
	err       error
}

func (c *cancellationStub) RequestCancellation(context.Context) error {
	c.calls++
	if c.err == nil && c.snapshots != nil && c.after.Sequence() != 0 {
		c.snapshots.current = c.after
	}
	return c.err
}

func errorCode(err error) ErrorCode {
	var applicationError *ApplicationError
	if errors.As(err, &applicationError) {
		return applicationError.Code()
	}
	return ""
}
