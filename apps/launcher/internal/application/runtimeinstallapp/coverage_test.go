package runtimeinstallapp

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF001RuntimeApplicationContractGuardMatrix(t *testing.T) {
	t.Parallel()

	validCompletion := Completion{
		InputDigest: runtimeinstall.Sum([]byte("input")), OutputDigest: runtimeinstall.Sum([]byte("output")),
		ArtifactDigest: runtimeinstall.Sum([]byte("artifact")), Ownership: runtimeinstall.OwnershipReusedExternal,
	}
	for name, completion := range map[string]Completion{
		"input":  {OutputDigest: validCompletion.OutputDigest},
		"output": {InputDigest: validCompletion.InputDigest},
	} {
		if _, err := NewCompletedOutput(completion); err == nil {
			t.Fatalf("NewCompletedOutput() accepted missing %s", name)
		}
	}
	completed, err := NewCompletedOutput(validCompletion)
	if err != nil || !completed.validFor(runtimeinstall.PhaseVerifyRuntimeCapabilities) {
		t.Fatalf("valid completed output = %#v, %v", completed, err)
	}
	missingArtifact, _ := NewCompletedOutput(Completion{
		InputDigest: validCompletion.InputDigest, OutputDigest: validCompletion.OutputDigest,
	})
	if missingArtifact.validFor(runtimeinstall.PhaseVerifyRuntimeArtifact) ||
		missingArtifact.validFor(runtimeinstall.PhaseVerifyRuntimeCapabilities) {
		t.Fatal("incomplete completion evidence passed a trust-sensitive phase")
	}
	for _, outcome := range []Outcome{OutcomeUnknown, OutcomeCompleted, OutcomeRebootRequired, Outcome(255)} {
		if _, err := NewExpectedOutput(outcome); err == nil {
			t.Fatalf("NewExpectedOutput(%d) succeeded", outcome)
		}
	}
	for _, outcome := range []Outcome{
		OutcomeFailedRecoverable, OutcomeAdministratorRequired, OutcomeCancelled,
		OutcomeUnsupportedHost, OutcomeRuntimeConflict,
	} {
		output, err := NewExpectedOutput(outcome)
		if err != nil || !output.validFor(runtimeinstall.PhaseDetectHost) {
			t.Fatalf("NewExpectedOutput(%d) = %#v, %v", outcome, output, err)
		}
	}
	if _, err := NewRebootOutput(runtimeinstall.Hash{}); err == nil {
		t.Fatal("NewRebootOutput() accepted a zero receipt")
	}
	reboot, err := NewRebootOutput(runtimeinstall.Sum([]byte("receipt")))
	if err != nil || !reboot.validFor(runtimeinstall.PhaseInstallPrerequisites) ||
		!reboot.validFor(runtimeinstall.PhaseInstallRuntime) || reboot.validFor(runtimeinstall.PhaseDetectHost) {
		t.Fatalf("reboot output phase policy = %#v, %v", reboot, err)
	}
	if (Output{}).validFor(runtimeinstall.PhaseDetectHost) ||
		(Output{valid: true, outcome: OutcomeUnknown}).validFor(runtimeinstall.PhaseDetectHost) {
		t.Fatal("unconstructed output is valid")
	}

	applicationErr := applicationError(ErrorCodeConflict, true)
	if applicationErr.Code() != ErrorCodeConflict || !applicationErr.Retryable() ||
		applicationErr.Error() != string(ErrorCodeConflict) {
		t.Fatalf("application error projection = %#v", applicationErr)
	}
	if _, ok := (Result{}).CompletionReceipt(); ok {
		t.Fatal("zero result exposes completion authority")
	}
}

func TestPF001RuntimeApplicationClosedStateMappingMatrix(t *testing.T) {
	t.Parallel()

	states := map[OperationStateExpectation]struct{}{
		{runtimeinstall.OperationStateReady, OutcomeCompleted, ErrorCodeNone}:                                               {},
		{runtimeinstall.OperationStateRebootPending, OutcomeRebootRequired, ErrorCodeRebootRequired}:                        {},
		{runtimeinstall.OperationStateFailedRecoverable, OutcomeFailedRecoverable, ErrorCodeInternal}:                       {},
		{runtimeinstall.OperationStatePausedForAdministrator, OutcomeAdministratorRequired, ErrorCodeAdministratorRequired}: {},
		{runtimeinstall.OperationStateCancelled, OutcomeCancelled, ErrorCodeCancelled}:                                      {},
		{runtimeinstall.OperationStateUnsupportedHost, OutcomeUnsupportedHost, ErrorCodeUnsupportedHost}:                    {},
		{runtimeinstall.OperationStateRuntimeConflict, OutcomeRuntimeConflict, ErrorCodeRuntimeConflict}:                    {},
		{runtimeinstall.OperationStateRunning, OutcomeUnknown, ErrorCodeNone}:                                               {},
		{runtimeinstall.OperationStateUnknown, OutcomeUnknown, ErrorCodeNone}:                                               {},
	}
	for expectation := range states {
		if outcomeForState(expectation.state) != expectation.outcome || codeForState(expectation.state) != expectation.code {
			t.Fatalf("state mapping for %s is inconsistent", expectation.state)
		}
	}
	for outcome, state := range map[Outcome]runtimeinstall.OperationState{
		OutcomeFailedRecoverable:     runtimeinstall.OperationStateFailedRecoverable,
		OutcomeAdministratorRequired: runtimeinstall.OperationStatePausedForAdministrator,
		OutcomeCancelled:             runtimeinstall.OperationStateCancelled,
		OutcomeUnsupportedHost:       runtimeinstall.OperationStateUnsupportedHost,
		OutcomeRuntimeConflict:       runtimeinstall.OperationStateRuntimeConflict,
		OutcomeUnknown:               runtimeinstall.OperationStateUnknown,
		OutcomeCompleted:             runtimeinstall.OperationStateUnknown,
		OutcomeRebootRequired:        runtimeinstall.OperationStateUnknown,
		Outcome(255):                 runtimeinstall.OperationStateUnknown,
	} {
		if stateForOutcome(outcome) != state {
			t.Fatalf("outcome mapping for %d is inconsistent", outcome)
		}
	}
}

type OperationStateExpectation struct {
	state   runtimeinstall.OperationState
	outcome Outcome
	code    ErrorCode
}

func TestPF001RuntimeApplicationMapsEveryRepositoryBoundary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		err       error
		want      ErrorCode
		retryable bool
	}{
		{name: "conflict", err: ErrOperationConflict, want: ErrorCodeConflict, retryable: true},
		{name: "integrity", err: ErrOperationIntegrity, want: ErrorCodeIntegrityViolation},
		{name: "cancelled", err: context.Canceled, want: ErrorCodeDeadlineExceeded, retryable: true},
		{name: "deadline", err: context.DeadlineExceeded, want: ErrorCodeDeadlineExceeded, retryable: true},
		{name: "unknown", err: errors.New("private repository path"), want: ErrorCodeInternal},
	}
	if mapRepositoryError(nil) != nil {
		t.Fatal("nil repository error was mapped to a failure")
	}
	for _, test := range tests {
		mapped := mapRepositoryError(test.err)
		var typed *ApplicationError
		if !errors.As(mapped, &typed) || typed.Code() != test.want || typed.Retryable() != test.retryable ||
			typed.Error() != string(test.want) {
			t.Fatalf("mapRepositoryError(%s) = %#v", test.name, mapped)
		}
	}
	if errorCode(errors.New("untyped")) != ErrorCodeInternal ||
		errorCode(applicationError(ErrorCodeCancelled, false)) != ErrorCodeCancelled {
		t.Fatal("errorCode() did not preserve the closed taxonomy")
	}
	if nilInterface(1) || nilInterface(struct{}{}) || !nilInterface(nil) {
		t.Fatal("nilInterface() value detection is inconsistent")
	}
}

func TestPF001RuntimeApplicationRejectsInvalidEntryAndRepositoryResults(t *testing.T) {
	t.Parallel()

	harnessRepository := newMemoryRepository()
	// Parallel subtests share only immutable dependency capabilities. Initialize
	// the ownership repository before they start so dependency construction does
	// not race on lazy fixture state.
	harness := &phaseHarness{
		repository: harnessRepository,
		ownership:  &memoryOwnershipRepository{},
	}
	tests := []struct {
		name    string
		command Command
		load    func(context.Context, string) (*runtimeinstall.Operation, error)
		want    ErrorCode
	}{
		{name: "empty plan", command: Command{OperationID: "operation"}, want: ErrorCodeInvalidArgument},
		{name: "invalid operation", command: Command{OperationID: " operation", CanonicalPlan: testCanonicalRuntimePlan()}, want: ErrorCodeInvalidArgument},
		{name: "nil loaded operation", command: Command{OperationID: "operation", CanonicalPlan: testCanonicalRuntimePlan()}, load: func(context.Context, string) (*runtimeinstall.Operation, error) { return nil, nil }, want: ErrorCodeInternal},
		{name: "load conflict", command: Command{OperationID: "operation", CanonicalPlan: testCanonicalRuntimePlan()}, load: func(context.Context, string) (*runtimeinstall.Operation, error) { return nil, ErrOperationConflict }, want: ErrorCodeConflict},
		{name: "load integrity", command: Command{OperationID: "operation", CanonicalPlan: testCanonicalRuntimePlan()}, load: func(context.Context, string) (*runtimeinstall.Operation, error) { return nil, ErrOperationIntegrity }, want: ErrorCodeIntegrityViolation},
		{name: "load deadline", command: Command{OperationID: "operation", CanonicalPlan: testCanonicalRuntimePlan()}, load: func(context.Context, string) (*runtimeinstall.Operation, error) { return nil, context.DeadlineExceeded }, want: ErrorCodeDeadlineExceeded},
		{name: "load unknown", command: Command{OperationID: "operation", CanonicalPlan: testCanonicalRuntimePlan()}, load: func(context.Context, string) (*runtimeinstall.Operation, error) {
			return nil, errors.New("private load path")
		}, want: ErrorCodeInternal},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			repository := &operationRepositoryStub{load: test.load}
			if repository.load == nil {
				repository.load = func(context.Context, string) (*runtimeinstall.Operation, error) { return nil, ErrOperationNotFound }
			}
			application, err := New(testDependencies(repository, harness))
			if err != nil {
				t.Fatal(err)
			}
			_, actual := application.Ensure(context.Background(), test.command)
			if errorCode(actual) != test.want {
				t.Fatalf("Ensure() error = %#v, want %s", actual, test.want)
			}
		})
	}
}

func TestPF001RuntimeApplicationResumesAdministratorPause(t *testing.T) {
	t.Parallel()

	repository := newMemoryRepository()
	harness := &phaseHarness{repository: repository, outcomeAt: runtimeinstall.PhaseDetectHost, outcome: OutcomeAdministratorRequired}
	application := newTestApplication(t, repository, harness)
	first, err := application.Ensure(context.Background(), testCommand())
	if err != nil || first.State != runtimeinstall.OperationStatePausedForAdministrator {
		t.Fatalf("first Ensure() = %#v, %v", first, err)
	}
	harness.outcomeAt = runtimeinstall.PhaseUnknown
	second, err := application.Ensure(context.Background(), testCommand())
	if err != nil || second.State != runtimeinstall.OperationStateReady || second.Attempt != 1 {
		t.Fatalf("resumed Ensure() = %#v, %v", second, err)
	}
}

type operationRepositoryStub struct {
	load func(context.Context, string) (*runtimeinstall.Operation, error)
	save func(context.Context, runtimeinstall.OperationSnapshot) error
}

func (s *operationRepositoryStub) Load(ctx context.Context, id string) (*runtimeinstall.Operation, error) {
	return s.load(ctx, id)
}

func (s *operationRepositoryStub) Save(ctx context.Context, snapshot runtimeinstall.OperationSnapshot) error {
	if s.save != nil {
		return s.save(ctx, snapshot)
	}
	return nil
}
