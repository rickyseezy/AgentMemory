package installapp

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001InstallApplicationRejectsInvalidCommandsBeforeAcquiringLock(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		command InstallCommand
	}{
		{name: "missing operation ID", command: InstallCommand{CanonicalPlan: []byte("plan")}},
		{name: "missing plan", command: InstallCommand{OperationID: "operation"}},
		{name: "zero receipt", command: InstallCommand{
			OperationID: "operation", CanonicalPlan: []byte("plan"), ResumeReceipt: new(install.Digest),
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			lock := &memoryLockPort{}
			capabilities := newPhaseCapabilities()
			deps := dependencies(newMemoryOperationRepository(), capabilities)
			deps.InstallationLock = lock
			application, err := NewInstallApplication(deps)
			if err != nil {
				t.Fatalf("NewInstallApplication() error = %v", err)
			}

			_, err = application.Install(context.Background(), test.command)
			assertApplicationErrorCode(t, err, ErrorCodeValidation)
			if lock.acquisitions != 0 {
				t.Fatalf("lock acquisitions = %d, want zero", lock.acquisitions)
			}
		})
	}
}

func TestPF001InstallApplicationSanitizesInfrastructureBoundaryFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		prepare  func(*Dependencies, *memoryOperationRepository)
		wantCode ErrorCode
	}{
		{
			name: "lock acquisition",
			prepare: func(deps *Dependencies, _ *memoryOperationRepository) {
				deps.InstallationLock = failingLockPort{acquireError: errors.New("raw lock failure")}
			},
			wantCode: ErrorCodeDependencyUnavailable,
		},
		{
			name: "nil lock",
			prepare: func(deps *Dependencies, _ *memoryOperationRepository) {
				deps.InstallationLock = failingLockPort{returnNil: true}
			},
			wantCode: ErrorCodeInternal,
		},
		{
			name: "repository load",
			prepare: func(_ *Dependencies, repository *memoryOperationRepository) {
				repository.loadError = errors.New("raw journal path")
			},
			wantCode: ErrorCodeDependencyUnavailable,
		},
		{
			name: "repository integrity",
			prepare: func(_ *Dependencies, repository *memoryOperationRepository) {
				repository.loadError = errors.Join(
					ErrOperationIntegrity,
					errors.New("authenticated snapshot payload was invalid"),
				)
			},
			wantCode: ErrorCodeIntegrityViolation,
		},
		{
			name: "repository returned nil",
			prepare: func(_ *Dependencies, repository *memoryOperationRepository) {
				repository.returnNil = true
			},
			wantCode: ErrorCodeInternal,
		},
		{
			name: "lock release",
			prepare: func(deps *Dependencies, _ *memoryOperationRepository) {
				deps.InstallationLock = failingLockPort{releaseError: errors.New("raw release failure")}
			},
			wantCode: ErrorCodeDependencyUnavailable,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			repository := newMemoryOperationRepository()
			capabilities := newPhaseCapabilities()
			deps := dependencies(repository, capabilities)
			test.prepare(&deps, repository)
			application, err := NewInstallApplication(deps)
			if err != nil {
				t.Fatalf("NewInstallApplication() error = %v", err)
			}

			_, err = application.Install(context.Background(), command(testOperationID("infra-"+test.name), "plan"))
			assertApplicationErrorCode(t, err, test.wantCode)
			if test.wantCode == ErrorCodeIntegrityViolation {
				var applicationError *ApplicationError
				if !errors.As(err, &applicationError) || applicationError.Retryable() {
					t.Fatalf("integrity error = %v, want non-retryable ApplicationError", err)
				}
			}
			if err.Error() == "raw lock failure" || err.Error() == "raw journal path" || err.Error() == "raw release failure" {
				t.Fatalf("infrastructure details escaped: %v", err)
			}
		})
	}
}

func TestPF001InstallApplicationReportsPostSideEffectPersistenceFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		configure func(*phaseCapabilities)
	}{
		{
			name:      "after completed evidence",
			configure: func(*phaseCapabilities) {},
		},
		{
			name: "after declared recoverable outcome",
			configure: func(capabilities *phaseCapabilities) {
				capabilities.outputs[install.PhaseVerifyHost] = mustExpectedOutput(t, PhaseOutcomeFailedRecoverable)
			},
		},
		{
			name: "after unexpected failure transition",
			configure: func(capabilities *phaseCapabilities) {
				capabilities.errors[install.PhaseVerifyHost] = errors.New("adapter failed")
			},
		},
		{
			name: "after cancellation transition",
			configure: func(capabilities *phaseCapabilities) {
				capabilities.errors[install.PhaseVerifyHost] = context.Canceled
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			repository := newMemoryOperationRepository()
			repository.failSaveAt = 3
			capabilities := newPhaseCapabilities()
			test.configure(capabilities)
			application := mustApplication(t, repository, capabilities)

			_, err := application.Install(context.Background(), command(testOperationID("post-save-"+test.name), "plan"))
			assertApplicationErrorCode(t, err, ErrorCodeDependencyUnavailable)
			assertPhasesEqual(t, capabilities.calls, []install.Phase{install.PhaseVerifyHost})
		})
	}
}

func TestPF001InstallApplicationRejectsWrongResumeReceiptWithoutSideEffects(t *testing.T) {
	t.Parallel()

	repository := newMemoryOperationRepository()
	capabilities := newPhaseCapabilities()
	receipt := install.DigestBytes([]byte("right receipt"))
	capabilities.outputs[install.PhaseEnsureContainerRuntime] = mustRebootOutput(
		t, receipt, mustSafeAction(t, "reboot.then.resume"),
	)
	application := mustApplication(t, repository, capabilities)
	installCommand := command("wrong-receipt", "plan")
	if _, err := application.Install(context.Background(), installCommand); err != nil {
		t.Fatalf("first Install() error = %v", err)
	}
	callsBefore := len(capabilities.calls)
	savesBefore := repository.saves
	wrongReceipt := install.DigestBytes([]byte("wrong receipt"))
	installCommand.ResumeReceipt = &wrongReceipt

	_, err := application.Install(context.Background(), installCommand)
	assertApplicationErrorCode(t, err, ErrorCodeIntegrityViolation)
	if len(capabilities.calls) != callsBefore || repository.saves != savesBefore {
		t.Fatal("wrong receipt performed or persisted work")
	}
}

func TestPF001InstallApplicationPersistsEachResumeTransitionBeforeWork(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		firstPort func(*phaseCapabilities)
		resume    func(*InstallCommand)
	}{
		{
			name: "recoverable retry",
			firstPort: func(capabilities *phaseCapabilities) {
				capabilities.errors[install.PhaseVerifyHost] = errors.New("interrupted")
			},
			resume: func(*InstallCommand) {},
		},
		{
			name: "verified reboot resume",
			firstPort: func(capabilities *phaseCapabilities) {
				receipt := install.DigestBytes([]byte("receipt"))
				capabilities.outputs[install.PhaseEnsureContainerRuntime] = mustRebootOutput(
					t, receipt, mustSafeAction(t, "reboot.then.resume"),
				)
			},
			resume: func(command *InstallCommand) {
				receipt := install.DigestBytes([]byte("receipt"))
				command.ResumeReceipt = &receipt
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			repository := newMemoryOperationRepository()
			capabilities := newPhaseCapabilities()
			test.firstPort(capabilities)
			application := mustApplication(t, repository, capabilities)
			installCommand := command(testOperationID("resume-save-"+test.name), "plan")
			_, _ = application.Install(context.Background(), installCommand)

			delete(capabilities.errors, install.PhaseVerifyHost)
			delete(capabilities.outputs, install.PhaseEnsureContainerRuntime)
			test.resume(&installCommand)
			repository.failSaveAt = repository.saves + 1
			callsBefore := len(capabilities.calls)

			_, err := application.Install(context.Background(), installCommand)
			assertApplicationErrorCode(t, err, ErrorCodeDependencyUnavailable)
			if len(capabilities.calls) != callsBefore {
				t.Fatal("phase ran before resume transition was durable")
			}
		})
	}
}

func TestPF001InstallApplicationContinuesAnExistingRunningOperation(t *testing.T) {
	t.Parallel()

	repository := newMemoryOperationRepository()
	operationID, _ := install.NewOperationID("existing-running")
	plan, _ := install.BindPlan([]byte("plan"))
	operation, _ := install.NewOperation(operationID, plan)
	if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatalf("seed Save() error = %v", err)
	}
	capabilities := newPhaseCapabilities()
	application := mustApplication(t, repository, capabilities)

	result, err := application.Install(context.Background(), command("existing-running", "plan"))
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if result.State != install.StateReady {
		t.Fatalf("state = %s, want Ready", result.State)
	}
}

func TestPF001PhaseRequestIsImmutableByCopyAndPlanBound(t *testing.T) {
	t.Parallel()

	operationID, _ := install.NewOperationID("request")
	plan, _ := install.BindPlan([]byte("plan"))
	operation, _ := install.NewOperation(operationID, plan)
	originalPlan := []byte("canonical plan")
	request := newPhaseRequest(operation, originalPlan)
	originalPlan[0] = 'X'

	if request.OperationID() != operationID || !request.PlanDigest().Equal(plan) || request.Attempt() != 1 {
		t.Fatal("phase request did not preserve aggregate cursor")
	}
	firstCopy := request.CanonicalPlan()
	firstCopy[0] = 'Y'
	if string(request.CanonicalPlan()) != "canonical plan" {
		t.Fatal("CanonicalPlan() exposed mutable storage")
	}
	if _, ok := request.ResumeReceipt(); ok {
		t.Fatal("ordinary phase request exposed a reboot receipt")
	}
	receipt := install.DigestBytes([]byte("verified runtime receipt"))
	resumed := newRuntimeResumePhaseRequest(operation, []byte("canonical plan"), receipt)
	actualReceipt, ok := resumed.ResumeReceipt()
	if !ok || !actualReceipt.Equal(receipt) {
		t.Fatal("resumed runtime phase request lost its verified receipt")
	}
	if _, err := NewPhaseRequestForIntegration(operationID, plan, 1, []byte("plan"), install.Digest{}); err == nil {
		t.Fatal("integration request accepted a zero resume receipt")
	}
	if _, err := NewPhaseRequestForIntegration(operationID, plan, 1, []byte("plan"), receipt, receipt); err == nil {
		t.Fatal("integration request accepted multiple resume receipts")
	}
}

func TestPF001PhaseOutcomeStringsAreStable(t *testing.T) {
	t.Parallel()

	tests := map[PhaseOutcome]string{
		PhaseOutcomeUnknown:               "unknown",
		PhaseOutcomeCompleted:             "completed",
		PhaseOutcomeFailedRecoverable:     "failed_recoverable",
		PhaseOutcomeAdministratorRequired: "administrator_required",
		PhaseOutcomeCancelled:             "cancelled",
		PhaseOutcomeUnsupportedHost:       "unsupported_host",
		PhaseOutcomeRuntimeConflict:       "runtime_conflict",
		PhaseOutcomeRebootRequired:        "reboot_required",
		PhaseOutcome(255):                 "unknown",
	}
	for outcome, expected := range tests {
		if actual := outcome.String(); actual != expected {
			t.Fatalf("PhaseOutcome(%d).String() = %q, want %q", outcome, actual, expected)
		}
	}
}

func TestPF001PhaseOutputValidationDecisionTable(t *testing.T) {
	t.Parallel()

	digest := install.DigestBytes([]byte("digest"))
	boundary := mustBoundary(t, "rollback.phase")
	action := mustSafeAction(t, "retry.phase")
	base := CompletionOutput{
		InputDigest:            digest,
		OutputDigest:           digest,
		VerifiedArtifactDigest: digest,
		RuntimeOwnership:       install.RuntimeOwnershipUndetermined,
		CompensationBoundary:   boundary,
		NextSafeAction:         action,
	}

	tests := []struct {
		name  string
		input CompletionOutput
	}{
		{name: "zero output", input: withCompletion(base, func(input *CompletionOutput) { input.OutputDigest = install.Digest{} })},
		{name: "invalid ownership", input: withCompletion(base, func(input *CompletionOutput) { input.RuntimeOwnership = install.RuntimeOwnershipUnknown })},
		{name: "missing boundary", input: withCompletion(base, func(input *CompletionOutput) { input.CompensationBoundary = install.CompensationBoundary{} })},
		{name: "missing action", input: withCompletion(base, func(input *CompletionOutput) { input.NextSafeAction = install.SafeAction{} })},
	}
	for _, test := range tests {
		if _, err := NewCompletedPhaseOutput(test.input); err == nil {
			t.Fatalf("%s: constructor accepted invalid completion", test.name)
		}
	}
	withoutArtifact := base
	withoutArtifact.VerifiedArtifactDigest = install.Digest{}
	if _, err := NewCompletedPhaseOutput(withoutArtifact); err != nil {
		t.Fatalf("constructor rejected a valid non-artifact completion: %v", err)
	}

	fact, _ := install.NewNonSecretFact("phase", "verified")
	facts := []install.NonSecretFact{fact}
	base.Facts = facts
	output, err := NewCompletedPhaseOutput(base)
	if err != nil {
		t.Fatalf("valid completion error = %v", err)
	}
	facts[0] = install.NonSecretFact{}
	if len(output.completion.Facts) != 1 || output.completion.Facts[0].Name() != "phase" {
		t.Fatal("completion constructor retained caller-owned facts slice")
	}

	if output.validFor(install.PhaseVerifyHost) == false {
		t.Fatal("valid completion was rejected")
	}
	if (PhaseOutput{}).validFor(install.PhaseVerifyHost) {
		t.Fatal("zero output was accepted")
	}
	reboot, _ := NewRebootRequiredPhaseOutput(digest, action)
	if reboot.validFor(install.PhaseVerifyHost) {
		t.Fatal("reboot output was accepted outside EnsureContainerRuntime")
	}
	if _, err := NewRebootRequiredPhaseOutput(digest, install.SafeAction{}); err == nil {
		t.Fatal("reboot output accepted a missing action")
	}
	if _, err := NewExpectedPhaseOutput(PhaseOutcomeUnknown, action); err == nil {
		t.Fatal("expected output accepted unknown outcome")
	}
	if _, err := NewExpectedPhaseOutput(PhaseOutcomeFailedRecoverable, install.SafeAction{}); err == nil {
		t.Fatal("expected output accepted a missing action")
	}
}

func TestPF001PhaseOutputProjectsOnlyConstructorVerifiedEvidence(t *testing.T) {
	t.Parallel()
	completed := completedOutputForPhase(install.PhaseVerifyRelease)
	if completed.Outcome() != PhaseOutcomeCompleted || completed.InputDigest().IsZero() ||
		completed.OutputDigest().IsZero() || completed.VerifiedArtifactDigest().IsZero() ||
		!completed.RuntimeOwnership().Valid() || completed.NextSafeAction() == "" {
		t.Fatalf("completed output=%+v", completed)
	}
	receipt := install.DigestBytes([]byte("reboot receipt"))
	reboot := mustRebootOutput(t, receipt, mustSafeAction(t, "restart.host"))
	projected, present := reboot.ResumeReceipt()
	if reboot.Outcome() != PhaseOutcomeRebootRequired || !present || !projected.Equal(receipt) ||
		reboot.NextSafeAction() != "restart.host" {
		t.Fatalf("reboot output=%+v receipt=%+v present=%t", reboot, projected, present)
	}
	if _, present := completed.ResumeReceipt(); present {
		t.Fatal("completed output exposed a reboot receipt")
	}
}

func TestPF001PhaseOutputEnforcesPhaseSpecificProofPolicy(t *testing.T) {
	t.Parallel()

	digest := install.DigestBytes([]byte("digest"))
	base := CompletionOutput{
		InputDigest:            digest,
		OutputDigest:           digest,
		VerifiedArtifactDigest: digest,
		RuntimeOwnership:       install.RuntimeOwnershipReusedExternal,
		CompensationBoundary:   mustBoundary(t, "rollback.phase"),
		NextSafeAction:         mustSafeAction(t, "continue.phase"),
	}

	tests := []struct {
		name  string
		phase install.Phase
		input CompletionOutput
		valid bool
	}{
		{
			name:  "host starts undetermined",
			phase: install.PhaseVerifyHost,
			input: withCompletion(base, func(input *CompletionOutput) {
				input.RuntimeOwnership = install.RuntimeOwnershipUndetermined
			}),
			valid: true,
		},
		{name: "host rejects resolved ownership", phase: install.PhaseVerifyHost, input: base},
		{name: "runtime accepts resolved ownership", phase: install.PhaseEnsureContainerRuntime, input: base, valid: true},
		{
			name:  "runtime rejects missing verified installer artifact",
			phase: install.PhaseEnsureContainerRuntime,
			input: withCompletion(base, func(input *CompletionOutput) {
				input.VerifiedArtifactDigest = install.Digest{}
			}),
		},
		{
			name:  "runtime rejects undetermined ownership",
			phase: install.PhaseEnsureContainerRuntime,
			input: withCompletion(base, func(input *CompletionOutput) {
				input.RuntimeOwnership = install.RuntimeOwnershipUndetermined
			}),
		},
		{
			name:  "release rejects missing artifact proof",
			phase: install.PhaseVerifyRelease,
			input: withCompletion(base, func(input *CompletionOutput) {
				input.VerifiedArtifactDigest = install.Digest{}
			}),
		},
		{name: "release accepts artifact proof", phase: install.PhaseVerifyRelease, input: base, valid: true},
		{
			name:  "compose rejects missing artifact proof",
			phase: install.PhaseEnsureComposeBundle,
			input: withCompletion(base, func(input *CompletionOutput) {
				input.VerifiedArtifactDigest = install.Digest{}
			}),
		},
		{name: "compose accepts artifact proof", phase: install.PhaseEnsureComposeBundle, input: base, valid: true},
		{name: "later phase carries resolved ownership", phase: install.PhaseVerifyReadiness, input: base, valid: true},
		{
			name:  "later phase rejects unresolved ownership",
			phase: install.PhaseVerifyReadiness,
			input: withCompletion(base, func(input *CompletionOutput) {
				input.RuntimeOwnership = install.RuntimeOwnershipNotApplicable
			}),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			output, err := NewCompletedPhaseOutput(test.input)
			if err != nil {
				t.Fatalf("NewCompletedPhaseOutput() error = %v", err)
			}
			if got := output.validFor(test.phase); got != test.valid {
				t.Fatalf("validFor(%s) = %t, want %t", test.phase, got, test.valid)
			}
		})
	}
}

func TestPF001ApplicationErrorMappingDecisionTable(t *testing.T) {
	t.Parallel()

	invalidIDError := func() error {
		_, err := install.NewOperationID("")
		return err
	}()
	integrityError := func() error {
		_, err := install.RestoreOperation(install.RestoreInput{})
		return err
	}()
	conflictError := func() error {
		id, _ := install.NewOperationID("conflict")
		plan, _ := install.BindPlan([]byte("plan"))
		operation, _ := install.NewOperation(id, plan)
		_ = operation.Cancel(plan)
		_, err := operation.Resume(plan)
		return err
	}()

	tests := []struct {
		name string
		err  error
		code ErrorCode
	}{
		{name: "uncoded", err: errors.New("raw"), code: ErrorCodeIntegrityViolation},
		{name: "validation", err: invalidIDError, code: ErrorCodeValidation},
		{name: "integrity", err: integrityError, code: ErrorCodeIntegrityViolation},
		{name: "conflict", err: conflictError, code: ErrorCodeConflict},
		{name: "unknown coded", err: fakeCodedDomainError{}, code: ErrorCodeIntegrityViolation},
	}
	for _, test := range tests {
		mapped := mapDomainError(test.err)
		if mapped.Code() != test.code {
			t.Fatalf("%s: code = %s, want %s", test.name, mapped.Code(), test.code)
		}
		_ = mapped.Retryable()
	}
}

func TestPF001ApplicationErrorCodesUseCanonicalTaxonomy(t *testing.T) {
	t.Parallel()

	expected := map[ErrorCode]string{
		ErrorCodeValidation:            "AM_VALIDATION",
		ErrorCodeIdempotencyConflict:   "AM_IDEMPOTENCY_CONFLICT",
		ErrorCodeIntegrityViolation:    "AM_INTEGRITY_VIOLATION",
		ErrorCodeConflict:              "AM_CONFLICT",
		ErrorCodeDependencyUnavailable: "AM_DEPENDENCY_UNAVAILABLE",
		ErrorCodeDeadlineExceeded:      "AM_DEADLINE_EXCEEDED",
		ErrorCodeInternal:              "AM_INTERNAL",
		ErrorCodeSetupAdminRequired:    "AM_SETUP_ADMIN_REQUIRED",
		ErrorCodeUnsupportedHost:       "AM_UNSUPPORTED_HOST",
		ErrorCodeRuntimeConflict:       "AM_RUNTIME_CONFLICT",
		ErrorCodeRebootRequired:        "AM_REBOOT_REQUIRED",
	}
	for code, canonical := range expected {
		if string(code) != canonical {
			t.Fatalf("error code %q = %q, want canonical %q", code, code, canonical)
		}
	}
}

func TestPF001DefensiveApplicationBranchesRejectInvalidState(t *testing.T) {
	t.Parallel()

	repository := newMemoryOperationRepository()
	capabilities := newPhaseCapabilities()
	application := mustApplication(t, repository, capabilities)
	if _, err := application.dispatch(context.Background(), install.PhaseUnknown, PhaseRequest{}); err == nil {
		t.Fatal("dispatch accepted unknown phase")
	}

	id, _ := install.NewOperationID("terminal")
	plan, _ := install.BindPlan([]byte("plan"))
	outputs := []PhaseOutput{
		completedOutputForPhase(install.PhaseVerifyHost),
		mustExpectedOutput(t, PhaseOutcomeFailedRecoverable),
		mustExpectedOutput(t, PhaseOutcomeAdministratorRequired),
		mustExpectedOutput(t, PhaseOutcomeCancelled),
		mustExpectedOutput(t, PhaseOutcomeUnsupportedHost),
		mustExpectedOutput(t, PhaseOutcomeRuntimeConflict),
	}
	for _, output := range outputs {
		terminal, _ := install.NewOperation(id, plan)
		if output.outcome == PhaseOutcomeUnsupportedHost {
			_ = terminal.MarkRuntimeConflict(plan)
		} else {
			_ = terminal.MarkUnsupportedHost(plan)
		}
		if _, _, err := application.applyOutput(terminal, output); err == nil {
			t.Fatalf("applyOutput accepted %s from terminal state", output.outcome)
		}
	}
	terminal, _ := install.NewOperation(id, plan)
	_ = terminal.MarkUnsupportedHost(plan)
	if _, _, err := application.applyOutput(terminal, PhaseOutput{}); err == nil {
		t.Fatal("applyOutput accepted unknown output")
	}
	reboot, _ := NewRebootRequiredPhaseOutput(
		install.DigestBytes([]byte("receipt")), mustSafeAction(t, "reboot.then.resume"),
	)
	if _, _, err := application.applyOutput(terminal, reboot); err == nil {
		t.Fatal("applyOutput accepted reboot outside runtime phase")
	}

	if _, err := application.failUnexpected(context.Background(), terminal, plan); err == nil {
		t.Fatal("failUnexpected accepted terminal operation")
	}
	if isNil(42) {
		t.Fatal("isNil considered a scalar nil")
	}
}

func withCompletion(input CompletionOutput, mutate func(*CompletionOutput)) CompletionOutput {
	mutate(&input)
	return input
}

func testOperationID(value string) string {
	return strings.ReplaceAll(value, " ", "-")
}

type failingLockPort struct {
	acquireError error
	releaseError error
	returnNil    bool
}

func (p failingLockPort) Acquire(context.Context) (InstallationLock, error) {
	if p.acquireError != nil {
		return nil, p.acquireError
	}
	if p.returnNil {
		return nil, nil
	}
	return failingLock{releaseError: p.releaseError}, nil
}

type failingLock struct {
	releaseError error
}

func (l failingLock) Release(context.Context) error { return l.releaseError }

type fakeCodedDomainError struct{}

func (fakeCodedDomainError) Error() string           { return "unknown coded domain error" }
func (fakeCodedDomainError) Code() install.ErrorCode { return install.ErrorCode("unknown_for_test") }
func (fakeCodedDomainError) Retryable() bool         { return false }

func TestPF001TypedNilDependencyIsRejected(t *testing.T) {
	t.Parallel()

	capabilities := newPhaseCapabilities()
	deps := dependencies(newMemoryOperationRepository(), capabilities)
	var typedNil *memoryOperationRepository
	deps.Operations = typedNil
	application, err := NewInstallApplication(deps)
	if err == nil || application != nil {
		t.Fatalf("typed nil constructor result = (%v, %v), want nil/error", application, err)
	}

	if reflect.TypeOf(deps.Operations).Kind() != reflect.Pointer {
		t.Fatal("test precondition: dependency was not a typed pointer")
	}
}
