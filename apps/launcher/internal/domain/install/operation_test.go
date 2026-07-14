package install

import (
	"errors"
	"fmt"
	"testing"
)

func TestPF001OperationCompletesOnlyTheExactVerifiedSequence(t *testing.T) {
	operation, plan := newTestOperation(t)
	phases := OrderedPhases()

	for index, phase := range phases {
		if operation.State() == StateReady {
			t.Fatalf("Ready was reached before phase %s", phase)
		}
		if operation.CurrentPhase() != phase {
			t.Fatalf("phase %d: got %s, want %s", index, operation.CurrentPhase(), phase)
		}
		if err := operation.CompleteStep(testEvidence(t, phase, operation.Attempt(), plan, false)); err != nil {
			t.Fatalf("complete %s: %v", phase, err)
		}
	}

	if operation.State() != StateReady {
		t.Fatalf("state = %s, want Ready", operation.State())
	}
	if _, exists := operation.FirstUnverified(); exists {
		t.Fatal("Ready operation reports an unverified phase")
	}
	if got := len(operation.CompletedEvidence()); got != len(phases) {
		t.Fatalf("completed evidence = %d, want %d", got, len(phases))
	}
}

func TestPF001OperationRejectsSkippedPhase(t *testing.T) {
	operation, plan := newTestOperation(t)
	evidence := testEvidence(t, PhaseVerifyRelease, 1, plan, true)

	err := operation.CompleteStep(evidence)

	var transition *TransitionError
	if !errors.As(err, &transition) {
		t.Fatalf("error = %T %v, want TransitionError", err, err)
	}
	if transition.Code() != ErrorCodeConflict {
		t.Fatalf("code = %s, want %s", transition.Code(), ErrorCodeConflict)
	}
	if operation.CurrentPhase() != PhaseVerifyHost || operation.State() != StateRunning || operation.AggregateVersion() != 0 {
		t.Fatal("rejected transition changed the operation")
	}
}

func TestPF001OperationAcceptsIdenticalEvidenceReplay(t *testing.T) {
	operation, plan := newTestOperation(t)
	evidence := testEvidence(t, PhaseVerifyHost, 1, plan, false)
	initialVersion := operation.AggregateVersion()

	if err := operation.CompleteStep(evidence); err != nil {
		t.Fatal(err)
	}
	completedVersion := operation.AggregateVersion()
	if err := operation.CompleteStep(evidence); err != nil {
		t.Fatalf("identical replay: %v", err)
	}

	if got := len(operation.CompletedEvidence()); got != 1 {
		t.Fatalf("completed evidence = %d, want 1", got)
	}
	if operation.CurrentPhase() != PhaseEnsureContainerRuntime {
		t.Fatalf("current phase = %s", operation.CurrentPhase())
	}
	if completedVersion != initialVersion+1 || operation.AggregateVersion() != completedVersion {
		t.Fatalf(
			"aggregate versions = initial %d, completed %d, replayed %d",
			initialVersion,
			completedVersion,
			operation.AggregateVersion(),
		)
	}
}

func TestPF001AggregateVersionAdvancesExactlyOncePerMutation(t *testing.T) {
	operation, plan := newTestOperation(t)
	if got := operation.AggregateVersion(); got != 0 {
		t.Fatalf("new operation aggregate version = %d, want 0", got)
	}

	if err := operation.FailRecoverable(plan); err != nil {
		t.Fatal(err)
	}
	if got := operation.AggregateVersion(); got != 1 {
		t.Fatalf("failed aggregate version = %d, want 1", got)
	}
	if err := operation.FailRecoverable(plan); err != nil {
		t.Fatal(err)
	}
	if got := operation.AggregateVersion(); got != 1 {
		t.Fatalf("idempotent failure aggregate version = %d, want 1", got)
	}

	if _, err := operation.Resume(plan); err != nil {
		t.Fatal(err)
	}
	if got := operation.AggregateVersion(); got != 2 {
		t.Fatalf("resumed aggregate version = %d, want 2", got)
	}
	if _, err := operation.Resume(plan); err != nil {
		t.Fatal(err)
	}
	if got := operation.AggregateVersion(); got != 2 {
		t.Fatalf("idempotent running resume aggregate version = %d, want 2", got)
	}
}

func TestPF001RestoreRejectsAggregateVersionOlderThanEvidence(t *testing.T) {
	operation, plan := newTestOperation(t)
	if err := operation.CompleteStep(testEvidence(t, PhaseVerifyHost, 1, plan, false)); err != nil {
		t.Fatal(err)
	}
	snapshot := operation.Snapshot()

	_, err := RestoreOperation(RestoreInput{
		OperationID:      snapshot.OperationID(),
		PlanDigest:       snapshot.PlanDigest(),
		AggregateVersion: 0,
		State:            snapshot.State(),
		CurrentPhase:     snapshot.CurrentPhase(),
		Attempt:          snapshot.Attempt(),
		Completed:        snapshot.CompletedEvidence(),
	})
	assertErrorCode(t, err, ErrorCodeIntegrityViolation)
}

func TestPF001RestoreRejectsRuntimeCompletionWithoutVerifiedInstallerArtifact(t *testing.T) {
	operation, plan := newTestOperation(t)
	if err := operation.CompleteStep(testEvidence(t, PhaseVerifyHost, 1, plan, false)); err != nil {
		t.Fatal(err)
	}
	if err := operation.CompleteStep(testEvidence(t, PhaseEnsureContainerRuntime, 1, plan, true)); err != nil {
		t.Fatal(err)
	}
	snapshot := operation.Snapshot()
	completed := snapshot.CompletedEvidence()
	completed[1].verifiedArtifactDigest = Digest{}
	completed[1].fingerprint = completed[1].calculateFingerprint()

	_, err := RestoreOperation(RestoreInput{
		OperationID:      snapshot.OperationID(),
		PlanDigest:       snapshot.PlanDigest(),
		AggregateVersion: snapshot.AggregateVersion(),
		State:            snapshot.State(),
		CurrentPhase:     snapshot.CurrentPhase(),
		Attempt:          snapshot.Attempt(),
		Completed:        completed,
	})
	assertErrorCode(t, err, ErrorCodeIntegrityViolation)
}

func TestPF001RestoreAllowsVersionZeroOnlyForPristineOperation(t *testing.T) {
	operation, plan := newTestOperation(t)
	tests := []RestoreInput{
		{
			OperationID: operation.ID(), PlanDigest: plan, AggregateVersion: 0,
			State: StateFailedRecoverable, CurrentPhase: PhaseVerifyHost, Attempt: 1,
		},
		{
			OperationID: operation.ID(), PlanDigest: plan, AggregateVersion: 0,
			State: StateRunning, CurrentPhase: PhaseVerifyHost, Attempt: 2,
		},
	}
	for _, input := range tests {
		_, err := RestoreOperation(input)
		assertErrorCode(t, err, ErrorCodeIntegrityViolation)
	}

	pristine := operation.Snapshot()
	_, err := RestoreOperation(RestoreInput{
		OperationID:      pristine.OperationID(),
		PlanDigest:       pristine.PlanDigest(),
		AggregateVersion: pristine.AggregateVersion(),
		State:            pristine.State(),
		CurrentPhase:     pristine.CurrentPhase(),
		Attempt:          pristine.Attempt(),
		Completed:        pristine.CompletedEvidence(),
	})
	if err != nil {
		t.Fatalf("restore pristine operation: %v", err)
	}
}

func TestPF001OperationRejectsConflictingEvidenceReplay(t *testing.T) {
	operation, plan := newTestOperation(t)
	first := testEvidence(t, PhaseVerifyHost, 1, plan, false)
	second := testEvidence(t, PhaseVerifyHost, 1, plan, false)
	second.outputDigest = DigestBytes([]byte("contradictory output"))
	second.fingerprint = second.calculateFingerprint()

	if err := operation.CompleteStep(first); err != nil {
		t.Fatal(err)
	}
	err := operation.CompleteStep(second)

	assertErrorCode(t, err, ErrorCodeIntegrityViolation)
	if got := len(operation.CompletedEvidence()); got != 1 {
		t.Fatalf("completed evidence = %d, want 1", got)
	}
	if got := operation.AggregateVersion(); got != 1 {
		t.Fatalf("conflicting replay aggregate version = %d, want 1", got)
	}
}

func TestPF001OperationRejectsDifferentPlanWithoutMutation(t *testing.T) {
	operation, originalPlan := newTestOperation(t)
	differentPlan := mustPlan(t, "different-plan")
	evidence := testEvidence(t, PhaseVerifyHost, 1, differentPlan, false)

	err := operation.CompleteStep(evidence)

	var binding *PlanBindingError
	if !errors.As(err, &binding) {
		t.Fatalf("error = %T %v, want PlanBindingError", err, err)
	}
	if binding.Code() != ErrorCodeIdempotencyConflict || !binding.Expected().Equal(originalPlan) || !binding.Actual().Equal(differentPlan) {
		t.Fatal("plan binding error did not retain typed digest context")
	}
	if operation.CurrentPhase() != PhaseVerifyHost || len(operation.CompletedEvidence()) != 0 {
		t.Fatal("plan mismatch changed the operation")
	}
}

func TestPF001RecoverableResumeContinuesFirstUnverifiedPhaseOnce(t *testing.T) {
	operation, plan := newTestOperation(t)
	completePrefix(t, operation, plan, 4)
	wantPhase := OrderedPhases()[4]

	if err := operation.FailRecoverable(plan); err != nil {
		t.Fatal(err)
	}
	action, err := operation.Resume(plan)
	if err != nil {
		t.Fatal(err)
	}
	if action != ResumeActionCurrentPhase || operation.State() != StateRunning || operation.CurrentPhase() != wantPhase || operation.Attempt() != 2 {
		t.Fatalf("resume = (%d, %s, %s, %d)", action, operation.State(), operation.CurrentPhase(), operation.Attempt())
	}

	action, err = operation.Resume(plan)
	if err != nil {
		t.Fatal(err)
	}
	if action != ResumeActionAlreadyRunning || operation.Attempt() != 2 {
		t.Fatalf("idempotent resume = (%d, attempt %d)", action, operation.Attempt())
	}
	if err := operation.CompleteStep(testEvidence(t, wantPhase, 2, plan, false)); err != nil {
		t.Fatalf("complete resumed phase: %v", err)
	}
}

func TestPF001ReadyResumeReturnsAlreadyReady(t *testing.T) {
	operation, plan := newTestOperation(t)
	completePrefix(t, operation, plan, len(OrderedPhases()))

	action, err := operation.Resume(plan)

	if err != nil {
		t.Fatal(err)
	}
	if action != ResumeActionAlreadyReady || operation.State() != StateReady {
		t.Fatalf("resume = %d, state = %s", action, operation.State())
	}
}

func TestPF001RebootRequiresBoundVerifiedReceipt(t *testing.T) {
	operation, plan := newTestOperation(t)
	if err := operation.CompleteStep(testEvidence(t, PhaseVerifyHost, 1, plan, false)); err != nil {
		t.Fatal(err)
	}
	receipt := DigestBytes([]byte("one-use-reboot-receipt"))
	checkpoint := mustCheckpoint(t, plan, receipt)

	if err := operation.MarkRebootPending(plan, checkpoint); err != nil {
		t.Fatal(err)
	}
	stored, exists := operation.Snapshot().RebootCheckpoint()
	if !exists || !stored.PlanDigest().Equal(plan) || stored.Phase() != PhaseEnsureContainerRuntime ||
		stored.Attempt() != 1 || !stored.ReceiptDigest().Equal(receipt) ||
		stored.NextSafeAction().String() != "setup.resume_after_restart" {
		t.Fatal("snapshot did not preserve the reboot checkpoint")
	}
	if err := operation.MarkRebootPending(plan, checkpoint); err != nil {
		t.Fatalf("identical checkpoint replay: %v", err)
	}
	action, err := operation.Resume(plan)
	if err != nil || action != ResumeActionAwaitVerification || operation.Attempt() != 1 {
		t.Fatalf("unverified resume = (%d, %v, attempt %d)", action, err, operation.Attempt())
	}

	err = operation.VerifyResume(plan, DigestBytes([]byte("wrong-receipt")))
	assertErrorCode(t, err, ErrorCodeIntegrityViolation)
	if operation.State() != StateRebootPending {
		t.Fatal("wrong receipt changed reboot state")
	}
	if err := operation.VerifyResume(plan, receipt); err != nil {
		t.Fatal(err)
	}
	if err := operation.VerifyResume(plan, receipt); err != nil {
		t.Fatalf("identical verification replay: %v", err)
	}
	if operation.State() != StateResumeVerified {
		t.Fatalf("state = %s, want ResumeVerified", operation.State())
	}

	action, err = operation.Resume(plan)
	if err != nil || action != ResumeActionCurrentPhase {
		t.Fatalf("verified resume = (%d, %v)", action, err)
	}
	if operation.State() != StateRunning || operation.CurrentPhase() != PhaseEnsureContainerRuntime || operation.Attempt() != 2 {
		t.Fatalf("cursor = (%s, %s, %d)", operation.State(), operation.CurrentPhase(), operation.Attempt())
	}
}

func TestPF001RestoresAuthenticatedRebootCursor(t *testing.T) {
	operation, plan := newTestOperation(t)
	if err := operation.CompleteStep(testEvidence(t, PhaseVerifyHost, 1, plan, false)); err != nil {
		t.Fatal(err)
	}
	receipt := DigestBytes([]byte("receipt"))
	checkpoint := mustCheckpoint(t, plan, receipt)
	if err := operation.MarkRebootPending(plan, checkpoint); err != nil {
		t.Fatal(err)
	}
	snapshot := operation.Snapshot()
	stored, _ := snapshot.RebootCheckpoint()

	restored, err := RestoreOperation(RestoreInput{
		OperationID:      snapshot.OperationID(),
		PlanDigest:       snapshot.PlanDigest(),
		AggregateVersion: snapshot.AggregateVersion(),
		State:            snapshot.State(),
		CurrentPhase:     snapshot.CurrentPhase(),
		Attempt:          snapshot.Attempt(),
		Completed:        snapshot.CompletedEvidence(),
		RebootCheckpoint: &stored,
	})
	if err != nil {
		t.Fatal(err)
	}
	if restored.State() != StateRebootPending {
		t.Fatalf("state = %s", restored.State())
	}
	if restored.AggregateVersion() != snapshot.AggregateVersion() {
		t.Fatalf("aggregate version = %d, want %d", restored.AggregateVersion(), snapshot.AggregateVersion())
	}
	if err := restored.VerifyResume(plan, receipt); err != nil {
		t.Fatal(err)
	}
}

func TestPF001RebootIsRejectedOutsideContainerRuntimePhase(t *testing.T) {
	operation, plan := newTestOperation(t)
	action := mustAction(t, "setup.resume_after_restart")
	_, err := NewRebootCheckpoint(plan, PhaseVerifyHost, 1, DigestBytes([]byte("receipt")), action)

	assertErrorCode(t, err, ErrorCodeValidation)
	if operation.State() != StateRunning {
		t.Fatal("invalid checkpoint changed operation")
	}
}

func TestPF001RebootRejectsForeignOrConflictingCheckpoint(t *testing.T) {
	operation, plan := newTestOperation(t)
	if err := operation.CompleteStep(testEvidence(t, PhaseVerifyHost, 1, plan, false)); err != nil {
		t.Fatal(err)
	}
	foreignPlan := mustPlan(t, "foreign")
	foreign := mustCheckpoint(t, foreignPlan, DigestBytes([]byte("foreign")))
	assertErrorCode(t, operation.MarkRebootPending(plan, foreign), ErrorCodeIdempotencyConflict)

	first := mustCheckpoint(t, plan, DigestBytes([]byte("first")))
	if err := operation.MarkRebootPending(plan, first); err != nil {
		t.Fatal(err)
	}
	second := mustCheckpoint(t, plan, DigestBytes([]byte("second")))
	assertErrorCode(t, operation.MarkRebootPending(plan, second), ErrorCodeIntegrityViolation)
}

func TestPF001ResumeVerificationRejectsWrongState(t *testing.T) {
	operation, plan := newTestOperation(t)
	err := operation.VerifyResume(plan, DigestBytes([]byte("receipt")))
	assertErrorCode(t, err, ErrorCodeConflict)
}

func TestPF001TerminalStateCannotResume(t *testing.T) {
	tests := []struct {
		name       string
		transition func(*Operation, PlanDigest) error
		want       State
	}{
		{name: "cancelled", transition: (*Operation).Cancel, want: StateCancelled},
		{name: "unsupported", transition: (*Operation).MarkUnsupportedHost, want: StateUnsupportedHost},
		{name: "runtime conflict", transition: (*Operation).MarkRuntimeConflict, want: StateRuntimeConflict},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operation, plan := newTestOperation(t)
			if err := test.transition(operation, plan); err != nil {
				t.Fatal(err)
			}
			if err := test.transition(operation, plan); err != nil {
				t.Fatalf("same terminal transition was not idempotent: %v", err)
			}
			if operation.State() != test.want || !operation.State().Terminal() {
				t.Fatalf("state = %s", operation.State())
			}
			_, err := operation.Resume(plan)
			assertErrorCode(t, err, ErrorCodeConflict)
		})
	}
}

func TestPF001AdministratorPauseResumesSamePhase(t *testing.T) {
	operation, plan := newTestOperation(t)
	if err := operation.PauseForAdministrator(plan); err != nil {
		t.Fatal(err)
	}
	if err := operation.PauseForAdministrator(plan); err != nil {
		t.Fatalf("pause replay: %v", err)
	}
	if operation.State() != StatePausedForAdministrator {
		t.Fatalf("state = %s", operation.State())
	}
	action, err := operation.Resume(plan)
	if err != nil || action != ResumeActionCurrentPhase || operation.CurrentPhase() != PhaseVerifyHost || operation.Attempt() != 2 {
		t.Fatalf("resume = (%d, %v, %s, %d)", action, err, operation.CurrentPhase(), operation.Attempt())
	}
}

func TestPF001RestoreFindsFirstUnverifiedPhase(t *testing.T) {
	operation, plan := newTestOperation(t)
	completePrefix(t, operation, plan, 6)
	if err := operation.FailRecoverable(plan); err != nil {
		t.Fatal(err)
	}
	snapshot := operation.Snapshot()

	restored, err := RestoreOperation(RestoreInput{
		OperationID:      snapshot.OperationID(),
		PlanDigest:       snapshot.PlanDigest(),
		AggregateVersion: snapshot.AggregateVersion(),
		State:            snapshot.State(),
		CurrentPhase:     snapshot.CurrentPhase(),
		Attempt:          snapshot.Attempt(),
		Completed:        snapshot.CompletedEvidence(),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := OrderedPhases()[6]
	if got, exists := restored.FirstUnverified(); !exists || got != want || restored.CurrentPhase() != want {
		t.Fatalf("first unverified = (%s, %t), cursor = %s", got, exists, restored.CurrentPhase())
	}
}

func TestPF001RestoreRejectsNonContiguousOrForeignEvidence(t *testing.T) {
	id := mustOperationID(t)
	plan := mustPlan(t, "plan")
	foreign := mustPlan(t, "foreign-plan")

	tests := []struct {
		name      string
		completed []StepEvidence
		current   Phase
	}{
		{
			name:      "skipped first phase",
			completed: []StepEvidence{testEvidence(t, PhaseEnsureContainerRuntime, 1, plan, false)},
			current:   PhaseVerifyRelease,
		},
		{
			name:      "foreign plan",
			completed: []StepEvidence{testEvidence(t, PhaseVerifyHost, 1, foreign, false)},
			current:   PhaseEnsureContainerRuntime,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := RestoreOperation(RestoreInput{
				OperationID:  id,
				PlanDigest:   plan,
				State:        StateFailedRecoverable,
				CurrentPhase: test.current,
				Attempt:      1,
				Completed:    test.completed,
			})
			assertErrorCode(t, err, ErrorCodeIntegrityViolation)
		})
	}
}

func TestPF001OperationRejectsRuntimeOwnershipDrift(t *testing.T) {
	operation, plan := newTestOperation(t)
	host := mustProofPolicyEvidence(t, proofPolicyEvidenceInput(
		t,
		PhaseVerifyHost,
		plan,
		RuntimeOwnershipUndetermined,
	))
	runtimeInput := proofPolicyEvidenceInput(
		t,
		PhaseEnsureContainerRuntime,
		plan,
		RuntimeOwnershipReusedExternal,
	)
	runtimeInput.VerifiedArtifactDigest = DigestBytes([]byte("runtime installer artifact"))
	runtime := mustProofPolicyEvidence(t, runtimeInput)
	releaseInput := proofPolicyEvidenceInput(
		t,
		PhaseVerifyRelease,
		plan,
		RuntimeOwnershipProvisionedByAgentMemory,
	)
	releaseInput.VerifiedArtifactDigest = DigestBytes([]byte("release artifact"))
	release := mustProofPolicyEvidence(t, releaseInput)

	for _, evidence := range []StepEvidence{host, runtime} {
		if err := operation.CompleteStep(evidence); err != nil {
			t.Fatalf("CompleteStep(%s) error = %v", evidence.Phase(), err)
		}
	}
	versionBeforeDrift := operation.AggregateVersion()
	assertErrorCode(t, operation.CompleteStep(release), ErrorCodeIntegrityViolation)
	if operation.CurrentPhase() != PhaseVerifyRelease || len(operation.CompletedEvidence()) != 2 {
		t.Fatal("ownership drift changed the aggregate cursor")
	}
	if operation.AggregateVersion() != versionBeforeDrift {
		t.Fatal("ownership drift advanced the aggregate version")
	}
}

func TestPF001RestoreRejectsRuntimeOwnershipDrift(t *testing.T) {
	id := mustOperationID(t)
	plan := mustPlan(t, "ownership-chain")
	host := mustProofPolicyEvidence(t, proofPolicyEvidenceInput(
		t,
		PhaseVerifyHost,
		plan,
		RuntimeOwnershipUndetermined,
	))
	runtimeInput := proofPolicyEvidenceInput(
		t,
		PhaseEnsureContainerRuntime,
		plan,
		RuntimeOwnershipReusedExternal,
	)
	runtimeInput.VerifiedArtifactDigest = DigestBytes([]byte("runtime installer artifact"))
	runtime := mustProofPolicyEvidence(t, runtimeInput)
	releaseInput := proofPolicyEvidenceInput(
		t,
		PhaseVerifyRelease,
		plan,
		RuntimeOwnershipProvisionedByAgentMemory,
	)
	releaseInput.VerifiedArtifactDigest = DigestBytes([]byte("release artifact"))
	release := mustProofPolicyEvidence(t, releaseInput)

	_, err := RestoreOperation(RestoreInput{
		OperationID:  id,
		PlanDigest:   plan,
		State:        StateRunning,
		CurrentPhase: PhaseReserveSpace,
		Attempt:      1,
		Completed:    []StepEvidence{host, runtime, release},
	})
	assertErrorCode(t, err, ErrorCodeIntegrityViolation)
}

func mustProofPolicyEvidence(t testing.TB, input StepEvidenceInput) StepEvidence {
	t.Helper()
	evidence, err := NewStepEvidence(input)
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func TestPF001RestoreRejectsReadyWithMissingEvidence(t *testing.T) {
	operation, plan := newTestOperation(t)
	completePrefix(t, operation, plan, len(OrderedPhases())-1)

	_, err := RestoreOperation(RestoreInput{
		OperationID:  operation.ID(),
		PlanDigest:   plan,
		State:        StateReady,
		CurrentPhase: operation.CurrentPhase(),
		Attempt:      operation.Attempt(),
		Completed:    operation.CompletedEvidence(),
	})

	assertErrorCode(t, err, ErrorCodeIntegrityViolation)
}

func TestPF001RestoreRejectsContradictoryCursorShapes(t *testing.T) {
	operation, plan := newTestOperation(t)
	completePrefix(t, operation, plan, 1)
	evidence := operation.CompletedEvidence()
	receipt := DigestBytes([]byte("receipt"))
	checkpoint := mustCheckpoint(t, plan, receipt)

	tests := []struct {
		name  string
		input RestoreInput
	}{
		{
			name:  "unknown state",
			input: RestoreInput{OperationID: operation.ID(), PlanDigest: plan, State: StateUnknown, CurrentPhase: PhaseEnsureContainerRuntime, Attempt: 1, Completed: evidence},
		},
		{
			name:  "zero attempt",
			input: RestoreInput{OperationID: operation.ID(), PlanDigest: plan, State: StateRunning, CurrentPhase: PhaseEnsureContainerRuntime, Attempt: 0, Completed: evidence},
		},
		{
			name:  "wrong cursor",
			input: RestoreInput{OperationID: operation.ID(), PlanDigest: plan, State: StateRunning, CurrentPhase: PhaseVerifyRelease, Attempt: 1, Completed: evidence},
		},
		{
			name:  "reboot without checkpoint",
			input: RestoreInput{OperationID: operation.ID(), PlanDigest: plan, State: StateRebootPending, CurrentPhase: PhaseEnsureContainerRuntime, Attempt: 1, Completed: evidence},
		},
		{
			name:  "running with checkpoint",
			input: RestoreInput{OperationID: operation.ID(), PlanDigest: plan, State: StateRunning, CurrentPhase: PhaseEnsureContainerRuntime, Attempt: 1, Completed: evidence, RebootCheckpoint: &checkpoint},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := RestoreOperation(test.input)
			assertErrorCode(t, err, ErrorCodeIntegrityViolation)
		})
	}
}

func TestPF001RestoreRejectsMissingIdentityAndExcessHistory(t *testing.T) {
	operation, plan := newTestOperation(t)
	valid := RestoreInput{
		OperationID:  operation.ID(),
		PlanDigest:   plan,
		State:        StateRunning,
		CurrentPhase: PhaseVerifyHost,
		Attempt:      1,
	}

	tests := []struct {
		name   string
		mutate func(*RestoreInput)
	}{
		{name: "missing operation", mutate: func(input *RestoreInput) { input.OperationID = OperationID{} }},
		{name: "missing plan", mutate: func(input *RestoreInput) { input.PlanDigest = PlanDigest{} }},
		{name: "excess history", mutate: func(input *RestoreInput) {
			input.Completed = make([]StepEvidence, len(OrderedPhases())+1)
		}},
		{name: "corrupt evidence", mutate: func(input *RestoreInput) {
			evidence := testEvidence(t, PhaseVerifyHost, 1, plan, false)
			evidence.fingerprint = DigestBytes([]byte("corrupt"))
			input.Completed = []StepEvidence{evidence}
			input.CurrentPhase = PhaseEnsureContainerRuntime
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := valid
			test.mutate(&input)
			_, err := RestoreOperation(input)
			assertErrorCode(t, err, ErrorCodeIntegrityViolation)
		})
	}
}

func TestPF001RestoreRejectsContradictoryReadyState(t *testing.T) {
	operation, plan := newTestOperation(t)
	completePrefix(t, operation, plan, len(OrderedPhases()))
	ready := operation.Snapshot()
	completed := ready.CompletedEvidence()
	receipt := DigestBytes([]byte("receipt"))
	checkpoint := mustCheckpoint(t, plan, receipt)

	tests := []struct {
		name  string
		state State
		phase Phase
		check *RebootCheckpoint
	}{
		{name: "not Ready after all evidence", state: StateFailedRecoverable, phase: PhaseCommitActiveRelease},
		{name: "Ready has wrong final cursor", state: StateReady, phase: PhaseVerifyReadiness},
		{name: "Ready retains checkpoint", state: StateReady, phase: PhaseCommitActiveRelease, check: &checkpoint},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := RestoreOperation(RestoreInput{
				OperationID:      operation.ID(),
				PlanDigest:       plan,
				State:            test.state,
				CurrentPhase:     test.phase,
				Attempt:          operation.Attempt(),
				Completed:        completed,
				RebootCheckpoint: test.check,
			})
			assertErrorCode(t, err, ErrorCodeIntegrityViolation)
		})
	}
}

func TestPF001RestoreRejectsMismatchedRebootCheckpoint(t *testing.T) {
	operation, plan := newTestOperation(t)
	if err := operation.CompleteStep(testEvidence(t, PhaseVerifyHost, 1, plan, false)); err != nil {
		t.Fatal(err)
	}
	foreignPlan := mustPlan(t, "foreign")
	action := mustAction(t, "setup.resume_after_restart")

	tests := []struct {
		name       string
		checkpoint RebootCheckpoint
	}{
		{name: "foreign plan", checkpoint: RebootCheckpoint{planDigest: foreignPlan, phase: PhaseEnsureContainerRuntime, attempt: 1, receipt: DigestBytes([]byte("one")), nextAction: action}},
		{name: "wrong attempt", checkpoint: RebootCheckpoint{planDigest: plan, phase: PhaseEnsureContainerRuntime, attempt: 2, receipt: DigestBytes([]byte("two")), nextAction: action}},
		{name: "invalid checkpoint", checkpoint: RebootCheckpoint{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := RestoreOperation(RestoreInput{
				OperationID:      operation.ID(),
				PlanDigest:       plan,
				State:            StateRebootPending,
				CurrentPhase:     PhaseEnsureContainerRuntime,
				Attempt:          1,
				Completed:        operation.CompletedEvidence(),
				RebootCheckpoint: &test.checkpoint,
			})
			assertErrorCode(t, err, ErrorCodeIntegrityViolation)
		})
	}
}

func TestPF001SnapshotCannotMutateOperationEvidence(t *testing.T) {
	operation, plan := newTestOperation(t)
	if err := operation.CompleteStep(testEvidence(t, PhaseVerifyHost, 1, plan, false)); err != nil {
		t.Fatal(err)
	}

	completed := operation.Snapshot().CompletedEvidence()
	completed[0].phase = PhaseCommitActiveRelease
	completed[0].facts[0].value = "mutated"

	actual := operation.CompletedEvidence()[0]
	if actual.Phase() != PhaseVerifyHost || actual.Facts()[0].Value() == "mutated" {
		t.Fatal("snapshot mutation escaped into aggregate evidence")
	}
}

func TestPF001AggregateVersionOverflowRejectsMutationAtomically(t *testing.T) {
	operation, plan := newTestOperation(t)
	restored, err := RestoreOperation(RestoreInput{
		OperationID:      operation.ID(),
		PlanDigest:       plan,
		AggregateVersion: ^uint64(0),
		State:            StateRunning,
		CurrentPhase:     PhaseVerifyHost,
		Attempt:          1,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = restored.Cancel(plan)
	assertErrorCode(t, err, ErrorCodeIntegrityViolation)
	if restored.State() != StateRunning || restored.AggregateVersion() != ^uint64(0) {
		t.Fatalf("overflow changed aggregate: state=%s version=%d", restored.State(), restored.AggregateVersion())
	}
}

func FuzzPF001ReadyRequiresEveryOrderedPhase(f *testing.F) {
	for _, seed := range []uint8{0, 1, 7, 13, 14, 15, 255} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, requested uint8) {
		operation, plan := newTestOperation(t)
		count := int(requested) % (len(OrderedPhases()) + 1)
		completePrefix(t, operation, plan, count)

		if got, want := operation.State() == StateReady, count == len(OrderedPhases()); got != want {
			t.Fatalf("count %d: Ready = %t, want %t", count, got, want)
		}
		if count < len(OrderedPhases()) {
			phase, exists := operation.FirstUnverified()
			if !exists || phase != OrderedPhases()[count] {
				t.Fatalf("count %d: first unverified = (%s, %t)", count, phase, exists)
			}
		}
	})
}

func newTestOperation(t testing.TB) (*Operation, PlanDigest) {
	t.Helper()
	plan := mustPlan(t, "canonical-test-install-plan")
	operation, err := NewOperation(mustOperationID(t), plan)
	if err != nil {
		t.Fatal(err)
	}
	return operation, plan
}

func mustOperationID(t testing.TB) OperationID {
	t.Helper()
	id, err := NewOperationID("019f5c00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustPlan(t testing.TB, canonical string) PlanDigest {
	t.Helper()
	plan, err := BindPlan([]byte(canonical))
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func testEvidence(t testing.TB, phase Phase, attempt uint32, plan PlanDigest, withArtifact bool) StepEvidence {
	t.Helper()
	fact, err := NewNonSecretFact("probe_status", "verified")
	if err != nil {
		t.Fatal(err)
	}
	boundary, err := NewCompensationBoundary("remove_agentmemory_owned_partial")
	if err != nil {
		t.Fatal(err)
	}
	action := mustAction(t, "setup.continue")
	artifact := Digest{}
	if withArtifact || PhaseRequiresVerifiedArtifact(phase) {
		artifact = DigestBytes([]byte("artifact:" + phase.String()))
	}
	runtimeOwnership := RuntimeOwnershipUndetermined
	if phase != PhaseVerifyHost {
		runtimeOwnership = RuntimeOwnershipReusedExternal
	}
	evidence, err := NewStepEvidence(StepEvidenceInput{
		Phase:                  phase,
		Attempt:                attempt,
		PlanDigest:             plan,
		InputDigest:            DigestBytes([]byte(fmt.Sprintf("input:%s:%d", phase, attempt))),
		OutputDigest:           DigestBytes([]byte(fmt.Sprintf("output:%s:%d", phase, attempt))),
		VerifiedArtifactDigest: artifact,
		Facts:                  []NonSecretFact{fact},
		RuntimeOwnership:       runtimeOwnership,
		CompensationBoundary:   boundary,
		NextSafeAction:         action,
	})
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func mustAction(t testing.TB, key string) SafeAction {
	t.Helper()
	action, err := NewSafeAction(key)
	if err != nil {
		t.Fatal(err)
	}
	return action
}

func mustCheckpoint(t testing.TB, plan PlanDigest, receipt Digest) RebootCheckpoint {
	t.Helper()
	checkpoint, err := NewRebootCheckpoint(
		plan,
		PhaseEnsureContainerRuntime,
		1,
		receipt,
		mustAction(t, "setup.resume_after_restart"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return checkpoint
}

func completePrefix(t testing.TB, operation *Operation, plan PlanDigest, count int) {
	t.Helper()
	for _, phase := range OrderedPhases()[:count] {
		if err := operation.CompleteStep(testEvidence(t, phase, operation.Attempt(), plan, false)); err != nil {
			t.Fatalf("complete %s: %v", phase, err)
		}
	}
}

func assertErrorCode(t testing.TB, err error, want ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want %s", want)
	}
	var coded CodedError
	if !errors.As(err, &coded) {
		t.Fatalf("error = %T %v, want CodedError", err, err)
	}
	if coded.Code() != want {
		t.Fatalf("code = %s, want %s", coded.Code(), want)
	}
	if coded.Retryable() {
		t.Fatalf("%s unexpectedly marked retryable", coded.Code())
	}
}
