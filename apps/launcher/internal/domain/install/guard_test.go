package install

import (
	"errors"
	"strings"
	"testing"
)

func TestPF001TypedErrorsExposeSafeStableContracts(t *testing.T) {
	operation, plan := newTestOperation(t)
	foreignPlan := mustPlan(t, "foreign")

	validation := newValidationError("field", "reason")
	if validation.Error() != "install validation failed for field: reason" {
		t.Fatalf("validation error = %q", validation.Error())
	}

	binding := &PlanBindingError{expected: plan, actual: foreignPlan}
	if binding.Error() == "" || binding.Retryable() {
		t.Fatal("plan binding error contract is incomplete")
	}

	transition := newTransitionError(operation.State(), operation.CurrentPhase(), "Test")
	if transition.Error() == "" || transition.State() != StateRunning || transition.Phase() != PhaseVerifyHost {
		t.Fatal("transition error omitted safe state context")
	}

	integrity := newIntegrityError("broken chain")
	if integrity.Error() != "install evidence integrity violation: broken chain" {
		t.Fatalf("integrity error = %q", integrity.Error())
	}
}

func TestPF001EvidenceConstructorRejectsIncompleteOrOversizedProof(t *testing.T) {
	plan := mustPlan(t, "plan")
	boundary, err := NewCompensationBoundary("none")
	if err != nil {
		t.Fatal(err)
	}
	valid := StepEvidenceInput{
		Phase:                PhaseVerifyHost,
		Attempt:              1,
		PlanDigest:           plan,
		InputDigest:          DigestBytes([]byte("input")),
		OutputDigest:         DigestBytes([]byte("output")),
		RuntimeOwnership:     RuntimeOwnershipUndetermined,
		CompensationBoundary: boundary,
		NextSafeAction:       mustAction(t, "setup.continue"),
	}

	tests := []struct {
		name   string
		mutate func(*StepEvidenceInput)
	}{
		{name: "unknown phase", mutate: func(input *StepEvidenceInput) { input.Phase = PhaseUnknown }},
		{name: "zero attempt", mutate: func(input *StepEvidenceInput) { input.Attempt = 0 }},
		{name: "zero plan", mutate: func(input *StepEvidenceInput) { input.PlanDigest = PlanDigest{} }},
		{name: "zero input", mutate: func(input *StepEvidenceInput) { input.InputDigest = Digest{} }},
		{name: "zero output", mutate: func(input *StepEvidenceInput) { input.OutputDigest = Digest{} }},
		{name: "unknown ownership", mutate: func(input *StepEvidenceInput) { input.RuntimeOwnership = RuntimeOwnershipUnknown }},
		{name: "zero boundary", mutate: func(input *StepEvidenceInput) { input.CompensationBoundary = CompensationBoundary{} }},
		{name: "zero next action", mutate: func(input *StepEvidenceInput) { input.NextSafeAction = SafeAction{} }},
		{name: "too many facts", mutate: func(input *StepEvidenceInput) {
			fact, factErr := NewNonSecretFact("probe", "ok")
			if factErr != nil {
				t.Fatal(factErr)
			}
			input.Facts = make([]NonSecretFact, maxEvidenceFacts+1)
			for index := range input.Facts {
				input.Facts[index] = fact
			}
		}},
		{name: "invalid fact object", mutate: func(input *StepEvidenceInput) {
			input.Facts = []NonSecretFact{{name: "bad name", value: "ok"}}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := valid
			test.mutate(&input)
			_, err := NewStepEvidence(input)
			assertErrorCode(t, err, ErrorCodeValidation)
		})
	}
}

func TestPF001ValueObjectsRejectOversizedOrMalformedContent(t *testing.T) {
	tests := []struct {
		name string
		run  func() error
	}{
		{name: "long boundary", run: func() error { _, err := NewCompensationBoundary(strings.Repeat("a", maxBoundarySize+1)); return err }},
		{name: "long action", run: func() error { _, err := NewSafeAction(strings.Repeat("a", maxActionSize+1)); return err }},
		{name: "long fact name", run: func() error { _, err := NewNonSecretFact(strings.Repeat("a", maxFactNameSize+1), "ok"); return err }},
		{name: "long fact value", run: func() error { _, err := NewNonSecretFact("probe", strings.Repeat("a", maxFactValueSize+1)); return err }},
		{name: "long operation ID", run: func() error { _, err := NewOperationID(strings.Repeat("a", maxOperationIDSize+1)); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertErrorCode(t, test.run(), ErrorCodeValidation)
		})
	}
}

func TestPF001RebootCheckpointRejectsIncompleteBinding(t *testing.T) {
	plan := mustPlan(t, "plan")
	receipt := DigestBytes([]byte("receipt"))
	action := mustAction(t, "setup.resume_after_restart")
	tests := []struct {
		name    string
		plan    PlanDigest
		phase   Phase
		attempt uint32
		receipt Digest
		action  SafeAction
	}{
		{name: "zero plan", phase: PhaseEnsureContainerRuntime, attempt: 1, receipt: receipt, action: action},
		{name: "wrong phase", plan: plan, phase: PhaseVerifyHost, attempt: 1, receipt: receipt, action: action},
		{name: "zero attempt", plan: plan, phase: PhaseEnsureContainerRuntime, receipt: receipt, action: action},
		{name: "zero receipt", plan: plan, phase: PhaseEnsureContainerRuntime, attempt: 1, action: action},
		{name: "zero action", plan: plan, phase: PhaseEnsureContainerRuntime, attempt: 1, receipt: receipt},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewRebootCheckpoint(test.plan, test.phase, test.attempt, test.receipt, test.action)
			assertErrorCode(t, err, ErrorCodeValidation)
		})
	}
}

func TestPF001OperationGuardsInvalidTransitions(t *testing.T) {
	operation, plan := newTestOperation(t)
	foreign := mustPlan(t, "foreign")

	if _, err := NewOperation(OperationID{}, plan); err == nil {
		t.Fatal("zero operation ID was accepted")
	}
	if _, err := NewOperation(operation.ID(), PlanDigest{}); err == nil {
		t.Fatal("zero plan was accepted")
	}
	if err := operation.FailRecoverable(foreign); err == nil {
		t.Fatal("foreign plan changed failure state")
	}
	if err := operation.FailRecoverable(plan); err != nil {
		t.Fatal(err)
	}
	if err := operation.FailRecoverable(plan); err != nil {
		t.Fatal(err)
	}
	if err := operation.CompleteStep(testEvidence(t, PhaseVerifyHost, 1, plan, false)); err == nil {
		t.Fatal("completed a step while failed")
	}
	if err := operation.MarkRebootPending(plan, mustCheckpoint(t, plan, DigestBytes([]byte("receipt")))); err == nil {
		t.Fatal("entered reboot from the wrong phase and state")
	}
}

func TestPF001OperationRejectsCorruptEvidenceAndAttempt(t *testing.T) {
	operation, plan := newTestOperation(t)
	corrupt := testEvidence(t, PhaseVerifyHost, 1, plan, false)
	corrupt.fingerprint = DigestBytes([]byte("corrupt"))
	assertErrorCode(t, operation.CompleteStep(corrupt), ErrorCodeValidation)

	wrongAttempt := testEvidence(t, PhaseVerifyHost, 2, plan, false)
	assertErrorCode(t, operation.CompleteStep(wrongAttempt), ErrorCodeIntegrityViolation)
	if len(operation.CompletedEvidence()) != 0 {
		t.Fatal("invalid evidence advanced the cursor")
	}
}

func TestPF001ResumeRejectsAttemptOverflowAndInvalidState(t *testing.T) {
	operation, plan := newTestOperation(t)
	operation.state = StateFailedRecoverable
	operation.attempt = ^uint32(0)
	_, err := operation.Resume(plan)
	assertErrorCode(t, err, ErrorCodeIntegrityViolation)

	operation.state = StateUnknown
	operation.attempt = 1
	_, err = operation.Resume(plan)
	assertErrorCode(t, err, ErrorCodeConflict)
}

func TestPF001ErrorImplementationsRemainCoded(t *testing.T) {
	errorsToCheck := []error{
		newValidationError("field", "reason"),
		&PlanBindingError{},
		newTransitionError(StateRunning, PhaseVerifyHost, "operation"),
		newIntegrityError("reason"),
	}
	for _, candidate := range errorsToCheck {
		var coded CodedError
		if !errors.As(candidate, &coded) || coded.Retryable() {
			t.Fatalf("error %T does not satisfy the non-retryable coded contract", candidate)
		}
	}
}
