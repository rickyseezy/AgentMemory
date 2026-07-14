package readiness

import (
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const testGeneration = "019f5f21-5678-7def-9123-abcdef012345"

func TestPF001ReadinessGateRequiresEveryFreshBoundProbe(t *testing.T) {
	t.Parallel()

	input := validGateInput(t)
	receipt, failures := NewGate().Evaluate(input)
	if len(failures) != 0 || receipt.IsZero() {
		t.Fatalf("receipt/failures = %+v/%+v", receipt, failures)
	}
	if receipt.OperationID() != input.OperationID || !receipt.PlanDigest().Equal(input.PlanDigest) ||
		receipt.ReleaseID() != input.ReleaseID || receipt.GenerationID() != input.GenerationID ||
		!receipt.ManifestDigest().Equal(input.ManifestDigest) || !receipt.ComposeDigest().Equal(input.ComposeDigest) ||
		!receipt.EvaluatedAt().Equal(input.EvaluatedAt) || len(receipt.Results()) != len(RequiredProbes()) {
		t.Fatal("receipt lost a readiness binding")
	}
	firstDigest := receipt.Digest()
	input.Results[0], input.Results[1] = input.Results[1], input.Results[0]
	second, failures := NewGate().Evaluate(input)
	if len(failures) != 0 || !second.Digest().Equal(firstDigest) {
		t.Fatal("receipt digest depends on caller result order")
	}
}

func TestPF001ReadinessGateDecisionTableFailsClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*GateInput)
		code   FailureCode
	}{
		{name: "missing", mutate: func(input *GateInput) { input.Results = input.Results[1:] }, code: FailureMissingProbe},
		{name: "duplicate", mutate: func(input *GateInput) { input.Results = append(input.Results, input.Results[0]) }, code: FailureDuplicateProbe},
		{name: "failed", mutate: func(input *GateInput) {
			input.Results[0] = resultFor(t, input, ProbeSQLiteIntegrity, StatusFailed, input.EvaluatedAt)
		}, code: FailureProbeFailed},
		{name: "foreign operation", mutate: func(input *GateInput) {
			foreign, _ := install.NewOperationID("foreign")
			resultInput := resultInputFor(input, ProbeSQLiteIntegrity, StatusPassed, input.EvaluatedAt)
			resultInput.OperationID = foreign
			input.Results[0], _ = NewResult(resultInput)
		}, code: FailureBindingMismatch},
		{name: "foreign plan", mutate: func(input *GateInput) {
			foreign, _ := install.BindPlan([]byte("foreign"))
			resultInput := resultInputFor(input, ProbeSQLiteIntegrity, StatusPassed, input.EvaluatedAt)
			resultInput.PlanDigest = foreign
			input.Results[0], _ = NewResult(resultInput)
		}, code: FailureBindingMismatch},
		{name: "foreign release", mutate: func(input *GateInput) {
			resultInput := resultInputFor(input, ProbeSQLiteIntegrity, StatusPassed, input.EvaluatedAt)
			resultInput.ReleaseID = "other"
			input.Results[0], _ = NewResult(resultInput)
		}, code: FailureBindingMismatch},
		{name: "foreign generation", mutate: func(input *GateInput) {
			resultInput := resultInputFor(input, ProbeSQLiteIntegrity, StatusPassed, input.EvaluatedAt)
			resultInput.GenerationID = "019f5f21-5678-7def-a123-abcdef012345"
			input.Results[0], _ = NewResult(resultInput)
		}, code: FailureBindingMismatch},
		{name: "foreign manifest", mutate: func(input *GateInput) {
			resultInput := resultInputFor(input, ProbeSQLiteIntegrity, StatusPassed, input.EvaluatedAt)
			resultInput.ManifestDigest = install.DigestBytes([]byte("other"))
			input.Results[0], _ = NewResult(resultInput)
		}, code: FailureBindingMismatch},
		{name: "foreign compose", mutate: func(input *GateInput) {
			resultInput := resultInputFor(input, ProbeSQLiteIntegrity, StatusPassed, input.EvaluatedAt)
			resultInput.ComposeDigest = install.DigestBytes([]byte("other"))
			input.Results[0], _ = NewResult(resultInput)
		}, code: FailureBindingMismatch},
		{name: "stale", mutate: func(input *GateInput) {
			input.Results[0] = resultFor(t, input, ProbeSQLiteIntegrity, StatusPassed, input.EvaluatedAt.Add(-6*time.Minute))
		}, code: FailureStaleEvidence},
		{name: "future", mutate: func(input *GateInput) {
			input.Results[0] = resultFor(t, input, ProbeSQLiteIntegrity, StatusPassed, input.EvaluatedAt.Add(time.Microsecond))
		}, code: FailureStaleEvidence},
		{name: "invalid gate", mutate: func(input *GateInput) { input.ReleaseID = "" }, code: FailureInvalidInput},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := validGateInput(t)
			test.mutate(&input)
			receipt, failures := NewGate().Evaluate(input)
			if !receipt.IsZero() || !hasFailure(failures, test.code) {
				t.Fatalf("receipt/failures = %+v/%+v, want %s", receipt, failures, test.code)
			}
		})
	}
}

func TestPF001ReadinessProbeResultValidationAndImmutability(t *testing.T) {
	t.Parallel()

	input := validGateInput(t)
	valid := resultInputFor(&input, ProbeSQLiteIntegrity, StatusPassed, input.EvaluatedAt)
	result, err := NewResult(valid)
	if err != nil {
		t.Fatal(err)
	}
	if result.Probe() != ProbeSQLiteIntegrity || result.Status() != StatusPassed ||
		result.OperationID() != input.OperationID || !result.PlanDigest().Equal(input.PlanDigest) ||
		result.ReleaseID() != input.ReleaseID || result.GenerationID() != input.GenerationID ||
		!result.ManifestDigest().Equal(input.ManifestDigest) || !result.ComposeDigest().Equal(input.ComposeDigest) ||
		result.EvidenceDigest().IsZero() || !result.ObservedAt().Equal(input.EvaluatedAt) {
		t.Fatal("probe result accessors lost evidence")
	}

	invalid := []ResultInput{
		{},
		withResultMutation(valid, func(value *ResultInput) { value.Probe = ProbeUnknown }),
		withResultMutation(valid, func(value *ResultInput) { value.Status = StatusUnknown }),
		withResultMutation(valid, func(value *ResultInput) { value.OperationID = install.OperationID{} }),
		withResultMutation(valid, func(value *ResultInput) { value.PlanDigest = install.PlanDigest{} }),
		withResultMutation(valid, func(value *ResultInput) { value.ReleaseID = "bad release" }),
		withResultMutation(valid, func(value *ResultInput) { value.GenerationID = "019f5f21-5678-4def-9123-abcdef012345" }),
		withResultMutation(valid, func(value *ResultInput) { value.ManifestDigest = install.Digest{} }),
		withResultMutation(valid, func(value *ResultInput) { value.ComposeDigest = install.Digest{} }),
		withResultMutation(valid, func(value *ResultInput) { value.EvidenceDigest = install.Digest{} }),
		withResultMutation(valid, func(value *ResultInput) { value.ObservedAt = time.Time{} }),
	}
	for _, value := range invalid {
		if _, err := NewResult(value); err == nil {
			t.Fatalf("NewResult() accepted invalid input: %+v", value)
		}
	}

	probes := RequiredProbes()
	probes[0] = ProbeUnknown
	if RequiredProbes()[0] != ProbeSQLiteIntegrity {
		t.Fatal("RequiredProbes() exposed mutable storage")
	}
	results := input.Results
	receipt, failures := NewGate().Evaluate(input)
	if len(failures) != 0 {
		t.Fatal(failures)
	}
	returned := receipt.Results()
	returned[0] = Result{}
	results[0] = Result{}
	if receipt.Results()[0].Probe() != ProbeSQLiteIntegrity {
		t.Fatal("Receipt.Results() exposed mutable storage")
	}
}

func validGateInput(t testing.TB) GateInput {
	t.Helper()
	operationID, err := install.NewOperationID("019f5f20-1234-7abc-8123-0123456789ab")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := install.BindPlan([]byte("canonical-plan"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	input := GateInput{
		OperationID:    operationID,
		PlanDigest:     plan,
		ReleaseID:      "agentmemory-1.0.0",
		GenerationID:   testGeneration,
		ManifestDigest: install.DigestBytes([]byte("manifest")),
		ComposeDigest:  install.DigestBytes([]byte("compose")),
		EvaluatedAt:    now,
	}
	for _, probe := range RequiredProbes() {
		input.Results = append(input.Results, resultFor(t, &input, probe, StatusPassed, now))
	}
	return input
}

func resultFor(t testing.TB, input *GateInput, probe Probe, status Status, observedAt time.Time) Result {
	t.Helper()
	result, err := NewResult(resultInputFor(input, probe, status, observedAt))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func resultInputFor(input *GateInput, probe Probe, status Status, observedAt time.Time) ResultInput {
	return ResultInput{
		Probe:          probe,
		Status:         status,
		OperationID:    input.OperationID,
		PlanDigest:     input.PlanDigest,
		ReleaseID:      input.ReleaseID,
		GenerationID:   input.GenerationID,
		ManifestDigest: input.ManifestDigest,
		ComposeDigest:  input.ComposeDigest,
		EvidenceDigest: install.DigestBytes([]byte(probe.String())),
		ObservedAt:     observedAt,
	}
}

func withResultMutation(input ResultInput, mutate func(*ResultInput)) ResultInput {
	mutate(&input)
	return input
}

func hasFailure(failures []Failure, code FailureCode) bool {
	for _, failure := range failures {
		if failure.Code == code {
			return true
		}
	}
	return false
}
