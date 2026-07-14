package install

import (
	"errors"
	"testing"
)

func TestPF001NonArtifactPhaseNeedsNoFabricatedArtifactDigest(t *testing.T) {
	plan := mustPlan(t, "plan")
	evidence := testEvidence(t, PhaseEnsureDirectories, 1, plan, false)

	if !evidence.VerifiedArtifactDigest().IsZero() {
		t.Fatal("non-artifact phase fabricated an artifact digest")
	}
	if !evidence.valid() {
		t.Fatal("valid non-artifact evidence was rejected")
	}
}

func TestPF001StepEvidenceCopiesAndSortsFacts(t *testing.T) {
	plan := mustPlan(t, "plan")
	first, err := NewNonSecretFact("zeta", "one")
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewNonSecretFact("alpha", "two")
	if err != nil {
		t.Fatal(err)
	}
	facts := []NonSecretFact{first, second}
	boundary, err := NewCompensationBoundary("none")
	if err != nil {
		t.Fatal(err)
	}
	input := StepEvidenceInput{
		Phase:                PhaseVerifyHost,
		Attempt:              1,
		PlanDigest:           plan,
		InputDigest:          DigestBytes([]byte("input")),
		OutputDigest:         DigestBytes([]byte("output")),
		Facts:                facts,
		RuntimeOwnership:     RuntimeOwnershipUndetermined,
		CompensationBoundary: boundary,
		NextSafeAction:       mustAction(t, "setup.continue"),
	}
	evidence, err := NewStepEvidence(input)
	if err != nil {
		t.Fatal(err)
	}

	facts[0].value = "changed after construction"
	got := evidence.Facts()
	if got[0].Name() != "alpha" || got[1].Name() != "zeta" || got[1].Value() != "one" {
		t.Fatalf("facts were not copied and sorted: %#v", got)
	}
	got[0].value = "changed through accessor"
	if evidence.Facts()[0].Value() != "two" {
		t.Fatal("Facts accessor exposed mutable evidence")
	}

	reversed := input
	reversed.Facts = []NonSecretFact{second, first}
	other, err := NewStepEvidence(reversed)
	if err != nil {
		t.Fatal(err)
	}
	if !evidence.Equal(other) {
		t.Fatal("equivalent fact sets produced different fingerprints")
	}
}

func TestPF001StepEvidenceRejectsDuplicateFacts(t *testing.T) {
	fact, err := NewNonSecretFact("probe", "one")
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewNonSecretFact("probe", "two")
	if err != nil {
		t.Fatal(err)
	}
	boundary, err := NewCompensationBoundary("none")
	if err != nil {
		t.Fatal(err)
	}

	_, err = NewStepEvidence(StepEvidenceInput{
		Phase:                PhaseVerifyHost,
		Attempt:              1,
		PlanDigest:           mustPlan(t, "plan"),
		InputDigest:          DigestBytes([]byte("input")),
		OutputDigest:         DigestBytes([]byte("output")),
		Facts:                []NonSecretFact{fact, other},
		RuntimeOwnership:     RuntimeOwnershipUndetermined,
		CompensationBoundary: boundary,
		NextSafeAction:       mustAction(t, "setup.continue"),
	})

	assertErrorCode(t, err, ErrorCodeValidation)
}

func TestPF001NonSecretFactRejectsSensitiveNames(t *testing.T) {
	for _, name := range []string{"api_key", "provider_token", "database_password", "secret_value", "private_key_digest"} {
		t.Run(name, func(t *testing.T) {
			_, err := NewNonSecretFact(name, "redacted")
			var validation *ValidationError
			if !errors.As(err, &validation) || validation.Field() != "fact_name" {
				t.Fatalf("error = %T %v", err, err)
			}
		})
	}
}

func TestPF001NonSecretFactRejectsCredentialBearingValues(t *testing.T) {
	values := []string{
		"Bearer abcdefghijklmnopqrstuvwxyz",
		"ghp_0123456789abcdefghijklmnopqrstuv",
		"sk-proj-0123456789abcdefghijklmnop",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
		"https://user:password@example.test/status",
		"-----BEGIN PRIVATE KEY-----",
		"password=hunter2",
		"0123456789abcdef0123456789abcdef0123456789abcdef",
	}

	for _, value := range values {
		t.Run(value, func(t *testing.T) {
			_, err := NewNonSecretFact("probe_status", value)
			var validation *ValidationError
			if !errors.As(err, &validation) || validation.Field() != "fact_value" {
				t.Fatalf("error = %T %v", err, err)
			}
		})
	}
}

func TestPF001NonSecretFactPreservesConservativeSafeValues(t *testing.T) {
	values := []string{
		"verified",
		"24.0.7",
		"/Users/example/AgentMemory",
		`C:\\ProgramData\\AgentMemory`,
		"Windows 11 (build 26100)",
		"reused_external",
		"verified-13",
	}

	for _, value := range values {
		t.Run(value, func(t *testing.T) {
			fact, err := NewNonSecretFact("probe_status", value)
			if err != nil {
				t.Fatalf("safe fact value rejected: %v", err)
			}
			if fact.Value() != value {
				t.Fatalf("value = %q, want %q", fact.Value(), value)
			}
		})
	}
}

func TestPF001StepEvidenceEnforcesPhaseSpecificProofPolicy(t *testing.T) {
	plan := mustPlan(t, "proof-policy")

	tests := []struct {
		name      string
		phase     Phase
		artifact  bool
		ownership RuntimeOwnership
		wantError bool
	}{
		{name: "host starts undetermined", phase: PhaseVerifyHost, ownership: RuntimeOwnershipUndetermined},
		{name: "host cannot claim resolved ownership", phase: PhaseVerifyHost, ownership: RuntimeOwnershipReusedExternal, wantError: true},
		{name: "runtime requires artifact", phase: PhaseEnsureContainerRuntime, ownership: RuntimeOwnershipReusedExternal, wantError: true},
		{name: "runtime resolves external ownership", phase: PhaseEnsureContainerRuntime, artifact: true, ownership: RuntimeOwnershipReusedExternal},
		{name: "runtime resolves managed ownership", phase: PhaseEnsureContainerRuntime, artifact: true, ownership: RuntimeOwnershipProvisionedByAgentMemory},
		{name: "runtime cannot remain undetermined", phase: PhaseEnsureContainerRuntime, ownership: RuntimeOwnershipUndetermined, wantError: true},
		{name: "runtime cannot be not applicable", phase: PhaseEnsureContainerRuntime, ownership: RuntimeOwnershipNotApplicable, wantError: true},
		{name: "release requires artifact", phase: PhaseVerifyRelease, ownership: RuntimeOwnershipReusedExternal, wantError: true},
		{name: "release accepts artifact", phase: PhaseVerifyRelease, artifact: true, ownership: RuntimeOwnershipReusedExternal},
		{name: "compose requires artifact", phase: PhaseEnsureComposeBundle, ownership: RuntimeOwnershipProvisionedByAgentMemory, wantError: true},
		{name: "compose accepts artifact", phase: PhaseEnsureComposeBundle, artifact: true, ownership: RuntimeOwnershipProvisionedByAgentMemory},
		{name: "later phase carries resolved ownership", phase: PhaseVerifyReadiness, ownership: RuntimeOwnershipReusedExternal},
		{name: "later phase rejects undetermined ownership", phase: PhaseVerifyReadiness, ownership: RuntimeOwnershipUndetermined, wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := proofPolicyEvidenceInput(t, test.phase, plan, test.ownership)
			if test.artifact {
				input.VerifiedArtifactDigest = DigestBytes([]byte("verified artifact"))
			}
			evidence, err := NewStepEvidence(input)
			if test.wantError {
				assertErrorCode(t, err, ErrorCodeValidation)
				return
			}
			if err != nil {
				t.Fatalf("NewStepEvidence() error = %v", err)
			}
			if !evidence.valid() {
				t.Fatal("constructed proof does not remain valid")
			}
		})
	}
}

func TestPF001StepEvidenceValidationRejectsReFingerprintedPolicyViolations(t *testing.T) {
	plan := mustPlan(t, "proof-validation")
	validInput := proofPolicyEvidenceInput(
		t,
		PhaseVerifyRelease,
		plan,
		RuntimeOwnershipReusedExternal,
	)
	validInput.VerifiedArtifactDigest = DigestBytes([]byte("verified artifact"))
	fact, err := NewNonSecretFact("probe_status", "verified")
	if err != nil {
		t.Fatal(err)
	}
	validInput.Facts = []NonSecretFact{fact}
	valid := mustProofPolicyEvidence(t, validInput)

	tests := []struct {
		name   string
		mutate func(*StepEvidence)
	}{
		{name: "missing required artifact", mutate: func(evidence *StepEvidence) {
			evidence.verifiedArtifactDigest = Digest{}
		}},
		{name: "unresolved runtime ownership", mutate: func(evidence *StepEvidence) {
			evidence.runtimeOwnership = RuntimeOwnershipUndetermined
		}},
		{name: "credential-bearing fact", mutate: func(evidence *StepEvidence) {
			evidence.facts[0].value = "password=hunter2"
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := valid.clone()
			test.mutate(&evidence)
			evidence.fingerprint = evidence.calculateFingerprint()
			if evidence.valid() {
				t.Fatal("re-fingerprinted policy violation was accepted")
			}
		})
	}
}

func proofPolicyEvidenceInput(
	t testing.TB,
	phase Phase,
	plan PlanDigest,
	ownership RuntimeOwnership,
) StepEvidenceInput {
	t.Helper()
	boundary, err := NewCompensationBoundary("none")
	if err != nil {
		t.Fatal(err)
	}
	return StepEvidenceInput{
		Phase:                phase,
		Attempt:              1,
		PlanDigest:           plan,
		InputDigest:          DigestBytes([]byte("input")),
		OutputDigest:         DigestBytes([]byte("output")),
		RuntimeOwnership:     ownership,
		CompensationBoundary: boundary,
		NextSafeAction:       mustAction(t, "setup.continue"),
	}
}

func TestPF001PlanDigestAndEvidenceAreDeterministic(t *testing.T) {
	first := mustPlan(t, "canonical bytes")
	second := mustPlan(t, "canonical bytes")
	if !first.Equal(second) || first.String() != second.String() {
		t.Fatal("same canonical plan did not produce the same binding")
	}

	firstEvidence := testEvidence(t, PhaseVerifyRelease, 3, first, true)
	secondEvidence := testEvidence(t, PhaseVerifyRelease, 3, second, true)
	if !firstEvidence.Equal(secondEvidence) {
		t.Fatal("same evidence did not produce the same fingerprint")
	}
}

func TestPF001StepEvidenceExposesImmutablePersistenceFields(t *testing.T) {
	plan := mustPlan(t, "plan")
	evidence := testEvidence(t, PhaseVerifyRelease, 3, plan, true)

	if evidence.Phase() != PhaseVerifyRelease || evidence.Attempt() != 3 {
		t.Fatalf("cursor = (%s, %d)", evidence.Phase(), evidence.Attempt())
	}
	if !evidence.PlanDigest().Equal(plan) || evidence.InputDigest().IsZero() || evidence.OutputDigest().IsZero() {
		t.Fatal("evidence omitted required digest fields")
	}
	if evidence.VerifiedArtifactDigest().IsZero() || evidence.Fingerprint().IsZero() {
		t.Fatal("artifact evidence omitted its artifact or fingerprint digest")
	}
	if evidence.RuntimeOwnership() != RuntimeOwnershipReusedExternal {
		t.Fatalf("runtime ownership = %s", evidence.RuntimeOwnership())
	}
	if evidence.CompensationBoundary().String() != "remove_agentmemory_owned_partial" {
		t.Fatalf("compensation = %s", evidence.CompensationBoundary())
	}
	if evidence.NextSafeAction().String() != "setup.continue" {
		t.Fatalf("next action = %s", evidence.NextSafeAction())
	}
}

func TestPF001RuntimeOwnershipHasStablePersistenceNames(t *testing.T) {
	tests := []struct {
		ownership RuntimeOwnership
		want      string
	}{
		{RuntimeOwnershipUnknown, "unknown"},
		{RuntimeOwnershipUndetermined, "undetermined"},
		{RuntimeOwnershipReusedExternal, "reused_external"},
		{RuntimeOwnershipProvisionedByAgentMemory, "provisioned_by_agentmemory"},
		{RuntimeOwnershipNotApplicable, "not_applicable"},
	}
	for _, test := range tests {
		if got := test.ownership.String(); got != test.want {
			t.Errorf("ownership %d = %q, want %q", test.ownership, got, test.want)
		}
	}
}

func TestPF001ConstructorsReturnTypedValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		run  func() error
	}{
		{name: "empty plan", run: func() error { _, err := BindPlan(nil); return err }},
		{name: "unsafe action", run: func() error { _, err := NewSafeAction("run docker now"); return err }},
		{name: "unsafe boundary", run: func() error { _, err := NewCompensationBoundary("rm -rf"); return err }},
		{name: "invalid operation", run: func() error { _, err := NewOperationID("../operation"); return err }},
		{name: "zero digest", run: func() error {
			_, err := ParseDigest("0000000000000000000000000000000000000000000000000000000000000000")
			return err
		}},
		{name: "short digest", run: func() error { _, err := ParseDigest("abcd"); return err }},
		{name: "nonhex digest", run: func() error {
			_, err := ParseDigest("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
			return err
		}},
		{name: "empty operation", run: func() error { _, err := NewOperationID(""); return err }},
		{name: "padded operation", run: func() error { _, err := NewOperationID(" operation "); return err }},
		{name: "control fact value", run: func() error { _, err := NewNonSecretFact("probe", "line\nbreak"); return err }},
		{name: "invalid fact name", run: func() error { _, err := NewNonSecretFact("Probe Status", "ok"); return err }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertErrorCode(t, test.run(), ErrorCodeValidation)
		})
	}
}

func TestPF001DigestRoundTrip(t *testing.T) {
	digest := DigestBytes([]byte("round-trip"))
	parsed, err := ParseDigest(digest.String())
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Equal(digest) {
		t.Fatal("parsed digest changed value")
	}
	plan, err := ParsePlanDigest(digest.String())
	if err != nil {
		t.Fatal(err)
	}
	if plan.String() != digest.String() {
		t.Fatal("parsed plan digest changed value")
	}
}
