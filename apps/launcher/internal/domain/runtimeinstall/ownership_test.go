package runtimeinstall

import (
	"testing"
)

func TestPF006OwnershipRecordCapturesPreparedMutationAndFinalEvidence(t *testing.T) {
	t.Parallel()
	plan, err := NewPlanV1(supportedHost(t), NewAbsentRuntimeDiscovery(), certifiedCatalog(t))
	if err != nil {
		t.Fatal(err)
	}
	operation, err := NewOperation("018f47f2-a5a1-7cc1-8e4f-123456789abc", plan.Digest())
	if err != nil {
		t.Fatal(err)
	}
	completeOwnershipPhases(t, operation, PhaseAwaitRuntimeConsent)
	authority := ownershipAuthorityForTest(t, plan)
	prepared, err := NewRuntimeOwnershipRecord(plan, operation.Snapshot(), authority, nil)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Status() != OwnershipStatusPrepared ||
		prepared.Disposition() != OwnershipProvisionedByAgentMemory ||
		prepared.OperationID() != operation.ID() || prepared.PlanDigest() != plan.Digest() ||
		prepared.Vendor() != plan.Product() || prepared.Version() != plan.Version() ||
		prepared.Channel() != plan.Channel() || prepared.Endpoint() != "unix:///run/user/1000/docker.sock" ||
		prepared.Context() != "explicit-local-endpoint" || prepared.Publisher() != "docker-release-key-2026" ||
		prepared.PreExistingStateDigest().IsZero() || prepared.ConsentDigest().IsZero() ||
		prepared.ArtifactDigest() != authority.ArtifactDigest() || len(prepared.Mutations()) != 0 ||
		len(prepared.Continuations()) != 0 || prepared.CompatibilityDigest() != (Hash{}) {
		t.Fatal("prepared ownership record omitted an exact authority or pre-mutation binding")
	}

	completeOwnershipPhases(t, operation, PhaseInstallPrerequisites)
	reboot := Sum([]byte("one-use-reboot-receipt"))
	if err := operation.RequireReboot(reboot); err != nil {
		t.Fatal(err)
	}
	paused, err := NewRuntimeOwnershipRecord(plan, operation.Snapshot(), authority, &prepared)
	if err != nil {
		t.Fatal(err)
	}
	if continuations := paused.Continuations(); len(continuations) != 1 || continuations[0] != reboot {
		t.Fatal("reboot continuation was not retained in ownership evidence")
	}
	if len(paused.Mutations()) != 2 || len(paused.PrivilegeReceiptDigests()) != 1 {
		t.Fatal("prepared ownership record omitted acquired/prerequisite mutation evidence")
	}
	if err := operation.ResumeAfterReboot(reboot); err != nil {
		t.Fatal(err)
	}
	completeOwnershipPhases(t, operation, PhaseVerifyRuntimeCapabilities)
	finalized, err := NewRuntimeOwnershipRecord(plan, operation.Snapshot(), authority, &paused)
	if err != nil {
		t.Fatal(err)
	}
	if finalized.Status() != OwnershipStatusFinalized || finalized.OperationState() != OperationStateReady ||
		finalized.CompatibilityDigest().IsZero() || len(finalized.Mutations()) != 4 ||
		len(finalized.PrivilegeReceiptDigests()) != 2 || len(finalized.Continuations()) != 1 ||
		!finalized.CanFollow(paused) || finalized.Digest().IsZero() {
		t.Fatal("final ownership record omitted recovery, mutation, or compatibility evidence")
	}
	components := finalized.Components()
	components[0] = "tampered"
	settings := finalized.Settings()
	settings[0] = "tampered"
	mutations := finalized.Mutations()
	mutations[0].AfterDigest = Hash{}
	if finalized.Components()[0] == "tampered" || finalized.Settings()[0] == "tampered" ||
		finalized.Mutations()[0].AfterDigest.IsZero() {
		t.Fatal("ownership record exposed mutable storage")
	}
	restored, err := RestoreRuntimeOwnershipRecord(finalized.Snapshot())
	if err != nil || restored.Digest() != finalized.Digest() || !restored.CanFollow(paused) {
		t.Fatalf("RestoreRuntimeOwnershipRecord()=%v,%v", restored.Digest(), err)
	}
}

func TestPF006OwnershipRecordRejectsSubstitutionRegressionAndPrematureProjection(t *testing.T) {
	t.Parallel()
	plan, _ := NewPlanV1(supportedHost(t), NewAbsentRuntimeDiscovery(), certifiedCatalog(t))
	operation, _ := NewOperation("018f47f2-a5a1-7cc1-8e4f-123456789abc", plan.Digest())
	authority := ownershipAuthorityForTest(t, plan)
	if RuntimeOwnershipRequired(operation.Snapshot()) {
		t.Fatal("ownership record was required before consent and mutation authority")
	}
	if _, err := NewRuntimeOwnershipRecord(plan, operation.Snapshot(), authority, nil); err == nil {
		t.Fatal("premature ownership record was accepted")
	}
	completeOwnershipPhases(t, operation, PhaseAwaitRuntimeConsent)
	if !RuntimeOwnershipRequired(operation.Snapshot()) {
		t.Fatal("ownership record was not required before first mutation")
	}
	base, err := NewRuntimeOwnershipRecord(plan, operation.Snapshot(), authority, nil)
	if err != nil {
		t.Fatal(err)
	}
	badAuthority := authority.Snapshot()
	badAuthority.Endpoint = "tcp://remote.example:2375"
	foreign, err := NewRuntimeOwnershipAuthority(badAuthority)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRuntimeOwnershipRecord(plan, operation.Snapshot(), foreign, &base); err == nil {
		t.Fatal("authority substitution was accepted")
	}
	tampered := base.Snapshot()
	tampered.Digest = Sum([]byte("forged-record"))
	if _, err := RestoreRuntimeOwnershipRecord(tampered); err == nil {
		t.Fatal("record digest substitution was accepted")
	}
	if base.CanFollow(base) {
		t.Fatal("same-revision record claimed monotonic advancement")
	}
}

func TestPF006OwnershipAuthorityRejectsIncompleteOrAmbiguousFacts(t *testing.T) {
	t.Parallel()
	plan, _ := NewPlanV1(supportedHost(t), NewAbsentRuntimeDiscovery(), certifiedCatalog(t))
	valid := ownershipAuthorityForTest(t, plan).Snapshot()
	tests := map[string]func(*RuntimeOwnershipAuthoritySnapshot){
		"vendor":      func(value *RuntimeOwnershipAuthoritySnapshot) { value.Vendor = "" },
		"version":     func(value *RuntimeOwnershipAuthoritySnapshot) { value.Version = " latest " },
		"channel":     func(value *RuntimeOwnershipAuthoritySnapshot) { value.Channel = "edge" },
		"endpoint":    func(value *RuntimeOwnershipAuthoritySnapshot) { value.Endpoint = "" },
		"context":     func(value *RuntimeOwnershipAuthoritySnapshot) { value.Context = "" },
		"publisher":   func(value *RuntimeOwnershipAuthoritySnapshot) { value.Publisher = "" },
		"publisher d": func(value *RuntimeOwnershipAuthoritySnapshot) { value.PublisherDigest = Hash{} },
		"artifact":    func(value *RuntimeOwnershipAuthoritySnapshot) { value.ArtifactDigest = Hash{} },
		"components":  func(value *RuntimeOwnershipAuthoritySnapshot) { value.Components = nil },
		"settings":    func(value *RuntimeOwnershipAuthoritySnapshot) { value.Settings = []string{"z", "a"} },
		"duplicate":   func(value *RuntimeOwnershipAuthoritySnapshot) { value.Components = []string{"engine", "engine"} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.Components = append([]string(nil), valid.Components...)
			candidate.Settings = append([]string(nil), valid.Settings...)
			mutate(&candidate)
			if _, err := NewRuntimeOwnershipAuthority(candidate); err == nil {
				t.Fatal("invalid ownership authority was accepted")
			}
		})
	}
}

func ownershipAuthorityForTest(t *testing.T, plan Plan) RuntimeOwnershipAuthority {
	t.Helper()
	authority, err := NewRuntimeOwnershipAuthority(RuntimeOwnershipAuthoritySnapshot{
		Vendor: plan.Product(), Version: plan.Version(), Channel: plan.Channel(),
		Endpoint: "unix:///run/user/1000/docker.sock", Context: "explicit-local-endpoint",
		Publisher: "docker-release-key-2026", PublisherDigest: Sum([]byte("publisher")),
		ArtifactDigest: Sum([]byte("artifact")),
		Components:     []string{"compose@2.39.1", "engine@28.3.2"},
		Settings:       []string{"repository:docker-stable", "service:docker.service"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func completeOwnershipPhases(t *testing.T, operation *Operation, through Phase) {
	t.Helper()
	for operation.State() == OperationStateRunning && operation.CurrentPhase() <= through {
		phase := operation.CurrentPhase()
		artifact := Hash{}
		if phase >= PhaseVerifyRuntimeArtifact {
			artifact = Sum([]byte("artifact"))
		}
		ownership := OwnershipUnknown
		if phase == PhaseVerifyRuntimeCapabilities {
			ownership = OwnershipProvisionedByAgentMemory
		}
		evidence, err := NewTransitionEvidence(
			phase, operation.Attempt(), operation.PlanDigest(),
			Sum([]byte("before-"+phase.String())), Sum([]byte("after-"+phase.String())),
			artifact, ownership,
		)
		if err != nil || operation.Complete(phase, evidence) != nil {
			t.Fatalf("complete %s: %v", phase, err)
		}
	}
}
