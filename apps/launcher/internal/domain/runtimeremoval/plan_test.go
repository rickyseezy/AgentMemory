package runtimeremoval

import (
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF001ManagedRuntimeRemovalPlanRequiresFinalizedOwnershipAndEmptyExhaustiveScan(t *testing.T) {
	t.Parallel()
	plan, ownership := removalOwnershipFixture(t, runtimeinstall.OwnershipProvisionedByAgentMemory)
	scan := emptyRemovalScan(t, ownership)
	operationID, _ := install.NewOperationID("019f60a0-0000-7abc-8123-0123456789ab")
	removal, err := NewPlan(operationID, plan.CanonicalBytes(), ownership, scan)
	if err != nil || !removal.Valid() || removal.OperationID() != operationID ||
		removal.SourceOperationID() != ownership.OperationID() || removal.Platform() != runtimeinstall.PlatformLinux ||
		removal.ScanDigest() != scan.Digest() || removal.ImpactConfirmation() != ImpactPreserveLocalRuntimeData {
		t.Fatalf("removal plan = %+v/%v", removal, err)
	}
	canonical := removal.CanonicalRuntimePlan()
	canonical[0] ^= 0xff
	if !removal.Valid() {
		t.Fatal("removal plan exposed mutable canonical runtime authority")
	}
	restored, err := RestorePlan(removal.Snapshot())
	if err != nil || restored.Digest() != removal.Digest() {
		t.Fatalf("restore removal plan = %+v/%v", restored, err)
	}
	removal.endpoint = "unix:///foreign.sock"
	if removal.Valid() {
		t.Fatal("mutated removal plan remained valid")
	}
}

func TestPF001ManagedRuntimeRemovalPlanRefusesExternalUncertainOrDependentRuntime(t *testing.T) {
	t.Parallel()
	managedPlan, managed := removalOwnershipFixture(t, runtimeinstall.OwnershipProvisionedByAgentMemory)
	externalPlan, external := removalOwnershipFixture(t, runtimeinstall.OwnershipReusedExternal)
	operationID, _ := install.NewOperationID("019f60a0-0000-7abc-8123-0123456789ab")
	if _, err := NewPlan(operationID, externalPlan.CanonicalBytes(), external, emptyRemovalScan(t, external)); err == nil {
		t.Fatal("external runtime removal was authorized")
	}
	dependent := emptyRemovalScanInputs(managed)
	dependent[0].Count = 1
	dependentScan, err := NewDependencyScan(DependencyScanInput{
		OwnershipRecordDigest: managed.Digest(), Endpoint: managed.Endpoint(), Proofs: dependent,
	})
	if err != nil {
		t.Fatal(err)
	}
	if dependentScan.SafeToRemove() {
		t.Fatal("dependent scan was safe")
	}
	if _, err := NewPlan(operationID, managedPlan.CanonicalBytes(), managed, dependentScan); err == nil {
		t.Fatal("dependent runtime removal was authorized")
	}
	uncertain := emptyRemovalScanInputs(managed)
	uncertain[3].Complete = false
	if _, err := NewDependencyScan(DependencyScanInput{
		OwnershipRecordDigest: managed.Digest(), Endpoint: managed.Endpoint(), Proofs: uncertain,
	}); err == nil {
		t.Fatal("uncertain scan was accepted")
	}
	missing := emptyRemovalScanInputs(managed)[:6]
	if _, err := NewDependencyScan(DependencyScanInput{
		OwnershipRecordDigest: managed.Digest(), Endpoint: managed.Endpoint(), Proofs: missing,
	}); err == nil {
		t.Fatal("incomplete scan was accepted")
	}
}

func TestPF001ManagedRuntimeRemovalOperationPersistsConsentBeforeDestruction(t *testing.T) {
	t.Parallel()
	plan, ownership := removalOwnershipFixture(t, runtimeinstall.OwnershipProvisionedByAgentMemory)
	operationID, _ := install.NewOperationID("019f60a0-0000-7abc-8123-0123456789ab")
	scan := emptyRemovalScan(t, ownership)
	removal, _ := NewPlan(operationID, plan.CanonicalBytes(), ownership, scan)
	operation, err := NewOperation(removal)
	if err != nil || operation.State() != StateAwaitingConsent {
		t.Fatalf("operation = %+v/%v", operation, err)
	}
	consent := runtimeinstall.Sum([]byte("second-impact-consent"))
	if err := operation.AuthorizeRemoval(removal.Digest(), consent); err != nil {
		t.Fatal(err)
	}
	if err := operation.BeginRemoval(removal.Digest(), scan.Digest()); err != nil {
		t.Fatal(err)
	}
	receipt := runtimeinstall.Sum([]byte("native-removal-and-absence"))
	if err := operation.CompleteRemoval(removal.Digest(), receipt); err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreOperation(operation.Snapshot())
	if err != nil || restored.State() != StateRemoved || restored.ConsentReceipt() != consent ||
		restored.RemovalReceipt() != receipt || restored.Version() != 3 {
		t.Fatalf("restored = %+v/%v", restored, err)
	}
	if err := restored.CompleteRemoval(removal.Digest(), receipt); err != nil || restored.Version() != 3 {
		t.Fatalf("idempotent completion = %v/%d", err, restored.Version())
	}
	tampered := operation.Snapshot()
	tampered.ConsentReceipt = runtimeinstall.Hash{}
	if _, err := RestoreOperation(tampered); err == nil {
		t.Fatal("tampered removal operation was restored")
	}
	tampered = operation.Snapshot()
	tampered.Plan.Endpoint = "unix:///foreign.sock"
	if _, err := RestoreOperation(tampered); err == nil {
		t.Fatal("substituted persisted removal plan was restored")
	}
}

func emptyRemovalScan(t *testing.T, ownership runtimeinstall.RuntimeOwnershipRecord) DependencyScan {
	t.Helper()
	scan, err := NewDependencyScan(DependencyScanInput{
		OwnershipRecordDigest: ownership.Digest(), Endpoint: ownership.Endpoint(),
		Proofs: emptyRemovalScanInputs(ownership),
	})
	if err != nil {
		t.Fatal(err)
	}
	return scan
}

func emptyRemovalScanInputs(_ runtimeinstall.RuntimeOwnershipRecord) []DependencyProofInput {
	result := make([]DependencyProofInput, 0, len(orderedDependencies))
	for _, kind := range orderedDependencies {
		result = append(result, DependencyProofInput{
			Kind: kind, EvidenceDigest: runtimeinstall.Sum([]byte("empty-" + kind.String())), Complete: true,
		})
	}
	return result
}

func removalOwnershipFixture(
	t *testing.T,
	disposition runtimeinstall.OwnershipDisposition,
) (runtimeinstall.Plan, runtimeinstall.RuntimeOwnershipRecord) {
	t.Helper()
	host, err := runtimeinstall.NewHostCapabilities(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "24.04", true, true, true, true,
		8, 32<<30, 24<<30, 100<<30,
	)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := runtimeinstall.NewCertifiedRuntime(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "docker_engine", "29.6.1", "stable", 7,
		runtimeinstall.Sum([]byte("catalog")), runtimeinstall.RuntimeTermsInput{
			ID: runtimeinstall.DockerEngineTermsID, Version: "apache-2.0", URL: "https://docs.docker.com/engine/",
			Digest: runtimeinstall.Sum([]byte("terms")), Presentation: runtimeinstall.TermsPresentationAgentMemory,
		}, 1, 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	discovery := runtimeinstall.NewAbsentRuntimeDiscovery()
	if disposition == runtimeinstall.OwnershipReusedExternal {
		discovery, err = runtimeinstall.NewRuntimeDiscovery(
			runtimeinstall.RuntimeConditionRunning, catalog.Product(), catalog.Version(),
			"unix:///run/user/1000/docker.sock", true, true, true, disposition, 0,
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	plan, err := runtimeinstall.NewPlanV1(host, discovery, catalog)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := runtimeinstall.NewOperation("019f60a0-1111-7abc-8123-0123456789ab", plan.Digest())
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range runtimeinstall.OrderedPhases() {
		artifact := runtimeinstall.Hash{}
		if phase >= runtimeinstall.PhaseVerifyRuntimeArtifact {
			artifact = runtimeinstall.Sum([]byte("runtime-artifact"))
		}
		ownership := runtimeinstall.OwnershipUnknown
		if phase == runtimeinstall.PhaseVerifyRuntimeCapabilities {
			ownership = disposition
		}
		evidence, evidenceErr := runtimeinstall.NewTransitionEvidence(
			phase, operation.Attempt(), plan.Digest(), runtimeinstall.Sum([]byte("before-"+phase.String())),
			runtimeinstall.Sum([]byte("after-"+phase.String())), artifact, ownership,
		)
		if evidenceErr != nil || operation.Complete(phase, evidence) != nil {
			t.Fatalf("complete %s: %v", phase, evidenceErr)
		}
	}
	authority, err := runtimeinstall.NewRuntimeOwnershipAuthority(runtimeinstall.RuntimeOwnershipAuthoritySnapshot{
		Vendor: plan.Product(), Version: plan.Version(), Channel: plan.Channel(),
		Endpoint: "unix:///run/user/1000/docker.sock", Context: "explicit-local-endpoint",
		Publisher: "docker-stable:key", PublisherDigest: runtimeinstall.Sum([]byte("publisher")),
		ArtifactDigest: runtimeinstall.Sum([]byte("runtime-artifact")),
		Components:     []string{"engine@29.6.1"}, Settings: []string{"service:docker.service"},
	})
	if err != nil {
		t.Fatal(err)
	}
	record, err := runtimeinstall.NewRuntimeOwnershipRecord(plan, operation.Snapshot(), authority, nil)
	if err != nil {
		t.Fatal(err)
	}
	return plan, record
}
