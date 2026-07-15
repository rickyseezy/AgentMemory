package runtimeremoval

import (
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF001ManagedRuntimeRemovalAccessorsAndEveryDurableState(t *testing.T) {
	t.Parallel()
	runtimePlan, ownership := removalOwnershipFixture(t, runtimeinstall.OwnershipProvisionedByAgentMemory)
	scan := emptyRemovalScan(t, ownership)
	operationID, _ := install.NewOperationID("019f60a0-0000-7abc-8123-0123456789ab")
	plan, err := NewPlan(operationID, runtimePlan.CanonicalBytes(), ownership, scan)
	if err != nil {
		t.Fatal(err)
	}
	if plan.RuntimePlanDigest() != runtimePlan.Digest() || plan.OwnershipRecordDigest() != ownership.Digest() ||
		plan.Product() != ownership.Vendor() || plan.Version() != ownership.Version() ||
		plan.Endpoint() != ownership.Endpoint() || plan.ArtifactDigest() != ownership.ArtifactDigest() ||
		len(scan.Proofs()) != len(OrderedDependencyKinds()) {
		t.Fatal("removal plan accessors did not retain authority")
	}
	operation, _ := NewOperation(plan)
	if operation.ID() != operationID || operation.PlanDigest() != plan.Digest() ||
		operation.Plan().Digest() != plan.Digest() || !operation.ExecutionScanDigest().IsZero() {
		t.Fatal("removal operation accessors did not retain authority")
	}
	if _, err := RestoreOperation(operation.Snapshot()); err != nil {
		t.Fatal(err)
	}
	consent := runtimeinstall.Sum([]byte("consent"))
	if err := operation.AuthorizeRemoval(plan.Digest(), consent); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreOperation(operation.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if err := operation.BeginRemoval(plan.Digest(), scan.Digest()); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreOperation(operation.Snapshot()); err != nil {
		t.Fatal(err)
	}
	declined, _ := NewOperation(plan)
	if err := declined.Decline(plan.Digest()); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreOperation(declined.Snapshot()); err != nil {
		t.Fatal(err)
	}
}

func TestPF001ManagedRuntimeRemovalRejectsInvalidTransitionsAndSnapshots(t *testing.T) {
	t.Parallel()
	runtimePlan, ownership := removalOwnershipFixture(t, runtimeinstall.OwnershipProvisionedByAgentMemory)
	scan := emptyRemovalScan(t, ownership)
	operationID, _ := install.NewOperationID("019f60a0-0000-7abc-8123-0123456789ab")
	plan, _ := NewPlan(operationID, runtimePlan.CanonicalBytes(), ownership, scan)
	operation, _ := NewOperation(plan)
	foreign := runtimeinstall.Sum([]byte("foreign"))
	if operation.AuthorizeRemoval(foreign, foreign) == nil || operation.Decline(foreign) == nil ||
		operation.BeginRemoval(plan.Digest(), scan.Digest()) == nil ||
		operation.CompleteRemoval(plan.Digest(), foreign) == nil {
		t.Fatal("invalid removal transition was accepted")
	}
	if operation.AuthorizeRemoval(plan.Digest(), foreign) != nil ||
		operation.AuthorizeRemoval(plan.Digest(), foreign) == nil || operation.Decline(plan.Digest()) == nil ||
		operation.BeginRemoval(foreign, scan.Digest()) == nil || operation.BeginRemoval(plan.Digest(), runtimeinstall.Hash{}) == nil ||
		operation.BeginRemoval(plan.Digest(), scan.Digest()) != nil ||
		operation.CompleteRemoval(foreign, foreign) == nil || operation.CompleteRemoval(plan.Digest(), foreign) != nil ||
		operation.CompleteRemoval(plan.Digest(), runtimeinstall.Sum([]byte("different"))) == nil {
		t.Fatal("removal transition guards failed")
	}

	for name, mutate := range map[string]func(*OperationSnapshot){
		"schema":   func(snapshot *OperationSnapshot) { snapshot.SchemaVersion++ },
		"identity": func(snapshot *OperationSnapshot) { snapshot.OperationID = "invalid" },
		"plan identity": func(snapshot *OperationSnapshot) {
			snapshot.Plan.OperationID = "019f60a0-2222-7abc-8123-0123456789ab"
		},
		"unknown":   func(snapshot *OperationSnapshot) { snapshot.State = StateUnknown },
		"future":    func(snapshot *OperationSnapshot) { snapshot.State = State(255) },
		"version":   func(snapshot *OperationSnapshot) { snapshot.Version = 99 },
		"execution": func(snapshot *OperationSnapshot) { snapshot.ExecutionScan = runtimeinstall.Hash{} },
	} {
		t.Run(name, func(t *testing.T) {
			snapshot := operation.Snapshot()
			mutate(&snapshot)
			if _, err := RestoreOperation(snapshot); err == nil {
				t.Fatal("invalid removal snapshot was restored")
			}
		})
	}
}

func TestPF001ManagedRuntimeRemovalRejectsMalformedDependencyVocabularyAndPlanSnapshots(t *testing.T) {
	t.Parallel()
	runtimePlan, ownership := removalOwnershipFixture(t, runtimeinstall.OwnershipProvisionedByAgentMemory)
	inputs := emptyRemovalScanInputs(ownership)
	inputs[1].Kind = DependencyContainers
	if _, err := NewDependencyScan(DependencyScanInput{
		OwnershipRecordDigest: ownership.Digest(), Endpoint: ownership.Endpoint(), Proofs: inputs,
	}); err == nil {
		t.Fatal("duplicate/reordered dependency kind was accepted")
	}
	inputs = emptyRemovalScanInputs(ownership)
	inputs[0].EvidenceDigest = runtimeinstall.Hash{}
	if _, err := NewDependencyScan(DependencyScanInput{
		OwnershipRecordDigest: ownership.Digest(), Endpoint: ownership.Endpoint(), Proofs: inputs,
	}); err == nil {
		t.Fatal("zero dependency evidence was accepted")
	}
	operationID, _ := install.NewOperationID("019f60a0-0000-7abc-8123-0123456789ab")
	plan, _ := NewPlan(operationID, runtimePlan.CanonicalBytes(), ownership, emptyRemovalScan(t, ownership))
	for name, mutate := range map[string]func(*PlanSnapshot){
		"schema":    func(snapshot *PlanSnapshot) { snapshot.SchemaVersion++ },
		"operation": func(snapshot *PlanSnapshot) { snapshot.OperationID = "invalid" },
		"source":    func(snapshot *PlanSnapshot) { snapshot.SourceOperationID = "invalid" },
		"digest":    func(snapshot *PlanSnapshot) { snapshot.Digest = runtimeinstall.Sum([]byte("foreign")) },
	} {
		t.Run(name, func(t *testing.T) {
			snapshot := plan.Snapshot()
			mutate(&snapshot)
			if _, err := RestorePlan(snapshot); err == nil {
				t.Fatal("invalid removal plan snapshot was restored")
			}
		})
	}
	if DependencyUnknown.String() != "unknown" || DependencyKind(255).String() != "unknown" {
		t.Fatal("unknown dependency vocabulary is not closed")
	}
}
