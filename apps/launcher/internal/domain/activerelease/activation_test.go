package activerelease

import (
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001ActivationAggregateEnforcesDurableCommitOrder(t *testing.T) {
	t.Parallel()

	operationID, err := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := install.BindPlan([]byte("canonical plan"))
	if err != nil {
		t.Fatal(err)
	}
	pointer := mustPointer(t, validPointerInput())
	aggregate, err := NewActivation(operationID, plan, install.Digest{}, pointer)
	if err != nil {
		t.Fatal(err)
	}
	if aggregate.State() != StateCreated || aggregate.Version() != 0 || !aggregate.Pointer().Digest().Equal(pointer.Digest()) {
		t.Fatalf("new activation = %+v", aggregate.Snapshot())
	}
	if aggregate.OperationID() != operationID || !aggregate.PlanDigest().Equal(plan) ||
		!aggregate.ExpectedHostDigest().IsZero() || !aggregate.CoreStageDigest().IsZero() {
		t.Fatal("new activation accessors lost a binding")
	}
	createdSnapshot := aggregate.Snapshot()
	if createdSnapshot.SchemaVersion != activationSchemaVersion || createdSnapshot.OperationID != operationID.String() ||
		createdSnapshot.PlanDigest != plan.String() || createdSnapshot.ExpectedHostDigest != "" ||
		createdSnapshot.State != StateCreated || createdSnapshot.CoreStageDigest != "" || createdSnapshot.Version != 0 ||
		createdSnapshot.Target.PointerDigest != pointer.Digest().String() {
		t.Fatalf("created snapshot = %+v", createdSnapshot)
	}

	stage := install.DigestBytes([]byte("core stage"))
	if err := aggregate.RecordCorePrepared(stage); err != nil {
		t.Fatal(err)
	}
	if err := aggregate.RecordHostCommitted(pointer.Digest()); err != nil {
		t.Fatal(err)
	}
	if err := aggregate.RecordCoreCommitted(stage, pointer.Digest()); err != nil {
		t.Fatal(err)
	}
	if aggregate.State() != StateCommitted || aggregate.Version() != 3 {
		t.Fatalf("committed activation = %+v", aggregate.Snapshot())
	}
	committedSnapshot := aggregate.Snapshot()
	if committedSnapshot.State != StateCommitted || committedSnapshot.Version != 3 ||
		committedSnapshot.CoreStageDigest != stage.String() || committedSnapshot.ExpectedHostDigest != "" {
		t.Fatalf("committed snapshot = %+v", committedSnapshot)
	}

	restored, err := RestoreActivation(aggregate.Snapshot())
	if err != nil || restored.State() != StateCommitted || !restored.CoreStageDigest().Equal(stage) {
		t.Fatalf("RestoreActivation() = %+v, %v", restored, err)
	}
}

func TestPF001CoreStageDigestMatchesPythonCanonicalContract(t *testing.T) {
	t.Parallel()
	pointer := mustPointer(t, validPointerInput())
	if pointer.Digest().String() != "5096de10e5cbbf8ddc2cfae38b2283beff89fa1354272913d87fceb484fcbd7b" {
		t.Fatalf("pointer digest = %s", pointer.Digest().String())
	}
	operationID, err := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	if err != nil {
		t.Fatal(err)
	}
	stage, err := StageDigest(operationID, pointer)
	if err != nil {
		t.Fatal(err)
	}
	if stage.String() != "3eecdea699b3fc251c76079c92ac88e29b24d3f496255347b08928a9ae13b2c5" {
		t.Fatalf("stage digest = %s", stage.String())
	}
	if _, err := StageDigest(install.OperationID{}, pointer); err == nil {
		t.Fatal("StageDigest accepted empty operation")
	}
	if _, err := StageDigest(operationID, Pointer{}); err == nil {
		t.Fatal("StageDigest accepted empty pointer")
	}
}

func TestPF001ActivationConstructorAndRestoreBindEverySnapshotField(t *testing.T) {
	t.Parallel()

	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	plan, _ := install.BindPlan([]byte("canonical plan"))
	pointer := mustPointer(t, validPointerInput())
	previous := install.DigestBytes([]byte("previous"))
	for index, candidate := range []struct {
		operation install.OperationID
		plan      install.PlanDigest
		pointer   Pointer
	}{
		{operation: install.OperationID{}, plan: plan, pointer: pointer},
		{operation: operationID, plan: install.PlanDigest{}, pointer: pointer},
		{operation: operationID, plan: plan, pointer: Pointer{}},
	} {
		if _, err := NewActivation(candidate.operation, candidate.plan, previous, candidate.pointer); err == nil {
			t.Fatalf("invalid constructor %d was accepted", index)
		}
	}
	activation, err := NewActivation(operationID, plan, previous, pointer)
	if err != nil {
		t.Fatal(err)
	}
	if !activation.ExpectedHostDigest().Equal(previous) {
		t.Fatal("expected host digest was not retained")
	}
	snapshot := activation.Snapshot()
	if snapshot.ExpectedHostDigest != previous.String() {
		t.Fatalf("expected host snapshot = %q", snapshot.ExpectedHostDigest)
	}

	invalidDigests := []func(*ActivationSnapshot){
		func(value *ActivationSnapshot) { value.PlanDigest = "bad" },
		func(value *ActivationSnapshot) { value.ExpectedHostDigest = "bad" },
		func(value *ActivationSnapshot) { value.Target.ManifestDigest = "bad" },
		func(value *ActivationSnapshot) { value.CoreStageDigest = "bad" },
	}
	for index, mutate := range invalidDigests {
		candidate := snapshot
		mutate(&candidate)
		if _, err := RestoreActivation(candidate); err == nil {
			t.Fatalf("invalid digest snapshot %d was accepted", index)
		}
	}

	stage := install.DigestBytes([]byte("stage"))
	_ = activation.RecordCorePrepared(stage)
	prepared := activation.Snapshot()
	for _, state := range []State{StateCorePrepared, StateHostCommitted, StateCommitted} {
		candidate := prepared
		candidate.State = state
		candidate.Version = uint64(state - StateCreated)
		if _, err := RestoreActivation(candidate); err != nil {
			t.Fatalf("valid state %v restore failed: %v", state, err)
		}
	}
	missingStage := prepared
	missingStage.CoreStageDigest = ""
	if _, err := RestoreActivation(missingStage); err == nil {
		t.Fatal("prepared state without stage was accepted")
	}
}

func TestPF001ActivationAggregateRejectsSkippedOrCrossBoundTransitions(t *testing.T) {
	t.Parallel()

	activation := newActivationForTest(t)
	pointerDigest := activation.Pointer().Digest()
	stage := install.DigestBytes([]byte("stage"))
	foreign := install.DigestBytes([]byte("foreign"))
	if err := activation.RecordHostCommitted(pointerDigest); err == nil {
		t.Fatal("host commit skipped core preparation")
	}
	if err := activation.RecordCorePrepared(install.Digest{}); err == nil {
		t.Fatal("core preparation accepted empty receipt")
	}
	if err := activation.RecordCorePrepared(stage); err != nil {
		t.Fatal(err)
	}
	if err := activation.RecordCorePrepared(stage); err != nil {
		t.Fatalf("idempotent prepare failed: %v", err)
	}
	if err := activation.RecordCorePrepared(foreign); err == nil {
		t.Fatal("idempotent prepare accepted a foreign receipt")
	}
	if err := activation.RecordHostCommitted(foreign); err == nil {
		t.Fatal("host commit accepted foreign pointer")
	}
	if err := activation.RecordHostCommitted(pointerDigest); err != nil {
		t.Fatal(err)
	}
	if err := activation.RecordHostCommitted(pointerDigest); err != nil {
		t.Fatalf("idempotent host commit failed: %v", err)
	}
	if err := activation.RecordCoreCommitted(foreign, pointerDigest); err == nil {
		t.Fatal("core commit accepted foreign stage")
	}
	if err := activation.RecordCoreCommitted(stage, foreign); err == nil {
		t.Fatal("core commit accepted foreign pointer")
	}
	if err := activation.RecordCoreCommitted(stage, pointerDigest); err != nil {
		t.Fatal(err)
	}
	if err := activation.RecordCoreCommitted(stage, pointerDigest); err != nil {
		t.Fatalf("idempotent Core commit failed: %v", err)
	}
	if err := activation.RecordCoreCommitted(foreign, pointerDigest); err == nil {
		t.Fatal("committed state accepted a foreign stage")
	}
}

func TestPF001ActivationRestoreRejectsUnknownOrContradictorySnapshots(t *testing.T) {
	t.Parallel()

	activation := newActivationForTest(t)
	snapshots := []ActivationSnapshot{
		{},
		func() ActivationSnapshot { value := activation.Snapshot(); value.SchemaVersion++; return value }(),
		func() ActivationSnapshot { value := activation.Snapshot(); value.State = StateCommitted; return value }(),
		func() ActivationSnapshot { value := activation.Snapshot(); value.Version = 2; return value }(),
		func() ActivationSnapshot { value := activation.Snapshot(); value.OperationID = "bad/id"; return value }(),
		func() ActivationSnapshot { value := activation.Snapshot(); value.PlanDigest = "bad"; return value }(),
		func() ActivationSnapshot {
			value := activation.Snapshot()
			value.ExpectedHostDigest = "bad"
			return value
		}(),
		func() ActivationSnapshot {
			value := activation.Snapshot()
			value.Target.PointerDigest = "bad"
			return value
		}(),
		func() ActivationSnapshot { value := activation.Snapshot(); value.State = StateUnknown; return value }(),
	}
	for index, snapshot := range snapshots {
		if _, err := RestoreActivation(snapshot); err == nil {
			t.Fatalf("snapshot %d was accepted", index)
		}
	}
}

func newActivationForTest(t *testing.T) *Activation {
	t.Helper()
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	plan, _ := install.BindPlan([]byte("canonical plan"))
	activation, err := NewActivation(operationID, plan, install.DigestBytes([]byte("previous")), mustPointer(t, validPointerInput()))
	if err != nil {
		t.Fatal(err)
	}
	return activation
}
