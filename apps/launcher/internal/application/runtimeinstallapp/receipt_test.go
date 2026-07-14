package runtimeinstallapp

import (
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestCompletionReceiptDerivesOnlyFromCompleteValidatedAggregate(t *testing.T) {
	t.Parallel()

	snapshot := readyRuntimeSnapshot(t, runtimeinstall.OwnershipReusedExternal)
	receipt, err := NewCompletionReceipt(snapshot)
	if err != nil {
		t.Fatalf("NewCompletionReceipt() error = %v", err)
	}
	if receipt.OperationID() != snapshot.OperationID || receipt.PlanDigest() != snapshot.PlanDigest ||
		receipt.AggregateVersion() != snapshot.Version || receipt.EvidenceDigest().IsZero() ||
		receipt.InputDigest().IsZero() || receipt.OutputDigest().IsZero() ||
		receipt.ArtifactDigest().IsZero() || receipt.Ownership() != runtimeinstall.OwnershipReusedExternal ||
		!receipt.Valid() {
		t.Fatalf("completion receipt is incomplete: %#v", receipt)
	}

	tampered := snapshot
	tampered.Evidence = append([]runtimeinstall.TransitionEvidence(nil), snapshot.Evidence...)
	tampered.Evidence[len(tampered.Evidence)-1].Ownership = runtimeinstall.OwnershipUnknown
	if _, err := NewCompletionReceipt(tampered); err == nil {
		t.Fatal("tampered completion history produced a receipt")
	}
	notReady := snapshot
	notReady.State = runtimeinstall.OperationStateRunning
	if _, err := NewCompletionReceipt(notReady); err == nil {
		t.Fatal("non-ready snapshot produced a completion receipt")
	}
}

func TestNewResultFromSnapshotProjectsReadyPauseAndRebootEvidence(t *testing.T) {
	t.Parallel()

	ready := readyRuntimeSnapshot(t, runtimeinstall.OwnershipProvisionedByAgentMemory)
	readyResult, err := NewResultFromSnapshot(ready)
	if err != nil {
		t.Fatalf("NewResultFromSnapshot(ready) error = %v", err)
	}
	completion, ok := readyResult.CompletionReceipt()
	if !ok || !completion.Valid() || readyResult.Outcome != OutcomeCompleted ||
		readyResult.State != runtimeinstall.OperationStateReady || readyResult.PlanDigest() != ready.PlanDigest {
		t.Fatal("ready result lost completion authority")
	}
	if _, ok := readyResult.RebootReceipt(); ok {
		t.Fatal("ready result exposed a reboot receipt")
	}

	rebootOperation, err := runtimeinstall.NewOperation("operation-reboot", runtimeinstall.Sum([]byte("plan")))
	if err != nil {
		t.Fatalf("NewOperation() error = %v", err)
	}
	advanceRuntimeTo(t, rebootOperation, runtimeinstall.PhaseInstallPrerequisites, runtimeinstall.OwnershipUnknown)
	rebootReceipt := runtimeinstall.Sum([]byte("one-use-reboot"))
	if err := rebootOperation.RequireReboot(rebootReceipt); err != nil {
		t.Fatalf("RequireReboot() error = %v", err)
	}
	rebootResult, err := NewResultFromSnapshot(rebootOperation.Snapshot())
	if err != nil {
		t.Fatalf("NewResultFromSnapshot(reboot) error = %v", err)
	}
	actualReboot, ok := rebootResult.RebootReceipt()
	if !ok || actualReboot != rebootReceipt || rebootResult.Outcome != OutcomeRebootRequired {
		t.Fatal("reboot result lost one-use receipt authority")
	}

	pausedOperation, err := runtimeinstall.NewOperation("operation-paused", runtimeinstall.Sum([]byte("plan")))
	if err != nil {
		t.Fatalf("NewOperation() error = %v", err)
	}
	if err := pausedOperation.Pause(runtimeinstall.OperationStatePausedForAdministrator); err != nil {
		t.Fatalf("Pause() error = %v", err)
	}
	paused, err := NewResultFromSnapshot(pausedOperation.Snapshot())
	if err != nil || paused.Outcome != OutcomeAdministratorRequired ||
		paused.ErrorCode != ErrorCodeAdministratorRequired {
		t.Fatalf("NewResultFromSnapshot(paused) = (%#v, %v)", paused, err)
	}
}

func TestNewResultFromSnapshotRejectsUnrestorableState(t *testing.T) {
	t.Parallel()

	if _, err := NewResultFromSnapshot(runtimeinstall.OperationSnapshot{}); err == nil {
		t.Fatal("zero snapshot produced a result")
	}
	if (CompletionReceipt{}).Valid() {
		t.Fatal("zero completion receipt is valid")
	}
}

func readyRuntimeSnapshot(
	t *testing.T,
	ownership runtimeinstall.OwnershipDisposition,
) runtimeinstall.OperationSnapshot {
	t.Helper()
	operation, err := runtimeinstall.NewOperation("operation-ready", runtimeinstall.Sum([]byte("nested-plan")))
	if err != nil {
		t.Fatalf("NewOperation() error = %v", err)
	}
	advanceRuntimeTo(t, operation, runtimeinstall.PhaseUnknown, ownership)
	return operation.Snapshot()
}

func advanceRuntimeTo(
	t *testing.T,
	operation *runtimeinstall.Operation,
	stopBefore runtimeinstall.Phase,
	ownership runtimeinstall.OwnershipDisposition,
) {
	t.Helper()
	artifact := runtimeinstall.Sum([]byte("verified-artifact"))
	for _, phase := range runtimeinstall.OrderedPhases() {
		if phase == stopBefore {
			return
		}
		phaseArtifact := runtimeinstall.Hash{}
		if phase >= runtimeinstall.PhaseVerifyRuntimeArtifact {
			phaseArtifact = artifact
		}
		phaseOwnership := runtimeinstall.OwnershipUnknown
		if phase == runtimeinstall.PhaseVerifyRuntimeCapabilities {
			phaseOwnership = ownership
		}
		evidence, err := runtimeinstall.NewTransitionEvidence(
			phase,
			operation.Attempt(),
			operation.PlanDigest(),
			runtimeinstall.Sum([]byte("input-"+phase.String())),
			runtimeinstall.Sum([]byte("output-"+phase.String())),
			phaseArtifact,
			phaseOwnership,
		)
		if err != nil {
			t.Fatalf("NewTransitionEvidence(%s) error = %v", phase, err)
		}
		if err := operation.Complete(phase, evidence); err != nil {
			t.Fatalf("Complete(%s) error = %v", phase, err)
		}
	}
}
