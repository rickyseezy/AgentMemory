package runtimeinstall

import "testing"

func TestPF001RuntimeOperationRequiresEveryOrderedPhaseBeforeReady(t *testing.T) {
	t.Parallel()

	operation := newRuntimeOperationForTest(t)
	want := []Phase{
		PhaseDetectHost,
		PhaseDetectRuntime,
		PhasePlanRuntime,
		PhaseAwaitRuntimeConsent,
		PhaseAcquireRuntime,
		PhaseVerifyRuntimeArtifact,
		PhaseInstallPrerequisites,
		PhaseInstallRuntime,
		PhaseAwaitThirdPartyTerms,
		PhaseStartRuntime,
		PhaseVerifyRuntimeCapabilities,
	}
	if got := OrderedPhases(); len(got) != len(want) {
		t.Fatalf("phase count = %d, want %d", len(got), len(want))
	} else {
		for index := range want {
			if got[index] != want[index] {
				t.Fatalf("phase %d = %s, want %s", index, got[index], want[index])
			}
		}
	}

	for index, phase := range want {
		if operation.State() == OperationStateReady {
			t.Fatalf("operation became ready before phase %d", index)
		}
		if operation.CurrentPhase() != phase {
			t.Fatalf("cursor = %s, want %s", operation.CurrentPhase(), phase)
		}
		if err := operation.Complete(phase, evidenceForPhase(t, operation, phase)); err != nil {
			t.Fatalf("complete %s: %v", phase, err)
		}
	}
	if operation.State() != OperationStateReady || operation.CurrentPhase() != PhaseUnknown {
		t.Fatalf("final state/cursor = %s/%s", operation.State(), operation.CurrentPhase())
	}
	if operation.Version() != uint64(len(want)) {
		t.Fatalf("version = %d, want %d", operation.Version(), len(want))
	}
}

func TestPF001RuntimeOperationRejectsSkippedStaleOrPlanMismatchedEvidence(t *testing.T) {
	t.Parallel()

	operation := newRuntimeOperationForTest(t)
	tests := []struct {
		name     string
		phase    Phase
		evidence TransitionEvidence
	}{
		{
			name:     "skipped phase",
			phase:    PhasePlanRuntime,
			evidence: evidenceForPhase(t, operation, PhasePlanRuntime),
		},
		{
			name:  "wrong plan",
			phase: PhaseDetectHost,
			evidence: mustEvidence(t, PhaseDetectHost, 1, mustHash(t, "other-plan"),
				mustHash(t, "input"), mustHash(t, "output"), Hash{}, OwnershipUnknown),
		},
		{
			name:  "wrong attempt",
			phase: PhaseDetectHost,
			evidence: mustEvidence(t, PhaseDetectHost, 2, operation.PlanDigest(),
				mustHash(t, "input"), mustHash(t, "output"), Hash{}, OwnershipUnknown),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := operation.Snapshot()
			if err := operation.Complete(test.phase, test.evidence); err == nil {
				t.Fatal("invalid transition unexpectedly succeeded")
			}
			after := operation.Snapshot()
			if before.Version != after.Version || before.CurrentPhase != after.CurrentPhase || len(before.Evidence) != len(after.Evidence) {
				t.Fatal("rejected transition mutated aggregate")
			}
		})
	}
}

func TestPF001RuntimeOperationRebootReceiptIsOnePhaseBoundAndOneUse(t *testing.T) {
	t.Parallel()

	operation := newRuntimeOperationForTest(t)
	completeUntil(t, operation, PhaseInstallPrerequisites)
	receipt := mustHash(t, "resume-receipt")
	if err := operation.RequireReboot(receipt); err != nil {
		t.Fatal(err)
	}
	if operation.State() != OperationStateRebootPending {
		t.Fatalf("state = %s", operation.State())
	}
	if err := operation.ResumeAfterReboot(mustHash(t, "wrong")); err == nil {
		t.Fatal("wrong reboot receipt was accepted")
	}
	if err := operation.ResumeAfterReboot(receipt); err != nil {
		t.Fatal(err)
	}
	if operation.State() != OperationStateRunning || operation.Attempt() != 2 {
		t.Fatalf("resume state/attempt = %s/%d", operation.State(), operation.Attempt())
	}
	if err := operation.ResumeAfterReboot(receipt); err == nil {
		t.Fatal("consumed reboot receipt was replayed")
	}
}

func TestPF001RuntimeOperationSnapshotRoundTripFailsClosed(t *testing.T) {
	t.Parallel()

	operation := newRuntimeOperationForTest(t)
	completeUntil(t, operation, PhaseAcquireRuntime)
	snapshot := operation.Snapshot()
	restored, err := RestoreOperation(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Snapshot().Version != snapshot.Version || restored.CurrentPhase() != snapshot.CurrentPhase {
		t.Fatal("restored operation differs from source")
	}

	tampered := snapshot
	tampered.CurrentPhase = PhaseVerifyRuntimeCapabilities
	if _, err := RestoreOperation(tampered); err == nil {
		t.Fatal("tampered cursor was accepted")
	}
	tampered = snapshot
	tampered.Version--
	if _, err := RestoreOperation(tampered); err == nil {
		t.Fatal("regressed version was accepted")
	}
}

func newRuntimeOperationForTest(t *testing.T) *Operation {
	t.Helper()
	operation, err := NewOperation("019f5f20-1234-7abc-8123-0123456789ab", mustHash(t, "parent-plan"))
	if err != nil {
		t.Fatal(err)
	}
	return operation
}

func evidenceForPhase(t *testing.T, operation *Operation, phase Phase) TransitionEvidence {
	t.Helper()
	artifact := Hash{}
	if phase == PhaseVerifyRuntimeArtifact || phase == PhaseInstallPrerequisites || phase == PhaseInstallRuntime ||
		phase == PhaseAwaitThirdPartyTerms || phase == PhaseStartRuntime || phase == PhaseVerifyRuntimeCapabilities {
		artifact = mustHash(t, "verified-runtime-artifact")
	}
	ownership := OwnershipUnknown
	if phase == PhaseVerifyRuntimeCapabilities {
		ownership = OwnershipProvisionedByAgentMemory
	}
	return mustEvidence(
		t,
		phase,
		operation.Attempt(),
		operation.PlanDigest(),
		mustHash(t, "input-"+phase.String()),
		mustHash(t, "output-"+phase.String()),
		artifact,
		ownership,
	)
}

func mustEvidence(
	t *testing.T,
	phase Phase,
	attempt uint32,
	plan Hash,
	input Hash,
	output Hash,
	artifact Hash,
	ownership OwnershipDisposition,
) TransitionEvidence {
	t.Helper()
	evidence, err := NewTransitionEvidence(phase, attempt, plan, input, output, artifact, ownership)
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func completeUntil(t *testing.T, operation *Operation, target Phase) {
	t.Helper()
	for operation.CurrentPhase() != target {
		phase := operation.CurrentPhase()
		if phase == PhaseUnknown {
			t.Fatalf("target %s not reached", target)
		}
		if err := operation.Complete(phase, evidenceForPhase(t, operation, phase)); err != nil {
			t.Fatal(err)
		}
	}
}
