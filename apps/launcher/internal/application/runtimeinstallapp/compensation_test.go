package runtimeinstallapp

import (
	"context"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF001RuntimeCompensationReceiptBindsExactOwnedCleanup(t *testing.T) {
	t.Parallel()
	request := testRuntimeCompensationRequest(t)
	runtimeDigest := runtimeinstall.Sum([]byte("runtime-before-and-after"))
	input := RuntimeCompensationReceiptInput{
		RuntimeBeforeDigest:    runtimeDigest,
		RuntimeAfterDigest:     runtimeDigest,
		ArtifactCleanupDigest:  runtimeinstall.Sum([]byte("artifact-cleanup")),
		RemovedArtifactDigests: []runtimeinstall.Hash{request.OwnershipRecord().ArtifactDigest()},
		RemovedSettings:        []string{"repository:docker-stable"},
		RuntimePreserved:       true,
	}
	receipt, err := NewRuntimeCompensationReceipt(request, input)
	if err != nil || !receipt.ValidFor(request) || receipt.Digest().IsZero() {
		t.Fatalf("receipt = %+v/%v", receipt, err)
	}
	input.RemovedArtifactDigests[0] = runtimeinstall.Sum([]byte("mutated"))
	input.RemovedSettings[0] = "mutated"
	if !receipt.ValidFor(request) || receipt.RemovedSettings()[0] != "repository:docker-stable" {
		t.Fatal("receipt retained caller-owned slices")
	}
	canonical := request.CanonicalPlan()
	canonical[0] ^= 0xff
	if !request.valid() {
		t.Fatal("request exposed mutable canonical authority")
	}
}

func TestPF001RuntimeCompensationReceiptRejectsRuntimeOrAuthorityDrift(t *testing.T) {
	t.Parallel()
	request := testRuntimeCompensationRequest(t)
	runtimeDigest := runtimeinstall.Sum([]byte("runtime"))
	valid := RuntimeCompensationReceiptInput{
		RuntimeBeforeDigest: runtimeDigest, RuntimeAfterDigest: runtimeDigest,
		ArtifactCleanupDigest: runtimeinstall.Sum([]byte("cleanup")), RuntimePreserved: true,
	}
	tests := map[string]func(*RuntimeCompensationReceiptInput){
		"runtime changed": func(input *RuntimeCompensationReceiptInput) {
			input.RuntimeAfterDigest = runtimeinstall.Sum([]byte("changed"))
		},
		"runtime not preserved": func(input *RuntimeCompensationReceiptInput) { input.RuntimePreserved = false },
		"foreign artifact": func(input *RuntimeCompensationReceiptInput) {
			input.RemovedArtifactDigests = []runtimeinstall.Hash{runtimeinstall.Sum([]byte("foreign"))}
		},
		"foreign setting": func(input *RuntimeCompensationReceiptInput) {
			input.RemovedSettings = []string{"service:foreign.service"}
		},
		"duplicate setting": func(input *RuntimeCompensationReceiptInput) {
			input.RemovedSettings = []string{"service:docker.service", "service:docker.service"}
		},
	}
	for name, mutate := range tests {
		input := valid
		mutate(&input)
		if _, err := NewRuntimeCompensationReceipt(request, input); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	receipt, err := NewRuntimeCompensationReceipt(request, valid)
	if err != nil {
		t.Fatal(err)
	}
	receipt.artifactCleanupDigest = runtimeinstall.Sum([]byte("substituted"))
	if receipt.ValidFor(request) {
		t.Fatal("mutated receipt was accepted")
	}
}

func testRuntimeCompensationRequest(t *testing.T) RuntimeCompensationRequest {
	t.Helper()
	plan, err := runtimeinstall.DecodePlanV1(testCanonicalRuntimePlan())
	if err != nil {
		t.Fatal(err)
	}
	operation, err := runtimeinstall.NewOperation(testCommand().OperationID, plan.Digest())
	if err != nil {
		t.Fatal(err)
	}
	for operation.CurrentPhase() <= runtimeinstall.PhaseAcquireRuntime {
		phase := operation.CurrentPhase()
		evidence, evidenceErr := runtimeinstall.NewTransitionEvidence(
			phase, operation.Attempt(), plan.Digest(), runtimeinstall.Sum([]byte("before-"+phase.String())),
			runtimeinstall.Sum([]byte("after-"+phase.String())), runtimeinstall.Hash{}, runtimeinstall.OwnershipUnknown,
		)
		if evidenceErr != nil || operation.Complete(phase, evidence) != nil {
			t.Fatalf("complete %s: %v", phase, evidenceErr)
		}
	}
	if err := operation.Cancel(); err != nil {
		t.Fatal(err)
	}
	harness := &phaseHarness{}
	authority, err := harness.ResolveRuntimeOwnershipAuthority(context.Background(), plan.CanonicalBytes())
	if err != nil {
		t.Fatal(err)
	}
	record, err := runtimeinstall.NewRuntimeOwnershipRecord(plan, operation.Snapshot(), authority, nil)
	if err != nil {
		t.Fatal(err)
	}
	request, err := newRuntimeCompensationRequest(plan.CanonicalBytes(), record)
	if err != nil {
		t.Fatal(err)
	}
	return request
}
