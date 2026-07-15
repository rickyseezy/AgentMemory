package runtimeconsent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeremoval"
)

func TestPF001RemovalBrokerBindsAndConsumesExplicitNonPreselectedApproval(t *testing.T) {
	t.Parallel()
	plan := removalConsentPlan(t)
	signer := &removalConsentSignerStub{receipt: runtimeinstall.Sum([]byte("protected-removal-consent"))}
	broker, err := NewRemovalBroker(signer, removalConsentClock{now: time.Date(2026, 7, 15, 19, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	err = broker.SubmitManagedRuntimeRemovalDecision(t.Context(), plan, ManagedRuntimeRemovalDecisionInput{
		OperationID: plan.OperationID().String(), PlanDigest: plan.Digest(),
		Impact: plan.ImpactConfirmation(), Approved: true, ExplicitConfirmation: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := broker.AwaitManagedRuntimeRemovalConsent(t.Context(), plan)
	if err != nil || !decision.Approved || !decision.Explicit || decision.PlanDigest != plan.Digest() ||
		decision.Impact != plan.ImpactConfirmation() || decision.Receipt != signer.receipt || signer.calls != 1 {
		t.Fatalf("decision=%+v signer=%d error=%v", decision, signer.calls, err)
	}
	if _, err := broker.AwaitManagedRuntimeRemovalConsent(t.Context(), plan); err == nil {
		t.Fatal("consent decision was reusable")
	}
}

func TestPF001RemovalBrokerDeclineIsUnprivilegedAndDurablyNonDestructive(t *testing.T) {
	t.Parallel()
	plan := removalConsentPlan(t)
	signer := &removalConsentSignerStub{receipt: runtimeinstall.Sum([]byte("must-not-be-used"))}
	broker, err := NewRemovalBroker(signer, removalConsentClock{now: time.Date(2026, 7, 15, 19, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	err = broker.SubmitManagedRuntimeRemovalDecision(t.Context(), plan, ManagedRuntimeRemovalDecisionInput{
		OperationID: plan.OperationID().String(), PlanDigest: plan.Digest(),
		Impact: plan.ImpactConfirmation(), Approved: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := broker.AwaitManagedRuntimeRemovalConsent(t.Context(), plan)
	if err != nil || decision.Approved || decision.Explicit || !decision.Receipt.IsZero() || signer.calls != 0 {
		t.Fatalf("decision=%+v signer=%d error=%v", decision, signer.calls, err)
	}
}

func TestPF001RemovalBrokerRejectsSubstitutionMissingConfirmationAndConflicts(t *testing.T) {
	t.Parallel()
	plan := removalConsentPlan(t)
	signer := &removalConsentSignerStub{receipt: runtimeinstall.Sum([]byte("receipt"))}
	broker, err := NewRemovalBroker(signer, removalConsentClock{now: time.Date(2026, 7, 15, 19, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	base := ManagedRuntimeRemovalDecisionInput{
		OperationID: plan.OperationID().String(), PlanDigest: plan.Digest(),
		Impact: plan.ImpactConfirmation(), Approved: true, ExplicitConfirmation: true,
	}
	for name, mutate := range map[string]func(*ManagedRuntimeRemovalDecisionInput){
		"operation": func(value *ManagedRuntimeRemovalDecisionInput) { value.OperationID = "foreign" },
		"plan": func(value *ManagedRuntimeRemovalDecisionInput) {
			value.PlanDigest = runtimeinstall.Sum([]byte("foreign"))
		},
		"impact":       func(value *ManagedRuntimeRemovalDecisionInput) { value.Impact = "remove-everything" },
		"confirmation": func(value *ManagedRuntimeRemovalDecisionInput) { value.ExplicitConfirmation = false },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			if err := broker.SubmitManagedRuntimeRemovalDecision(t.Context(), plan, candidate); err == nil {
				t.Fatal("substituted consent accepted")
			}
		})
	}
	if err := broker.SubmitManagedRuntimeRemovalDecision(t.Context(), plan, base); err != nil {
		t.Fatal(err)
	}
	if err := broker.SubmitManagedRuntimeRemovalDecision(t.Context(), plan, base); err == nil {
		t.Fatal("second pending removal consent accepted")
	}
	if broker, err := NewRemovalBroker(nil, removalConsentClock{}); err == nil || broker != nil {
		t.Fatal("incomplete removal broker accepted")
	}
}

type removalConsentSignerStub struct {
	receipt runtimeinstall.Hash
	err     error
	calls   int
}

func (s *removalConsentSignerStub) SignManagedRuntimeRemovalConsent(
	context.Context,
	runtimeremoval.Plan,
	time.Time,
) (runtimeinstall.Hash, error) {
	s.calls++
	return s.receipt, s.err
}

type removalConsentClock struct{ now time.Time }

func (c removalConsentClock) Now() time.Time { return c.now }

func TestPF001RemovalBrokerContainsSignerFailures(t *testing.T) {
	t.Parallel()
	plan := removalConsentPlan(t)
	broker, err := NewRemovalBroker(
		&removalConsentSignerStub{err: errors.New("private signer failure")},
		removalConsentClock{now: time.Date(2026, 7, 15, 19, 0, 0, 0, time.UTC)},
	)
	if err != nil {
		t.Fatal(err)
	}
	input := ManagedRuntimeRemovalDecisionInput{
		OperationID: plan.OperationID().String(), PlanDigest: plan.Digest(), Impact: plan.ImpactConfirmation(),
		Approved: true, ExplicitConfirmation: true,
	}
	if err := broker.SubmitManagedRuntimeRemovalDecision(t.Context(), plan, input); err == nil {
		t.Fatal("signer failure accepted")
	}
}

func TestPF001RemovalBrokerDiscardsUnconsumedTerminalOrFailedDecision(t *testing.T) {
	t.Parallel()
	plan := removalConsentPlan(t)
	broker, err := NewRemovalBroker(
		&removalConsentSignerStub{receipt: runtimeinstall.Sum([]byte("receipt"))},
		removalConsentClock{now: time.Date(2026, 7, 15, 20, 0, 0, 0, time.UTC)},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.SubmitManagedRuntimeRemovalDecision(t.Context(), plan, ManagedRuntimeRemovalDecisionInput{
		OperationID: plan.OperationID().String(), PlanDigest: plan.Digest(),
		Impact: plan.ImpactConfirmation(), Approved: true, ExplicitConfirmation: true,
	}); err != nil {
		t.Fatal(err)
	}
	broker.DiscardManagedRuntimeRemovalDecision(plan)
	if _, err := broker.AwaitManagedRuntimeRemovalConsent(t.Context(), plan); !errors.Is(err, ErrConflict) {
		t.Fatalf("discarded decision error=%v", err)
	}
	broker.DiscardManagedRuntimeRemovalDecision(plan)
}

func removalConsentPlan(t testing.TB) runtimeremoval.Plan {
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
	runtimePlan, err := runtimeinstall.NewPlanV1(host, runtimeinstall.NewAbsentRuntimeDiscovery(), catalog)
	if err != nil {
		t.Fatal(err)
	}
	sourceID := "019f60a0-1111-7abc-8123-0123456789ab"
	operation, err := runtimeinstall.NewOperation(sourceID, runtimePlan.Digest())
	if err != nil {
		t.Fatal(err)
	}
	artifact := runtimeinstall.Sum([]byte("artifact"))
	for _, phase := range runtimeinstall.OrderedPhases() {
		phaseArtifact := runtimeinstall.Hash{}
		if phase >= runtimeinstall.PhaseVerifyRuntimeArtifact {
			phaseArtifact = artifact
		}
		ownership := runtimeinstall.OwnershipUnknown
		if phase == runtimeinstall.PhaseVerifyRuntimeCapabilities {
			ownership = runtimeinstall.OwnershipProvisionedByAgentMemory
		}
		evidence, evidenceError := runtimeinstall.NewTransitionEvidence(
			phase, operation.Attempt(), runtimePlan.Digest(), runtimeinstall.Sum([]byte("before-"+phase.String())),
			runtimeinstall.Sum([]byte("after-"+phase.String())), phaseArtifact, ownership,
		)
		if evidenceError != nil || operation.Complete(phase, evidence) != nil {
			t.Fatalf("complete %s: %v", phase, evidenceError)
		}
	}
	authority, err := runtimeinstall.NewRuntimeOwnershipAuthority(runtimeinstall.RuntimeOwnershipAuthoritySnapshot{
		Vendor: runtimePlan.Product(), Version: runtimePlan.Version(), Channel: runtimePlan.Channel(),
		Endpoint: "unix:///run/user/1000/docker.sock", Context: "explicit-local-endpoint",
		Publisher: "docker-stable", PublisherDigest: runtimeinstall.Sum([]byte("publisher")),
		ArtifactDigest: artifact, Components: []string{"docker-ce@29.6.1"}, Settings: []string{"rootless:true"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ownership, err := runtimeinstall.NewRuntimeOwnershipRecord(runtimePlan, operation.Snapshot(), authority, nil)
	if err != nil {
		t.Fatal(err)
	}
	proofs := make([]runtimeremoval.DependencyProofInput, 0, len(runtimeremoval.OrderedDependencyKinds()))
	for _, kind := range runtimeremoval.OrderedDependencyKinds() {
		proofs = append(proofs, runtimeremoval.DependencyProofInput{
			Kind: kind, Complete: true, EvidenceDigest: runtimeinstall.Sum([]byte("empty-" + kind.String())),
		})
	}
	scan, err := runtimeremoval.NewDependencyScan(runtimeremoval.DependencyScanInput{
		OwnershipRecordDigest: ownership.Digest(), Endpoint: ownership.Endpoint(), Proofs: proofs,
	})
	if err != nil {
		t.Fatal(err)
	}
	removalID, err := install.NewOperationID("019f60a0-0000-7abc-8123-0123456789ab")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := runtimeremoval.NewPlan(removalID, runtimePlan.CanonicalBytes(), ownership, scan)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}
