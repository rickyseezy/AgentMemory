package filesystem

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeinstallapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF006RuntimeOwnershipRepositoryRoundTripsPreparedAndFinalizedRecords(t *testing.T) {
	t.Parallel()
	journal := &repositoryJournalStub{}
	repository := mustRuntimeOwnershipRepository(t, journal)
	plan, operation, authority := runtimeOwnershipInputs(t)
	completeRuntimeOwnershipThrough(t, operation, runtimeinstall.PhaseAwaitRuntimeConsent)
	prepared, err := runtimeinstall.NewRuntimeOwnershipRecord(plan, operation.Snapshot(), authority, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.SaveRuntimeOwnership(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.LoadRuntimeOwnership(context.Background(), operation.ID())
	if err != nil || loaded.Digest() != prepared.Digest() || loaded.Status() != runtimeinstall.OwnershipStatusPrepared {
		t.Fatalf("prepared load = %s/%d/%v", loaded.Digest(), loaded.Status(), err)
	}
	if err := repository.SaveRuntimeOwnership(context.Background(), prepared); err != nil {
		t.Fatalf("idempotent save = %v", err)
	}
	completeRuntimeOwnershipThrough(t, operation, runtimeinstall.PhaseVerifyRuntimeCapabilities)
	finalized, err := runtimeinstall.NewRuntimeOwnershipRecord(plan, operation.Snapshot(), authority, &prepared)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.SaveRuntimeOwnership(context.Background(), finalized); err != nil {
		t.Fatal(err)
	}
	loaded, err = repository.LoadRuntimeOwnership(context.Background(), operation.ID())
	if err != nil || loaded.Status() != runtimeinstall.OwnershipStatusFinalized ||
		loaded.CompatibilityDigest().IsZero() || journal.latest.Revision != 2 || len(journal.appends) != 2 {
		t.Fatalf("final load/revision/appends = %d/%d/%d/%v", loaded.Status(), journal.latest.Revision, len(journal.appends), err)
	}
	if !journal.latest.CapturedAt.Equal(repositoryFixedTime.UTC()) || journal.confirms != 5 {
		t.Fatalf("capture/confirms = %s/%d", journal.latest.CapturedAt, journal.confirms)
	}
}

func TestPF006RuntimeOwnershipRepositoryRejectsRollbackDivergenceAndTamper(t *testing.T) {
	t.Parallel()
	journal := &repositoryJournalStub{}
	repository := mustRuntimeOwnershipRepository(t, journal)
	plan, operation, authority := runtimeOwnershipInputs(t)
	completeRuntimeOwnershipThrough(t, operation, runtimeinstall.PhaseAwaitRuntimeConsent)
	prepared, _ := runtimeinstall.NewRuntimeOwnershipRecord(plan, operation.Snapshot(), authority, nil)
	if err := repository.SaveRuntimeOwnership(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	completeRuntimeOwnershipThrough(t, operation, runtimeinstall.PhaseAcquireRuntime)
	advanced, _ := runtimeinstall.NewRuntimeOwnershipRecord(plan, operation.Snapshot(), authority, &prepared)
	if err := repository.SaveRuntimeOwnership(context.Background(), advanced); err != nil {
		t.Fatal(err)
	}
	if err := repository.SaveRuntimeOwnership(context.Background(), prepared); !errors.Is(err, runtimeinstallapp.ErrOwnershipConflict) {
		t.Fatalf("rollback error = %v", err)
	}

	original := bytes.Clone(journal.latest.Payload)
	journal.latest.Payload = bytes.Replace(original, []byte(`"vendor":"docker-engine"`), []byte(`"vendor":"foreign"`), 1)
	if _, err := repository.LoadRuntimeOwnership(context.Background(), operation.ID()); !errors.Is(err, runtimeinstallapp.ErrOwnershipIntegrity) {
		t.Fatalf("tamper error = %v", err)
	}
	journal.latest.Payload = bytes.Replace(original, []byte(`"vendor":`), []byte(`"future":true,"vendor":`), 1)
	if _, err := repository.LoadRuntimeOwnership(context.Background(), operation.ID()); !errors.Is(err, runtimeinstallapp.ErrOwnershipIntegrity) {
		t.Fatalf("unknown field error = %v", err)
	}
	journal.latest.Payload = bytes.Replace(original, []byte(`"vendor":`), []byte(`"vendor":"docker-engine","vendor":`), 1)
	if _, err := repository.LoadRuntimeOwnership(context.Background(), operation.ID()); !errors.Is(err, runtimeinstallapp.ErrOwnershipIntegrity) {
		t.Fatalf("duplicate field error = %v", err)
	}
}

func TestPF006RuntimeOwnershipRepositoryFailsClosedOnMissingCapabilitiesAndState(t *testing.T) {
	t.Parallel()
	clock := repositoryClockStub{now: repositoryFixedTime.UTC()}
	fence := &repositoryFenceStub{}
	provider := &repositoryJournalProviderStub{journal: &repositoryJournalStub{}}
	for name, construct := range map[string]func() (*RuntimeOwnershipRepository, error){
		"provider": func() (*RuntimeOwnershipRepository, error) { return NewRuntimeOwnershipRepository(nil, clock, fence) },
		"clock": func() (*RuntimeOwnershipRepository, error) {
			return NewRuntimeOwnershipRepository(provider, nil, fence)
		},
		"fence": func() (*RuntimeOwnershipRepository, error) {
			return NewRuntimeOwnershipRepository(provider, clock, nil)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if repository, err := construct(); repository != nil || err == nil {
				t.Fatal("incomplete repository was accepted")
			}
		})
	}
	repository := mustRuntimeOwnershipRepository(t, &repositoryJournalStub{})
	if _, err := repository.LoadRuntimeOwnership(context.Background(), "missing"); !errors.Is(err, runtimeinstallapp.ErrOwnershipNotFound) {
		t.Fatalf("missing ownership error = %v", err)
	}
	zeroClock, err := NewRuntimeOwnershipRepository(provider, repositoryClockStub{}, fence)
	if err != nil {
		t.Fatal(err)
	}
	plan, operation, authority := runtimeOwnershipInputs(t)
	completeRuntimeOwnershipThrough(t, operation, runtimeinstall.PhaseAwaitRuntimeConsent)
	record, _ := runtimeinstall.NewRuntimeOwnershipRecord(plan, operation.Snapshot(), authority, nil)
	if err := zeroClock.SaveRuntimeOwnership(context.Background(), record); !errors.Is(err, runtimeinstallapp.ErrOwnershipIntegrity) {
		t.Fatalf("zero clock error = %v", err)
	}
}

func mustRuntimeOwnershipRepository(
	t testing.TB,
	journal *repositoryJournalStub,
) *RuntimeOwnershipRepository {
	t.Helper()
	repository, err := NewRuntimeOwnershipRepository(
		&repositoryJournalProviderStub{journal: journal},
		repositoryClockStub{now: repositoryFixedTime.UTC()},
		&repositoryFenceStub{},
	)
	if err != nil {
		t.Fatal(err)
	}
	return repository
}

func runtimeOwnershipInputs(
	t testing.TB,
) (runtimeinstall.Plan, *runtimeinstall.Operation, runtimeinstall.RuntimeOwnershipAuthority) {
	t.Helper()
	host, err := runtimeinstall.NewHostCapabilities(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "24.04", true, true, true, true,
		8, 32<<30, 24<<30, 100<<30,
	)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := runtimeinstall.NewCertifiedRuntime(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "docker-engine", "28.3.2", "stable", 42,
		runtimeinstall.Sum([]byte("catalog")), runtimeinstall.RuntimeTermsInput{
			ID: runtimeinstall.DockerEngineTermsID, Version: "apache-2.0", URL: "https://docs.docker.com/engine/",
			Digest: runtimeinstall.Sum([]byte("terms")), Presentation: runtimeinstall.TermsPresentationAgentMemory,
		}, 1024, 4096,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := runtimeinstall.NewPlanV1(host, runtimeinstall.NewAbsentRuntimeDiscovery(), catalog)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := runtimeinstall.NewOperation("019f5f20-1234-7abc-8123-0123456789ab", plan.Digest())
	if err != nil {
		t.Fatal(err)
	}
	authority, err := runtimeinstall.NewRuntimeOwnershipAuthority(runtimeinstall.RuntimeOwnershipAuthoritySnapshot{
		Vendor: plan.Product(), Version: plan.Version(), Channel: plan.Channel(),
		Endpoint: "unix:///run/user/1000/docker.sock", Context: "explicit-local-endpoint",
		Publisher: "docker-release-key-2026", PublisherDigest: runtimeinstall.Sum([]byte("publisher")),
		ArtifactDigest: runtimeinstall.Sum([]byte("artifact")),
		Components:     []string{"compose@2.39.1", "engine@28.3.2"},
		Settings:       []string{"repository:docker-stable", "service:docker.service"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan, operation, authority
}

func completeRuntimeOwnershipThrough(
	t testing.TB,
	operation *runtimeinstall.Operation,
	through runtimeinstall.Phase,
) {
	t.Helper()
	for operation.State() == runtimeinstall.OperationStateRunning && operation.CurrentPhase() <= through {
		phase := operation.CurrentPhase()
		artifact := runtimeinstall.Hash{}
		if phase >= runtimeinstall.PhaseVerifyRuntimeArtifact {
			artifact = runtimeinstall.Sum([]byte("artifact"))
		}
		ownership := runtimeinstall.OwnershipUnknown
		if phase == runtimeinstall.PhaseVerifyRuntimeCapabilities {
			ownership = runtimeinstall.OwnershipProvisionedByAgentMemory
		}
		evidence, err := runtimeinstall.NewTransitionEvidence(
			phase, operation.Attempt(), operation.PlanDigest(), runtimeinstall.Sum([]byte("before-"+phase.String())),
			runtimeinstall.Sum([]byte("after-"+phase.String())), artifact, ownership,
		)
		if err != nil || operation.Complete(phase, evidence) != nil {
			t.Fatalf("complete %s: %v", phase, err)
		}
	}
}
