package filesystem

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeremovalapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeremoval"
)

func TestPF001RuntimeRemovalRepositoryImplementsApplicationPort(t *testing.T) {
	t.Parallel()
	var repository runtimeremovalapp.OperationRepository = &RuntimeRemovalOperationRepository{}
	_ = repository
}

func TestPF001RuntimeRemovalRepositoryRoundTripsConsentIntentAndReceipt(t *testing.T) {
	t.Parallel()
	journal := &repositoryJournalStub{}
	repository := mustRuntimeRemovalRepository(t, journal)
	operation := runtimeRemovalRepositoryOperation(t)
	if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}
	consent := runtimeinstall.Sum([]byte("explicit-second-consent"))
	if err := operation.AuthorizeRemoval(operation.PlanDigest(), consent); err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}
	executionScan := operation.Plan().ScanDigest()
	if err := operation.BeginRemoval(operation.PlanDigest(), executionScan); err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}
	receipt := runtimeinstall.Sum([]byte("native-removal-and-absence"))
	if err := operation.CompleteRemoval(operation.PlanDigest(), receipt); err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.Load(context.Background(), operation.ID().String())
	if err != nil || loaded.State() != runtimeremoval.StateRemoved || loaded.ConsentReceipt() != consent ||
		loaded.ExecutionScanDigest() != executionScan || loaded.RemovalReceipt() != receipt || journal.latest.Revision != 4 {
		t.Fatalf("loaded = %+v/%v journal revision=%d", loaded, err, journal.latest.Revision)
	}
	if err := repository.Save(context.Background(), loaded.Snapshot()); err != nil || journal.latest.Revision != 4 {
		t.Fatalf("idempotent save = %v revision=%d", err, journal.latest.Revision)
	}
}

func TestPF001RuntimeRemovalRepositoryRejectsRollbackDivergenceAndTamper(t *testing.T) {
	t.Parallel()
	journal := &repositoryJournalStub{}
	repository := mustRuntimeRemovalRepository(t, journal)
	operation := runtimeRemovalRepositoryOperation(t)
	initial := operation.Snapshot()
	if err := repository.Save(context.Background(), initial); err != nil {
		t.Fatal(err)
	}
	if err := operation.AuthorizeRemoval(operation.PlanDigest(), runtimeinstall.Sum([]byte("consent"))); err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(context.Background(), initial); !errors.Is(err, runtimeremovalapp.ErrOperationConflict) {
		t.Fatalf("rollback error = %v", err)
	}

	original := bytes.Clone(journal.latest.Payload)
	journal.latest.Payload = bytes.Replace(original, []byte(`"state":2`), []byte(`"state":255`), 1)
	if _, err := repository.Load(context.Background(), operation.ID().String()); !errors.Is(err, runtimeremovalapp.ErrIntegrity) {
		t.Fatalf("invalid state error = %v", err)
	}
	journal.latest.Payload = bytes.Replace(original, []byte(`"state":`), []byte(`"future":true,"state":`), 1)
	if _, err := repository.Load(context.Background(), operation.ID().String()); !errors.Is(err, runtimeremovalapp.ErrIntegrity) {
		t.Fatalf("unknown field error = %v", err)
	}
	journal.latest.Payload = bytes.Replace(original, []byte(`"state":`), []byte(`"state":2,"state":`), 1)
	if _, err := repository.Load(context.Background(), operation.ID().String()); !errors.Is(err, runtimeremovalapp.ErrIntegrity) {
		t.Fatalf("duplicate field error = %v", err)
	}
}

func TestPF001RuntimeRemovalRepositoryFailsClosedWithoutDurabilityCapabilities(t *testing.T) {
	t.Parallel()
	clock := repositoryClockStub{now: repositoryFixedTime.UTC()}
	fence := &repositoryFenceStub{}
	provider := &repositoryJournalProviderStub{journal: &repositoryJournalStub{}}
	for name, construct := range map[string]func() (*RuntimeRemovalOperationRepository, error){
		"provider": func() (*RuntimeRemovalOperationRepository, error) {
			return NewRuntimeRemovalOperationRepository(nil, clock, fence)
		},
		"clock": func() (*RuntimeRemovalOperationRepository, error) {
			return NewRuntimeRemovalOperationRepository(provider, nil, fence)
		},
		"fence": func() (*RuntimeRemovalOperationRepository, error) {
			return NewRuntimeRemovalOperationRepository(provider, clock, nil)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if repository, err := construct(); err == nil || repository != nil {
				t.Fatal("incomplete removal repository was accepted")
			}
		})
	}
	repository := mustRuntimeRemovalRepository(t, &repositoryJournalStub{})
	if _, err := repository.Load(context.Background(), "019f60a0-0000-7abc-8123-0123456789ab"); !errors.Is(err, runtimeremovalapp.ErrOperationNotFound) {
		t.Fatalf("missing error = %v", err)
	}
}

func mustRuntimeRemovalRepository(
	t testing.TB,
	journal *repositoryJournalStub,
) *RuntimeRemovalOperationRepository {
	t.Helper()
	repository, err := NewRuntimeRemovalOperationRepository(
		&repositoryJournalProviderStub{journal: journal},
		repositoryClockStub{now: repositoryFixedTime.UTC()},
		&repositoryFenceStub{},
	)
	if err != nil {
		t.Fatal(err)
	}
	return repository
}

func runtimeRemovalRepositoryOperation(t testing.TB) *runtimeremoval.Operation {
	t.Helper()
	plan, runtimeOperation, authority := runtimeOwnershipInputs(t)
	completeRuntimeOwnershipThrough(t, runtimeOperation, runtimeinstall.PhaseVerifyRuntimeCapabilities)
	ownership, err := runtimeinstall.NewRuntimeOwnershipRecord(plan, runtimeOperation.Snapshot(), authority, nil)
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
	operationID, err := install.NewOperationID("019f60a0-0000-7abc-8123-0123456789ab")
	if err != nil {
		t.Fatal(err)
	}
	removalPlan, err := runtimeremoval.NewPlan(operationID, plan.CanonicalBytes(), ownership, scan)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := runtimeremoval.NewOperation(removalPlan)
	if err != nil {
		t.Fatal(err)
	}
	return operation
}
