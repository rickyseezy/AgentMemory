package artifactjournal

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
)

func TestPF001ExpandedTargetJournalRoundTripsIndependentCASState(t *testing.T) {
	t.Parallel()
	journal := &memoryJournal{}
	repository, err := NewExpandedTargetRepository(&provider{journal: journal}, fixedClock{})
	if err != nil {
		t.Fatal(err)
	}
	authority, aggregate := expandedTargetJournalFixture(t)
	initial := aggregate.Snapshot()
	if err := repository.SaveExpandedTarget(context.Background(), 0, initial); err != nil {
		t.Fatal(err)
	}
	if err := repository.SaveExpandedTarget(context.Background(), 0, initial); err != nil || len(journal.snapshots) != 1 {
		t.Fatalf("initial replay error=%v snapshots=%d", err, len(journal.snapshots))
	}
	lease := authority.ConsumeAuthorization().Lease()
	observation, _ := artifactacquisition.NewExpandedTargetObservation(artifactacquisition.ExpandedTargetObservationInput{
		LeaseID: lease.ID(), ReceiptToken: authority.ConsumeAuthorization().ReceiptToken(), PlanDigest: lease.PlanDigest(),
		PoolID: lease.Pool().ID(), PoolKind: lease.Pool().Kind(), SourceDigest: lease.SourceDigest(), SourceBytes: lease.SourceBytes(),
		TargetDigest: lease.ExpectedTargetDigest(), ReservedBytes: lease.Bytes(),
		ReservedAllocatedBytes: authority.ConsumeAuthorization().ReceiptAllocatedBytes(), TargetKind: authority.TargetKind(),
		TargetStorageID: authority.TargetStorageID(), TargetAuthorityDigest: authority.Digest(), Owner: lease.Owner(),
		TargetRoot:    lease.TargetRoot(),
		MeasuredBytes: 3, AllocatedBytes: 3, ReservationPresent: false, TargetPresent: true,
	})
	_, _ = aggregate.RecordConsumed(observation)
	if err := repository.SaveExpandedTarget(context.Background(), 0, aggregate.Snapshot()); err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.LoadExpandedTarget(context.Background(), lease.ID())
	if err != nil || loaded.Version != 1 || loaded.MeasuredBytes != 3 || loaded.SourceDigest != lease.SourceDigest().Hex() {
		t.Fatalf("LoadExpandedTarget()=%+v,%v", loaded, err)
	}
	if _, err := artifactacquisition.RestoreExpandedTargetAggregate(authority, loaded); err != nil {
		t.Fatal(err)
	}
	if err := repository.SaveExpandedTarget(context.Background(), 0, loaded); !errors.Is(err, artifactapp.ErrAggregateConflict) {
		t.Fatalf("stale target CAS error=%v", err)
	}
}

func TestPF001ExpandedTargetJournalRejectsMalformedBindingsBeforeAppend(t *testing.T) {
	t.Parallel()
	_, aggregate := expandedTargetJournalFixture(t)
	valid := aggregate.Snapshot()
	for name, mutate := range map[string]func(*artifactacquisition.ExpandedTargetSnapshot){
		"schema":            func(value *artifactacquisition.ExpandedTargetSnapshot) { value.SchemaVersion++ },
		"lease":             func(value *artifactacquisition.ExpandedTargetSnapshot) { value.LeaseID = "foreign" },
		"source digest":     func(value *artifactacquisition.ExpandedTargetSnapshot) { value.SourceDigest = "bad" },
		"source bytes":      func(value *artifactacquisition.ExpandedTargetSnapshot) { value.SourceBytes = 0 },
		"target kind":       func(value *artifactacquisition.ExpandedTargetSnapshot) { value.TargetKind = "archive/tar" },
		"target storage":    func(value *artifactacquisition.ExpandedTargetSnapshot) { value.TargetStorageID = "../foreign" },
		"authority digest":  func(value *artifactacquisition.ExpandedTargetSnapshot) { value.TargetAuthorityDigest = "bad" },
		"measured overflow": func(value *artifactacquisition.ExpandedTargetSnapshot) { value.MeasuredBytes = value.ReservedBytes + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			copyOf := valid
			mutate(&copyOf)
			repository, err := NewExpandedTargetRepository(&provider{journal: &memoryJournal{}}, fixedClock{})
			if err != nil {
				t.Fatal(err)
			}
			if err := repository.SaveExpandedTarget(context.Background(), 0, copyOf); !errors.Is(err, artifactapp.ErrAggregateIntegrity) {
				t.Fatalf("SaveExpandedTarget() error=%v", err)
			}
		})
	}
}

func expandedTargetJournalFixture(
	t *testing.T,
) (artifactacquisition.ExpandedTargetAuthority, *artifactacquisition.ExpandedTargetAggregate) {
	t.Helper()
	_, leases := capacityAggregateFixture(t)
	var lease artifactacquisition.CapacityLease
	for _, candidate := range leases {
		if candidate.Purpose() == artifactacquisition.LeaseExpanded {
			lease = candidate
		}
	}
	capacity, _ := artifactacquisition.NewCapacityAggregate("install-capacity-journal", lease.PlanDigest(), []artifactacquisition.CapacityLease{lease})
	receipt, _ := artifactacquisition.NewLeaseReceipt(lease.ID(), lease.Pool(), lease.Bytes(), "reservation-receipt", true)
	_, _ = capacity.RecordReserved(lease, receipt)
	consume, _, err := capacity.BeginConsume(lease.ID())
	if err != nil {
		t.Fatal(err)
	}
	authority, err := artifactacquisition.NewExpandedTargetAuthority(
		consume, string(lease.TargetKind()), lease.TargetStorageID(), lease.TargetAuthorityDigest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	aggregate, err := artifactacquisition.NewExpandedTargetAggregate(authority)
	if err != nil {
		t.Fatal(err)
	}
	return authority, aggregate
}
