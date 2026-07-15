package artifactjournal

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001CapacityJournalRoundTripsSchemaThreeReleaseHistoryWithCAS(t *testing.T) {
	t.Parallel()
	journal := &memoryJournal{}
	repository := newCapacityRepository(t, journal)
	aggregate, leases := capacityAggregateFixture(t)
	initial := aggregate.Snapshot()
	if err := repository.SaveCapacity(context.Background(), 0, initial); err != nil {
		t.Fatal(err)
	}
	if err := repository.SaveCapacity(context.Background(), 0, initial); err != nil || len(journal.snapshots) != 1 {
		t.Fatalf("initial replay error=%v snapshots=%d", err, len(journal.snapshots))
	}
	for _, lease := range leases {
		receipt, _ := artifactacquisition.NewLeaseReceipt(lease.ID(), lease.Pool(), lease.Bytes(), "lease-token", true)
		_, _ = aggregate.RecordReserved(lease, receipt)
	}
	authorizations, err := aggregate.BeginCompensation()
	if err != nil {
		t.Fatal(err)
	}
	for _, authorization := range authorizations {
		receipt, _ := artifactacquisition.NewLeaseReceipt(
			authorization.Lease().ID(), authorization.Lease().Pool(), authorization.Lease().Bytes(), "release-token", false,
		)
		_, _ = aggregate.RecordReleased(authorization, receipt)
	}
	settled := aggregate.Snapshot()
	if settled.SchemaVersion != 6 || settled.ReleaseBatches != 1 {
		t.Fatalf("settled snapshot=%+v", settled)
	}
	// The repository admits one aggregate-version transition per append. Replay
	// each durable state exactly as the application does.
	current := initial
	for version := uint64(1); version <= settled.Version; version++ {
		next := aggregateSnapshotAtVersion(t, leases, version)
		if err := repository.SaveCapacity(context.Background(), current.Version, next); err != nil {
			t.Fatalf("SaveCapacity(version=%d)=%v", version, err)
		}
		current = next
	}
	loaded, err := repository.LoadCapacity(context.Background(), initial.OperationID)
	if err != nil || loaded.Version != settled.Version || loaded.ReleaseBatches != 1 {
		t.Fatalf("LoadCapacity()=%+v,%v", loaded, err)
	}
	if err := repository.SaveCapacity(context.Background(), 0, settled); !errors.Is(err, artifactapp.ErrAggregateConflict) {
		t.Fatalf("stale capacity CAS error=%v", err)
	}
}

func TestPF001CapacityJournalRejectsMalformedReleaseMetadataBeforeAppend(t *testing.T) {
	t.Parallel()
	aggregate, _ := capacityAggregateFixture(t)
	valid := aggregate.Snapshot()
	tests := []struct {
		name   string
		mutate func(*artifactacquisition.CapacityAggregateSnapshot)
	}{
		{name: "schema", mutate: func(value *artifactacquisition.CapacityAggregateSnapshot) { value.SchemaVersion = 1 }},
		{name: "release batches", mutate: func(value *artifactacquisition.CapacityAggregateSnapshot) {
			value.ReleaseBatches = uint64(len(value.Leases) + 1)
		}},
		{name: "unsafe new owner", mutate: func(value *artifactacquisition.CapacityAggregateSnapshot) { value.Leases[0].NewOwner = "foreign/owner" }},
		{name: "unsafe release token", mutate: func(value *artifactacquisition.CapacityAggregateSnapshot) {
			value.Leases[0].ReleaseReceiptToken = strings.Repeat("a", 129)
		}},
		{name: "bad target digest", mutate: func(value *artifactacquisition.CapacityAggregateSnapshot) { value.Leases[0].TargetDigest = "bad" }},
		{name: "usage overflow", mutate: func(value *artifactacquisition.CapacityAggregateSnapshot) {
			value.Leases[0].UsageBytes = value.Leases[0].Bytes + 1
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			copyOf := valid
			copyOf.Leases = append([]artifactacquisition.CapacityLeaseSnapshot(nil), valid.Leases...)
			test.mutate(&copyOf)
			if err := newCapacityRepository(t, &memoryJournal{}).SaveCapacity(context.Background(), 0, copyOf); !errors.Is(err, artifactapp.ErrAggregateIntegrity) {
				t.Fatalf("SaveCapacity() error=%v", err)
			}
		})
	}
}

func newCapacityRepository(t *testing.T, journal *memoryJournal) *CapacityRepository {
	t.Helper()
	repository, err := NewCapacityRepository(&provider{journal: journal}, fixedClock{})
	if err != nil {
		t.Fatal(err)
	}
	return repository
}

func capacityAggregateFixture(t *testing.T) (*artifactacquisition.CapacityAggregate, []artifactacquisition.CapacityLease) {
	t.Helper()
	digest := releaseinventory.DigestBytes([]byte("abc"))
	targetAuthority, targetErr := releaseinventory.NewReleaseExpandedTarget(digest, 3, releaseinventory.ReleaseExpandedTargetInput{
		Kind: releaseinventory.ExpandedTargetComposeBundle, StorageID: "compose/compose.yaml", Digest: digest, Bytes: 3,
	})
	if targetErr != nil {
		t.Fatal(targetErr)
	}
	plan, err := artifactacquisition.NewPlan(artifactacquisition.PlanInput{
		PlanDigest: releaseinventory.DigestBytes([]byte("capacity-journal-plan")),
		ProxyMode:  artifactacquisition.ProxyModeSystem,
		Artifacts: []artifactacquisition.ArtifactInput{{
			ID: "core", Digest: digest, Size: 3, ExpandedBytes: 3, ExpandedDigest: digest,
			TargetKind: targetAuthority.Kind(), TargetStorageID: targetAuthority.StorageID(), TargetAuthorityDigest: targetAuthority.AuthorityDigest(),
			Sources: []string{"bundle://core"},
			Chunks:  []artifactacquisition.ChunkInput{{Offset: 0, Size: 3, Digest: releaseinventory.DigestBytes([]byte("abc"))}},
		}},
		Totals: artifactacquisition.TotalsInput{
			DownloadBytes: 3, ExpandedBytes: 3, RollbackHeadroomBytes: 7, SafetyHeadroomBytes: 11, RequiredBytes: 24,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	host, _ := artifactacquisition.NewStoragePool("host-pool", artifactapp.CapacityHostCAS)
	release, _ := artifactacquisition.NewStoragePool("release-pool", artifactapp.CapacityHostRelease)
	target, _ := artifactacquisition.NewStoragePool("docker-pool", artifactapp.CapacityDockerEngine)
	leases, err := plan.CapacityLeases("install-capacity-journal", host, release, target, "/releases/release-1")
	if err != nil {
		t.Fatal(err)
	}
	aggregate, err := artifactacquisition.NewCapacityAggregate("install-capacity-journal", plan.Digest(), leases)
	if err != nil {
		t.Fatal(err)
	}
	return aggregate, leases
}

func aggregateSnapshotAtVersion(
	t *testing.T,
	leases []artifactacquisition.CapacityLease,
	want uint64,
) artifactacquisition.CapacityAggregateSnapshot {
	t.Helper()
	aggregate, err := artifactacquisition.NewCapacityAggregate("install-capacity-journal", leases[0].PlanDigest(), leases)
	if err != nil {
		t.Fatal(err)
	}
	for _, lease := range leases {
		if aggregate.Version() == want {
			return aggregate.Snapshot()
		}
		receipt, _ := artifactacquisition.NewLeaseReceipt(lease.ID(), lease.Pool(), lease.Bytes(), "lease-token", true)
		_, _ = aggregate.RecordReserved(lease, receipt)
	}
	if aggregate.Version() == want {
		return aggregate.Snapshot()
	}
	authorizations, _ := aggregate.BeginCompensation()
	if aggregate.Version() == want {
		return aggregate.Snapshot()
	}
	for _, authorization := range authorizations {
		receipt, _ := artifactacquisition.NewLeaseReceipt(
			authorization.Lease().ID(), authorization.Lease().Pool(), authorization.Lease().Bytes(), "release-token", false,
		)
		_, _ = aggregate.RecordReleased(authorization, receipt)
		if aggregate.Version() == want {
			return aggregate.Snapshot()
		}
	}
	t.Fatalf("unreachable capacity version %d", want)
	return artifactacquisition.CapacityAggregateSnapshot{}
}
