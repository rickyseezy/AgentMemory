package artifactacquisition

import (
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001ExpandedTargetLifecycleBindsSourceTargetOwnerAndExactUsage(t *testing.T) {
	t.Parallel()
	lease, consume := expandedTargetLeaseAndConsume(t, "install-expanded")
	authority, err := NewExpandedTargetAuthority(
		consume, string(lease.TargetKind()), lease.TargetStorageID(), lease.TargetAuthorityDigest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	target, err := NewExpandedTargetAggregate(authority)
	if err != nil || target.State() != ExpandedTargetConsumePending || target.Version() != 0 {
		t.Fatalf("NewExpandedTargetAggregate()=%+v,%v", target, err)
	}
	consumed := expandedObservation(t, authority, lease.Owner(), 6, true)
	if changed, recordErr := target.RecordConsumed(consumed); recordErr != nil || !changed {
		t.Fatalf("RecordConsumed()=%t,%v", changed, recordErr)
	}
	if target.MeasuredBytes() != 6 || target.CurrentOwner() != lease.Owner() {
		t.Fatalf("consumed projection bytes=%d owner=%q", target.MeasuredBytes(), target.CurrentOwner())
	}
	if changed, replayErr := target.RecordConsumed(consumed); replayErr != nil || changed {
		t.Fatalf("RecordConsumed replay=%t,%v", changed, replayErr)
	}

	tampered := consumed
	tampered.SourceDigest = releaseinventory.DigestBytes([]byte("foreign-source"))
	if _, recordErr := target.RecordConsumed(tampered); !errors.Is(recordErr, ErrInvalidTransition) {
		t.Fatalf("source substitution accepted: %v", recordErr)
	}
	restored, err := RestoreExpandedTargetAggregate(authority, target.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if changed, beginErr := restored.BeginTransfer("generation-active"); beginErr != nil || !changed {
		t.Fatalf("BeginTransfer()=%t,%v", changed, beginErr)
	}
	if changed, beginErr := restored.BeginTransfer("generation-active"); beginErr != nil || changed ||
		restored.NewOwner() != "generation-active" || restored.Authority().TargetStorageID() != authority.TargetStorageID() {
		t.Fatalf("BeginTransfer replay=%t,%v", changed, beginErr)
	}
	transferred := expandedObservation(t, authority, "generation-active", 6, true)
	if changed, recordErr := restored.RecordTransferred(transferred); recordErr != nil || !changed {
		t.Fatalf("RecordTransferred()=%t,%v", changed, recordErr)
	}
	if changed, recordErr := restored.RecordTransferred(transferred); recordErr != nil || changed {
		t.Fatalf("RecordTransferred replay=%t,%v", changed, recordErr)
	}

	capacity, _ := NewCapacityAggregate("install-expanded", lease.PlanDigest(), []CapacityLease{lease})
	_, _ = capacity.RecordReserved(lease, capacityReceipt(t, lease, true))
	_, _, _ = capacity.BeginConsume(lease.ID())
	proof, _ := NewCapacityMutationProof(capacityReceipt(t, lease, false), lease.ExpectedTargetDigest(), 6, lease.Owner())
	_, _ = capacity.RecordConsumed(lease.ID(), proof)
	_, _, _ = capacity.BeginTransfer(lease.ID(), "generation-active")
	transferProof, _ := NewCapacityMutationProof(capacityReceipt(t, lease, false), lease.ExpectedTargetDigest(), 6, "generation-active")
	_, _ = capacity.RecordTransferred(lease.ID(), transferProof)
	releases, err := capacity.BeginUninstall("generation-active", "installation-active")
	if err != nil || len(releases) != 1 {
		t.Fatalf("BeginUninstall()=%+v,%v", releases, err)
	}
	if changed, beginErr := restored.BeginRelease(releases[0]); beginErr != nil || !changed {
		t.Fatalf("BeginRelease()=%t,%v", changed, beginErr)
	}
	if changed, beginErr := restored.BeginRelease(releases[0]); beginErr != nil || changed {
		t.Fatalf("BeginRelease replay=%t,%v", changed, beginErr)
	}
	released := expandedObservation(t, authority, "generation-active", 6, false)
	if changed, recordErr := restored.RecordReleased(released); recordErr != nil || !changed {
		t.Fatalf("RecordReleased()=%t,%v", changed, recordErr)
	}
	if restored.State() != ExpandedTargetReleased {
		t.Fatalf("released state=%s", restored.State())
	}
	if changed, recordErr := restored.RecordReleased(released); recordErr != nil || changed {
		t.Fatalf("RecordReleased replay=%t,%v", changed, recordErr)
	}
	if _, err := RestoreExpandedTargetAggregate(authority, restored.Snapshot()); err != nil {
		t.Fatalf("restore released target: %v", err)
	}
}

func TestPF001ExpandedTargetRestoreAndRetirementRejectDriftWithoutRepair(t *testing.T) {
	t.Parallel()
	lease, consume := expandedTargetLeaseAndConsume(t, "install-expanded-drift")
	authority, _ := NewExpandedTargetAuthority(
		consume, string(lease.TargetKind()), lease.TargetStorageID(), lease.TargetAuthorityDigest(),
	)
	target, _ := NewExpandedTargetAggregate(authority)
	snapshot := target.Snapshot()
	for name, mutate := range map[string]func(*ExpandedTargetSnapshot){
		"source digest": func(value *ExpandedTargetSnapshot) {
			value.SourceDigest = releaseinventory.DigestBytes([]byte("foreign")).Hex()
		},
		"source bytes": func(value *ExpandedTargetSnapshot) { value.SourceBytes++ },
		"storage":      func(value *ExpandedTargetSnapshot) { value.TargetStorageID = "foreign-target" },
		"authority": func(value *ExpandedTargetSnapshot) {
			value.TargetAuthorityDigest = releaseinventory.DigestBytes([]byte("foreign")).Hex()
		},
		"version": func(value *ExpandedTargetSnapshot) { value.Version++ },
	} {
		t.Run(name, func(t *testing.T) {
			copyOf := snapshot
			mutate(&copyOf)
			if _, err := RestoreExpandedTargetAggregate(authority, copyOf); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("tampered restore error=%v", err)
			}
		})
	}

	capacity, _ := NewCapacityAggregate("install-expanded-drift", lease.PlanDigest(), []CapacityLease{lease})
	_, _ = capacity.RecordReserved(lease, capacityReceipt(t, lease, true))
	_, _, _ = capacity.BeginConsume(lease.ID())
	releases, _ := capacity.BeginCompensation()
	if len(releases) != 1 {
		t.Fatalf("compensation releases=%d", len(releases))
	}
	if _, err := target.BeginRelease(releases[0]); err != nil {
		t.Fatal(err)
	}
	foreign := expandedObservation(t, authority, lease.Owner(), 0, false)
	foreign.TargetStorageID = "foreign-target"
	if _, err := target.RecordReleased(foreign); !errors.Is(err, ErrInvalidTransition) || target.State() != ExpandedTargetReleasePending {
		t.Fatalf("foreign retirement error=%v state=%s", err, target.State())
	}
}

func expandedTargetLeaseAndConsume(t *testing.T, operationID string) (CapacityLease, CapacityConsumeAuthorization) {
	t.Helper()
	plan := testPlan(t)
	host, _ := NewStoragePool("host-pool-1", "host-cas")
	release, _ := NewStoragePool("release-pool-1", "host-release")
	target, _ := NewStoragePool("docker-pool-1", "docker-engine")
	leases, _ := plan.CapacityLeases(operationID, host, release, target, "/releases/release-1")
	lease := leaseForPurpose(t, leases, LeaseExpanded)
	aggregate, _ := NewCapacityAggregate(operationID, plan.Digest(), []CapacityLease{lease})
	_, _ = aggregate.RecordReserved(lease, capacityReceipt(t, lease, true))
	authorization, _, err := aggregate.BeginConsume(lease.ID())
	if err != nil || !authorization.Valid() {
		t.Fatalf("BeginConsume()=%+v,%v", authorization, err)
	}
	return lease, authorization
}

func expandedObservation(
	t *testing.T,
	authority ExpandedTargetAuthority,
	owner string,
	measured uint64,
	targetPresent bool,
) ExpandedTargetObservation {
	t.Helper()
	observation, err := NewExpandedTargetObservation(ExpandedTargetObservationInput{
		LeaseID: authority.ConsumeAuthorization().Lease().ID(), ReceiptToken: authority.ConsumeAuthorization().ReceiptToken(),
		PlanDigest: authority.ConsumeAuthorization().Lease().PlanDigest(),
		PoolID:     authority.ConsumeAuthorization().Lease().Pool().ID(), PoolKind: authority.ConsumeAuthorization().Lease().Pool().Kind(),
		SourceDigest: authority.ConsumeAuthorization().Lease().SourceDigest(), SourceBytes: authority.ConsumeAuthorization().Lease().SourceBytes(),
		TargetDigest: authority.ConsumeAuthorization().Lease().ExpectedTargetDigest(), ReservedBytes: authority.ConsumeAuthorization().Lease().Bytes(),
		ReservedAllocatedBytes: authority.ConsumeAuthorization().ReceiptAllocatedBytes(),
		TargetKind:             authority.TargetKind(), TargetStorageID: authority.TargetStorageID(), TargetAuthorityDigest: authority.Digest(),
		TargetRoot: authority.ConsumeAuthorization().Lease().TargetRoot(),
		Owner:      owner, MeasuredBytes: measured, AllocatedBytes: measured,
		ReservationPresent: false, TargetPresent: targetPresent,
	})
	if err != nil {
		t.Fatal(err)
	}
	return observation
}
