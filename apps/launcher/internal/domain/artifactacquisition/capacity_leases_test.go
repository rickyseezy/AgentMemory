package artifactacquisition

import (
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001CapacityLeaseScheduleSeparatesEveryPurposeAndBackingPool(t *testing.T) {
	t.Parallel()
	plan := testPlan(t)
	host, _ := NewStoragePool("host-pool-1", "host-cas")
	release, _ := NewStoragePool("release-pool-1", "host-release")
	target, _ := NewStoragePool("docker-pool-1", "docker-engine")
	leases, err := plan.CapacityLeases("install-capacity", host, release, target, "/releases/release-1")
	if err != nil || len(leases) != 3 {
		t.Fatalf("CapacityLeases()=%+v,%v", leases, err)
	}
	want := map[LeasePurpose]uint64{LeaseExpanded: 6, LeaseRollback: 20, LeaseSafety: 30}
	seen := map[string]struct{}{}
	var reserved uint64
	for _, lease := range leases {
		if !lease.Valid() || lease.Bytes() != want[lease.Purpose()] || !lease.PlanDigest().Equal(plan.Digest()) {
			t.Fatalf("invalid lease %+v", lease)
		}
		if _, duplicate := seen[lease.ID()]; duplicate {
			t.Fatalf("duplicate lease %q", lease.ID())
		}
		seen[lease.ID()] = struct{}{}
		reserved += lease.Bytes()
		if lease.Purpose() == LeaseExpanded {
			if lease.Pool() != release || lease.TargetRoot() != "/releases/release-1" {
				t.Fatalf("release target pool/root=%+v,%q", lease.Pool(), lease.TargetRoot())
			}
			artifact, _ := plan.Artifact(lease.ArtifactID())
			if !lease.SourceDigest().Equal(artifact.Digest()) || lease.SourceBytes() != artifact.Size() {
				t.Fatalf("expanded source binding=(%s,%d)", lease.SourceDigest().Hex(), lease.SourceBytes())
			}
		} else if lease.Pool() != target || !lease.SourceDigest().IsZero() || lease.SourceBytes() != 0 {
			t.Fatalf("headroom lease has source binding purpose=%s", lease.Purpose())
		}
	}
	if reserved != plan.Totals().RequiredBytes()-plan.Totals().DownloadBytes() {
		t.Fatalf("non-download leases=%d want=%d", reserved, plan.Totals().RequiredBytes()-plan.Totals().DownloadBytes())
	}
	other, _ := NewStoragePool("release-pool-2", "host-release")
	changed, _ := plan.CapacityLeases("install-capacity", host, other, target, "/releases/release-1")
	if changed[0].ID() == leases[0].ID() {
		t.Fatal("pool substitution did not alter signed-plan-bound lease identity")
	}
}

func TestPF001CapacityLeaseScheduleBindsExactProjectionIdentityAndParentAuthority(t *testing.T) {
	t.Parallel()
	plan := testPlan(t)
	host, _ := NewStoragePool("host-pool-1", "host-cas")
	release, _ := NewStoragePool("release-pool-1", "host-release")
	target, _ := NewStoragePool("docker-pool-1", "docker-engine")
	parent := releaseinventory.DigestBytes([]byte("canonical-parent-plan"))
	authority := SecretProjectionLeaseAuthority{
		InstallationID: "019f5f20-1234-7abc-8123-0123456789ab",
		ReleaseID:      "agentmemory-1.0.0",
		GenerationID:   "019f5f21-5678-7def-9123-abcdef012345",
	}
	projections := []SecretProjectionCapacityInput{
		{Name: "agentmemory_projection_neo4j", Purpose: "protected-neo4j", ReservedBytes: 1024 * 1024},
		{Name: "agentmemory_projection_core", Purpose: "protected-core", ReservedBytes: 1024 * 1024},
		{Name: "agentmemory_projection_migrate", Purpose: "protected-migrate", ReservedBytes: 1024 * 1024},
		{Name: "agentmemory_projection_embedding", Purpose: "protected-embedding", ReservedBytes: 1024 * 1024},
		{Name: "agentmemory_projection_reranking", Purpose: "protected-reranking", ReservedBytes: 1024 * 1024},
		{Name: "agentmemory_projection_extraction", Purpose: "protected-extraction", ReservedBytes: 1024 * 1024},
	}
	leases, err := plan.CapacityLeasesForAuthority(
		"install-capacity", parent, host, release, target, "/releases/release-1", authority, projections,
	)
	if err != nil || len(leases) != 9 {
		t.Fatalf("CapacityLeasesForAuthority()=%+v,%v", leases, err)
	}
	seen := make(map[string]struct{}, 6)
	for _, lease := range leases {
		if !lease.Valid() || !lease.PlanDigest().Equal(parent) {
			t.Fatalf("invalid parent-bound lease %+v", lease)
		}
		if lease.Purpose() != LeaseSecretProjection {
			continue
		}
		if lease.ResourcePurpose() == "" || !lease.TargetDigest().IsZero() {
			t.Fatalf("projection resource/target binding=%q/%s", lease.ResourcePurpose(), lease.TargetDigest().Hex())
		}
		if lease.ProjectionInstallationID() != authority.InstallationID ||
			lease.ProjectionReleaseID() != authority.ReleaseID ||
			lease.ProjectionGenerationID() != authority.GenerationID || lease.Bytes() != 1024*1024 {
			t.Fatalf("projection authority=%+v", lease)
		}
		if _, duplicate := seen[lease.ArtifactID()]; duplicate {
			t.Fatalf("duplicate projection lease %q", lease.ArtifactID())
		}
		seen[lease.ArtifactID()] = struct{}{}
	}
	if len(seen) != 6 {
		t.Fatalf("projection leases=%d", len(seen))
	}
	changedAuthority := authority
	changedAuthority.ReleaseID = "agentmemory-1.0.1"
	changed, err := plan.CapacityLeasesForAuthority(
		"install-capacity", parent, host, release, target, "/releases/release-1", changedAuthority, projections,
	)
	if err != nil || changed[1].ID() == leases[1].ID() {
		t.Fatal("signed release label substitution did not change lease identity")
	}

	invalid := append([]SecretProjectionCapacityInput(nil), projections...)
	invalid[1] = invalid[0]
	for name, input := range map[string]struct {
		authority   SecretProjectionLeaseAuthority
		projections []SecretProjectionCapacityInput
	}{
		"missing":        {authority: authority, projections: projections[:5]},
		"extra":          {authority: authority, projections: append(projections, projections[0])},
		"duplicate":      {authority: authority, projections: invalid},
		"missing labels": {projections: projections},
		"foreign labels": {authority: SecretProjectionLeaseAuthority{InstallationID: authority.InstallationID, ReleaseID: authority.ReleaseID, GenerationID: "foreign"}, projections: projections},
	} {
		if _, err := plan.CapacityLeasesForAuthority(
			"install-capacity", parent, host, release, target, "/releases/release-1", input.authority, input.projections,
		); err == nil {
			t.Fatalf("%s projection authority accepted", name)
		}
	}
}

func TestPF001CapacityLeaseCrashReplayRequiresMatchingPendingStateAndExactProof(t *testing.T) {
	t.Parallel()
	plan := testPlan(t)
	host, _ := NewStoragePool("host-pool-1", "host-cas")
	release, _ := NewStoragePool("release-pool-1", "host-release")
	target, _ := NewStoragePool("docker-pool-1", "docker-engine")
	leases, _ := plan.CapacityLeases("install-crash", host, release, target, "/releases/release-1")
	aggregate, _ := NewCapacityAggregate("install-crash", plan.Digest(), leases)
	for _, lease := range leases {
		receipt := capacityReceipt(t, lease, true)
		if changed, err := aggregate.RecordReserved(lease, receipt); err != nil || !changed {
			t.Fatalf("RecordReserved()=%t,%v", changed, err)
		}
	}
	expanded := leaseForPurpose(t, leases, LeaseExpanded)
	previous := aggregate.Version()
	if _, changed, err := aggregate.BeginConsume(expanded.ID()); err != nil || !changed {
		t.Fatalf("BeginConsume()=%t,%v", changed, err)
	}
	pending := aggregate.Snapshot()
	if pending.Version != previous+1 {
		t.Fatalf("pending version=%d", pending.Version)
	}
	restored, err := RestoreCapacityAggregate(leases, pending)
	if err != nil {
		t.Fatal(err)
	}
	missing := capacityReceipt(t, expanded, false)
	materialized := expanded.ExpectedTargetDigest()
	proof, _ := NewCapacityMutationProof(missing, materialized, expanded.Bytes(), expanded.Owner())
	if changed, err := restored.RecordConsumed(expanded.ID(), proof); err != nil || !changed {
		t.Fatalf("RecordConsumed()=%t,%v", changed, err)
	}
	wrongProof, _ := NewCapacityMutationProof(missing, releaseinventory.DigestBytes([]byte("arbitrary-target")), expanded.Bytes(), expanded.Owner())
	if _, err := aggregate.RecordConsumed(expanded.ID(), wrongProof); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("unsigned materialized target accepted: %v", err)
	}

	rollback := leaseForPurpose(t, leases, LeaseRollback)
	if _, _, err := restored.BeginTransfer(rollback.ID(), "generation-2"); err != nil {
		t.Fatal(err)
	}
	transfer, _ := NewCapacityMutationProof(capacityReceipt(t, rollback, false), releaseinventory.Digest{}, 0, "generation-2")
	if changed, err := restored.RecordTransferred(rollback.ID(), transfer); err != nil || !changed {
		t.Fatalf("RecordTransferred()=%t,%v", changed, err)
	}

	// Missing bytes outside the matching pending transition are never accepted.
	badConsume, _ := NewCapacityMutationProof(capacityReceipt(t, rollback, false), materialized, 1, rollback.Owner())
	if _, err := restored.RecordConsumed(rollback.ID(), badConsume); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("missing reserved lease accepted: %v", err)
	}
	foreignPool, _ := NewStoragePool("foreign-pool", "docker-engine")
	foreignReceipt, _ := NewLeaseReceipt(expanded.ID(), foreignPool, expanded.Bytes(), "receipt-token", false)
	foreignProof, _ := NewCapacityMutationProof(foreignReceipt, materialized, expanded.Bytes(), expanded.Owner())
	if _, err := aggregate.RecordConsumed(expanded.ID(), foreignProof); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("pool substitution accepted: %v", err)
	}
	substitutedReceipt, _ := NewLeaseReceipt(expanded.ID(), expanded.Pool(), expanded.Bytes(), "substituted-token", false)
	substitutedProof, _ := NewCapacityMutationProof(substitutedReceipt, materialized, expanded.Bytes(), expanded.Owner())
	if _, err := aggregate.RecordConsumed(expanded.ID(), substitutedProof); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("receipt-token substitution accepted: %v", err)
	}
}

func TestPF001CapacityCancellationReconcilesEveryPendingMutationWithoutGuessingOwnership(t *testing.T) {
	t.Parallel()
	plan := testPlan(t)
	host, _ := NewStoragePool("host-pool-1", "host-cas")
	release, _ := NewStoragePool("release-pool-1", "host-release")
	target, _ := NewStoragePool("docker-pool-1", "docker-engine")
	leases, _ := plan.CapacityLeases("install-cancel", host, release, target, "/releases/release-1")
	aggregate, _ := NewCapacityAggregate("install-cancel", plan.Digest(), leases)
	for _, lease := range leases {
		_, _ = aggregate.RecordReserved(lease, capacityReceipt(t, lease, true))
	}
	expanded := leaseForPurpose(t, leases, LeaseExpanded)
	_, _, _ = aggregate.BeginConsume(expanded.ID())
	consumed, _ := NewCapacityMutationProof(capacityReceipt(t, expanded, false), expanded.ExpectedTargetDigest(), 6, expanded.Owner())
	_, _ = aggregate.RecordConsumed(expanded.ID(), consumed)
	_, _, _ = aggregate.BeginTransfer(expanded.ID(), "generation-retained")
	rollback := leaseForPurpose(t, leases, LeaseRollback)
	_, _, _ = aggregate.BeginTransfer(rollback.ID(), "generation-retained")

	pending, err := aggregate.BeginCompensation()
	if err != nil || len(pending) != len(leases) {
		t.Fatalf("BeginCompensation()=%+v,%v", pending, err)
	}
	wantFrom := map[LeasePurpose]LeaseState{
		LeaseExpanded: LeaseTransferPending,
		LeaseRollback: LeaseTransferPending,
		LeaseSafety:   LeaseReserved,
	}
	for _, authorization := range pending {
		if authorization.FromState() != wantFrom[authorization.Lease().Purpose()] ||
			authorization.Kind() != CapacityReleaseCompensation {
			t.Fatalf("release authority=%+v", authorization)
		}
		if authorization.Lease().Purpose() != LeaseSafety && authorization.NewOwner() != "generation-retained" {
			t.Fatalf("candidate owner=%q", authorization.NewOwner())
		}
		if _, err := aggregate.RecordReleased(authorization, capacityReceipt(t, authorization.Lease(), false)); err != nil {
			t.Fatal(err)
		}
	}
	if state, _ := aggregate.State(expanded.ID()); state != LeaseReleased {
		t.Fatalf("expanded state=%s", state)
	}
	if state, _ := aggregate.State(rollback.ID()); state != LeaseReleased {
		t.Fatalf("rollback state=%s", state)
	}
	if replay, err := aggregate.BeginCompensation(); err != nil || len(replay) != 0 {
		t.Fatalf("release replay=%+v,%v", replay, err)
	}
	if _, err := RestoreCapacityAggregate(leases, aggregate.Snapshot()); err != nil {
		t.Fatalf("RestoreCapacityAggregate()=%v", err)
	}
}

func TestPF001CapacityActivationTransfersExpandedTargetsAndUninstallRequiresExactOwners(t *testing.T) {
	t.Parallel()
	plan := testPlan(t)
	host, _ := NewStoragePool("host-pool-1", "host-cas")
	release, _ := NewStoragePool("release-pool-1", "host-release")
	target, _ := NewStoragePool("docker-pool-1", "docker-engine")
	leases, _ := plan.CapacityLeases("install-uninstall", host, release, target, "/releases/release-1")
	aggregate, _ := NewCapacityAggregate("install-uninstall", plan.Digest(), leases)
	for _, lease := range leases {
		_, _ = aggregate.RecordReserved(lease, capacityReceipt(t, lease, true))
	}
	expanded := leaseForPurpose(t, leases, LeaseExpanded)
	_, _, _ = aggregate.BeginConsume(expanded.ID())
	consumed, _ := NewCapacityMutationProof(capacityReceipt(t, expanded, false), expanded.ExpectedTargetDigest(), 6, expanded.Owner())
	_, _ = aggregate.RecordConsumed(expanded.ID(), consumed)

	for _, lease := range leases {
		owner := "generation-active"
		if lease.Purpose() == LeaseSafety {
			owner = "installation-active"
		}
		if _, changed, err := aggregate.BeginTransfer(lease.ID(), owner); err != nil || !changed {
			t.Fatalf("BeginTransfer(%s)=%t,%v", lease.Purpose(), changed, err)
		}
		targetDigest, usage := releaseinventory.Digest{}, uint64(0)
		if lease.Purpose() == LeaseExpanded {
			targetDigest, usage = lease.ExpectedTargetDigest(), uint64(6)
		}
		proof, _ := NewCapacityMutationProof(capacityReceipt(t, lease, false), targetDigest, usage, owner)
		if _, err := aggregate.RecordTransferred(lease.ID(), proof); err != nil {
			t.Fatalf("RecordTransferred(%s)=%v", lease.Purpose(), err)
		}
	}
	if _, err := aggregate.BeginUninstall("foreign-generation", "installation-active"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("foreign uninstall error=%v", err)
	}
	authorizations, err := aggregate.BeginUninstall("generation-active", "installation-active")
	if err != nil || len(authorizations) != len(leases) {
		t.Fatalf("BeginUninstall()=%+v,%v", authorizations, err)
	}
	if _, err := aggregate.RecordReleased(authorizations[0], capacityReceipt(t, authorizations[0].Lease(), false)); err != nil {
		t.Fatal(err)
	}
	aggregate, err = RestoreCapacityAggregate(leases, aggregate.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	authorizations, err = aggregate.BeginUninstall("generation-active", "installation-active")
	if err != nil || len(authorizations) != len(leases)-1 {
		t.Fatalf("BeginUninstall replay()=%+v,%v", authorizations, err)
	}
	for _, authorization := range authorizations {
		if authorization.Kind() != CapacityReleaseUninstall || authorization.FromState() != LeaseTransferred {
			t.Fatalf("uninstall authority=%+v", authorization)
		}
		if authorization.Lease().Purpose() == LeaseExpanded &&
			!authorization.TargetDigest().Equal(authorization.Lease().ExpectedTargetDigest()) {
			t.Fatalf("uninstall target digest=%s", authorization.TargetDigest().Hex())
		}
		if _, err := aggregate.RecordReleased(authorization, capacityReceipt(t, authorization.Lease(), false)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := RestoreCapacityAggregate(leases, aggregate.Snapshot()); err != nil {
		t.Fatalf("RestoreCapacityAggregate()=%v", err)
	}
}

func TestPF001CapacityCompensationCanReleaseNeverRecordedReservation(t *testing.T) {
	t.Parallel()
	plan := testPlan(t)
	host, _ := NewStoragePool("host-pool-1", "host-cas")
	release, _ := NewStoragePool("release-pool-1", "host-release")
	target, _ := NewStoragePool("docker-pool-1", "docker-engine")
	leases, _ := plan.CapacityLeases("install-reserve-pending", host, release, target, "/releases/release-1")
	aggregate, _ := NewCapacityAggregate("install-reserve-pending", plan.Digest(), leases)
	authorizations, err := aggregate.BeginCompensation()
	if err != nil || len(authorizations) != len(leases) {
		t.Fatalf("BeginCompensation()=%+v,%v", authorizations, err)
	}
	for _, authorization := range authorizations {
		if authorization.FromState() != LeaseReservePending || authorization.ReceiptToken() != "" {
			t.Fatalf("reserve-pending authority=%+v", authorization)
		}
		if _, err := aggregate.RecordReleased(authorization, capacityReceipt(t, authorization.Lease(), false)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := RestoreCapacityAggregate(leases, aggregate.Snapshot()); err != nil {
		t.Fatalf("RestoreCapacityAggregate()=%v", err)
	}
}

func TestPF001CapacityEvidenceAccessorsPreserveExactMeasuredAuthority(t *testing.T) {
	t.Parallel()
	plan := testPlan(t)
	host, _ := NewStoragePool("host-pool-1", "host-cas")
	release, _ := NewStoragePool("release-pool-1", "host-release")
	target, _ := NewStoragePool("docker-pool-1", "docker-engine")
	leases, _ := plan.CapacityLeases("install-evidence", host, release, target, "/releases/release-1")
	expanded := leaseForPurpose(t, leases, LeaseExpanded)

	receipt, err := NewMeasuredLeaseReceipt(
		expanded.ID(), expanded.Pool(), expanded.Bytes(), expanded.Bytes()+4, "measured-receipt", true,
	)
	if err != nil || receipt.LeaseID() != expanded.ID() || receipt.Pool() != expanded.Pool() ||
		receipt.Bytes() != expanded.Bytes() || receipt.AllocatedBytes() != expanded.Bytes()+4 ||
		receipt.Token() != "measured-receipt" || !receipt.Present() {
		t.Fatalf("measured receipt=%+v,%v", receipt, err)
	}
	authorization, err := RestoreCapacityConsumeAuthorization(
		expanded, receipt.Token(), receipt.AllocatedBytes(),
	)
	if err != nil || authorization.Lease() != expanded || authorization.ReceiptToken() != receipt.Token() ||
		authorization.ReceiptAllocatedBytes() != receipt.AllocatedBytes() || !authorization.Valid() {
		t.Fatalf("restored consume authority=%+v,%v", authorization, err)
	}
	if _, err := RestoreCapacityConsumeAuthorization(expanded, receipt.Token(), 1, 2); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("ambiguous allocated-byte restore error=%v", err)
	}

	missing, _ := NewMeasuredLeaseReceipt(
		expanded.ID(), expanded.Pool(), expanded.Bytes(), receipt.AllocatedBytes(), receipt.Token(), false,
	)
	proof, err := NewMeasuredCapacityMutationProof(
		missing, expanded.ExpectedTargetDigest(), expanded.Bytes(), expanded.Bytes(), expanded.Owner(),
	)
	if err != nil || proof.Receipt() != missing || !proof.TargetDigest().Equal(expanded.ExpectedTargetDigest()) ||
		proof.UsageBytes() != expanded.Bytes() || proof.AllocatedBytes() != expanded.Bytes() || proof.Owner() != expanded.Owner() {
		t.Fatalf("measured mutation proof=%+v,%v", proof, err)
	}

	aggregate, _ := NewCapacityAggregate("install-evidence", plan.Digest(), leases)
	for _, lease := range leases {
		measured, _ := NewMeasuredLeaseReceipt(
			lease.ID(), lease.Pool(), lease.Bytes(), lease.Bytes()+4, "measured-receipt", true,
		)
		_, _ = aggregate.RecordReserved(lease, measured)
	}
	releases, err := aggregate.BeginReleaseRemainder()
	if err != nil || len(releases) != len(leases) {
		t.Fatalf("BeginReleaseRemainder()=%+v,%v", releases, err)
	}
	for _, releaseAuthorization := range releases {
		lease := releaseAuthorization.Lease()
		if !releaseAuthorization.Valid() || releaseAuthorization.FromState() != LeaseReserved ||
			releaseAuthorization.Kind() != CapacityReleaseRemainder ||
			releaseAuthorization.ReceiptToken() != "measured-receipt" ||
			releaseAuthorization.ReceiptAllocatedBytes() != lease.Bytes()+4 ||
			!releaseAuthorization.ExpectedTargetDigest().Equal(lease.ExpectedTargetDigest()) ||
			releaseAuthorization.UsageBytes() != 0 || releaseAuthorization.AllocatedBytes() != 0 ||
			releaseAuthorization.NewOwner() != "" {
			t.Fatalf("release authority=%+v", releaseAuthorization)
		}
	}
}

func TestPF001CapacityRestoreRejectsTamperingAndImpossibleStates(t *testing.T) {
	t.Parallel()
	plan := testPlan(t)
	host, _ := NewStoragePool("host-pool-1", "host-cas")
	release, _ := NewStoragePool("release-pool-1", "host-release")
	target, _ := NewStoragePool("docker-pool-1", "docker-engine")
	leases, _ := plan.CapacityLeases("install-restore", host, release, target, "/releases/release-1")
	aggregate, _ := NewCapacityAggregate("install-restore", plan.Digest(), leases)
	snapshot := aggregate.Snapshot()
	for name, mutate := range map[string]func(*CapacityAggregateSnapshot){
		"pool":          func(value *CapacityAggregateSnapshot) { value.Leases[0].PoolID = "substituted" },
		"bytes":         func(value *CapacityAggregateSnapshot) { value.Leases[0].Bytes++ },
		"state":         func(value *CapacityAggregateSnapshot) { value.Leases[0].State = string(LeaseConsumed) },
		"unknown state": func(value *CapacityAggregateSnapshot) { value.Leases[0].State = "foreign" },
		"unknown lease": func(value *CapacityAggregateSnapshot) { value.Leases[0].LeaseID = "foreign" },
		"duplicate":     func(value *CapacityAggregateSnapshot) { value.Leases[1] = value.Leases[0] },
		"malformed target digest": func(value *CapacityAggregateSnapshot) {
			value.Leases[0].TargetDigest = "not-a-digest"
		},
		"invalid operation": func(value *CapacityAggregateSnapshot) { value.OperationID = "invalid operation" },
		"release batch without state": func(value *CapacityAggregateSnapshot) {
			value.ReleaseBatches = 1
			value.Version = 1
		},
		"version": func(value *CapacityAggregateSnapshot) {
			value.Version = 0
			value.Leases[0].State = string(LeaseReserved)
			value.Leases[0].ReceiptToken = "token"
		},
		"high version": func(value *CapacityAggregateSnapshot) { value.Version = 99 },
	} {
		t.Run(name, func(t *testing.T) {
			copyOf := snapshot
			copyOf.Leases = append([]CapacityLeaseSnapshot(nil), snapshot.Leases...)
			mutate(&copyOf)
			if _, err := RestoreCapacityAggregate(leases, copyOf); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("tampered restore error=%v", err)
			}
		})
	}
}

func capacityReceipt(t *testing.T, lease CapacityLease, present bool) LeaseReceipt {
	t.Helper()
	receipt, err := NewLeaseReceipt(lease.ID(), lease.Pool(), lease.Bytes(), "receipt-token", present)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func leaseForPurpose(t *testing.T, leases []CapacityLease, purpose LeasePurpose) CapacityLease {
	t.Helper()
	for _, lease := range leases {
		if lease.Purpose() == purpose {
			return lease
		}
	}
	t.Fatalf("missing %s lease", purpose)
	return CapacityLease{}
}
