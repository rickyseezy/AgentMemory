package dockercli

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001ExpandedTargetsRejectMissingSignedRepresentationBeforeMutation(t *testing.T) {
	t.Parallel()
	_, consume := expandedDockerAuthorization(t, "expanded-unsupported")
	repository := &memoryExpandedTargetRepository{}
	engine := &fakeExpandedTargetEngine{}
	adapter, err := NewExpandedTargets(UnsupportedExpandedTargetAuthorityResolver{}, repository, engine)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.MaterializeExpanded(context.Background(), consume); !errors.Is(err, artifactapp.ErrExpandedTargetUnsupported) {
		t.Fatalf("MaterializeExpanded() error=%v", err)
	}
	if repository.loadCalls != 0 || repository.saveCalls != 0 || engine.calls() != 0 {
		t.Fatalf("unsupported plan mutated state: repo=(%d,%d) engine=%d", repository.loadCalls, repository.saveCalls, engine.calls())
	}
}

func TestPF001ExpandedTargetsReconcileCrashesWithExactMeasuredBytes(t *testing.T) {
	t.Parallel()
	lease, consume := expandedDockerAuthorization(t, "expanded-reconcile")
	authority := explicitExpandedAuthority(t, consume)
	repository := &memoryExpandedTargetRepository{failSaveAt: 2}
	engine := &fakeExpandedTargetEngine{authority: authority, reservationPresent: true}
	adapter := newExpandedTargetAdapter(t, staticExpandedTargetAuthority{authority}, repository, engine)

	if _, err := adapter.MaterializeExpanded(context.Background(), consume); err == nil {
		t.Fatal("interrupted target journal save succeeded")
	}
	if engine.materializeCalls != 1 || !engine.targetPresent || engine.measured != 6 {
		t.Fatalf("materialization effect calls=%d present=%t measured=%d", engine.materializeCalls, engine.targetPresent, engine.measured)
	}
	proof, err := adapter.MaterializeExpanded(context.Background(), consume)
	if err != nil || proof.UsageBytes() != 6 || !proof.TargetDigest().Equal(lease.ExpectedTargetDigest()) ||
		proof.Receipt().Token() != consume.ReceiptToken() || proof.Receipt().Present() {
		t.Fatalf("reconciled proof=%+v,%v", proof, err)
	}
	if engine.materializeCalls != 1 {
		t.Fatalf("materialization replayed mutation calls=%d", engine.materializeCalls)
	}

	repository.failSaveAt = repository.saveCalls + 2
	if _, err := adapter.TransferExpanded(context.Background(), lease, "generation-active"); err == nil {
		t.Fatal("interrupted transfer journal save succeeded")
	}
	if engine.transferCalls != 1 || engine.owner != "generation-active" {
		t.Fatalf("transfer effect calls=%d owner=%q", engine.transferCalls, engine.owner)
	}
	transfer, err := adapter.TransferExpanded(context.Background(), lease, "generation-active")
	if err != nil || transfer.Owner() != "generation-active" || transfer.UsageBytes() != 6 {
		t.Fatalf("reconciled transfer=%+v,%v", transfer, err)
	}
	if engine.transferCalls != 1 {
		t.Fatalf("transfer mutation replayed calls=%d", engine.transferCalls)
	}
}

func TestPF001ExpandedTargetsRetireCancellationAndUninstallIdempotently(t *testing.T) {
	t.Parallel()
	lease, consume := expandedDockerAuthorization(t, "expanded-retire")
	authority := explicitExpandedAuthority(t, consume)
	repository := &memoryExpandedTargetRepository{}
	engine := &fakeExpandedTargetEngine{authority: authority, reservationPresent: true}
	adapter := newExpandedTargetAdapter(t, staticExpandedTargetAuthority{authority}, repository, engine)
	if _, err := adapter.MaterializeExpanded(context.Background(), consume); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.TransferExpanded(context.Background(), lease, "generation-active"); err != nil {
		t.Fatal(err)
	}
	release := transferredExpandedRelease(t, lease, 6, "generation-active", artifactacquisition.CapacityReleaseUninstall)
	repository.failSaveAt = repository.saveCalls + 2
	if _, err := adapter.ReleaseExpanded(context.Background(), release); err == nil {
		t.Fatal("interrupted retirement journal save succeeded")
	}
	if engine.retireCalls != 1 || engine.targetPresent || engine.reservationPresent {
		t.Fatalf("retirement effect calls=%d target=%t reservation=%t", engine.retireCalls, engine.targetPresent, engine.reservationPresent)
	}
	receipt, err := adapter.ReleaseExpanded(context.Background(), release)
	if err != nil || receipt.Present() || receipt.Token() != consume.ReceiptToken() {
		t.Fatalf("retirement replay=%+v,%v", receipt, err)
	}
	if engine.retireCalls != 2 { // replay verifies already-absent exact identities through the idempotent engine boundary.
		t.Fatalf("retirement replay calls=%d", engine.retireCalls)
	}

	// Cancellation before materialization is also journaled and proves both
	// target and reservation absent; no measured usage is invented.
	secondLease, secondConsume := expandedDockerAuthorization(t, "expanded-cancel")
	secondAuthority := explicitExpandedAuthority(t, secondConsume)
	secondRepository := &memoryExpandedTargetRepository{}
	secondEngine := &fakeExpandedTargetEngine{authority: secondAuthority, reservationPresent: true}
	second := newExpandedTargetAdapter(t, staticExpandedTargetAuthority{secondAuthority}, secondRepository, secondEngine)
	if err := second.PrimeConsumeIntent(context.Background(), secondConsume); err != nil {
		t.Fatal(err)
	}
	cancel := pendingExpandedRelease(t, secondLease)
	receipt, err = second.ReleaseExpanded(context.Background(), cancel)
	if err != nil || receipt.Present() || secondEngine.measured != 0 || secondEngine.targetPresent || secondEngine.reservationPresent {
		t.Fatalf("cancel retirement=%+v,%v measured=%d", receipt, err, secondEngine.measured)
	}
}

func TestPF001ExpandedTargetsRejectUntrustedDriftWithoutRepair(t *testing.T) {
	t.Parallel()
	_, consume := expandedDockerAuthorization(t, "expanded-drift")
	authority := explicitExpandedAuthority(t, consume)
	repository := &memoryExpandedTargetRepository{}
	engine := &fakeExpandedTargetEngine{authority: authority, reservationPresent: true, driftSource: true}
	adapter := newExpandedTargetAdapter(t, staticExpandedTargetAuthority{authority}, repository, engine)
	if err := adapter.PrimeConsumeIntent(context.Background(), consume); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.MaterializeExpanded(context.Background(), consume); err == nil {
		t.Fatal("source drift accepted")
	}
	if engine.materializeCalls != 0 || !engine.reservationPresent {
		t.Fatalf("drift repaired or mutated calls=%d reservation=%t", engine.materializeCalls, engine.reservationPresent)
	}
}

func TestPF001DockerCapacityCancellationRoutesUntouchedConsumePendingReservation(t *testing.T) {
	t.Parallel()
	runner := newCapacityLeaseRunner(t)
	reservations, lease := newCapacityLeaseAdapter(t, runner, artifactacquisition.LeaseExpanded)
	receipt, err := reservations.ReserveLease(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	capacity, _ := artifactacquisition.NewCapacityAggregate(
		lease.Owner(), lease.PlanDigest(), []artifactacquisition.CapacityLease{lease},
	)
	_, _ = capacity.RecordReserved(lease, receipt)
	consume, _, _ := capacity.BeginConsume(lease.ID())
	releases, _ := capacity.BeginCompensation()
	if len(releases) != 1 {
		t.Fatalf("releases=%d", len(releases))
	}
	if _, err := reservations.ReleaseCapacity(context.Background(), releases[0]); !errors.Is(err, artifactapp.ErrReservationUnsupported) || len(runner.volumes) != 1 {
		t.Fatalf("low-level release error=%v volumes=%d", err, len(runner.volumes))
	}
	authority := explicitExpandedAuthority(t, consume)
	expanded := newExpandedTargetAdapter(
		t, staticExpandedTargetAuthority{authority},
		&memoryExpandedTargetRepository{}, &fakeExpandedTargetEngine{authority: authority, reservationPresent: true},
	)
	adapter, err := NewDockerCapacity(reservations, expanded)
	if err != nil {
		t.Fatal(err)
	}
	settled, err := adapter.ReleaseCapacity(context.Background(), releases[0])
	if err != nil || settled.Present() || settled.Token() != receipt.Token() || len(runner.volumes) != 0 {
		t.Fatalf("composite release=%+v,%v volumes=%d", settled, err, len(runner.volumes))
	}
}

type staticExpandedTargetAuthority struct {
	authority artifactacquisition.ExpandedTargetAuthority
}

func (r staticExpandedTargetAuthority) ResolveExpandedTarget(
	_ context.Context,
	authorization artifactacquisition.CapacityConsumeAuthorization,
) (artifactacquisition.ExpandedTargetAuthority, error) {
	if authorization.Lease().ID() != r.authority.ConsumeAuthorization().Lease().ID() ||
		authorization.ReceiptToken() != r.authority.ConsumeAuthorization().ReceiptToken() {
		return artifactacquisition.ExpandedTargetAuthority{}, artifactapp.ErrExpandedTargetUnsupported
	}
	return r.authority, nil
}

type memoryExpandedTargetRepository struct {
	snapshot   *artifactacquisition.ExpandedTargetSnapshot
	loadCalls  int
	saveCalls  int
	failSaveAt int
}

func (r *memoryExpandedTargetRepository) LoadExpandedTarget(
	_ context.Context,
	_ string,
) (artifactacquisition.ExpandedTargetSnapshot, error) {
	r.loadCalls++
	if r.snapshot == nil {
		return artifactacquisition.ExpandedTargetSnapshot{}, artifactapp.ErrAggregateNotFound
	}
	return *r.snapshot, nil
}

func (r *memoryExpandedTargetRepository) SaveExpandedTarget(
	_ context.Context,
	expected uint64,
	snapshot artifactacquisition.ExpandedTargetSnapshot,
) error {
	r.saveCalls++
	if r.failSaveAt == r.saveCalls {
		return artifactapp.ErrAggregatePersistence
	}
	if r.snapshot == nil {
		if expected != 0 || snapshot.Version != 0 {
			return artifactapp.ErrAggregateConflict
		}
		copyOf := snapshot
		r.snapshot = &copyOf
		return nil
	}
	if r.snapshot.Version != expected || (snapshot.Version != expected && snapshot.Version != expected+1) {
		return artifactapp.ErrAggregateConflict
	}
	copyOf := snapshot
	r.snapshot = &copyOf
	return nil
}

type fakeExpandedTargetEngine struct {
	authority          artifactacquisition.ExpandedTargetAuthority
	reservationPresent bool
	targetPresent      bool
	owner              string
	measured           uint64
	driftSource        bool
	inspectCalls       int
	materializeCalls   int
	transferCalls      int
	retireCalls        int
}

func (e *fakeExpandedTargetEngine) calls() int {
	return e.inspectCalls + e.materializeCalls + e.transferCalls + e.retireCalls
}

func (e *fakeExpandedTargetEngine) InspectExpandedTarget(
	_ context.Context,
	authority artifactacquisition.ExpandedTargetAuthority,
	_ artifactacquisition.ExpandedTargetSnapshot,
) (artifactacquisition.ExpandedTargetObservation, error) {
	e.inspectCalls++
	return e.observation(authority)
}

func (e *fakeExpandedTargetEngine) MaterializeExpandedTarget(
	_ context.Context,
	authority artifactacquisition.ExpandedTargetAuthority,
) (artifactacquisition.ExpandedTargetObservation, error) {
	e.materializeCalls++
	if !e.reservationPresent || e.targetPresent {
		return artifactacquisition.ExpandedTargetObservation{}, artifactapp.ErrExpandedTargetOperation
	}
	e.reservationPresent, e.targetPresent = false, true
	e.owner, e.measured = authority.ConsumeAuthorization().Lease().Owner(), authority.ConsumeAuthorization().Lease().Bytes()
	return e.observation(authority)
}

func (e *fakeExpandedTargetEngine) TransferExpandedTarget(
	_ context.Context,
	authority artifactacquisition.ExpandedTargetAuthority,
	_ artifactacquisition.ExpandedTargetSnapshot,
	newOwner string,
) (artifactacquisition.ExpandedTargetObservation, error) {
	e.transferCalls++
	if !e.targetPresent || e.reservationPresent {
		return artifactacquisition.ExpandedTargetObservation{}, artifactapp.ErrExpandedTargetOperation
	}
	e.owner = newOwner
	return e.observation(authority)
}

func (e *fakeExpandedTargetEngine) RetireExpandedTarget(
	_ context.Context,
	authority artifactacquisition.ExpandedTargetAuthority,
	_ artifactacquisition.ExpandedTargetSnapshot,
	_ artifactacquisition.CapacityReleaseAuthorization,
) (artifactacquisition.ExpandedTargetObservation, error) {
	e.retireCalls++
	if e.owner == "" {
		e.owner = authority.ConsumeAuthorization().Lease().Owner()
	}
	e.reservationPresent, e.targetPresent = false, false
	return e.observation(authority)
}

func (e *fakeExpandedTargetEngine) observation(
	authority artifactacquisition.ExpandedTargetAuthority,
) (artifactacquisition.ExpandedTargetObservation, error) {
	lease := authority.ConsumeAuthorization().Lease()
	owner := e.owner
	if owner == "" {
		owner = lease.Owner()
	}
	source := lease.SourceDigest()
	if e.driftSource {
		source = releaseinventory.DigestBytes([]byte("foreign-source"))
	}
	return artifactacquisition.NewExpandedTargetObservation(artifactacquisition.ExpandedTargetObservationInput{
		LeaseID: lease.ID(), ReceiptToken: authority.ConsumeAuthorization().ReceiptToken(), PlanDigest: lease.PlanDigest(),
		PoolID: lease.Pool().ID(), PoolKind: lease.Pool().Kind(), SourceDigest: source, SourceBytes: lease.SourceBytes(),
		TargetDigest: lease.ExpectedTargetDigest(), ReservedBytes: lease.Bytes(),
		ReservedAllocatedBytes: authority.ConsumeAuthorization().ReceiptAllocatedBytes(), TargetKind: authority.TargetKind(),
		TargetStorageID: authority.TargetStorageID(), TargetAuthorityDigest: authority.Digest(), Owner: owner,
		TargetRoot:    lease.TargetRoot(),
		MeasuredBytes: e.measured, AllocatedBytes: e.measured,
		ReservationPresent: e.reservationPresent, TargetPresent: e.targetPresent,
	})
}

func newExpandedTargetAdapter(
	t *testing.T,
	resolver artifactapp.ExpandedTargetAuthorityResolver,
	repository artifactapp.ExpandedTargetRepository,
	engine artifactapp.ExpandedTargetEngine,
) *ExpandedTargets {
	t.Helper()
	adapter, err := NewExpandedTargets(resolver, repository, engine)
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func expandedDockerAuthorization(
	t *testing.T,
	operationID string,
) (artifactacquisition.CapacityLease, artifactacquisition.CapacityConsumeAuthorization) {
	t.Helper()
	plan := testArtifactPlan(t)
	host, _ := artifactacquisition.NewStoragePool("host-pool", artifactapp.CapacityHostCAS)
	release, _ := artifactacquisition.NewStoragePool("release-pool", artifactapp.CapacityHostRelease)
	target, _ := artifactacquisition.NewStoragePool("docker-pool", artifactapp.CapacityDockerEngine)
	leases, _ := plan.CapacityLeases(operationID, host, release, target, "/releases/release-1")
	var expanded artifactacquisition.CapacityLease
	for _, lease := range leases {
		if lease.Purpose() == artifactacquisition.LeaseExpanded {
			expanded = lease
		}
	}
	aggregate, _ := artifactacquisition.NewCapacityAggregate(operationID, plan.Digest(), []artifactacquisition.CapacityLease{expanded})
	receipt, _ := artifactacquisition.NewLeaseReceipt(expanded.ID(), expanded.Pool(), expanded.Bytes(), "reservation-receipt", true)
	_, _ = aggregate.RecordReserved(expanded, receipt)
	consume, _, err := aggregate.BeginConsume(expanded.ID())
	if err != nil {
		t.Fatal(err)
	}
	return expanded, consume
}

func explicitExpandedAuthority(
	t *testing.T,
	consume artifactacquisition.CapacityConsumeAuthorization,
) artifactacquisition.ExpandedTargetAuthority {
	t.Helper()
	authority, err := artifactacquisition.NewExpandedTargetAuthority(
		consume, string(consume.Lease().TargetKind()), consume.Lease().TargetStorageID(),
		consume.Lease().TargetAuthorityDigest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func transferredExpandedRelease(
	t *testing.T,
	lease artifactacquisition.CapacityLease,
	usage uint64,
	owner string,
	kind artifactacquisition.CapacityReleaseKind,
) artifactacquisition.CapacityReleaseAuthorization {
	t.Helper()
	aggregate, _ := artifactacquisition.NewCapacityAggregate(lease.Owner(), lease.PlanDigest(), []artifactacquisition.CapacityLease{lease})
	receipt, _ := artifactacquisition.NewLeaseReceipt(lease.ID(), lease.Pool(), lease.Bytes(), "reservation-receipt", true)
	_, _ = aggregate.RecordReserved(lease, receipt)
	_, _, _ = aggregate.BeginConsume(lease.ID())
	missing, _ := artifactacquisition.NewLeaseReceipt(lease.ID(), lease.Pool(), lease.Bytes(), "reservation-receipt", false)
	consumed, _ := artifactacquisition.NewCapacityMutationProof(missing, lease.ExpectedTargetDigest(), usage, lease.Owner())
	_, _ = aggregate.RecordConsumed(lease.ID(), consumed)
	_, _, _ = aggregate.BeginTransfer(lease.ID(), owner)
	transferred, _ := artifactacquisition.NewCapacityMutationProof(missing, lease.ExpectedTargetDigest(), usage, owner)
	_, _ = aggregate.RecordTransferred(lease.ID(), transferred)
	var releases []artifactacquisition.CapacityReleaseAuthorization
	if kind == artifactacquisition.CapacityReleaseUninstall {
		releases, _ = aggregate.BeginUninstall(owner, "installation-active")
	} else {
		releases, _ = aggregate.BeginCompensation()
	}
	return releases[0]
}

func pendingExpandedRelease(
	t *testing.T,
	lease artifactacquisition.CapacityLease,
) artifactacquisition.CapacityReleaseAuthorization {
	t.Helper()
	aggregate, _ := artifactacquisition.NewCapacityAggregate(lease.Owner(), lease.PlanDigest(), []artifactacquisition.CapacityLease{lease})
	receipt, _ := artifactacquisition.NewLeaseReceipt(lease.ID(), lease.Pool(), lease.Bytes(), "reservation-receipt", true)
	_, _ = aggregate.RecordReserved(lease, receipt)
	_, _, _ = aggregate.BeginConsume(lease.ID())
	releases, _ := aggregate.BeginCompensation()
	return releases[0]
}

func testArtifactPlan(t *testing.T) artifactacquisition.Plan {
	t.Helper()
	source := []byte("source")
	digest := releaseinventory.DigestBytes(source)
	target, targetErr := releaseinventory.NewReleaseExpandedTarget(digest, uint64(len(source)), releaseinventory.ReleaseExpandedTargetInput{
		Kind: releaseinventory.ExpandedTargetComposeBundle, StorageID: "compose/compose.yaml",
		Digest: digest, Bytes: uint64(len(source)),
	})
	if targetErr != nil {
		t.Fatal(targetErr)
	}
	plan, err := artifactacquisition.NewPlan(artifactacquisition.PlanInput{
		PlanDigest: releaseinventory.DigestBytes([]byte("expanded-plan")),
		Artifacts: []artifactacquisition.ArtifactInput{{
			ID: "core", Digest: digest, Size: uint64(len(source)),
			ExpandedBytes: uint64(len(source)), ExpandedDigest: digest,
			TargetKind: target.Kind(), TargetStorageID: target.StorageID(), TargetAuthorityDigest: target.AuthorityDigest(),
			Sources: []string{"https://updates.example/core"},
			Chunks: []artifactacquisition.ChunkInput{{
				Offset: 0, Size: uint64(len(source)), Digest: releaseinventory.DigestBytes(source),
			}},
		}},
		Totals: artifactacquisition.TotalsInput{
			DownloadBytes: uint64(len(source)), ExpandedBytes: uint64(len(source)),
			RollbackHeadroomBytes: 20, SafetyHeadroomBytes: 30,
			RequiredBytes: uint64(len(source))*2 + 50,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}
