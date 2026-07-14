//go:build darwin || linux || windows

package artifactfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001HostReleaseCapacityReservesBeforeDirectoryCreationAndRevalidatesAfter(t *testing.T) {
	t.Parallel()
	fixture := newHostReleaseFixture(t)
	receipt, err := fixture.capacity.ReserveLease(context.Background(), fixture.lease)
	if err != nil || !receipt.Present() || receipt.AllocatedBytes() < fixture.lease.Bytes() {
		t.Fatalf("ReserveLease()=%+v,%v", receipt, err)
	}
	if replay, replayError := fixture.capacity.ReserveLease(context.Background(), fixture.lease); replayError != nil || replay != receipt {
		t.Fatalf("ReserveLease replay=%+v,%v", replay, replayError)
	}
	if _, statErr := os.Lstat(fixture.releaseRoot); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("reservation created release directory: %v", statErr)
	}
	makeSecureTestDirectory(t, fixture.releaseRoot)
	revalidated, err := fixture.capacity.RevalidateLease(context.Background(), fixture.lease)
	if err != nil || revalidated != receipt {
		t.Fatalf("RevalidateLease()=%+v,%v want=%+v", revalidated, err, receipt)
	}
	if _, err := fixture.capacity.TransferLease(context.Background(), fixture.lease, "generation-owner"); !errors.Is(err, artifactapp.ErrReservationUnsupported) {
		t.Fatalf("host reservation transfer error=%v", err)
	}
	aggregate, _ := artifactacquisition.NewCapacityAggregate(
		fixture.lease.Owner(), fixture.lease.PlanDigest(), []artifactacquisition.CapacityLease{fixture.lease},
	)
	_, _ = aggregate.RecordReserved(fixture.lease, receipt)
	releases, _ := aggregate.BeginCompensation()
	settled, err := fixture.capacity.ReleaseCapacity(context.Background(), releases[0])
	if err != nil || settled.Present() || settled.AllocatedBytes() != receipt.AllocatedBytes() {
		t.Fatalf("ReleaseCapacity()=%+v,%v", settled, err)
	}
	if replay, replayError := fixture.capacity.ReleaseCapacity(context.Background(), releases[0]); replayError != nil ||
		replay.Present() || replay.AllocatedBytes() != receipt.AllocatedBytes() {
		t.Fatalf("ReleaseCapacity replay=%+v,%v", replay, replayError)
	}
	if _, err := fixture.capacity.RevalidateLease(context.Background(), fixture.lease); err == nil {
		t.Fatal("released reservation revalidated")
	}
}

func TestPF001HostReleaseAndComposeTargetBoundariesRejectIncompleteAuthority(t *testing.T) {
	t.Parallel()
	fixture := newHostReleaseFixture(t)
	var nilContext context.Context
	if _, err := attestHostReleasePool(""); err == nil {
		t.Fatal("empty host release locator attested")
	}
	if _, err := openNearestSecureAncestor(""); err == nil {
		t.Fatal("empty host release ancestor accepted")
	}
	symlink := filepath.Join(resolvedTempDir(t), "release-link")
	if err := os.Symlink(filepath.Dir(symlink), symlink); err != nil {
		if runtime.GOOS != "windows" {
			t.Fatal(err)
		}
	} else {
		if _, err := openNearestSecureAncestor(symlink); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
			t.Fatalf("symlink host release ancestor error=%v", err)
		}
	}
	if _, _, err := composeTargetLocation(artifactacquisition.CapacityLease{}, false); err == nil {
		t.Fatal("invalid compose target lease accepted")
	}
	if err := copyExactComposeSource(nilContext, nil, nil, fixture.lease); !errors.Is(err, artifactapp.ErrExpandedTargetOperation) {
		t.Fatalf("incomplete compose copy error=%v", err)
	}
	if _, err := verifyTargetFile(nilContext, nil, 0, releaseinventory.Digest{}); !errors.Is(err, artifactapp.ErrExpandedTargetOperation) {
		t.Fatalf("incomplete target verification error=%v", err)
	}
	receipt, err := fixture.capacity.ReserveLease(context.Background(), fixture.lease)
	if err != nil {
		t.Fatal(err)
	}
	aggregate, _ := artifactacquisition.NewCapacityAggregate(
		fixture.lease.Owner(), fixture.lease.PlanDigest(), []artifactacquisition.CapacityLease{fixture.lease},
	)
	_, _ = aggregate.RecordReserved(fixture.lease, receipt)
	consume, _, _ := aggregate.BeginConsume(fixture.lease.ID())
	authority, _ := artifactacquisition.NewExpandedTargetAuthority(
		consume, string(fixture.lease.TargetKind()), fixture.lease.TargetStorageID(), fixture.lease.TargetAuthorityDigest(),
	)
	engine, _ := NewComposeBundleTargetEngine(fixture.store, fixture.capacity)
	if _, err := engine.MaterializeExpandedTarget(nilContext, authority); !errors.Is(err, artifactapp.ErrExpandedTargetUnsupported) {
		t.Fatalf("nil materialize context error=%v", err)
	}
	if _, err := engine.InspectExpandedTarget(nilContext, authority, artifactacquisition.ExpandedTargetSnapshot{}); !errors.Is(err, artifactapp.ErrExpandedTargetUnsupported) {
		t.Fatalf("nil inspect context error=%v", err)
	}
	if _, err := engine.TransferExpandedTarget(nilContext, authority, artifactacquisition.ExpandedTargetSnapshot{}, "generation-owner"); !errors.Is(err, artifactapp.ErrExpandedTargetUnsupported) {
		t.Fatalf("nil transfer context error=%v", err)
	}
	if _, err := engine.MaterializeExpandedTarget(context.Background(), authority); !errors.Is(err, artifactapp.ErrExpandedTargetOperation) {
		t.Fatalf("missing CAS source error=%v", err)
	}
}

func TestPF001ComposeTargetEngineTransfersAndRetiresExactPublishedTarget(t *testing.T) {
	t.Parallel()
	fixture := newHostReleaseFixture(t)
	publishCASFixture(t, fixture.store, fixture.source)
	receipt, err := fixture.capacity.ReserveLease(context.Background(), fixture.lease)
	if err != nil {
		t.Fatal(err)
	}
	makeSecureTestDirectory(t, fixture.releaseRoot)
	aggregate, _ := artifactacquisition.NewCapacityAggregate(
		fixture.lease.Owner(), fixture.lease.PlanDigest(), []artifactacquisition.CapacityLease{fixture.lease},
	)
	_, _ = aggregate.RecordReserved(fixture.lease, receipt)
	consume, _, _ := aggregate.BeginConsume(fixture.lease.ID())
	authority, _ := artifactacquisition.NewExpandedTargetAuthority(
		consume, string(fixture.lease.TargetKind()), fixture.lease.TargetStorageID(), fixture.lease.TargetAuthorityDigest(),
	)
	engine, _ := NewComposeBundleTargetEngine(fixture.store, fixture.capacity)
	materialized, err := engine.MaterializeExpandedTarget(context.Background(), authority)
	if err != nil {
		t.Fatal(err)
	}
	newOwner := "generation-owner"
	transferred, err := engine.TransferExpandedTarget(context.Background(), authority, artifactacquisition.ExpandedTargetSnapshot{
		State: string(artifactacquisition.ExpandedTargetTransferPending), CurrentOwner: fixture.lease.Owner(), NewOwner: newOwner,
	}, newOwner)
	if err != nil || transferred.Owner != newOwner || !transferred.TargetPresent || transferred.ReservationPresent {
		t.Fatalf("TransferExpandedTarget()=%+v,%v", transferred, err)
	}
	missing, _ := artifactacquisition.NewMeasuredLeaseReceipt(
		fixture.lease.ID(), fixture.lease.Pool(), fixture.lease.Bytes(), receipt.AllocatedBytes(), receipt.Token(), false,
	)
	consumedProof, _ := artifactacquisition.NewMeasuredCapacityMutationProof(
		missing, fixture.lease.ExpectedTargetDigest(), materialized.MeasuredBytes, materialized.AllocatedBytes, fixture.lease.Owner(),
	)
	if _, err := aggregate.RecordConsumed(fixture.lease.ID(), consumedProof); err != nil {
		t.Fatal(err)
	}
	_, _, _ = aggregate.BeginTransfer(fixture.lease.ID(), newOwner)
	transferProof, _ := artifactacquisition.NewMeasuredCapacityMutationProof(
		missing, fixture.lease.ExpectedTargetDigest(), transferred.MeasuredBytes, transferred.AllocatedBytes, newOwner,
	)
	if _, err := aggregate.RecordTransferred(fixture.lease.ID(), transferProof); err != nil {
		t.Fatal(err)
	}
	releases, err := aggregate.BeginUninstall(newOwner, "installation-owner")
	if err != nil || len(releases) != 1 {
		t.Fatalf("BeginUninstall()=%+v,%v", releases, err)
	}
	snapshot := artifactacquisition.ExpandedTargetSnapshot{
		State: string(artifactacquisition.ExpandedTargetTransferred), CurrentOwner: newOwner,
		MeasuredBytes: transferred.MeasuredBytes, AllocatedBytes: transferred.AllocatedBytes,
	}
	retired, err := engine.RetireExpandedTarget(context.Background(), authority, snapshot, releases[0])
	if err != nil || retired.TargetPresent || retired.ReservationPresent || retired.Owner != newOwner {
		t.Fatalf("RetireExpandedTarget()=%+v,%v", retired, err)
	}
	if replay, replayError := engine.RetireExpandedTarget(context.Background(), authority, snapshot, releases[0]); replayError != nil || replay.TargetPresent || replay.ReservationPresent {
		t.Fatalf("RetireExpandedTarget replay=%+v,%v", replay, replayError)
	}
}

func TestPF001ComposeTargetEngineAtomicallyPublishesReservedBytesAndRejectsDrift(t *testing.T) {
	t.Parallel()
	fixture := newHostReleaseFixture(t)
	publishCASFixture(t, fixture.store, fixture.source)
	receipt, err := fixture.capacity.ReserveLease(context.Background(), fixture.lease)
	if err != nil {
		t.Fatal(err)
	}
	makeSecureTestDirectory(t, fixture.releaseRoot)
	aggregate, _ := artifactacquisition.NewCapacityAggregate(
		fixture.lease.Owner(), fixture.lease.PlanDigest(), []artifactacquisition.CapacityLease{fixture.lease},
	)
	_, _ = aggregate.RecordReserved(fixture.lease, receipt)
	consume, _, _ := aggregate.BeginConsume(fixture.lease.ID())
	authority, err := artifactacquisition.NewExpandedTargetAuthority(
		consume, string(fixture.lease.TargetKind()), fixture.lease.TargetStorageID(), fixture.lease.TargetAuthorityDigest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewComposeBundleTargetEngine(fixture.store, fixture.capacity)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := engine.MaterializeExpandedTarget(context.Background(), authority)
	if err != nil || !observation.TargetPresent || observation.ReservationPresent ||
		observation.MeasuredBytes != uint64(len(fixture.source)) || observation.AllocatedBytes != receipt.AllocatedBytes() {
		t.Fatalf("MaterializeExpandedTarget()=%+v,%v receipt=%+v", observation, err, receipt)
	}
	if replay, replayError := engine.MaterializeExpandedTarget(context.Background(), authority); replayError != nil ||
		!replay.TargetPresent || replay.ReservationPresent || replay.AllocatedBytes != observation.AllocatedBytes {
		t.Fatalf("MaterializeExpandedTarget replay=%+v,%v", replay, replayError)
	}
	targetPath := filepath.Join(fixture.releaseRoot, filepath.FromSlash(fixture.lease.TargetStorageID()))
	actual, err := os.ReadFile(targetPath) // #nosec G304 -- exact test-owned signed path.
	if err != nil || string(actual) != string(fixture.source) {
		t.Fatalf("target bytes=%q err=%v", actual, err)
	}
	if _, err := fixture.capacity.RevalidateLease(context.Background(), fixture.lease); err == nil {
		t.Fatal("atomic publication left the reservation present")
	}
	inspected, err := engine.InspectExpandedTarget(context.Background(), authority, artifactacquisition.ExpandedTargetSnapshot{
		State: string(artifactacquisition.ExpandedTargetConsumed), CurrentOwner: fixture.lease.Owner(),
	})
	if err != nil || !inspected.TargetPresent || inspected.AllocatedBytes != observation.AllocatedBytes {
		t.Fatalf("InspectExpandedTarget()=%+v,%v", inspected, err)
	}
	foreign := append([]byte(nil), fixture.source...)
	foreign[0] ^= 0xff
	if err := os.WriteFile(targetPath, foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.InspectExpandedTarget(context.Background(), authority, artifactacquisition.ExpandedTargetSnapshot{
		State: string(artifactacquisition.ExpandedTargetConsumed), CurrentOwner: fixture.lease.Owner(),
	}); !errors.Is(err, artifactapp.ErrExpandedTargetOperation) {
		t.Fatalf("drift inspection error=%v", err)
	}
}

func TestPF001ComposeTargetEngineFailsClosedAndRetiresUntouchedReservation(t *testing.T) {
	t.Parallel()
	fixture := newHostReleaseFixture(t)
	var nilContext context.Context
	if _, err := NewComposeBundleTargetEngine(nil, fixture.capacity); !errors.Is(err, artifactapp.ErrExpandedTargetUnsupported) {
		t.Fatalf("nil store constructor error=%v", err)
	}
	if _, err := NewComposeBundleTargetEngine(fixture.store, nil); !errors.Is(err, artifactapp.ErrExpandedTargetUnsupported) {
		t.Fatalf("nil capacity constructor error=%v", err)
	}
	if _, err := fixture.capacity.ReserveLease(nilContext, fixture.lease); !errors.Is(err, artifactapp.ErrReservationUnsupported) {
		t.Fatalf("nil reserve context error=%v", err)
	}
	if _, err := fixture.capacity.RevalidateLease(nilContext, fixture.lease); !errors.Is(err, artifactapp.ErrReservationUnsupported) {
		t.Fatalf("nil inspect context error=%v", err)
	}
	if _, err := fixture.capacity.ReleaseCapacity(context.Background(), artifactacquisition.CapacityReleaseAuthorization{}); !errors.Is(err, artifactapp.ErrReservationUnsupported) {
		t.Fatalf("invalid release authority error=%v", err)
	}
	publishCASFixture(t, fixture.store, fixture.source)
	receipt, err := fixture.capacity.ReserveLease(context.Background(), fixture.lease)
	if err != nil {
		t.Fatal(err)
	}
	// The production phase contract creates the protected release layout before
	// Compose materialization. Inspection must remain read-only within that layout.
	makeSecureTestDirectory(t, fixture.releaseRoot)
	aggregate, _ := artifactacquisition.NewCapacityAggregate(
		fixture.lease.Owner(), fixture.lease.PlanDigest(), []artifactacquisition.CapacityLease{fixture.lease},
	)
	_, _ = aggregate.RecordReserved(fixture.lease, receipt)
	consume, _, _ := aggregate.BeginConsume(fixture.lease.ID())
	authority, _ := artifactacquisition.NewExpandedTargetAuthority(
		consume, string(fixture.lease.TargetKind()), fixture.lease.TargetStorageID(), fixture.lease.TargetAuthorityDigest(),
	)
	engine, _ := NewComposeBundleTargetEngine(fixture.store, fixture.capacity)
	before, err := engine.InspectExpandedTarget(context.Background(), authority, artifactacquisition.ExpandedTargetSnapshot{
		State: string(artifactacquisition.ExpandedTargetConsumePending), CurrentOwner: fixture.lease.Owner(),
	})
	if err != nil || before.TargetPresent || !before.ReservationPresent {
		t.Fatalf("InspectExpandedTarget before publication=%+v,%v", before, err)
	}
	if _, err := engine.RetireExpandedTarget(
		context.Background(), authority, artifactacquisition.ExpandedTargetSnapshot{},
		artifactacquisition.CapacityReleaseAuthorization{},
	); !errors.Is(err, artifactapp.ErrExpandedTargetOperation) {
		t.Fatalf("invalid retire authority error=%v", err)
	}
	releases, err := aggregate.BeginCompensation()
	if err != nil || len(releases) != 1 {
		t.Fatalf("BeginCompensation()=%+v,%v", releases, err)
	}
	retired, err := engine.RetireExpandedTarget(context.Background(), authority, artifactacquisition.ExpandedTargetSnapshot{
		State: string(artifactacquisition.ExpandedTargetConsumePending), CurrentOwner: fixture.lease.Owner(),
	}, releases[0])
	if err != nil || retired.TargetPresent || retired.ReservationPresent {
		t.Fatalf("RetireExpandedTarget reservation=%+v,%v", retired, err)
	}
}

func TestPF001ComposeTargetTransferRejectsCoexistingReservation(t *testing.T) {
	t.Parallel()
	fixture := newHostReleaseFixture(t)
	publishCASFixture(t, fixture.store, fixture.source)
	receipt, _ := fixture.capacity.ReserveLease(context.Background(), fixture.lease)
	makeSecureTestDirectory(t, fixture.releaseRoot)
	aggregate, _ := artifactacquisition.NewCapacityAggregate(
		fixture.lease.Owner(), fixture.lease.PlanDigest(), []artifactacquisition.CapacityLease{fixture.lease},
	)
	_, _ = aggregate.RecordReserved(fixture.lease, receipt)
	consume, _, _ := aggregate.BeginConsume(fixture.lease.ID())
	authority, _ := artifactacquisition.NewExpandedTargetAuthority(
		consume, string(fixture.lease.TargetKind()), fixture.lease.TargetStorageID(), fixture.lease.TargetAuthorityDigest(),
	)
	engine, _ := NewComposeBundleTargetEngine(fixture.store, fixture.capacity)
	if _, err := engine.MaterializeExpandedTarget(context.Background(), authority); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.capacity.ReserveLease(context.Background(), fixture.lease); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.TransferExpandedTarget(
		context.Background(), authority, artifactacquisition.ExpandedTargetSnapshot{}, "generation-owner",
	); !errors.Is(err, artifactapp.ErrExpandedTargetOperation) {
		t.Fatalf("coexisting reservation transfer error=%v", err)
	}
}

type hostReleaseFixture struct {
	store       *Store
	capacity    *HostReleaseCapacity
	lease       artifactacquisition.CapacityLease
	releaseRoot string
	source      []byte
}

func newHostReleaseFixture(t *testing.T) hostReleaseFixture {
	t.Helper()
	base := resolvedTempDir(t)
	storeRoot := filepath.Join(base, "cas")
	makeSecureTestDirectory(t, storeRoot)
	store, err := newStoreWithReservationAttestor(storeRoot, func(*os.File) (bool, error) { return true, nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	releaseRoot := filepath.Join(base, "product", "releases", "release-1")
	pool, err := attestHostReleasePool(releaseRoot)
	if err != nil {
		t.Fatal(err)
	}
	source := []byte("{\"name\":\"agentmemory_test\",\"services\":{}}\n")
	digest := releaseinventory.DigestBytes(source)
	target, err := releaseinventory.NewReleaseExpandedTarget(digest, uint64(len(source)), releaseinventory.ReleaseExpandedTargetInput{
		Kind: releaseinventory.ExpandedTargetComposeBundle, StorageID: "compose/compose.yaml",
		Digest: digest, Bytes: uint64(len(source)),
	})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := artifactacquisition.NewExpandedCapacityLease(
		"install-host-release", "install-host-release", "compose", pool, uint64(len(source)),
		releaseinventory.DigestBytes([]byte("parent-plan")), digest, uint64(len(source)), digest,
		artifactacquisition.ExpandedLeaseTarget{
			Kind: target.Kind(), StorageID: target.StorageID(), AuthorityDigest: target.AuthorityDigest(), Root: releaseRoot,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return hostReleaseFixture{store: store, capacity: NewHostReleaseCapacity(), lease: lease, releaseRoot: releaseRoot, source: source}
}

func publishCASFixture(t *testing.T, store *Store, source []byte) {
	t.Helper()
	digest := releaseinventory.DigestBytes(source).Hex()
	directory, leaf, err := store.finalLocation("sha256/"+digest[:2]+"/"+digest, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = directory.Close() }()
	file, created, err := openSecureLeafAt(directory, leaf, true)
	if err != nil || !created {
		t.Fatalf("open CAS fixture created=%t err=%v", created, err)
	}
	defer file.close()
	written, err := file.file.Write(source)
	if err != nil || written != len(source) || durableSync(file.file) != nil || file.syncDirectory() != nil {
		t.Fatalf("write CAS fixture bytes=%d err=%v", written, err)
	}
}
