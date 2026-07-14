package artifactapp

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001CapacityApplicationPersistsEveryIntentBeforePoolMutation(t *testing.T) {
	t.Parallel()
	command := capacityCommand(t)
	repository := &memoryCapacityRepository{}
	pools := &fakePoolAttestor{}
	leases := &fakeCapacityLeases{repository: repository}
	application, err := NewCapacityApplication(CapacityDependencies{Repository: repository, Pools: pools, Leases: leases, Materializer: leases})
	if err != nil {
		t.Fatal(err)
	}

	reserved, err := application.ReserveCapacity(context.Background(), command)
	if err != nil || reserved.Version != 9 || leases.reserveCalls != 9 {
		t.Fatalf("ReserveCapacity()=%+v,%v calls=%d", reserved, err, leases.reserveCalls)
	}
	if replay, err := application.ReserveCapacity(context.Background(), command); err != nil || replay.Version != reserved.Version || leases.reserveCalls != 9 || leases.revalidateCalls != 9 {
		t.Fatalf("ReserveCapacity replay=%+v,%v reserve=%d validate=%d", replay, err, leases.reserveCalls, leases.revalidateCalls)
	}
	prepared, err := application.PrepareSecretProjectionCapacity(context.Background(), command, command.GenerationID)
	if err != nil || prepared.Version != 21 || leases.transferCalls != 6 {
		t.Fatalf("PrepareSecretProjectionCapacity()=%+v,%v calls=%d", prepared, err, leases.transferCalls)
	}
	if replay, replayError := application.PrepareSecretProjectionCapacity(context.Background(), command, command.GenerationID); replayError != nil || replay.Version != prepared.Version || leases.transferCalls != 6 {
		t.Fatalf("PrepareSecretProjectionCapacity replay=%+v,%v calls=%d", replay, replayError, leases.transferCalls)
	}
	for _, snapshot := range prepared.Leases {
		if snapshot.Purpose == string(artifactacquisition.LeaseSecretProjection) {
			if snapshot.State != string(artifactacquisition.LeaseTransferred) || snapshot.NewOwner != command.GenerationID {
				t.Fatalf("projection state=%+v", snapshot)
			}
		} else if snapshot.State != string(artifactacquisition.LeaseReserved) {
			t.Fatalf("non-projection transferred early: %+v", snapshot)
		}
	}

	consumed, err := application.ConsumeArtifactExpansion(context.Background(), command, "core")
	if err != nil || consumed.Version != 23 || leases.consumeCalls != 1 {
		t.Fatalf("ConsumeArtifactExpansion()=%+v,%v calls=%d", consumed, err, leases.consumeCalls)
	}
	transferred, err := application.TransferActivationCapacity(context.Background(), command, command.GenerationID, command.InstallationID)
	if err != nil || transferred.Version != 29 || leases.transferCalls != 9 {
		t.Fatalf("TransferActivationCapacity()=%+v,%v calls=%d", transferred, err, leases.transferCalls)
	}
	released, err := application.ReleaseOperationCapacity(context.Background(), command)
	if err != nil || released.Version != 29 || leases.releaseCalls != 0 {
		t.Fatalf("ReleaseOperationCapacity()=%+v,%v calls=%d", released, err, leases.releaseCalls)
	}
	if _, err := application.ReleaseOperationCapacity(context.Background(), command); err != nil || leases.releaseCalls != 0 {
		t.Fatalf("release replay error=%v calls=%d", err, leases.releaseCalls)
	}
}

func TestPF001CapacityCancellationPersistsExactReleaseBeforeSettlingEveryPendingState(t *testing.T) {
	t.Parallel()
	command := capacityCommand(t)
	repository := &memoryCapacityRepository{}
	leaser := &fakeCapacityLeases{repository: repository}
	application, _ := NewCapacityApplication(CapacityDependencies{
		Repository: repository, Pools: &fakePoolAttestor{}, Leases: leaser, Materializer: leaser,
	})
	if _, err := application.ReserveCapacity(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	leaser.failMaterializeAfterMutation = true
	if _, err := application.ConsumeArtifactExpansion(context.Background(), command, "core"); err == nil {
		t.Fatal("interrupted materialization succeeded")
	}
	rollback := leaseSnapshotForPurpose(t, repository.snapshot, artifactacquisition.LeaseRollback)
	aggregate := restoreCapacityForTest(t, command, repository.snapshot)
	if _, _, err := aggregate.BeginTransfer(rollback.LeaseID, "generation-pending"); err != nil {
		t.Fatal(err)
	}
	if err := repository.SaveCapacity(context.Background(), repository.snapshot.Version, aggregate.Snapshot()); err != nil {
		t.Fatal(err)
	}

	result, err := application.CompensateOperationCapacity(context.Background(), command)
	if err != nil || leaser.releaseCalls != 9 || result.Version == 0 {
		t.Fatalf("CompensateOperationCapacity()=%+v,%v releases=%d", result, err, leaser.releaseCalls)
	}
	wantFrom := map[artifactacquisition.LeasePurpose]artifactacquisition.LeaseState{
		artifactacquisition.LeaseExpanded:         artifactacquisition.LeaseConsumePending,
		artifactacquisition.LeaseSecretProjection: artifactacquisition.LeaseReserved,
		artifactacquisition.LeaseRollback:         artifactacquisition.LeaseTransferPending,
		artifactacquisition.LeaseSafety:           artifactacquisition.LeaseReserved,
	}
	for _, authorization := range leaser.releases {
		if authorization.Kind() != artifactacquisition.CapacityReleaseCompensation {
			t.Fatalf("release kind=%s", authorization.Kind())
		}
		if authorization.FromState() != wantFrom[authorization.Lease().Purpose()] {
			t.Fatalf("release state=%s for %s", authorization.FromState(), authorization.Lease().Purpose())
		}
	}
	if _, err := application.CompensateOperationCapacity(context.Background(), command); err != nil || leaser.releaseCalls != 9 {
		t.Fatalf("compensation replay error=%v releases=%d", err, leaser.releaseCalls)
	}
}

func TestPF001CapacityUninstallRejectsForeignOwnerBeforeMutation(t *testing.T) {
	t.Parallel()
	command := capacityCommand(t)
	repository := &memoryCapacityRepository{}
	leaser := &fakeCapacityLeases{repository: repository}
	application, _ := NewCapacityApplication(CapacityDependencies{
		Repository: repository, Pools: &fakePoolAttestor{}, Leases: leaser, Materializer: leaser,
	})
	_, _ = application.ReserveCapacity(context.Background(), command)
	_, _ = application.ConsumeArtifactExpansion(context.Background(), command, "core")
	_, _ = application.TransferActivationCapacity(context.Background(), command, command.GenerationID, command.InstallationID)
	if _, err := application.ReleaseActivatedCapacity(context.Background(), command, "foreign-generation", command.InstallationID); err == nil || leaser.releaseCalls != 0 {
		t.Fatalf("foreign uninstall error=%v releases=%d", err, leaser.releaseCalls)
	}
	if _, err := application.ReleaseActivatedCapacity(context.Background(), command, command.GenerationID, command.InstallationID); err != nil || leaser.releaseCalls != 9 {
		t.Fatalf("exact uninstall error=%v releases=%d", err, leaser.releaseCalls)
	}
	if _, err := application.ReleaseActivatedCapacity(context.Background(), command, command.GenerationID, command.InstallationID); err != nil || leaser.releaseCalls != 9 {
		t.Fatalf("uninstall replay error=%v releases=%d", err, leaser.releaseCalls)
	}
}

func TestPF001CapacityApplicationFailsClosedOnExactLowDiskAndPoolMismatch(t *testing.T) {
	t.Parallel()
	command := capacityCommand(t)
	for _, test := range []struct {
		name   string
		pools  *fakePoolAttestor
		leases *fakeCapacityLeases
	}{
		{name: "engine-volume-mismatch", pools: &fakePoolAttestor{volumePool: "other-pool"}, leases: &fakeCapacityLeases{}},
		{name: "exact-low-disk", pools: &fakePoolAttestor{}, leases: &fakeCapacityLeases{failAtReserve: 3}},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &memoryCapacityRepository{}
			test.leases.repository = repository
			application, _ := NewCapacityApplication(CapacityDependencies{Repository: repository, Pools: test.pools, Leases: test.leases, Materializer: test.leases})
			_, err := application.ReserveCapacity(context.Background(), command)
			if err == nil {
				t.Fatal("unsafe capacity topology succeeded")
			}
			if test.name == "engine-volume-mismatch" && test.leases.reserveCalls != 0 {
				t.Fatal("mutation occurred before pool agreement")
			}
			if test.name == "exact-low-disk" {
				if test.leases.reserveCalls != 3 || len(repository.snapshot.Leases) != 9 {
					t.Fatalf("calls=%d snapshot=%+v", test.leases.reserveCalls, repository.snapshot)
				}
				pending := 0
				for _, lease := range repository.snapshot.Leases {
					if lease.State == string(artifactacquisition.LeaseReservePending) {
						pending++
					}
				}
				if pending != 7 {
					t.Fatalf("pending leases=%d", pending)
				}
			}
		})
	}
}

func TestPF001CapacityApplicationRejectsPoolSubstitutionOnReplay(t *testing.T) {
	t.Parallel()
	command := capacityCommand(t)
	repository := &memoryCapacityRepository{}
	pools := &fakePoolAttestor{}
	leaser := &fakeCapacityLeases{repository: repository}
	application, _ := NewCapacityApplication(CapacityDependencies{Repository: repository, Pools: pools, Leases: leaser, Materializer: leaser})
	if _, err := application.ReserveCapacity(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	pools.enginePool = "replacement-pool"
	pools.volumePool = "replacement-pool"
	if _, err := application.ReserveCapacity(context.Background(), command); err == nil {
		t.Fatal("substituted pool restored authenticated state")
	}
}

func TestPF001CapacityApplicationRejectsIncompleteOrForeignProjectionAuthorityBeforeMutation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*CapacityCommand)
	}{
		{name: "missing", mutate: func(command *CapacityCommand) {
			command.SecretProjections = command.SecretProjections[:5]
		}},
		{name: "extra", mutate: func(command *CapacityCommand) {
			command.SecretProjections = append(command.SecretProjections, command.SecretProjections[0])
		}},
		{name: "duplicate", mutate: func(command *CapacityCommand) {
			command.SecretProjections[1] = command.SecretProjections[0]
		}},
		{name: "foreign-name", mutate: func(command *CapacityCommand) {
			command.SecretProjections[0].Name = "agentmemory_foreign"
		}},
		{name: "foreign-purpose", mutate: func(command *CapacityCommand) {
			command.SecretProjections[0].Purpose = "protected-foreign"
		}},
		{name: "foreign-size", mutate: func(command *CapacityCommand) {
			command.SecretProjections[0].ReservedBytes++
		}},
		{name: "missing-release", mutate: func(command *CapacityCommand) {
			command.ReleaseID = ""
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			command := capacityCommand(t)
			test.mutate(&command)
			leaser := &fakeCapacityLeases{}
			application, _ := NewCapacityApplication(CapacityDependencies{
				Repository: &memoryCapacityRepository{}, Pools: &fakePoolAttestor{},
				Leases: leaser, Materializer: leaser,
			})
			if _, err := application.ReserveCapacity(context.Background(), command); err == nil || leaser.reserveCalls != 0 {
				t.Fatalf("ReserveCapacity() error=%v mutations=%d", err, leaser.reserveCalls)
			}
		})
	}
}

func TestPF001CapacityApplicationRejectsReceiptTokenSubstitutionOnReplay(t *testing.T) {
	t.Parallel()
	command := capacityCommand(t)
	repository := &memoryCapacityRepository{}
	leaser := &fakeCapacityLeases{repository: repository}
	application, _ := NewCapacityApplication(CapacityDependencies{
		Repository: repository, Pools: &fakePoolAttestor{}, Leases: leaser, Materializer: leaser,
	})
	if _, err := application.ReserveCapacity(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	leaser.revalidateToken = "substituted-token"
	if _, err := application.ReserveCapacity(context.Background(), command); err == nil {
		t.Fatal("substituted capacity receipt restored authenticated state")
	}
}

func TestPF001CapacityApplicationReplaysEveryPersistedPendingMutationIdempotently(t *testing.T) {
	t.Parallel()
	command := capacityCommand(t)
	repository := &memoryCapacityRepository{}
	leaser := &fakeCapacityLeases{repository: repository, failAtReserve: 1}
	application, _ := NewCapacityApplication(CapacityDependencies{
		Repository: repository, Pools: &fakePoolAttestor{}, Leases: leaser, Materializer: leaser,
	})
	if _, err := application.ReserveCapacity(context.Background(), command); err == nil {
		t.Fatal("interrupted reserve succeeded")
	}
	leaser.failAtReserve = 0
	if _, err := application.ReserveCapacity(context.Background(), command); err != nil || leaser.reserveCalls != 10 {
		t.Fatalf("reserve replay error=%v calls=%d", err, leaser.reserveCalls)
	}
	leaser.failMaterializeAfterMutation = true
	if _, err := application.ConsumeArtifactExpansion(context.Background(), command, "core"); err == nil {
		t.Fatal("interrupted materialization succeeded")
	}
	if _, err := application.ConsumeArtifactExpansion(context.Background(), command, "core"); err != nil || leaser.consumeCalls != 2 {
		t.Fatalf("consume replay error=%v calls=%d", err, leaser.consumeCalls)
	}
	leaser.failTransferAfterMutation = true
	if _, err := application.TransferActivationCapacity(context.Background(), command, command.GenerationID, command.InstallationID); err == nil {
		t.Fatal("interrupted transfer succeeded")
	}
	result, err := application.TransferActivationCapacity(context.Background(), command, command.GenerationID, command.InstallationID)
	if err != nil || result.Version != 29 || leaser.transferCalls != 10 {
		t.Fatalf("transfer replay=%+v,%v calls=%d", result, err, leaser.transferCalls)
	}
}

type memoryCapacityRepository struct {
	snapshot artifactacquisition.CapacityAggregateSnapshot
	exists   bool
}

func (r *memoryCapacityRepository) LoadCapacity(context.Context, string) (artifactacquisition.CapacityAggregateSnapshot, error) {
	if !r.exists {
		return artifactacquisition.CapacityAggregateSnapshot{}, ErrAggregateNotFound
	}
	return r.snapshot, nil
}

func (r *memoryCapacityRepository) SaveCapacity(_ context.Context, expected uint64, snapshot artifactacquisition.CapacityAggregateSnapshot) error {
	if r.exists && r.snapshot.Version != expected {
		return ErrAggregateConflict
	}
	if !r.exists && expected != 0 {
		return ErrAggregateConflict
	}
	r.snapshot, r.exists = snapshot, true
	return nil
}

type fakePoolAttestor struct{ enginePool, volumePool string }

func (p *fakePoolAttestor) Attest(_ context.Context, target CapacityTarget) (artifactacquisition.StoragePool, error) {
	id := "host-pool"
	switch target.Kind {
	case CapacityDockerEngine:
		id = p.enginePool
		if id == "" {
			id = "docker-pool"
		}
	case CapacityDockerDataVolume:
		id = p.volumePool
		if id == "" {
			id = "docker-pool"
		}
	}
	return artifactacquisition.NewStoragePool(id, target.Kind)
}

type fakeCapacityLeases struct {
	repository                                                               *memoryCapacityRepository
	reserveCalls, revalidateCalls, consumeCalls, transferCalls, releaseCalls int
	failAtReserve                                                            int
	failMaterializeAfterMutation                                             bool
	failTransferAfterMutation                                                bool
	releases                                                                 []artifactacquisition.CapacityReleaseAuthorization
	revalidateToken                                                          string
}

func (l *fakeCapacityLeases) ReserveLease(_ context.Context, lease artifactacquisition.CapacityLease) (artifactacquisition.LeaseReceipt, error) {
	l.reserveCalls++
	if !l.persisted(lease.ID(), artifactacquisition.LeaseReservePending) {
		return artifactacquisition.LeaseReceipt{}, errors.New("reserve intent not durable")
	}
	if l.failAtReserve == l.reserveCalls {
		return artifactacquisition.LeaseReceipt{}, errors.New("low disk")
	}
	return artifactacquisition.NewLeaseReceipt(lease.ID(), lease.Pool(), lease.Bytes(), "lease-token", true)
}

func (l *fakeCapacityLeases) RevalidateLease(_ context.Context, lease artifactacquisition.CapacityLease) (artifactacquisition.LeaseReceipt, error) {
	l.revalidateCalls++
	token := l.revalidateToken
	if token == "" {
		token = "lease-token"
	}
	return artifactacquisition.NewLeaseReceipt(lease.ID(), lease.Pool(), lease.Bytes(), token, true)
}

func (l *fakeCapacityLeases) MaterializeExpanded(_ context.Context, authorization artifactacquisition.CapacityConsumeAuthorization) (artifactacquisition.CapacityMutationProof, error) {
	l.consumeCalls++
	if !authorization.Valid() {
		return artifactacquisition.CapacityMutationProof{}, errors.New("invalid consume authorization")
	}
	lease := authorization.Lease()
	if !l.persisted(lease.ID(), artifactacquisition.LeaseConsumePending) {
		return artifactacquisition.CapacityMutationProof{}, errors.New("consume intent not durable")
	}
	receipt, _ := artifactacquisition.NewLeaseReceipt(lease.ID(), lease.Pool(), lease.Bytes(), authorization.ReceiptToken(), false)
	if l.failMaterializeAfterMutation {
		l.failMaterializeAfterMutation = false
		return artifactacquisition.CapacityMutationProof{}, errors.New("interrupted after materialization")
	}
	return artifactacquisition.NewCapacityMutationProof(receipt, lease.ExpectedTargetDigest(), lease.Bytes(), lease.Owner())
}

func (l *fakeCapacityLeases) TransferLease(_ context.Context, lease artifactacquisition.CapacityLease, owner string) (artifactacquisition.CapacityMutationProof, error) {
	l.transferCalls++
	if !l.persisted(lease.ID(), artifactacquisition.LeaseTransferPending) {
		return artifactacquisition.CapacityMutationProof{}, errors.New("transfer intent not durable")
	}
	receipt, _ := artifactacquisition.NewLeaseReceipt(lease.ID(), lease.Pool(), lease.Bytes(), "lease-token", false)
	target, usage := releaseinventory.Digest{}, uint64(0)
	if lease.Purpose() == artifactacquisition.LeaseExpanded {
		target, usage = lease.ExpectedTargetDigest(), lease.Bytes()
	}
	if l.failTransferAfterMutation {
		l.failTransferAfterMutation = false
		return artifactacquisition.CapacityMutationProof{}, errors.New("interrupted after transfer")
	}
	return artifactacquisition.NewCapacityMutationProof(receipt, target, usage, owner)
}

func (l *fakeCapacityLeases) ReleaseCapacity(_ context.Context, authorization artifactacquisition.CapacityReleaseAuthorization) (artifactacquisition.LeaseReceipt, error) {
	l.releaseCalls++
	l.releases = append(l.releases, authorization)
	lease := authorization.Lease()
	if !l.persisted(lease.ID(), artifactacquisition.LeaseReleasePending) {
		return artifactacquisition.LeaseReceipt{}, errors.New("release intent not durable")
	}
	return artifactacquisition.NewLeaseReceipt(lease.ID(), lease.Pool(), lease.Bytes(), "lease-token", false)
}

func leaseSnapshotForPurpose(t *testing.T, snapshot artifactacquisition.CapacityAggregateSnapshot, purpose artifactacquisition.LeasePurpose) artifactacquisition.CapacityLeaseSnapshot {
	t.Helper()
	for _, lease := range snapshot.Leases {
		if lease.Purpose == string(purpose) {
			return lease
		}
	}
	t.Fatalf("missing %s lease", purpose)
	return artifactacquisition.CapacityLeaseSnapshot{}
}

func restoreCapacityForTest(t *testing.T, command CapacityCommand, snapshot artifactacquisition.CapacityAggregateSnapshot) *artifactacquisition.CapacityAggregate {
	t.Helper()
	host, _ := artifactacquisition.NewStoragePool("host-pool", CapacityHostCAS)
	release, _ := artifactacquisition.NewStoragePool("host-pool", CapacityHostRelease)
	target, _ := artifactacquisition.NewStoragePool("docker-pool", CapacityDockerEngine)
	parent, projections, authorityErr := validateCapacityAuthority(command)
	if authorityErr != nil {
		t.Fatal(authorityErr)
	}
	leases, err := command.Plan.CapacityLeasesForAuthority(
		command.OperationID, parent, host, release, target, command.HostRelease.Locator,
		artifactacquisition.SecretProjectionLeaseAuthority{
			InstallationID: command.InstallationID, ReleaseID: command.ReleaseID, GenerationID: command.GenerationID,
		}, projections,
	)
	if err != nil {
		t.Fatal(err)
	}
	aggregate, err := artifactacquisition.RestoreCapacityAggregate(leases, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return aggregate
}

func (l *fakeCapacityLeases) persisted(id string, state artifactacquisition.LeaseState) bool {
	if l.repository == nil {
		return false
	}
	for _, lease := range l.repository.snapshot.Leases {
		if lease.LeaseID == id {
			return lease.State == string(state)
		}
	}
	return false
}

func capacityCommand(t *testing.T) CapacityCommand {
	t.Helper()
	digest := releaseinventory.DigestBytes([]byte("abc"))
	target, targetErr := releaseinventory.NewReleaseExpandedTarget(digest, 3, releaseinventory.ReleaseExpandedTargetInput{
		Kind: releaseinventory.ExpandedTargetComposeBundle, StorageID: "compose/compose.yaml", Digest: digest, Bytes: 3,
	})
	if targetErr != nil {
		t.Fatal(targetErr)
	}
	plan, err := artifactacquisition.NewPlan(artifactacquisition.PlanInput{
		PlanDigest: releaseinventory.DigestBytes([]byte("capacity-plan")),
		Artifacts: []artifactacquisition.ArtifactInput{{ID: "core", Digest: digest, Size: 3, ExpandedBytes: 3,
			ExpandedDigest: digest, TargetKind: target.Kind(), TargetStorageID: target.StorageID(), TargetAuthorityDigest: target.AuthorityDigest(),
			Sources: []string{"bundle://core"}, Chunks: []artifactacquisition.ChunkInput{{Offset: 0, Size: 3, Digest: digest}}}},
		Totals: artifactacquisition.TotalsInput{DownloadBytes: 3, ExpandedBytes: 3, RollbackHeadroomBytes: 7, SafetyHeadroomBytes: 11, RequiredBytes: 24},
	})
	if err != nil {
		t.Fatal(err)
	}
	parent, _ := install.BindPlan([]byte("canonical parent capacity plan"))
	installationID := "019f5f20-1234-7abc-8123-0123456789ab"
	generationID := "019f5f21-5678-7def-9123-abcdef012345"
	identity, _ := composeplan.NewIdentity(installationID, generationID)
	projectionAuthority, _ := identity.SecretProjectionCapacities()
	projections := make([]SecretProjectionCapacity, 0, len(projectionAuthority))
	for _, authority := range projectionAuthority {
		projections = append(projections, SecretProjectionCapacity{
			Name: authority.Name(), Purpose: authority.Purpose(), ReservedBytes: authority.ReservedBytes(),
		})
	}
	return CapacityCommand{OperationID: "install-capacity", ParentPlanDigest: parent,
		InstallationID: installationID, ReleaseID: "agentmemory-1.0.0", GenerationID: generationID,
		Plan: plan, SecretProjections: projections,
		HostCAS:          CapacityTarget{Kind: CapacityHostCAS, Locator: "/cas"},
		HostRelease:      CapacityTarget{Kind: CapacityHostRelease, Locator: "/releases/release-1"},
		DockerEngine:     CapacityTarget{Kind: CapacityDockerEngine, Locator: "docker://engine"},
		DockerDataVolume: CapacityTarget{Kind: CapacityDockerDataVolume, Locator: "docker://volume"}}
}
