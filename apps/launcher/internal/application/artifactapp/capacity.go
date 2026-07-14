package artifactapp

import (
	"context"
	"errors"
	"reflect"
	"sort"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

// CapacityTarget identifies the independently probed allocation backing that
// a production adapter must attest. Locator is adapter-owned and must never be
// persisted as the pool identity.
type CapacityTarget struct {
	Kind    string
	Locator string
}

// Closed capacity-target kinds resolved by production storage adapters.
const (
	CapacityHostCAS          = "host-cas"
	CapacityHostRelease      = "host-release"
	CapacityDockerEngine     = "docker-engine"
	CapacityDockerDataVolume = "docker-data-volume"
)

// CapacityPoolAttestor resolves a stable physical/engine allocation pool from
// a live target. It must fail closed for remote, CoW/snapshot-invalidated, or
// otherwise unverifiable pools.
type CapacityPoolAttestor interface {
	Attest(context.Context, CapacityTarget) (artifactacquisition.StoragePool, error)
}

// CapacityRepository stores authenticated, rollback-protected capacity state.
type CapacityRepository interface {
	LoadCapacity(context.Context, string) (artifactacquisition.CapacityAggregateSnapshot, error)
	SaveCapacity(context.Context, uint64, artifactacquisition.CapacityAggregateSnapshot) error
}

// CapacityLeasePort is the physical/engine mutation boundary. Every method is
// idempotent for an exact authorization and must reject pool substitution.
type CapacityLeasePort interface {
	ReserveLease(context.Context, artifactacquisition.CapacityLease) (artifactacquisition.LeaseReceipt, error)
	RevalidateLease(context.Context, artifactacquisition.CapacityLease) (artifactacquisition.LeaseReceipt, error)
	TransferLease(context.Context, artifactacquisition.CapacityLease, string) (artifactacquisition.CapacityMutationProof, error)
	ReleaseCapacity(context.Context, artifactacquisition.CapacityReleaseAuthorization) (artifactacquisition.LeaseReceipt, error)
}

// ExpandedMaterializer idempotently replaces one reserved expansion lease
// with an OCI/model/bundle target and returns its digest plus measured usage.
type ExpandedMaterializer interface {
	MaterializeExpanded(context.Context, artifactacquisition.CapacityConsumeAuthorization) (artifactacquisition.CapacityMutationProof, error)
}

// CapacityDependencies contains every independent capacity capability.
type CapacityDependencies struct {
	Repository   CapacityRepository
	Pools        CapacityPoolAttestor
	Leases       CapacityLeasePort
	Materializer ExpandedMaterializer
}

// CapacityApplication orchestrates authenticated capacity state before and after physical effects.
type CapacityApplication struct {
	repository   CapacityRepository
	pools        CapacityPoolAttestor
	leases       CapacityLeasePort
	materializer ExpandedMaterializer
}

// NewCapacityApplication rejects incomplete or typed-nil capacity composition.
func NewCapacityApplication(dependencies CapacityDependencies) (*CapacityApplication, error) {
	if capacityNil(dependencies.Repository) || capacityNil(dependencies.Pools) || capacityNil(dependencies.Leases) || capacityNil(dependencies.Materializer) {
		return nil, appError(ErrorInvalidCommand, "configure-capacity")
	}
	return &CapacityApplication{repository: dependencies.Repository, pools: dependencies.Pools, leases: dependencies.Leases, materializer: dependencies.Materializer}, nil
}

// CapacityCommand binds one signed artifact plan to exact live allocation targets.
type CapacityCommand struct {
	OperationID       string
	ParentPlanDigest  install.PlanDigest
	InstallationID    string
	ReleaseID         string
	GenerationID      string
	Plan              artifactacquisition.Plan
	SecretProjections []SecretProjectionCapacity
	HostCAS           CapacityTarget
	HostRelease       CapacityTarget
	DockerEngine      CapacityTarget
	DockerDataVolume  CapacityTarget
}

// SecretProjectionCapacity is the exact parent-derived Docker volume lease projection.
type SecretProjectionCapacity struct {
	Name          string
	Purpose       string
	ReservedBytes uint64
}

// CapacityResult exposes the durable aggregate revision and safe lease projections.
type CapacityResult struct {
	Version uint64
	Leases  []artifactacquisition.CapacityLeaseSnapshot
}

// ReserveCapacity creates or revalidates every signed-plan capacity lease idempotently.
func (a *CapacityApplication) ReserveCapacity(ctx context.Context, command CapacityCommand) (CapacityResult, error) {
	aggregate, planLeases, err := a.loadCapacity(ctx, command, true)
	if err != nil {
		return CapacityResult{}, err
	}
	for _, lease := range planLeases {
		state, _ := aggregate.State(lease.ID())
		switch state {
		case artifactacquisition.LeaseReservePending:
			receipt, reserveError := a.leases.ReserveLease(ctx, lease)
			if reserveError != nil {
				return CapacityResult{}, appError(ErrorReservation, "reserve-capacity-lease")
			}
			previous := aggregate.Version()
			if _, recordError := aggregate.RecordReserved(lease, receipt); recordError != nil {
				return CapacityResult{}, appError(ErrorIntegrity, "record-capacity-lease")
			}
			if saveError := a.repository.SaveCapacity(ctx, previous, aggregate.Snapshot()); saveError != nil {
				return CapacityResult{}, appError(ErrorRepository, "persist-capacity-lease")
			}
		case artifactacquisition.LeaseReserved:
			receipt, validateError := a.leases.RevalidateLease(ctx, lease)
			if validateError != nil {
				return CapacityResult{}, appError(ErrorIntegrity, "revalidate-capacity-lease")
			}
			if _, recordError := aggregate.RecordReserved(lease, receipt); recordError != nil {
				return CapacityResult{}, appError(ErrorIntegrity, "revalidate-capacity-lease")
			}
		case artifactacquisition.LeaseConsumePending, artifactacquisition.LeaseConsumed,
			artifactacquisition.LeaseTransferPending, artifactacquisition.LeaseTransferred:
			// A resumed later phase must not recreate or double-reserve a lease.
		case artifactacquisition.LeaseReleasePending, artifactacquisition.LeaseReleased:
			return CapacityResult{}, appError(ErrorIntegrity, "capacity-already-releasing")
		default:
			return CapacityResult{}, appError(ErrorIntegrity, "unknown-capacity-state")
		}
	}
	return capacityResult(aggregate), nil
}

// ConsumeArtifactExpansion persists ConsumePending before the adapter performs
// idempotent OCI/model/bundle materialization. Success is accepted only with
// an immutable target digest and measured physical/engine usage.
func (a *CapacityApplication) ConsumeArtifactExpansion(ctx context.Context, command CapacityCommand, artifactID string) (CapacityResult, error) {
	aggregate, leases, err := a.loadCapacity(ctx, command, false)
	if err != nil {
		return CapacityResult{}, err
	}
	lease, found := capacityLeaseFor(leases, artifactacquisition.LeaseExpanded, artifactID)
	if !found {
		return CapacityResult{}, appError(ErrorInvalidCommand, "find-expanded-lease")
	}
	state, _ := aggregate.State(lease.ID())
	if state == artifactacquisition.LeaseConsumed {
		return capacityResult(aggregate), nil
	}
	previous := aggregate.Version()
	authorization, changed, err := aggregate.BeginConsume(lease.ID())
	if err != nil {
		return CapacityResult{}, appError(ErrorIntegrity, "begin-expanded-consumption")
	}
	if changed {
		if err := a.repository.SaveCapacity(ctx, previous, aggregate.Snapshot()); err != nil {
			return CapacityResult{}, appError(ErrorRepository, "persist-consume-intent")
		}
	}
	proof, err := a.materializer.MaterializeExpanded(ctx, authorization)
	if err != nil {
		return CapacityResult{}, appError(ErrorReservation, "consume-expanded-lease")
	}
	previous = aggregate.Version()
	if _, err := aggregate.RecordConsumed(lease.ID(), proof); err != nil {
		return CapacityResult{}, appError(ErrorIntegrity, "record-expanded-consumption")
	}
	if err := a.repository.SaveCapacity(ctx, previous, aggregate.Snapshot()); err != nil {
		return CapacityResult{}, appError(ErrorRepository, "persist-expanded-consumption")
	}
	return capacityResult(aggregate), nil
}

// PrepareSecretProjectionCapacity consumes only the six protected-volume
// reservations into empty generation-owned volumes. It is the durable
// precondition for secret projection and deliberately leaves expanded,
// rollback, and safety capacity under operation ownership.
func (a *CapacityApplication) PrepareSecretProjectionCapacity(
	ctx context.Context,
	command CapacityCommand,
	generationID string,
) (CapacityResult, error) {
	if generationID == "" || generationID != command.GenerationID {
		return CapacityResult{}, appError(ErrorInvalidCommand, "projection-capacity-owner")
	}
	aggregate, leases, err := a.loadCapacity(ctx, command, false)
	if err != nil {
		return CapacityResult{}, err
	}
	return a.transferCapacity(ctx, aggregate, leases, func(lease artifactacquisition.CapacityLease) (string, bool) {
		return generationID, lease.Purpose() == artifactacquisition.LeaseSecretProjection
	})
}

// TransferActivationCapacity moves every expanded target plus rollback
// capacity to generation ownership and safety capacity to installation
// ownership. Projection capacity prepared before migrations is replay-skipped.
// A Ready operation therefore retains no target under transient ownership.
func (a *CapacityApplication) TransferActivationCapacity(ctx context.Context, command CapacityCommand, generationID, installationID string) (CapacityResult, error) {
	if generationID == "" || installationID == "" || generationID != command.GenerationID ||
		installationID != command.InstallationID {
		return CapacityResult{}, appError(ErrorInvalidCommand, "activation-capacity-owner")
	}
	aggregate, leases, err := a.loadCapacity(ctx, command, false)
	if err != nil {
		return CapacityResult{}, err
	}
	return a.transferCapacity(ctx, aggregate, leases, func(lease artifactacquisition.CapacityLease) (string, bool) {
		owner := ""
		switch lease.Purpose() {
		case artifactacquisition.LeaseExpanded:
			owner = generationID
		case artifactacquisition.LeaseSecretProjection:
			owner = generationID
		case artifactacquisition.LeaseRollback:
			owner = generationID
		case artifactacquisition.LeaseSafety:
			owner = installationID
		default:
			return "", false
		}
		return owner, true
	})
}

type capacityOwnerSelector func(artifactacquisition.CapacityLease) (string, bool)

func (a *CapacityApplication) transferCapacity(
	ctx context.Context,
	aggregate *artifactacquisition.CapacityAggregate,
	leases []artifactacquisition.CapacityLease,
	selectOwner capacityOwnerSelector,
) (CapacityResult, error) {
	if aggregate == nil || selectOwner == nil {
		return CapacityResult{}, appError(ErrorInvalidCommand, "capacity-transfer-selection")
	}
	for _, lease := range leases {
		owner, selected := selectOwner(lease)
		if !selected {
			continue
		}
		state, _ := aggregate.State(lease.ID())
		if state == artifactacquisition.LeaseTransferred {
			continue
		}
		previous := aggregate.Version()
		_, changed, beginError := aggregate.BeginTransfer(lease.ID(), owner)
		if beginError != nil {
			return CapacityResult{}, appError(ErrorIntegrity, "begin-capacity-transfer")
		}
		if changed {
			if saveError := a.repository.SaveCapacity(ctx, previous, aggregate.Snapshot()); saveError != nil {
				return CapacityResult{}, appError(ErrorRepository, "persist-capacity-transfer-intent")
			}
		}
		proof, transferError := a.leases.TransferLease(ctx, lease, owner)
		if transferError != nil {
			return CapacityResult{}, appError(ErrorReservation, "transfer-capacity")
		}
		previous = aggregate.Version()
		if _, recordError := aggregate.RecordTransferred(lease.ID(), proof); recordError != nil {
			return CapacityResult{}, appError(ErrorIntegrity, "record-capacity-transfer")
		}
		if saveError := a.repository.SaveCapacity(ctx, previous, aggregate.Snapshot()); saveError != nil {
			return CapacityResult{}, appError(ErrorRepository, "persist-capacity-transfer")
		}
	}
	return capacityResult(aggregate), nil
}

// ReleaseOperationCapacity settles only the operation-owned remainder after a
// successful activation. Any untransferred expanded target or pending transfer
// is an integrity failure rather than a silently leaked allocation.
func (a *CapacityApplication) ReleaseOperationCapacity(ctx context.Context, command CapacityCommand) (CapacityResult, error) {
	return a.releaseCapacity(ctx, command, capacityReleaseRemainder, "", "")
}

// CompensateOperationCapacity settles every exact allocation an abandoned
// operation could own, including interrupted reserve, materialize, and
// transfer mutations. The aggregate-minted authorization prevents adapters
// from widening cleanup to foreign bytes.
func (a *CapacityApplication) CompensateOperationCapacity(ctx context.Context, command CapacityCommand) (CapacityResult, error) {
	return a.releaseCapacity(ctx, command, capacityReleaseCompensation, "", "")
}

// ReleaseActivatedCapacity is the uninstall boundary. It accepts the exact
// generation and installation owners established during activation and fails
// before mutation if either owner differs from the authenticated journal.
func (a *CapacityApplication) ReleaseActivatedCapacity(
	ctx context.Context,
	command CapacityCommand,
	generationID string,
	installationID string,
) (CapacityResult, error) {
	return a.releaseCapacity(ctx, command, capacityReleaseUninstall, generationID, installationID)
}

type capacityReleaseMode uint8

const (
	capacityReleaseRemainder capacityReleaseMode = iota + 1
	capacityReleaseCompensation
	capacityReleaseUninstall
)

func (a *CapacityApplication) releaseCapacity(
	ctx context.Context,
	command CapacityCommand,
	mode capacityReleaseMode,
	generationID string,
	installationID string,
) (CapacityResult, error) {
	aggregate, _, err := a.loadCapacity(ctx, command, false)
	if err != nil {
		return CapacityResult{}, err
	}
	previous := aggregate.Version()
	var pending []artifactacquisition.CapacityReleaseAuthorization
	switch mode {
	case capacityReleaseRemainder:
		pending, err = aggregate.BeginReleaseRemainder()
	case capacityReleaseCompensation:
		pending, err = aggregate.BeginCompensation()
	case capacityReleaseUninstall:
		pending, err = aggregate.BeginUninstall(generationID, installationID)
	default:
		err = artifactacquisition.ErrInvalidTransition
	}
	if err != nil {
		return CapacityResult{}, appError(ErrorIntegrity, "begin-capacity-release")
	}
	if aggregate.Version() != previous {
		if err := a.repository.SaveCapacity(ctx, previous, aggregate.Snapshot()); err != nil {
			return CapacityResult{}, appError(ErrorRepository, "persist-capacity-release-intent")
		}
	}
	for _, authorization := range pending {
		receipt, releaseError := a.leases.ReleaseCapacity(ctx, authorization)
		if releaseError != nil {
			return CapacityResult{}, appError(ErrorCompensation, "release-capacity")
		}
		previous = aggregate.Version()
		if _, recordError := aggregate.RecordReleased(authorization, receipt); recordError != nil {
			return CapacityResult{}, appError(ErrorIntegrity, "record-capacity-release")
		}
		if saveError := a.repository.SaveCapacity(ctx, previous, aggregate.Snapshot()); saveError != nil {
			return CapacityResult{}, appError(ErrorRepository, "persist-capacity-release")
		}
	}
	return capacityResult(aggregate), nil
}

func (a *CapacityApplication) loadCapacity(ctx context.Context, command CapacityCommand, create bool) (*artifactacquisition.CapacityAggregate, []artifactacquisition.CapacityLease, error) {
	if ctx == nil {
		return nil, nil, appError(ErrorInvalidCommand, "validate-capacity")
	}
	parentDigest, projections, err := validateCapacityAuthority(command)
	if err != nil {
		return nil, nil, err
	}
	pools, err := a.attestPools(ctx, command)
	if err != nil {
		return nil, nil, err
	}
	leases, err := command.Plan.CapacityLeasesForAuthority(
		command.OperationID, parentDigest, pools[0], pools[1], pools[2], command.HostRelease.Locator,
		artifactacquisition.SecretProjectionLeaseAuthority{
			InstallationID: command.InstallationID, ReleaseID: command.ReleaseID, GenerationID: command.GenerationID,
		}, projections,
	)
	if err != nil {
		return nil, nil, appError(ErrorInvalidCommand, "project-capacity")
	}
	snapshot, err := a.repository.LoadCapacity(ctx, command.OperationID)
	if errors.Is(err, ErrAggregateNotFound) && create {
		aggregate, newError := artifactacquisition.NewCapacityAggregate(command.OperationID, parentDigest, leases)
		if newError != nil {
			return nil, nil, appError(ErrorInvalidCommand, "create-capacity")
		}
		if saveError := a.repository.SaveCapacity(ctx, 0, aggregate.Snapshot()); saveError != nil {
			return nil, nil, appError(ErrorRepository, "persist-capacity-intent")
		}
		return aggregate, leases, nil
	}
	if err != nil {
		return nil, nil, mapRepository(err, "load-capacity")
	}
	aggregate, err := artifactacquisition.RestoreCapacityAggregate(leases, snapshot)
	if err != nil {
		return nil, nil, appError(ErrorIntegrity, "restore-capacity")
	}
	return aggregate, leases, nil
}

func validateCapacityAuthority(
	command CapacityCommand,
) (releaseinventory.Digest, []artifactacquisition.SecretProjectionCapacityInput, error) {
	if command.ParentPlanDigest.IsZero() {
		return releaseinventory.Digest{}, nil, appError(ErrorInvalidCommand, "capacity-parent-plan")
	}
	parentDigest, err := releaseinventory.ParseDigest(command.ParentPlanDigest.String())
	if err != nil {
		return releaseinventory.Digest{}, nil, appError(ErrorInvalidCommand, "capacity-parent-plan")
	}
	identity, err := composeplan.NewIdentity(command.InstallationID, command.GenerationID)
	if err != nil || command.ReleaseID == "" {
		return releaseinventory.Digest{}, nil, appError(ErrorInvalidCommand, "capacity-identity")
	}
	expected, ok := identity.SecretProjectionCapacities()
	if !ok || len(command.SecretProjections) != len(expected) {
		return releaseinventory.Digest{}, nil, appError(ErrorInvalidCommand, "capacity-secret-projections")
	}
	provided := append([]SecretProjectionCapacity(nil), command.SecretProjections...)
	sort.Slice(provided, func(i, j int) bool { return provided[i].Name < provided[j].Name })
	sort.Slice(expected, func(i, j int) bool { return expected[i].Name() < expected[j].Name() })
	result := make([]artifactacquisition.SecretProjectionCapacityInput, 0, len(expected))
	for index, authority := range expected {
		if provided[index].Name != authority.Name() || provided[index].Purpose != authority.Purpose() ||
			provided[index].ReservedBytes != authority.ReservedBytes() {
			return releaseinventory.Digest{}, nil, appError(ErrorInvalidCommand, "capacity-secret-projections")
		}
		result = append(result, artifactacquisition.SecretProjectionCapacityInput{
			Name: authority.Name(), Purpose: authority.Purpose(), ReservedBytes: authority.ReservedBytes(),
		})
	}
	return parentDigest, result, nil
}

func (a *CapacityApplication) attestPools(ctx context.Context, command CapacityCommand) ([3]artifactacquisition.StoragePool, error) {
	var result [3]artifactacquisition.StoragePool
	if command.HostCAS.Kind != CapacityHostCAS || command.HostRelease.Kind != CapacityHostRelease ||
		command.DockerEngine.Kind != CapacityDockerEngine || command.DockerDataVolume.Kind != CapacityDockerDataVolume {
		return result, appError(ErrorInvalidCommand, "capacity-targets")
	}
	host, err := a.pools.Attest(ctx, command.HostCAS)
	if err != nil {
		return result, appError(ErrorReservation, "attest-host-cas")
	}
	hostRelease, err := a.pools.Attest(ctx, command.HostRelease)
	if err != nil {
		return result, appError(ErrorReservation, "attest-host-release")
	}
	engine, err := a.pools.Attest(ctx, command.DockerEngine)
	if err != nil {
		return result, appError(ErrorReservation, "attest-docker-engine")
	}
	volume, err := a.pools.Attest(ctx, command.DockerDataVolume)
	if err != nil {
		return result, appError(ErrorReservation, "attest-docker-volume")
	}
	// Current signed plan has one Expanded total. Until it carries per-runtime
	// target splits, engine and data-volume must prove the exact same backing
	// pool; accepting distinct pools would make the total ambiguous.
	if !host.Valid() || !hostRelease.Valid() || !engine.Valid() || !volume.Valid() || engine.ID() != volume.ID() {
		return result, appError(ErrorReservation, "capacity-pool-mismatch")
	}
	result[0], result[1], result[2] = host, hostRelease, engine
	return result, nil
}

func capacityLeaseFor(leases []artifactacquisition.CapacityLease, purpose artifactacquisition.LeasePurpose, artifactID string) (artifactacquisition.CapacityLease, bool) {
	for _, lease := range leases {
		if lease.Purpose() == purpose && lease.ArtifactID() == artifactID {
			return lease, true
		}
	}
	return artifactacquisition.CapacityLease{}, false
}

func capacityResult(aggregate *artifactacquisition.CapacityAggregate) CapacityResult {
	snapshot := aggregate.Snapshot()
	return CapacityResult{Version: snapshot.Version, Leases: snapshot.Leases}
}

func capacityNil(value any) bool {
	if value == nil {
		return true
	}
	r := reflect.ValueOf(value)
	return (r.Kind() == reflect.Pointer || r.Kind() == reflect.Interface || r.Kind() == reflect.Func || r.Kind() == reflect.Map || r.Kind() == reflect.Slice) && r.IsNil()
}
