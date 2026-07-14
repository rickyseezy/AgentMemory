package dockercli

import (
	"context"
	"errors"
	"reflect"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
)

// UnsupportedExpandedTargetAuthorityResolver is the production resolver for
// the current PF-001 signed release schema. That schema does not carry an
// explicit target representation kind, so it fails before journal or engine
// mutation instead of guessing archive semantics.
type UnsupportedExpandedTargetAuthorityResolver struct{}

// ResolveExpandedTarget always rejects the under-authorized current schema.
func (UnsupportedExpandedTargetAuthorityResolver) ResolveExpandedTarget(
	_ context.Context,
	_ artifactacquisition.CapacityConsumeAuthorization,
) (artifactacquisition.ExpandedTargetAuthority, error) {
	return artifactacquisition.ExpandedTargetAuthority{}, artifactapp.ErrExpandedTargetUnsupported
}

// SignedExpandedTargetAuthorityResolver projects the exact representation,
// release-relative storage identity, and authority digest already carried by
// the parent-bound expanded capacity lease. It performs no filename or media
// inference and unknown target kinds cannot produce a valid lease.
type SignedExpandedTargetAuthorityResolver struct{}

// ResolveExpandedTarget returns only the exact release-signed lease authority.
func (SignedExpandedTargetAuthorityResolver) ResolveExpandedTarget(
	ctx context.Context,
	authorization artifactacquisition.CapacityConsumeAuthorization,
) (artifactacquisition.ExpandedTargetAuthority, error) {
	if ctx == nil || ctx.Err() != nil || !authorization.Valid() {
		return artifactacquisition.ExpandedTargetAuthority{}, artifactapp.ErrExpandedTargetUnsupported
	}
	lease := authorization.Lease()
	authority, err := artifactacquisition.NewExpandedTargetAuthority(
		authorization, string(lease.TargetKind()), lease.TargetStorageID(), lease.TargetAuthorityDigest(),
	)
	if err != nil {
		return artifactacquisition.ExpandedTargetAuthority{}, artifactapp.ErrExpandedTargetUnsupported
	}
	return authority, nil
}

// ExpandedTargets is the crash-safe Docker target lifecycle adapter. The
// injected resolver must project explicit signed target authority; the engine
// may mutate only after the corresponding pending state is durable.
type ExpandedTargets struct {
	resolver   artifactapp.ExpandedTargetAuthorityResolver
	repository artifactapp.ExpandedTargetRepository
	engine     artifactapp.ExpandedTargetEngine
}

// NewExpandedTargets composes the explicit authority, authenticated journal,
// and representation-specific engine capabilities.
func NewExpandedTargets(
	resolver artifactapp.ExpandedTargetAuthorityResolver,
	repository artifactapp.ExpandedTargetRepository,
	engine artifactapp.ExpandedTargetEngine,
) (*ExpandedTargets, error) {
	if expandedTargetNil(resolver) || expandedTargetNil(repository) || expandedTargetNil(engine) {
		return nil, artifactapp.ErrExpandedTargetUnsupported
	}
	return &ExpandedTargets{resolver: resolver, repository: repository, engine: engine}, nil
}

// PrimeConsumeIntent resolves explicit authority and persists ConsumePending
// without invoking the target engine. It is useful for deterministic recovery
// composition and never invents a completed materialization.
func (a *ExpandedTargets) PrimeConsumeIntent(
	ctx context.Context,
	authorization artifactacquisition.CapacityConsumeAuthorization,
) error {
	_, _, err := a.loadOrCreate(ctx, authorization)
	return err
}

// MaterializeExpanded reconciles an interrupted exact effect or performs one
// representation-specific materialization after ConsumePending is durable.
func (a *ExpandedTargets) MaterializeExpanded(
	ctx context.Context,
	authorization artifactacquisition.CapacityConsumeAuthorization,
) (artifactacquisition.CapacityMutationProof, error) {
	authority, aggregate, err := a.loadOrCreate(ctx, authorization)
	if err != nil {
		return artifactacquisition.CapacityMutationProof{}, err
	}
	if aggregate.State() != artifactacquisition.ExpandedTargetReleasePending &&
		aggregate.State() != artifactacquisition.ExpandedTargetReleased {
		if err := a.reconcile(ctx, aggregate); err != nil {
			return artifactacquisition.CapacityMutationProof{}, err
		}
	}
	if aggregate.State() == artifactacquisition.ExpandedTargetConsumed {
		return expandedMutationProof(aggregate)
	}
	if aggregate.State() != artifactacquisition.ExpandedTargetConsumePending {
		return artifactacquisition.CapacityMutationProof{}, artifactapp.ErrExpandedTargetOperation
	}
	observation, err := a.engine.MaterializeExpandedTarget(ctx, authority)
	if err != nil {
		return artifactacquisition.CapacityMutationProof{}, errors.Join(artifactapp.ErrExpandedTargetOperation, err)
	}
	previous := aggregate.Version()
	if _, err := aggregate.RecordConsumed(observation); err != nil {
		return artifactacquisition.CapacityMutationProof{}, artifactapp.ErrAggregateIntegrity
	}
	if err := a.repository.SaveExpandedTarget(ctx, previous, aggregate.Snapshot()); err != nil {
		return artifactacquisition.CapacityMutationProof{}, err
	}
	return expandedMutationProof(aggregate)
}

// TransferExpanded moves one exact measured target to generation ownership.
func (a *ExpandedTargets) TransferExpanded(
	ctx context.Context,
	lease artifactacquisition.CapacityLease,
	newOwner string,
) (artifactacquisition.CapacityMutationProof, error) {
	aggregate, err := a.loadExisting(ctx, lease)
	if err != nil {
		return artifactacquisition.CapacityMutationProof{}, err
	}
	if aggregate.State() != artifactacquisition.ExpandedTargetReleasePending &&
		aggregate.State() != artifactacquisition.ExpandedTargetReleased {
		if err := a.reconcile(ctx, aggregate); err != nil {
			return artifactacquisition.CapacityMutationProof{}, err
		}
	}
	if aggregate.State() == artifactacquisition.ExpandedTargetTransferred {
		if aggregate.CurrentOwner() != newOwner {
			return artifactacquisition.CapacityMutationProof{}, artifactapp.ErrAggregateIntegrity
		}
		return expandedMutationProof(aggregate)
	}
	previous := aggregate.Version()
	changed, err := aggregate.BeginTransfer(newOwner)
	if err != nil {
		return artifactacquisition.CapacityMutationProof{}, artifactapp.ErrAggregateIntegrity
	}
	if changed {
		if err := a.repository.SaveExpandedTarget(ctx, previous, aggregate.Snapshot()); err != nil {
			return artifactacquisition.CapacityMutationProof{}, err
		}
	}
	observation, err := a.engine.TransferExpandedTarget(ctx, aggregate.Authority(), aggregate.Snapshot(), newOwner)
	if err != nil {
		return artifactacquisition.CapacityMutationProof{}, errors.Join(artifactapp.ErrExpandedTargetOperation, err)
	}
	previous = aggregate.Version()
	if _, err := aggregate.RecordTransferred(observation); err != nil {
		return artifactacquisition.CapacityMutationProof{}, artifactapp.ErrAggregateIntegrity
	}
	if err := a.repository.SaveExpandedTarget(ctx, previous, aggregate.Snapshot()); err != nil {
		return artifactacquisition.CapacityMutationProof{}, err
	}
	return expandedMutationProof(aggregate)
}

// ReleaseExpanded retires the exact target and any still-present consumed
// reservation for compensation or uninstall, then verifies both are absent.
func (a *ExpandedTargets) ReleaseExpanded(
	ctx context.Context,
	authorization artifactacquisition.CapacityReleaseAuthorization,
) (artifactacquisition.LeaseReceipt, error) {
	if !authorization.Valid() || authorization.Lease().Purpose() != artifactacquisition.LeaseExpanded {
		return artifactacquisition.LeaseReceipt{}, artifactapp.ErrAggregateIntegrity
	}
	aggregate, err := a.loadExisting(ctx, authorization.Lease())
	if err != nil {
		return artifactacquisition.LeaseReceipt{}, err
	}
	if aggregate.State() != artifactacquisition.ExpandedTargetReleasePending &&
		aggregate.State() != artifactacquisition.ExpandedTargetReleased {
		if err := a.reconcile(ctx, aggregate); err != nil {
			return artifactacquisition.LeaseReceipt{}, err
		}
	}
	previous := aggregate.Version()
	changed, err := aggregate.BeginRelease(authorization)
	if err != nil {
		return artifactacquisition.LeaseReceipt{}, artifactapp.ErrAggregateIntegrity
	}
	if changed {
		if err := a.repository.SaveExpandedTarget(ctx, previous, aggregate.Snapshot()); err != nil {
			return artifactacquisition.LeaseReceipt{}, err
		}
	}
	observation, err := a.engine.RetireExpandedTarget(ctx, aggregate.Authority(), aggregate.Snapshot(), authorization)
	if err != nil {
		return artifactacquisition.LeaseReceipt{}, errors.Join(artifactapp.ErrExpandedTargetOperation, err)
	}
	previous = aggregate.Version()
	changed, err = aggregate.RecordReleased(observation)
	if err != nil {
		return artifactacquisition.LeaseReceipt{}, artifactapp.ErrAggregateIntegrity
	}
	if changed {
		if err := a.repository.SaveExpandedTarget(ctx, previous, aggregate.Snapshot()); err != nil {
			return artifactacquisition.LeaseReceipt{}, err
		}
	}
	lease := aggregate.Authority().ConsumeAuthorization().Lease()
	return artifactacquisition.NewMeasuredLeaseReceipt(
		lease.ID(), lease.Pool(), lease.Bytes(), aggregate.Authority().ConsumeAuthorization().ReceiptAllocatedBytes(),
		aggregate.Authority().ConsumeAuthorization().ReceiptToken(), false,
	)
}

func (a *ExpandedTargets) loadOrCreate(
	ctx context.Context,
	authorization artifactacquisition.CapacityConsumeAuthorization,
) (artifactacquisition.ExpandedTargetAuthority, *artifactacquisition.ExpandedTargetAggregate, error) {
	authority, err := a.resolve(ctx, authorization)
	if err != nil {
		return artifactacquisition.ExpandedTargetAuthority{}, nil, err
	}
	snapshot, err := a.repository.LoadExpandedTarget(ctx, authorization.Lease().ID())
	if errors.Is(err, artifactapp.ErrAggregateNotFound) {
		aggregate, createError := artifactacquisition.NewExpandedTargetAggregate(authority)
		if createError != nil {
			return artifactacquisition.ExpandedTargetAuthority{}, nil, artifactapp.ErrAggregateIntegrity
		}
		if saveError := a.repository.SaveExpandedTarget(ctx, 0, aggregate.Snapshot()); saveError != nil {
			return artifactacquisition.ExpandedTargetAuthority{}, nil, saveError
		}
		return authority, aggregate, nil
	}
	if err != nil {
		return artifactacquisition.ExpandedTargetAuthority{}, nil, err
	}
	aggregate, err := artifactacquisition.RestoreExpandedTargetAggregate(authority, snapshot)
	if err != nil {
		return artifactacquisition.ExpandedTargetAuthority{}, nil, artifactapp.ErrAggregateIntegrity
	}
	return authority, aggregate, nil
}

func (a *ExpandedTargets) loadExisting(
	ctx context.Context,
	lease artifactacquisition.CapacityLease,
) (*artifactacquisition.ExpandedTargetAggregate, error) {
	if ctx == nil || !lease.Valid() || lease.Purpose() != artifactacquisition.LeaseExpanded {
		return nil, artifactapp.ErrAggregateIntegrity
	}
	snapshot, err := a.repository.LoadExpandedTarget(ctx, lease.ID())
	if err != nil {
		return nil, err
	}
	authorization, err := artifactacquisition.RestoreCapacityConsumeAuthorization(
		lease, snapshot.ReceiptToken, snapshot.ReservedAllocatedBytes,
	)
	if err != nil {
		return nil, artifactapp.ErrAggregateIntegrity
	}
	authority, err := a.resolve(ctx, authorization)
	if err != nil {
		return nil, err
	}
	aggregate, err := artifactacquisition.RestoreExpandedTargetAggregate(authority, snapshot)
	if err != nil {
		return nil, artifactapp.ErrAggregateIntegrity
	}
	return aggregate, nil
}

func (a *ExpandedTargets) resolve(
	ctx context.Context,
	authorization artifactacquisition.CapacityConsumeAuthorization,
) (artifactacquisition.ExpandedTargetAuthority, error) {
	if a == nil || ctx == nil || !authorization.Valid() {
		return artifactacquisition.ExpandedTargetAuthority{}, artifactapp.ErrExpandedTargetUnsupported
	}
	if err := ctx.Err(); err != nil {
		return artifactacquisition.ExpandedTargetAuthority{}, errors.Join(artifactapp.ErrExpandedTargetOperation, err)
	}
	authority, err := a.resolver.ResolveExpandedTarget(ctx, authorization)
	if err != nil {
		return artifactacquisition.ExpandedTargetAuthority{}, err
	}
	resolved := authority.ConsumeAuthorization()
	if !authority.Valid() || resolved.Lease().ID() != authorization.Lease().ID() ||
		resolved.ReceiptToken() != authorization.ReceiptToken() {
		return artifactacquisition.ExpandedTargetAuthority{}, artifactapp.ErrAggregateIntegrity
	}
	return authority, nil
}

func (a *ExpandedTargets) reconcile(
	ctx context.Context,
	aggregate *artifactacquisition.ExpandedTargetAggregate,
) error {
	previous := aggregate.Version()
	observation, err := a.engine.InspectExpandedTarget(ctx, aggregate.Authority(), aggregate.Snapshot())
	if err != nil {
		return errors.Join(artifactapp.ErrExpandedTargetOperation, err)
	}
	changed, err := aggregate.ReconcileObservation(observation)
	if err != nil {
		return artifactapp.ErrAggregateIntegrity
	}
	if changed {
		return a.repository.SaveExpandedTarget(ctx, previous, aggregate.Snapshot())
	}
	return nil
}

func expandedMutationProof(
	aggregate *artifactacquisition.ExpandedTargetAggregate,
) (artifactacquisition.CapacityMutationProof, error) {
	authorization := aggregate.Authority().ConsumeAuthorization()
	lease := authorization.Lease()
	receipt, err := artifactacquisition.NewMeasuredLeaseReceipt(
		lease.ID(), lease.Pool(), lease.Bytes(), authorization.ReceiptAllocatedBytes(), authorization.ReceiptToken(), false,
	)
	if err != nil {
		return artifactacquisition.CapacityMutationProof{}, artifactapp.ErrAggregateIntegrity
	}
	proof, err := artifactacquisition.NewMeasuredCapacityMutationProof(
		receipt, lease.ExpectedTargetDigest(), aggregate.MeasuredBytes(), aggregate.AllocatedBytes(), aggregate.CurrentOwner(),
	)
	if err != nil {
		return artifactacquisition.CapacityMutationProof{}, artifactapp.ErrAggregateIntegrity
	}
	return proof, nil
}

func expandedTargetNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	kind := reflected.Kind()
	if kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface || kind == reflect.Map ||
		kind == reflect.Pointer || kind == reflect.Slice {
		return reflected.IsNil()
	}
	return false
}

// DockerCapacity composes reservation volumes with explicit expanded-target
// lifecycle handling behind the application capacity contracts.
type DockerCapacity struct {
	reservations *CapacityLeases
	expanded     *ExpandedTargets
}

// NewDockerCapacity creates the complete Docker capacity adapter.
func NewDockerCapacity(
	reservations *CapacityLeases,
	expanded *ExpandedTargets,
) (*DockerCapacity, error) {
	if expandedTargetNil(reservations) || expanded == nil {
		return nil, artifactapp.ErrReservationUnsupported
	}
	return &DockerCapacity{reservations: reservations, expanded: expanded}, nil
}

// ReserveLease delegates exact reservation allocation.
func (a *DockerCapacity) ReserveLease(ctx context.Context, lease artifactacquisition.CapacityLease) (artifactacquisition.LeaseReceipt, error) {
	return a.reservations.ReserveLease(ctx, lease)
}

// RevalidateLease delegates exact reservation revalidation.
func (a *DockerCapacity) RevalidateLease(ctx context.Context, lease artifactacquisition.CapacityLease) (artifactacquisition.LeaseReceipt, error) {
	return a.reservations.RevalidateLease(ctx, lease)
}

// MaterializeExpanded delegates the explicitly authorized target lifecycle.
func (a *DockerCapacity) MaterializeExpanded(ctx context.Context, authorization artifactacquisition.CapacityConsumeAuthorization) (artifactacquisition.CapacityMutationProof, error) {
	return a.expanded.MaterializeExpanded(ctx, authorization)
}

// TransferLease routes expanded targets and reservation-only leases correctly.
func (a *DockerCapacity) TransferLease(ctx context.Context, lease artifactacquisition.CapacityLease, newOwner string) (artifactacquisition.CapacityMutationProof, error) {
	if lease.Purpose() == artifactacquisition.LeaseExpanded {
		return a.expanded.TransferExpanded(ctx, lease, newOwner)
	}
	return a.reservations.TransferLease(ctx, lease, newOwner)
}

// ReleaseCapacity routes target retirement when a target journal exists. A
// ConsumePending lease with no target journal is still an untouched exact
// reservation and is safely released through the reservation adapter.
func (a *DockerCapacity) ReleaseCapacity(ctx context.Context, authorization artifactacquisition.CapacityReleaseAuthorization) (artifactacquisition.LeaseReceipt, error) {
	if authorization.Lease().Purpose() != artifactacquisition.LeaseExpanded ||
		authorization.FromState() == artifactacquisition.LeaseReservePending ||
		authorization.FromState() == artifactacquisition.LeaseReserved {
		return a.reservations.ReleaseCapacity(ctx, authorization)
	}
	receipt, err := a.expanded.ReleaseExpanded(ctx, authorization)
	if errors.Is(err, artifactapp.ErrAggregateNotFound) &&
		authorization.FromState() == artifactacquisition.LeaseConsumePending {
		// ExpandedTargets returns NotFound only after an authenticated read.
		// Therefore no target intent was ever durable and the exact reserved
		// volume remains the only authorized object.
		return a.reservations.releaseCapacity(ctx, authorization, true)
	}
	return receipt, err
}

var (
	_ artifactapp.ExpandedMaterializer = (*ExpandedTargets)(nil)
	_ artifactapp.CapacityLeasePort    = (*DockerCapacity)(nil)
	_ artifactapp.ExpandedMaterializer = (*DockerCapacity)(nil)
)

// CapacityLifecycle is the production pool router: HostRelease reservations
// stay on the release filesystem, while rollback/safety/projection volumes use
// the attested Docker pool. Expanded target journals replace only HostRelease
// reservations and never treat Compose bytes as Docker-volume capacity.
type CapacityLifecycle struct {
	hostRelease artifactapp.CapacityLeasePort
	docker      *CapacityLeases
	expanded    *ExpandedTargets
}

// NewCapacityLifecycle composes all production capacity backends.
func NewCapacityLifecycle(
	hostRelease artifactapp.CapacityLeasePort,
	docker *CapacityLeases,
	expanded *ExpandedTargets,
) (*CapacityLifecycle, error) {
	if expandedTargetNil(hostRelease) || expandedTargetNil(docker) || expanded == nil {
		return nil, artifactapp.ErrReservationUnsupported
	}
	return &CapacityLifecycle{hostRelease: hostRelease, docker: docker, expanded: expanded}, nil
}

// ReserveLease routes by the authenticated lease pool kind.
func (a *CapacityLifecycle) ReserveLease(
	ctx context.Context,
	lease artifactacquisition.CapacityLease,
) (artifactacquisition.LeaseReceipt, error) {
	if lease.Pool().Kind() == artifactapp.CapacityHostRelease && lease.Purpose() == artifactacquisition.LeaseExpanded {
		return a.hostRelease.ReserveLease(ctx, lease)
	}
	if lease.Pool().Kind() == artifactapp.CapacityDockerEngine && lease.Purpose() != artifactacquisition.LeaseExpanded {
		return a.docker.ReserveLease(ctx, lease)
	}
	return artifactacquisition.LeaseReceipt{}, artifactapp.ErrReservationUnsupported
}

// RevalidateLease routes by the authenticated lease pool kind.
func (a *CapacityLifecycle) RevalidateLease(
	ctx context.Context,
	lease artifactacquisition.CapacityLease,
) (artifactacquisition.LeaseReceipt, error) {
	if lease.Pool().Kind() == artifactapp.CapacityHostRelease && lease.Purpose() == artifactacquisition.LeaseExpanded {
		return a.hostRelease.RevalidateLease(ctx, lease)
	}
	if lease.Pool().Kind() == artifactapp.CapacityDockerEngine && lease.Purpose() != artifactacquisition.LeaseExpanded {
		return a.docker.RevalidateLease(ctx, lease)
	}
	return artifactacquisition.LeaseReceipt{}, artifactapp.ErrReservationUnsupported
}

// MaterializeExpanded delegates the signed target lifecycle.
func (a *CapacityLifecycle) MaterializeExpanded(
	ctx context.Context,
	authorization artifactacquisition.CapacityConsumeAuthorization,
) (artifactacquisition.CapacityMutationProof, error) {
	if authorization.Lease().Pool().Kind() != artifactapp.CapacityHostRelease {
		return artifactacquisition.CapacityMutationProof{}, artifactapp.ErrExpandedTargetUnsupported
	}
	return a.expanded.MaterializeExpanded(ctx, authorization)
}

// TransferLease transfers expanded journal ownership or Docker reservation ownership.
func (a *CapacityLifecycle) TransferLease(
	ctx context.Context,
	lease artifactacquisition.CapacityLease,
	newOwner string,
) (artifactacquisition.CapacityMutationProof, error) {
	if lease.Purpose() == artifactacquisition.LeaseExpanded && lease.Pool().Kind() == artifactapp.CapacityHostRelease {
		return a.expanded.TransferExpanded(ctx, lease, newOwner)
	}
	if lease.Purpose() != artifactacquisition.LeaseExpanded && lease.Pool().Kind() == artifactapp.CapacityDockerEngine {
		return a.docker.TransferLease(ctx, lease, newOwner)
	}
	return artifactacquisition.CapacityMutationProof{}, artifactapp.ErrReservationUnsupported
}

// ReleaseCapacity retires exact target state or the untouched reservation
// selected by an aggregate-minted authorization.
func (a *CapacityLifecycle) ReleaseCapacity(
	ctx context.Context,
	authorization artifactacquisition.CapacityReleaseAuthorization,
) (artifactacquisition.LeaseReceipt, error) {
	lease := authorization.Lease()
	if lease.Purpose() != artifactacquisition.LeaseExpanded {
		if lease.Pool().Kind() != artifactapp.CapacityDockerEngine {
			return artifactacquisition.LeaseReceipt{}, artifactapp.ErrReservationUnsupported
		}
		return a.docker.ReleaseCapacity(ctx, authorization)
	}
	if lease.Pool().Kind() != artifactapp.CapacityHostRelease {
		return artifactacquisition.LeaseReceipt{}, artifactapp.ErrReservationUnsupported
	}
	if authorization.FromState() == artifactacquisition.LeaseReservePending ||
		authorization.FromState() == artifactacquisition.LeaseReserved {
		return a.hostRelease.ReleaseCapacity(ctx, authorization)
	}
	receipt, err := a.expanded.ReleaseExpanded(ctx, authorization)
	if errors.Is(err, artifactapp.ErrAggregateNotFound) && authorization.FromState() == artifactacquisition.LeaseConsumePending {
		return a.hostRelease.ReleaseCapacity(ctx, authorization)
	}
	return receipt, err
}

var (
	_ artifactapp.CapacityLeasePort    = (*CapacityLifecycle)(nil)
	_ artifactapp.ExpandedMaterializer = (*CapacityLifecycle)(nil)
)
