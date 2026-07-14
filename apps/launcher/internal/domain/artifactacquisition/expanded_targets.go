package artifactacquisition

import (
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

// ExpandedTargetState is the independently journaled lifecycle of the Docker
// representation that replaces an expanded capacity reservation.
type ExpandedTargetState string

// Every external expanded-target mutation has a durable pre-effect state.
const (
	ExpandedTargetConsumePending  ExpandedTargetState = "consume-pending"
	ExpandedTargetConsumed        ExpandedTargetState = "consumed"
	ExpandedTargetTransferPending ExpandedTargetState = "transfer-pending"
	ExpandedTargetTransferred     ExpandedTargetState = "transferred"
	ExpandedTargetReleasePending  ExpandedTargetState = "release-pending"
	ExpandedTargetReleased        ExpandedTargetState = "released"
)

// ExpandedTargetAuthority is an explicit signed-plan projection of the target
// representation. TargetKind must never be inferred from an artifact filename
// or media bytes. Digest binds the signed projection that supplied the kind
// and concrete Docker storage identity.
type ExpandedTargetAuthority struct {
	consume         CapacityConsumeAuthorization
	targetKind      string
	targetStorageID string
	authorityDigest releaseinventory.Digest
}

// NewExpandedTargetAuthority constructs explicit target representation authority.
func NewExpandedTargetAuthority(
	consume CapacityConsumeAuthorization,
	targetKind string,
	targetStorageID string,
	authorityDigest releaseinventory.Digest,
) (ExpandedTargetAuthority, error) {
	value := ExpandedTargetAuthority{
		consume: consume, targetKind: targetKind,
		targetStorageID: targetStorageID, authorityDigest: authorityDigest,
	}
	if !value.Valid() {
		return ExpandedTargetAuthority{}, ErrInvalidTransition
	}
	return value, nil
}

// ConsumeAuthorization returns the exact reservation replacement authority.
func (a ExpandedTargetAuthority) ConsumeAuthorization() CapacityConsumeAuthorization {
	return a.consume
}

// TargetKind returns the explicit signed representation kind.
func (a ExpandedTargetAuthority) TargetKind() string { return a.targetKind }

// TargetStorageID returns the exact Docker storage object identity.
func (a ExpandedTargetAuthority) TargetStorageID() string { return a.targetStorageID }

// Digest returns the digest of the signed target-authority projection.
func (a ExpandedTargetAuthority) Digest() releaseinventory.Digest { return a.authorityDigest }

// Valid reports whether all source, lease, target, and receipt bindings exist.
func (a ExpandedTargetAuthority) Valid() bool {
	lease := a.consume.lease
	return a.consume.Valid() && a.targetKind == string(lease.targetKind) &&
		a.targetStorageID == lease.targetStorageID && a.authorityDigest.Equal(lease.targetAuthorityDigest)
}

// ExpandedTargetObservationInput repeats all immutable identities so an
// adapter observation cannot silently substitute a source, pool, target, or
// owner during crash reconciliation.
type ExpandedTargetObservationInput struct {
	LeaseID                string
	ReceiptToken           string
	PlanDigest             releaseinventory.Digest
	PoolID                 string
	PoolKind               string
	SourceDigest           releaseinventory.Digest
	SourceBytes            uint64
	TargetDigest           releaseinventory.Digest
	ReservedBytes          uint64
	ReservedAllocatedBytes uint64
	TargetKind             string
	TargetStorageID        string
	TargetRoot             string
	TargetAuthorityDigest  releaseinventory.Digest
	Owner                  string
	MeasuredBytes          uint64
	AllocatedBytes         uint64
	ReservationPresent     bool
	TargetPresent          bool
}

// ExpandedTargetObservation is exact engine evidence. The fields remain
// exported as a persistence-neutral value, while Valid and aggregate methods
// enforce their conjunction before accepting a state change.
type ExpandedTargetObservation = ExpandedTargetObservationInput

// NewExpandedTargetObservation validates a complete engine observation.
func NewExpandedTargetObservation(input ExpandedTargetObservationInput) (ExpandedTargetObservation, error) {
	if !validExpandedTargetObservation(input) {
		return ExpandedTargetObservation{}, ErrInvalidTransition
	}
	return input, nil
}

func validExpandedTargetObservation(value ExpandedTargetObservation) bool {
	return validIdentifier(value.LeaseID) && validIdentifier(value.ReceiptToken) &&
		!value.PlanDigest.IsZero() && validIdentifier(value.PoolID) && validIdentifier(value.PoolKind) &&
		!value.SourceDigest.IsZero() && value.SourceBytes > 0 && value.SourceBytes <= maximumSafeBytes &&
		!value.TargetDigest.IsZero() && value.ReservedBytes > 0 && value.ReservedBytes <= maximumSafeBytes &&
		validIdentifier(value.TargetKind) && validTargetStorageID(value.TargetStorageID) &&
		value.TargetRoot != "" && len(value.TargetRoot) <= 4096 && !strings.ContainsAny(value.TargetRoot, "\x00\r\n") &&
		!value.TargetAuthorityDigest.IsZero() && validIdentifier(value.Owner) &&
		value.ReservedAllocatedBytes >= value.ReservedBytes && value.ReservedAllocatedBytes <= maximumSafeBytes &&
		value.MeasuredBytes <= value.ReservedBytes && value.AllocatedBytes <= value.ReservedAllocatedBytes &&
		(!value.TargetPresent || value.MeasuredBytes > 0 && value.AllocatedBytes > 0)
}

func validTargetStorageID(value string) bool {
	if value == "" || len(value) > 256 || strings.ContainsAny(value, "\x00\r\n\\") ||
		strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.Contains(value, "//") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// ExpandedTargetSnapshot is the authenticated, rollback-protected lifecycle
// record for one exact expanded Docker target.
type ExpandedTargetSnapshot struct {
	SchemaVersion          uint16
	Version                uint64
	LeaseID                string
	ArtifactID             string
	PlanDigest             string
	PoolID                 string
	PoolKind               string
	ReservedBytes          uint64
	ReservedAllocatedBytes uint64
	ReceiptToken           string
	InitialOwner           string
	SourceDigest           string
	SourceBytes            uint64
	TargetDigest           string
	TargetKind             string
	TargetStorageID        string
	TargetRoot             string
	TargetAuthorityDigest  string
	State                  string
	MeasuredBytes          uint64
	AllocatedBytes         uint64
	CurrentOwner           string
	NewOwner               string
	ReleaseFrom            string
	CapacityReleaseFrom    string
	ReleaseKind            string
}

// ExpandedTargetAggregate guards one target's consume, ownership, and retirement lifecycle.
type ExpandedTargetAggregate struct {
	authority           ExpandedTargetAuthority
	state               ExpandedTargetState
	version             uint64
	measuredBytes       uint64
	allocatedBytes      uint64
	currentOwner        string
	newOwner            string
	releaseFrom         ExpandedTargetState
	capacityReleaseFrom LeaseState
	releaseKind         CapacityReleaseKind
}

// NewExpandedTargetAggregate records ConsumePending before any target mutation.
func NewExpandedTargetAggregate(authority ExpandedTargetAuthority) (*ExpandedTargetAggregate, error) {
	if !authority.Valid() {
		return nil, ErrInvalidTransition
	}
	return &ExpandedTargetAggregate{
		authority: authority, state: ExpandedTargetConsumePending,
		currentOwner: authority.consume.lease.owner,
	}, nil
}

// RestoreExpandedTargetAggregate validates every immutable field and complete history.
func RestoreExpandedTargetAggregate(
	authority ExpandedTargetAuthority,
	snapshot ExpandedTargetSnapshot,
) (*ExpandedTargetAggregate, error) {
	if !authority.Valid() || !snapshotMatchesExpandedAuthority(snapshot, authority) {
		return nil, ErrIntegrity
	}
	value := &ExpandedTargetAggregate{
		authority: authority, state: ExpandedTargetState(snapshot.State), version: snapshot.Version,
		measuredBytes: snapshot.MeasuredBytes, allocatedBytes: snapshot.AllocatedBytes, currentOwner: snapshot.CurrentOwner,
		newOwner: snapshot.NewOwner, releaseFrom: ExpandedTargetState(snapshot.ReleaseFrom),
		capacityReleaseFrom: LeaseState(snapshot.CapacityReleaseFrom),
		releaseKind:         CapacityReleaseKind(snapshot.ReleaseKind),
	}
	if !value.validHistory() {
		return nil, ErrIntegrity
	}
	return value, nil
}

// State returns the durable target lifecycle state.
func (a *ExpandedTargetAggregate) State() ExpandedTargetState { return a.state }

// Version returns the optimistic target journal revision.
func (a *ExpandedTargetAggregate) Version() uint64 { return a.version }

// MeasuredBytes returns exact engine-measured target usage, never a reservation estimate.
func (a *ExpandedTargetAggregate) MeasuredBytes() uint64 { return a.measuredBytes }

// AllocatedBytes returns exact target blocks, distinct from logical length.
func (a *ExpandedTargetAggregate) AllocatedBytes() uint64 { return a.allocatedBytes }

// CurrentOwner returns the last durably proven target owner.
func (a *ExpandedTargetAggregate) CurrentOwner() string { return a.currentOwner }

// NewOwner returns the pending or proven generation owner, when present.
func (a *ExpandedTargetAggregate) NewOwner() string { return a.newOwner }

// Authority returns the immutable signed target projection.
func (a *ExpandedTargetAggregate) Authority() ExpandedTargetAuthority { return a.authority }

// ReconcileObservation classifies an exact read-only engine observation
// against the pending lifecycle. It records only a fully completed exact
// effect; unknown absence, dual presence, and substituted identity fail.
func (a *ExpandedTargetAggregate) ReconcileObservation(observation ExpandedTargetObservation) (bool, error) {
	switch a.state {
	case ExpandedTargetConsumePending:
		if observation.TargetPresent {
			return a.RecordConsumed(observation)
		}
		if !a.matchesObservation(observation, a.currentOwner, 0, 0, true, false) {
			return false, ErrInvalidTransition
		}
		return false, nil
	case ExpandedTargetConsumed:
		return a.RecordConsumed(observation)
	case ExpandedTargetTransferPending:
		if observation.Owner == a.newOwner {
			return a.RecordTransferred(observation)
		}
		if !a.matchesObservation(observation, a.currentOwner, a.measuredBytes, a.allocatedBytes, false, true) {
			return false, ErrInvalidTransition
		}
		return false, nil
	case ExpandedTargetTransferred:
		return a.RecordTransferred(observation)
	case ExpandedTargetReleased:
		return a.RecordReleased(observation)
	case ExpandedTargetReleasePending:
		return false, ErrInvalidTransition
	default:
		return false, ErrInvalidTransition
	}
}

// RecordConsumed accepts only an exact target and exact measured engine usage.
func (a *ExpandedTargetAggregate) RecordConsumed(observation ExpandedTargetObservation) (bool, error) {
	if a.state == ExpandedTargetConsumed {
		if !a.matchesObservation(observation, a.currentOwner, a.measuredBytes, a.allocatedBytes, false, true) {
			return false, ErrInvalidTransition
		}
		return false, nil
	}
	if a.state != ExpandedTargetConsumePending ||
		!a.matchesObservation(observation, a.currentOwner, observation.MeasuredBytes, observation.AllocatedBytes, false, true) ||
		observation.MeasuredBytes != a.authority.consume.lease.bytes || observation.AllocatedBytes == 0 {
		return false, ErrInvalidTransition
	}
	a.state, a.measuredBytes, a.allocatedBytes = ExpandedTargetConsumed, observation.MeasuredBytes, observation.AllocatedBytes
	a.version++
	return true, nil
}

// BeginTransfer persists generation ownership intent before the engine mutation.
func (a *ExpandedTargetAggregate) BeginTransfer(newOwner string) (bool, error) {
	if !validIdentifier(newOwner) {
		return false, ErrInvalidTransition
	}
	if a.state == ExpandedTargetTransferred {
		if a.newOwner != newOwner || a.currentOwner != newOwner {
			return false, ErrInvalidTransition
		}
		return false, nil
	}
	if a.state == ExpandedTargetTransferPending {
		if a.newOwner != newOwner {
			return false, ErrInvalidTransition
		}
		return false, nil
	}
	if a.state != ExpandedTargetConsumed {
		return false, ErrInvalidTransition
	}
	a.state, a.newOwner = ExpandedTargetTransferPending, newOwner
	a.version++
	return true, nil
}

// RecordTransferred records exact post-transfer identity, usage, and ownership.
func (a *ExpandedTargetAggregate) RecordTransferred(observation ExpandedTargetObservation) (bool, error) {
	if a.state == ExpandedTargetTransferred {
		if !a.matchesObservation(observation, a.currentOwner, a.measuredBytes, a.allocatedBytes, false, true) {
			return false, ErrInvalidTransition
		}
		return false, nil
	}
	if a.state != ExpandedTargetTransferPending ||
		!a.matchesObservation(observation, a.newOwner, a.measuredBytes, a.allocatedBytes, false, true) {
		return false, ErrInvalidTransition
	}
	a.state, a.currentOwner = ExpandedTargetTransferred, a.newOwner
	a.version++
	return true, nil
}

// BeginRelease validates the capacity aggregate's exact cleanup authority and
// persists target retirement intent. It accepts only crash-compatible target
// states; contradictory drift is never repaired or adopted.
func (a *ExpandedTargetAggregate) BeginRelease(authorization CapacityReleaseAuthorization) (bool, error) {
	if !a.releaseAuthorizationCompatible(authorization) {
		return false, ErrInvalidTransition
	}
	if a.state == ExpandedTargetReleasePending || a.state == ExpandedTargetReleased {
		if a.capacityReleaseFrom != authorization.from || a.releaseKind != authorization.kind {
			return false, ErrInvalidTransition
		}
		return false, nil
	}
	a.releaseFrom, a.capacityReleaseFrom, a.releaseKind = a.state, authorization.from, authorization.kind
	if a.newOwner == "" && authorization.newOwner != "" {
		a.newOwner = authorization.newOwner
	}
	a.state = ExpandedTargetReleasePending
	a.version++
	return true, nil
}

// RecordReleased accepts only verified absence of both the reservation and target.
func (a *ExpandedTargetAggregate) RecordReleased(observation ExpandedTargetObservation) (bool, error) {
	if a.state == ExpandedTargetReleased {
		if !a.matchesReleasedObservation(observation) {
			return false, ErrInvalidTransition
		}
		return false, nil
	}
	if a.state != ExpandedTargetReleasePending || !a.matchesReleasedObservation(observation) {
		return false, ErrInvalidTransition
	}
	a.state = ExpandedTargetReleased
	a.version++
	return true, nil
}

// Snapshot returns the complete persistence-neutral target lifecycle projection.
func (a *ExpandedTargetAggregate) Snapshot() ExpandedTargetSnapshot {
	lease := a.authority.consume.lease
	return ExpandedTargetSnapshot{
		SchemaVersion: 1, Version: a.version, LeaseID: lease.id, ArtifactID: lease.artifactID,
		PlanDigest: lease.planDigest.Hex(), PoolID: lease.pool.id, PoolKind: lease.pool.kind,
		ReservedBytes: lease.bytes, ReservedAllocatedBytes: a.authority.consume.receiptAllocatedBytes,
		ReceiptToken: a.authority.consume.receiptToken,
		InitialOwner: lease.owner, SourceDigest: lease.sourceDigest.Hex(), SourceBytes: lease.sourceBytes,
		TargetDigest: lease.expectedTargetDigest.Hex(), TargetKind: a.authority.targetKind,
		TargetStorageID: a.authority.targetStorageID, TargetRoot: lease.targetRoot,
		TargetAuthorityDigest: a.authority.authorityDigest.Hex(),
		State:                 string(a.state), MeasuredBytes: a.measuredBytes, AllocatedBytes: a.allocatedBytes,
		CurrentOwner: a.currentOwner,
		NewOwner:     a.newOwner, ReleaseFrom: string(a.releaseFrom),
		CapacityReleaseFrom: string(a.capacityReleaseFrom), ReleaseKind: string(a.releaseKind),
	}
}

func (a *ExpandedTargetAggregate) matchesObservation(
	observation ExpandedTargetObservation,
	owner string,
	measured uint64,
	allocated uint64,
	reservationPresent bool,
	targetPresent bool,
) bool {
	lease := a.authority.consume.lease
	return validExpandedTargetObservation(observation) && observation.LeaseID == lease.id &&
		observation.ReceiptToken == a.authority.consume.receiptToken &&
		observation.PlanDigest.Equal(lease.planDigest) && observation.PoolID == lease.pool.id &&
		observation.PoolKind == lease.pool.kind && observation.SourceDigest.Equal(lease.sourceDigest) &&
		observation.SourceBytes == lease.sourceBytes && observation.TargetDigest.Equal(lease.expectedTargetDigest) &&
		observation.ReservedBytes == lease.bytes && observation.ReservedAllocatedBytes == a.authority.consume.receiptAllocatedBytes &&
		observation.TargetKind == a.authority.targetKind &&
		observation.TargetStorageID == a.authority.targetStorageID &&
		observation.TargetRoot == lease.targetRoot &&
		observation.TargetAuthorityDigest.Equal(a.authority.authorityDigest) && observation.Owner == owner &&
		observation.MeasuredBytes == measured && observation.AllocatedBytes == allocated &&
		observation.ReservationPresent == reservationPresent &&
		observation.TargetPresent == targetPresent
}

func (a *ExpandedTargetAggregate) matchesReleasedObservation(observation ExpandedTargetObservation) bool {
	if observation.ReservationPresent || observation.TargetPresent || observation.MeasuredBytes != a.measuredBytes {
		return false
	}
	return a.matchesObservation(observation, a.currentOwner, a.measuredBytes, a.allocatedBytes, false, false) ||
		a.newOwner != "" && a.matchesObservation(observation, a.newOwner, a.measuredBytes, a.allocatedBytes, false, false)
}

func (a *ExpandedTargetAggregate) releaseAuthorizationCompatible(authorization CapacityReleaseAuthorization) bool {
	lease := a.authority.consume.lease
	if !authorization.valid() || !sameExpandedLeaseAuthority(authorization.lease, lease) ||
		a.authority.consume.receiptToken != authorization.receiptToken {
		return false
	}
	if !a.matchesCapacityReleaseHistory(authorization) {
		return false
	}
	if a.state == ExpandedTargetReleasePending || a.state == ExpandedTargetReleased {
		return a.capacityReleaseFrom == authorization.from && a.releaseKind == authorization.kind
	}
	switch authorization.from {
	case LeaseConsumePending:
		return a.state == ExpandedTargetConsumePending || a.state == ExpandedTargetConsumed
	case LeaseConsumed:
		return a.state == ExpandedTargetConsumed
	case LeaseTransferPending:
		return validIdentifier(authorization.newOwner) &&
			(a.state == ExpandedTargetConsumed || a.state == ExpandedTargetTransferPending || a.state == ExpandedTargetTransferred) &&
			(a.newOwner == "" || a.newOwner == authorization.newOwner)
	case LeaseTransferred:
		return a.state == ExpandedTargetTransferred && a.currentOwner == authorization.newOwner &&
			a.newOwner == authorization.newOwner
	case LeaseReservePending, LeaseReserved, LeaseReleasePending, LeaseReleased:
		return false
	default:
		return false
	}
}

func (a *ExpandedTargetAggregate) matchesCapacityReleaseHistory(
	authorization CapacityReleaseAuthorization,
) bool {
	lease := a.authority.consume.lease
	if authorization.from == LeaseConsumePending {
		return authorization.targetDigest.IsZero() && authorization.usageBytes == 0 &&
			authorization.allocatedBytes == 0 && authorization.newOwner == ""
	}
	if !authorization.targetDigest.Equal(lease.expectedTargetDigest) ||
		a.measuredBytes == 0 || authorization.usageBytes != a.measuredBytes ||
		a.allocatedBytes == 0 || authorization.allocatedBytes != a.allocatedBytes {
		return false
	}
	switch authorization.from {
	case LeaseConsumed:
		return authorization.newOwner == ""
	case LeaseTransferPending, LeaseTransferred:
		return validIdentifier(authorization.newOwner) &&
			(a.newOwner == "" || a.newOwner == authorization.newOwner)
	case LeaseReservePending, LeaseReserved, LeaseConsumePending, LeaseReleasePending, LeaseReleased:
		return false
	default:
		return false
	}
}

func sameExpandedLeaseAuthority(left, right CapacityLease) bool {
	return left.id == right.id && left.purpose == right.purpose && left.owner == right.owner &&
		left.artifactID == right.artifactID && left.pool == right.pool && left.bytes == right.bytes &&
		left.planDigest.Equal(right.planDigest) && left.sourceDigest.Equal(right.sourceDigest) &&
		left.sourceBytes == right.sourceBytes && left.expectedTargetDigest.Equal(right.expectedTargetDigest) &&
		left.targetKind == right.targetKind && left.targetStorageID == right.targetStorageID &&
		left.targetAuthorityDigest.Equal(right.targetAuthorityDigest) && left.targetRoot == right.targetRoot
}

func snapshotMatchesExpandedAuthority(snapshot ExpandedTargetSnapshot, authority ExpandedTargetAuthority) bool {
	lease := authority.consume.lease
	return snapshot.SchemaVersion == 1 && snapshot.LeaseID == lease.id &&
		snapshot.ArtifactID == lease.artifactID && snapshot.PlanDigest == lease.planDigest.Hex() &&
		snapshot.PoolID == lease.pool.id && snapshot.PoolKind == lease.pool.kind &&
		snapshot.ReservedBytes == lease.bytes && snapshot.ReservedAllocatedBytes == authority.consume.receiptAllocatedBytes &&
		snapshot.ReceiptToken == authority.consume.receiptToken &&
		snapshot.InitialOwner == lease.owner && snapshot.SourceDigest == lease.sourceDigest.Hex() &&
		snapshot.SourceBytes == lease.sourceBytes && snapshot.TargetDigest == lease.expectedTargetDigest.Hex() &&
		snapshot.TargetKind == authority.targetKind && snapshot.TargetStorageID == authority.targetStorageID &&
		snapshot.TargetRoot == lease.targetRoot &&
		snapshot.TargetAuthorityDigest == authority.authorityDigest.Hex()
}

func (a *ExpandedTargetAggregate) validHistory() bool {
	lease := a.authority.consume.lease
	if a.version > 5 || !validIdentifier(a.currentOwner) || a.measuredBytes > lease.bytes ||
		a.allocatedBytes > a.authority.consume.receiptAllocatedBytes {
		return false
	}
	base := func(state ExpandedTargetState) (uint64, bool) {
		switch state {
		case ExpandedTargetConsumePending:
			return 0, a.measuredBytes == 0 && a.allocatedBytes == 0 && a.currentOwner == lease.owner &&
				(a.state == ExpandedTargetReleasePending || a.state == ExpandedTargetReleased || a.newOwner == "")
		case ExpandedTargetConsumed:
			return 1, a.measuredBytes == lease.bytes && a.allocatedBytes > 0 && a.currentOwner == lease.owner &&
				(a.state == ExpandedTargetReleasePending || a.state == ExpandedTargetReleased || a.newOwner == "")
		case ExpandedTargetTransferPending:
			return 2, a.measuredBytes == lease.bytes && a.allocatedBytes > 0 && a.currentOwner == lease.owner && validIdentifier(a.newOwner)
		case ExpandedTargetTransferred:
			return 3, a.measuredBytes == lease.bytes && a.allocatedBytes > 0 && validIdentifier(a.newOwner) && a.currentOwner == a.newOwner
		case ExpandedTargetReleasePending, ExpandedTargetReleased:
			return 0, false
		default:
			return 0, false
		}
	}
	if a.state != ExpandedTargetReleasePending && a.state != ExpandedTargetReleased {
		expected, ok := base(a.state)
		return ok && a.version == expected && a.releaseFrom == "" && a.capacityReleaseFrom == "" && a.releaseKind == ""
	}
	prior, ok := base(a.releaseFrom)
	if !ok || !releasablePriorState(a.capacityReleaseFrom) || !validCapacityReleaseKind(a.releaseKind) {
		return false
	}
	if a.state == ExpandedTargetReleasePending {
		return a.version == prior+1
	}
	return a.version == prior+2
}
