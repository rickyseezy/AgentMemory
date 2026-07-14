package artifactacquisition

import "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"

const (
	releaseStateAllocating = "allocating"
	releaseStateActive     = "active"
	releaseStatePending    = "pending"
	releaseStateReleased   = "released"
)

// ReservationAuthorization is journal-backed authority to create exactly the
// plan-bound headroom and artifact capacity slots.
type ReservationAuthorization struct {
	reservationID string
	planDigest    releaseinventory.Digest
	requiredBytes uint64
	allocations   []ReservationAllocation
}

// ReservationID returns the exact plan-and-operation reservation identity.
func (a ReservationAuthorization) ReservationID() string { return a.reservationID }

// PlanDigest returns the exact signed acquisition plan binding.
func (a ReservationAuthorization) PlanDigest() releaseinventory.Digest { return a.planDigest }

// RequiredBytes returns the exact signed total capacity.
func (a ReservationAuthorization) RequiredBytes() uint64 { return a.requiredBytes }

// Allocations returns defensive copies of the artifact capacity layout.
func (a ReservationAuthorization) Allocations() []ReservationAllocation {
	return append([]ReservationAllocation(nil), a.allocations...)
}

// Valid reports whether the authorization is structurally complete.
func (a ReservationAuthorization) Valid() bool {
	if !validIdentifier(a.reservationID) || a.planDigest.IsZero() || a.requiredBytes == 0 ||
		a.requiredBytes > maximumSafeBytes || len(a.allocations) == 0 {
		return false
	}
	var download uint64
	for _, allocation := range a.allocations {
		if !allocation.Valid() || allocation.reservationID != a.reservationID || ^uint64(0)-download < allocation.bytes {
			return false
		}
		download += allocation.bytes
	}
	return download == a.requiredBytes
}

// ReleaseReason is the closed durable reason for relinquishing capacity.
type ReleaseReason string

const (
	// ReleaseReasonCompleted settles capacity after every final object is verified.
	ReleaseReasonCompleted ReleaseReason = "completed"
	// ReleaseReasonCancelled removes owned staging bytes after explicit cancellation.
	ReleaseReasonCancelled ReleaseReason = "cancelled"
	// ReleaseReasonRollback removes owned staging bytes during saga compensation.
	ReleaseReasonRollback ReleaseReason = "rollback"
)

func validReleaseReason(reason ReleaseReason) bool {
	return reason == ReleaseReasonCompleted || reason == ReleaseReasonCancelled || reason == ReleaseReasonRollback
}

// ReservationAllocation is one deterministic artifact-sized capacity slot.
// Its fields are private so only a plan-bound aggregate can authorize mutation.
type ReservationAllocation struct {
	reservationID string
	slotID        string
	partialID     string
	artifactID    string
	bytes         uint64
}

// ReservationStage describes the only filesystem layouts that may exist at a
// durable aggregate boundary. Pending stages deliberately admit both sides of
// one no-replace rename so a crash can be replayed without manufacturing
// capacity.
type ReservationStage string

// Closed physical reservation layouts understood by crash reconciliation.
const (
	ReservationStageSlot            ReservationStage = "slot"
	ReservationStageTransferPending ReservationStage = "transfer-pending"
	ReservationStageFinalizePending ReservationStage = "finalize-pending"
	ReservationStageFinal           ReservationStage = "final"
)

func validReservationStage(stage ReservationStage) bool {
	return stage == ReservationStageSlot || stage == ReservationStageTransferPending ||
		stage == ReservationStageFinalizePending || stage == ReservationStageFinal
}

// ReservationExpectation binds one plan artifact to its crash-recoverable
// physical-capacity layout. Private fields keep adapters from minting
// authority independently of authenticated aggregate state.
type ReservationExpectation struct {
	allocation ReservationAllocation
	artifact   Artifact
	stage      ReservationStage
}

// Allocation returns the exact operation-owned slot/partial identities.
func (e ReservationExpectation) Allocation() ReservationAllocation { return e.allocation }

// Artifact returns the exact signed artifact and final CAS identity.
func (e ReservationExpectation) Artifact() Artifact { return e.artifact }

// Stage returns the only allowed crash-recoverable layout class.
func (e ReservationExpectation) Stage() ReservationStage { return e.stage }

// Valid reports whether the expectation is plan- and allocation-consistent.
func (e ReservationExpectation) Valid() bool {
	return e.allocation.Valid() && validReservationStage(e.stage) &&
		e.allocation.artifactID == e.artifact.id && e.allocation.bytes == e.artifact.size &&
		!e.artifact.digest.IsZero() && e.artifact.ContentKey() == contentKeyFor(e.artifact.digest)
}

// ReservationRevalidationAuthorization is journal-backed authority to inspect
// (never create or repair) every byte that remains owned after a crash.
type ReservationRevalidationAuthorization struct {
	reservation  ReservationProof
	expectations []ReservationExpectation
}

// Reservation returns the immutable receipt that the adapter must reproduce.
func (a ReservationRevalidationAuthorization) Reservation() ReservationProof { return a.reservation }

// Expectations returns a defensive copy of every artifact layout.
func (a ReservationRevalidationAuthorization) Expectations() []ReservationExpectation {
	return append([]ReservationExpectation(nil), a.expectations...)
}

// Valid reports whether the authorization accounts for the exact reservation.
func (a ReservationRevalidationAuthorization) Valid() bool {
	if !validIdentifier(a.reservation.id) || !validIdentifier(a.reservation.filesystemID) ||
		a.reservation.bytes == 0 || a.reservation.bytes > maximumSafeBytes ||
		len(a.expectations) == 0 || len(a.expectations) > 4096 {
		return false
	}
	seen := make(map[string]struct{}, len(a.expectations))
	var total uint64
	for _, expectation := range a.expectations {
		if !expectation.Valid() || expectation.allocation.reservationID != a.reservation.id ||
			^uint64(0)-total < expectation.allocation.bytes {
			return false
		}
		if _, exists := seen[expectation.artifact.id]; exists {
			return false
		}
		seen[expectation.artifact.id] = struct{}{}
		total += expectation.allocation.bytes
	}
	return total == a.reservation.bytes
}

// ReservationID returns the exact plan-and-operation reservation identity.
func (a ReservationAllocation) ReservationID() string { return a.reservationID }

// SlotID returns the opaque reservation slot identity.
func (a ReservationAllocation) SlotID() string { return a.slotID }

// PartialID returns the exact aggregate-owned partial identity.
func (a ReservationAllocation) PartialID() string { return a.partialID }

// ArtifactID returns the signed logical artifact identity.
func (a ReservationAllocation) ArtifactID() string { return a.artifactID }

// Bytes returns the exact preallocated artifact size.
func (a ReservationAllocation) Bytes() uint64 { return a.bytes }

// Valid reports whether the allocation has a canonical aggregate derivation shape.
func (a ReservationAllocation) Valid() bool {
	return validIdentifier(a.reservationID) && validIdentifier(a.slotID) && validIdentifier(a.partialID) &&
		validIdentifier(a.artifactID) && a.bytes > 0 && a.bytes <= maximumSafeBytes
}

// ConsumptionAuthorization authorizes one atomic slot-to-partial transfer.
type ConsumptionAuthorization struct {
	allocation   ReservationAllocation
	filesystemID string
}

// ReservationID returns the exact reservation identity.
func (a ConsumptionAuthorization) ReservationID() string { return a.allocation.reservationID }

// SlotID returns the exact owned capacity slot identity.
func (a ConsumptionAuthorization) SlotID() string { return a.allocation.slotID }

// PartialID returns the exact owned destination partial identity.
func (a ConsumptionAuthorization) PartialID() string { return a.allocation.partialID }

// ArtifactID returns the signed artifact identity.
func (a ConsumptionAuthorization) ArtifactID() string { return a.allocation.artifactID }

// Bytes returns the exact number of transferred allocated bytes.
func (a ConsumptionAuthorization) Bytes() uint64 { return a.allocation.bytes }

// FilesystemID returns the reservation/content-store filesystem binding.
func (a ConsumptionAuthorization) FilesystemID() string { return a.filesystemID }

// Valid reports whether this authorization is structurally complete.
func (a ConsumptionAuthorization) Valid() bool {
	return a.allocation.Valid() && validIdentifier(a.filesystemID)
}

// ConsumptionProof is the adapter's exact observation of a completed transfer.
type ConsumptionProof struct {
	reservationID string
	partialID     string
	bytes         uint64
	filesystemID  string
}

// NewConsumptionProof validates an exact filesystem-bound transfer receipt.
func NewConsumptionProof(reservationID, partialID string, bytes uint64, filesystemID string) (ConsumptionProof, error) {
	if !validIdentifier(reservationID) || !validIdentifier(partialID) || bytes == 0 || bytes > maximumSafeBytes ||
		!validIdentifier(filesystemID) {
		return ConsumptionProof{}, ErrInvalidTransition
	}
	return ConsumptionProof{reservationID: reservationID, partialID: partialID, bytes: bytes, filesystemID: filesystemID}, nil
}

// ReservationID returns the observed reservation identity.
func (p ConsumptionProof) ReservationID() string { return p.reservationID }

// PartialID returns the observed destination partial identity.
func (p ConsumptionProof) PartialID() string { return p.partialID }

// Bytes returns the observed transferred allocation.
func (p ConsumptionProof) Bytes() uint64 { return p.bytes }

// FilesystemID returns the observed local filesystem identity.
func (p ConsumptionProof) FilesystemID() string { return p.filesystemID }

// ReleaseAuthorization is the journal-backed authority to remove every
// remaining owned reservation slot, owned partial, and headroom file.
type ReleaseAuthorization struct {
	reservation ReservationProof
	reason      ReleaseReason
	allocations []ReservationAllocation
}

// Committed reports whether a complete filesystem proof was journaled before release.
func (a ReleaseAuthorization) Committed() bool { return a.reservation.filesystemID != "" }

// Reservation returns the exact reservation receipt being released.
func (a ReleaseAuthorization) Reservation() ReservationProof { return a.reservation }

// Reason returns the closed release reason.
func (a ReleaseAuthorization) Reason() ReleaseReason { return a.reason }

// Allocations returns defensive copies of every owned slot/partial identity.
func (a ReleaseAuthorization) Allocations() []ReservationAllocation {
	return append([]ReservationAllocation(nil), a.allocations...)
}

// Valid reports whether the release authority is complete.
func (a ReleaseAuthorization) Valid() bool {
	if !validIdentifier(a.reservation.id) || a.reservation.bytes == 0 || a.reservation.bytes > maximumSafeBytes ||
		(a.reservation.filesystemID != "" && !validIdentifier(a.reservation.filesystemID)) ||
		!validReleaseReason(a.reason) || len(a.allocations) == 0 {
		return false
	}
	var total uint64
	for _, allocation := range a.allocations {
		if !allocation.Valid() || allocation.reservationID != a.reservation.id || ^uint64(0)-total < allocation.bytes {
			return false
		}
		total += allocation.bytes
	}
	return total <= a.reservation.bytes
}

// RequestReservation durably records exact allocation intent before the
// filesystem adapter can create any slot or headroom file.
func (a *Aggregate) RequestReservation() (bool, error) {
	if a.ReservationRequested() {
		if a.releaseState == releaseStateAllocating {
			return false, nil
		}
		return false, ErrInvalidTransition
	}
	if a.releaseState != "" || len(a.progress) != 0 {
		return false, ErrIntegrity
	}
	reservationID, err := a.plan.ReservationID(a.operationID)
	if err != nil {
		return false, ErrInvalidTransition
	}
	a.reservation = ReservationProof{id: reservationID, bytes: a.plan.totals.download}
	a.releaseState = releaseStateAllocating
	a.version++
	return true, nil
}

// AuthorizeReservation returns allocation authority only while the durable
// intent is awaiting a complete filesystem proof.
func (a *Aggregate) AuthorizeReservation() (ReservationAuthorization, error) {
	if a.releaseState != releaseStateAllocating || !a.ReservationRequested() || a.Reserved() {
		return ReservationAuthorization{}, ErrInvalidTransition
	}
	return a.reservationAuthorization()
}

// AuthorizeReservationRevalidation permits read-only physical proof throughout
// acquisition. Unlike Reserve, it cannot recreate a missing slot or headroom
// file and therefore remains safe after progress starts.
func (a *Aggregate) AuthorizeReservationRevalidation() (ReservationRevalidationAuthorization, error) {
	if a.releaseState != releaseStateActive || !a.Reserved() {
		return ReservationRevalidationAuthorization{}, ErrInvalidTransition
	}
	expectations := make([]ReservationExpectation, 0, len(a.plan.artifacts))
	var download uint64
	for _, artifact := range a.plan.artifacts {
		allocation := allocationFor(a.reservation.id, a.operationID, a.plan.digest, artifact)
		stage := ReservationStageSlot
		if current, exists := a.progress[artifact.id]; exists {
			switch {
			case current.completed:
				stage = ReservationStageFinal
			case current.reservationConsumed:
				stage = ReservationStageFinalizePending
			default:
				stage = ReservationStageTransferPending
			}
		}
		if ^uint64(0)-download < allocation.bytes {
			return ReservationRevalidationAuthorization{}, ErrIntegrity
		}
		download += allocation.bytes
		expectations = append(expectations, ReservationExpectation{allocation: allocation, artifact: artifact, stage: stage})
	}
	if download != a.reservation.bytes {
		return ReservationRevalidationAuthorization{}, ErrIntegrity
	}
	authorization := ReservationRevalidationAuthorization{reservation: a.reservation, expectations: expectations}
	if !authorization.Valid() {
		return ReservationRevalidationAuthorization{}, ErrIntegrity
	}
	return authorization, nil
}

func (a *Aggregate) reservationAuthorization() (ReservationAuthorization, error) {
	authorization := ReservationAuthorization{
		reservationID: a.reservation.id, planDigest: a.plan.digest, requiredBytes: a.reservation.bytes,
		allocations: a.ReservationAllocations(),
	}
	if !authorization.Valid() {
		return ReservationAuthorization{}, ErrIntegrity
	}
	return authorization, nil
}

// ReservationAllocations returns the complete deterministic download-capacity
// layout used by the filesystem adapter before any network access.
func (a *Aggregate) ReservationAllocations() []ReservationAllocation {
	reservationID, err := a.plan.ReservationID(a.operationID)
	if err != nil {
		return nil
	}
	result := make([]ReservationAllocation, 0, len(a.plan.artifacts))
	for _, artifact := range a.plan.artifacts {
		result = append(result, allocationFor(reservationID, a.operationID, a.plan.digest, artifact))
	}
	return result
}

// AuthorizeConsumption mints slot-transfer authority only after partial
// ownership has been durably established and while release is not pending.
func (a *Aggregate) AuthorizeConsumption(artifact Artifact) (ConsumptionAuthorization, error) {
	progress, exists := a.progress[artifact.id]
	if !exists || a.releaseState != releaseStateActive || progress.completed || !progress.digest.Equal(artifact.digest) {
		return ConsumptionAuthorization{}, ErrInvalidTransition
	}
	allocation := allocationFor(a.reservation.id, a.operationID, a.plan.digest, artifact)
	if progress.partialID != allocation.partialID || a.reservation.filesystemID == "" {
		return ConsumptionAuthorization{}, ErrIntegrity
	}
	return ConsumptionAuthorization{allocation: allocation, filesystemID: a.reservation.filesystemID}, nil
}

// RecordConsumption binds an exact adapter proof to the aggregate journal.
func (a *Aggregate) RecordConsumption(authorization ConsumptionAuthorization, proof ConsumptionProof) (bool, error) {
	progress, exists := a.progress[authorization.ArtifactID()]
	if !exists || a.releaseState != releaseStateActive || !authorization.Valid() || progress.completed ||
		authorization.ReservationID() != a.reservation.id || authorization.FilesystemID() != a.reservation.filesystemID ||
		proof.reservationID != authorization.ReservationID() || proof.partialID != authorization.PartialID() ||
		proof.bytes != authorization.Bytes() || proof.filesystemID != authorization.FilesystemID() ||
		progress.partialID != authorization.PartialID() {
		return false, ErrInvalidTransition
	}
	if progress.reservationConsumed {
		return false, nil
	}
	progress.reservationConsumed = true
	a.progress[authorization.ArtifactID()] = progress
	a.version++
	return true, nil
}

// ReservationConsumed reports durable per-artifact capacity consumption.
func (a *Aggregate) ReservationConsumed(artifact Artifact) bool {
	entry, exists := a.progress[artifact.id]
	return exists && entry.reservationConsumed && entry.digest.Equal(artifact.digest)
}

// RequestReservationRelease durably authorizes cleanup before the adapter is
// invoked. Completed release requires every planned final to be recorded.
func (a *Aggregate) RequestReservationRelease(reason ReleaseReason) (bool, error) {
	if !validReleaseReason(reason) || !a.ReservationRequested() {
		return false, ErrInvalidTransition
	}
	if a.releaseState == releaseStatePending || a.releaseState == releaseStateReleased {
		if a.releaseReason != reason {
			return false, ErrInvalidTransition
		}
		return false, nil
	}
	if a.releaseState != releaseStateActive && a.releaseState != releaseStateAllocating {
		return false, ErrIntegrity
	}
	if reason == ReleaseReasonCompleted {
		if !a.Reserved() {
			return false, ErrInvalidTransition
		}
		if len(a.progress) != len(a.plan.artifacts) {
			return false, ErrInvalidTransition
		}
		for _, artifact := range a.plan.artifacts {
			if !a.ArtifactCompleted(artifact) {
				return false, ErrInvalidTransition
			}
		}
	}
	a.releaseState, a.releaseReason = releaseStatePending, reason
	a.version++
	return true, nil
}

// AuthorizeRelease returns exact cleanup authority only for journal-pending release.
func (a *Aggregate) AuthorizeRelease() (ReleaseAuthorization, error) {
	if a.releaseState != releaseStatePending || !validReleaseReason(a.releaseReason) {
		return ReleaseAuthorization{}, ErrInvalidTransition
	}
	authorization := ReleaseAuthorization{
		reservation: a.reservation, reason: a.releaseReason, allocations: a.ReservationAllocations(),
	}
	if !authorization.Valid() {
		return ReleaseAuthorization{}, ErrIntegrity
	}
	return authorization, nil
}

// RecordReleased confirms that the authorized cleanup completed durably.
func (a *Aggregate) RecordReleased(authorization ReleaseAuthorization) (bool, error) {
	if a.releaseState == releaseStateReleased {
		if sameReleaseAuthorization(authorization, a.reservation, a.releaseReason, a.ReservationAllocations()) {
			return false, nil
		}
		return false, ErrInvalidTransition
	}
	if a.releaseState != releaseStatePending ||
		!sameReleaseAuthorization(authorization, a.reservation, a.releaseReason, a.ReservationAllocations()) {
		return false, ErrInvalidTransition
	}
	a.releaseState = releaseStateReleased
	a.version++
	return true, nil
}

// ReservationReleasePending reports a durable release intent awaiting cleanup.
func (a *Aggregate) ReservationReleasePending() bool { return a.releaseState == releaseStatePending }

// ReservationReleased reports complete durable reservation cleanup.
func (a *Aggregate) ReservationReleased() bool { return a.releaseState == releaseStateReleased }

// ReservationReleaseReason returns the closed reason when release was requested.
func (a *Aggregate) ReservationReleaseReason() ReleaseReason { return a.releaseReason }

func allocationFor(reservationID, operationID string, planDigest releaseinventory.Digest, artifact Artifact) ReservationAllocation {
	partial := partialID(operationID, planDigest, artifact)
	slotDigest := releaseinventory.DigestBytes([]byte("reservation-slot\x00" + reservationID + "\x00" + artifact.digest.Hex()))
	return ReservationAllocation{
		reservationID: reservationID, slotID: "s-" + slotDigest.Hex(), partialID: partial,
		artifactID: artifact.id, bytes: artifact.size,
	}
}

func sameReleaseAuthorization(
	authorization ReleaseAuthorization,
	reservation ReservationProof,
	reason ReleaseReason,
	allocations []ReservationAllocation,
) bool {
	if !authorization.Valid() || authorization.reservation != reservation || authorization.reason != reason ||
		len(authorization.allocations) != len(allocations) {
		return false
	}
	for index := range allocations {
		if authorization.allocations[index] != allocations[index] {
			return false
		}
	}
	return true
}
