package artifactacquisition

import (
	"crypto/sha256"
	"encoding/json"
	"sort"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

const aggregateSchemaVersion = uint16(2)

// ReservationProof is a local-filesystem reservation receipt returned by a
// reviewed platform adapter.
type ReservationProof struct {
	id           string
	bytes        uint64
	filesystemID string
}

// NewReservationProof validates a bounded local-filesystem receipt.
func NewReservationProof(id string, bytes uint64, filesystemID string) (ReservationProof, error) {
	if !validIdentifier(id) || bytes == 0 || bytes > maximumSafeBytes || !validIdentifier(filesystemID) {
		return ReservationProof{}, ErrInvalidTransition
	}
	return ReservationProof{id: id, bytes: bytes, filesystemID: filesystemID}, nil
}

// ID returns the opaque reservation identity.
func (p ReservationProof) ID() string { return p.id }

// Bytes returns durably reserved bytes.
func (p ReservationProof) Bytes() uint64 { return p.bytes }

// FilesystemID returns a non-path local filesystem identity.
func (p ReservationProof) FilesystemID() string { return p.filesystemID }

// FinalProof is an exact final content-addressed publication observation.
type FinalProof struct {
	digest     releaseinventory.Digest
	size       uint64
	contentKey string
}

// NewFinalProof validates final digest, size, and canonical key.
func NewFinalProof(digest releaseinventory.Digest, size uint64, contentKey string) (FinalProof, error) {
	if digest.IsZero() || size == 0 || contentKey != contentKeyFor(digest) {
		return FinalProof{}, ErrInvalidTransition
	}
	return FinalProof{digest: digest, size: size, contentKey: contentKey}, nil
}

// Digest returns the final observed digest.
func (p FinalProof) Digest() releaseinventory.Digest { return p.digest }

// Size returns the final observed size.
func (p FinalProof) Size() uint64 { return p.size }

// ContentKey returns the canonical CAS key.
func (p FinalProof) ContentKey() string { return p.contentKey }

// PartialAuthorization is an aggregate-minted token for exactly one owned partial.
type PartialAuthorization struct {
	partialID  string
	artifactID string
	digest     releaseinventory.Digest
	size       uint64
	contentKey string
}

// PartialID returns the opaque owned partial identity.
func (a PartialAuthorization) PartialID() string { return a.partialID }

// ArtifactID returns the signed logical artifact identity.
func (a PartialAuthorization) ArtifactID() string { return a.artifactID }

// Digest returns the expected final digest.
func (a PartialAuthorization) Digest() releaseinventory.Digest { return a.digest }

// Size returns the expected final size.
func (a PartialAuthorization) Size() uint64 { return a.size }

// ContentKey returns the canonical final CAS key.
func (a PartialAuthorization) ContentKey() string { return a.contentKey }

// Valid reports whether the unforgeable token is structurally complete.
func (a PartialAuthorization) Valid() bool {
	return validIdentifier(a.partialID) && validIdentifier(a.artifactID) && !a.digest.IsZero() &&
		a.size > 0 && a.contentKey == contentKeyFor(a.digest)
}

// ProgressSnapshot is one artifact's authenticated resumable state.
type ProgressSnapshot struct {
	ArtifactID          string
	ArtifactDigest      string
	PartialID           string
	VerifiedChunks      []uint32
	ReservationConsumed bool
	Completed           bool
}

// Snapshot is the complete plan-bound acquisition aggregate.
type Snapshot struct {
	SchemaVersion uint16
	OperationID   string
	PlanDigest    string
	Version       uint64
	ReservationID string
	ReservedBytes uint64
	FilesystemID  string
	ReleaseState  string
	ReleaseReason string
	Progress      []ProgressSnapshot
}

type progress struct {
	artifactID          string
	digest              releaseinventory.Digest
	partialID           string
	verified            map[uint32]struct{}
	reservationConsumed bool
	completed           bool
}

// Aggregate is the authenticated reservation/acquisition state machine.
type Aggregate struct {
	operationID   string
	plan          Plan
	version       uint64
	reservation   ReservationProof
	releaseState  string
	releaseReason ReleaseReason
	progress      map[string]progress
}

// NewAggregate creates an unreserved plan-bound operation.
func NewAggregate(operationID string, plan Plan) (*Aggregate, error) {
	if !validIdentifier(operationID) || plan.digest.IsZero() || len(plan.artifacts) == 0 {
		return nil, ErrInvalidPlan
	}
	return &Aggregate{operationID: operationID, plan: plan, progress: make(map[string]progress)}, nil
}

// Restore verifies authenticated state against the exact signed plan.
func Restore(plan Plan, snapshot Snapshot) (*Aggregate, error) {
	if snapshot.SchemaVersion != aggregateSchemaVersion || snapshot.PlanDigest != plan.digest.Hex() ||
		!validIdentifier(snapshot.OperationID) || len(snapshot.Progress) > len(plan.artifacts) {
		return nil, ErrIntegrity
	}
	aggregate, err := NewAggregate(snapshot.OperationID, plan)
	if err != nil {
		return nil, ErrIntegrity
	}
	aggregate.version = snapshot.Version
	if snapshot.ReservationID != "" || snapshot.ReservedBytes != 0 || snapshot.FilesystemID != "" {
		expectedID, idError := plan.ReservationID(snapshot.OperationID)
		if idError != nil || !validIdentifier(snapshot.ReservationID) || snapshot.ReservationID != expectedID ||
			snapshot.ReservedBytes != plan.totals.download ||
			(snapshot.FilesystemID != "" && !validIdentifier(snapshot.FilesystemID)) {
			return nil, ErrIntegrity
		}
		aggregate.reservation = ReservationProof{
			id: snapshot.ReservationID, bytes: snapshot.ReservedBytes, filesystemID: snapshot.FilesystemID,
		}
		aggregate.releaseState = snapshot.ReleaseState
		aggregate.releaseReason = ReleaseReason(snapshot.ReleaseReason)
	}
	if aggregate.reservation.id == "" {
		if snapshot.ReleaseState != "" || snapshot.ReleaseReason != "" {
			return nil, ErrIntegrity
		}
	} else {
		switch aggregate.releaseState {
		case releaseStateAllocating:
			if aggregate.releaseReason != "" || aggregate.reservation.filesystemID != "" {
				return nil, ErrIntegrity
			}
		case releaseStateActive:
			if aggregate.releaseReason != "" || aggregate.reservation.filesystemID == "" {
				return nil, ErrIntegrity
			}
		case releaseStatePending, releaseStateReleased:
			if !validReleaseReason(aggregate.releaseReason) {
				return nil, ErrIntegrity
			}
		default:
			return nil, ErrIntegrity
		}
	}
	minimumVersion := uint64(0)
	if aggregate.ReservationRequested() {
		minimumVersion++
		if aggregate.Reserved() {
			minimumVersion++
		}
	}
	for _, persisted := range snapshot.Progress {
		artifact, exists := plan.Artifact(persisted.ArtifactID)
		digest, parseError := releaseinventory.ParseDigest(persisted.ArtifactDigest)
		if !exists || parseError != nil || !digest.Equal(artifact.digest) || !validIdentifier(persisted.PartialID) {
			return nil, ErrIntegrity
		}
		if _, duplicate := aggregate.progress[persisted.ArtifactID]; duplicate {
			return nil, ErrIntegrity
		}
		expectedPartial := partialID(snapshot.OperationID, plan.digest, artifact)
		if persisted.PartialID != expectedPartial || len(persisted.VerifiedChunks) > len(artifact.chunks) {
			return nil, ErrIntegrity
		}
		verified := make(map[uint32]struct{}, len(persisted.VerifiedChunks))
		for position, index := range persisted.VerifiedChunks {
			if int(index) >= len(artifact.chunks) || index != uint32(position) {
				return nil, ErrIntegrity
			}
			if _, duplicate := verified[index]; duplicate {
				return nil, ErrIntegrity
			}
			verified[index] = struct{}{}
		}
		if persisted.Completed && (!persisted.ReservationConsumed || len(verified) != len(artifact.chunks)) {
			return nil, ErrIntegrity
		}
		aggregate.progress[persisted.ArtifactID] = progress{
			artifactID: persisted.ArtifactID, digest: digest, partialID: persisted.PartialID,
			verified: verified, reservationConsumed: persisted.ReservationConsumed, completed: persisted.Completed,
		}
		minimumVersion += 1 + uint64(len(verified))
		if persisted.ReservationConsumed {
			minimumVersion++
		}
		if persisted.Completed {
			minimumVersion++
		}
	}
	if aggregate.releaseState == releaseStatePending || aggregate.releaseState == releaseStateReleased {
		minimumVersion++
		if aggregate.releaseReason == ReleaseReasonCompleted {
			if len(aggregate.progress) != len(plan.artifacts) {
				return nil, ErrIntegrity
			}
			for _, artifact := range plan.artifacts {
				if !aggregate.ArtifactCompleted(artifact) {
					return nil, ErrIntegrity
				}
			}
		}
	}
	if aggregate.releaseState == releaseStateReleased {
		minimumVersion++
	}
	if snapshot.Version < minimumVersion || (!aggregate.Reserved() && len(snapshot.Progress) != 0) {
		return nil, ErrIntegrity
	}
	return aggregate, nil
}

// Version returns the optimistic concurrency token.
func (a *Aggregate) Version() uint64 { return a.version }

// OperationID returns the stable operation identity.
func (a *Aggregate) OperationID() string { return a.operationID }

// ReservationRequested reports whether allocation intent is durable.
func (a *Aggregate) ReservationRequested() bool { return a.reservation.id != "" }

// Reserved reports whether exact required local capacity was recorded.
func (a *Aggregate) Reserved() bool {
	return a.reservation.id != "" && a.reservation.filesystemID != ""
}

// ReservationActive reports that exact capacity remains owned and no release
// intent has been recorded. A stored proof alone is insufficient because
// released aggregates retain their immutable receipt for audit/replay.
func (a *Aggregate) ReservationActive() bool {
	return a.Reserved() && a.releaseState == releaseStateActive
}

// Reservation returns the recorded proof when present.
func (a *Aggregate) Reservation() (ReservationProof, bool) {
	return a.reservation, a.Reserved()
}

// RecordReservation binds exact plan capacity before any artifact can begin.
func (a *Aggregate) RecordReservation(proof ReservationProof) (bool, error) {
	expectedID, _ := a.plan.ReservationID(a.operationID)
	if proof.id != expectedID || proof.bytes != a.plan.totals.download || proof.filesystemID == "" {
		return false, ErrInvalidTransition
	}
	if a.Reserved() {
		if a.reservation != proof {
			return false, ErrInvalidTransition
		}
		return false, nil
	}
	if a.releaseState != releaseStateAllocating || a.reservation.id != proof.id || a.reservation.bytes != proof.bytes {
		return false, ErrInvalidTransition
	}
	a.reservation = proof
	a.releaseState = releaseStateActive
	a.version++
	return true, nil
}

// BeginArtifact durably establishes partial ownership before filesystem/network access.
func (a *Aggregate) BeginArtifact(artifact Artifact) (bool, error) {
	expected, exists := a.plan.Artifact(artifact.id)
	if !a.Reserved() || a.releaseState != releaseStateActive || !exists || !sameArtifact(expected, artifact) {
		return false, ErrInvalidTransition
	}
	if existing, exists := a.progress[artifact.id]; exists {
		if !existing.digest.Equal(artifact.digest) || existing.partialID != partialID(a.operationID, a.plan.digest, artifact) {
			return false, ErrIntegrity
		}
		return false, nil
	}
	a.progress[artifact.id] = progress{
		artifactID: artifact.id, digest: artifact.digest, partialID: partialID(a.operationID, a.plan.digest, artifact),
		verified: make(map[uint32]struct{}),
	}
	a.version++
	return true, nil
}

// ChunkVerified reports authenticated retained-chunk state.
func (a *Aggregate) ChunkVerified(artifact Artifact, chunk Chunk) bool {
	progress, exists := a.progress[artifact.id]
	if !exists || !progress.digest.Equal(artifact.digest) || int(chunk.index) >= len(artifact.chunks) {
		return false
	}
	_, exists = progress.verified[chunk.index]
	return exists
}

// MarkChunkVerified records only the exact signed chunk.
func (a *Aggregate) MarkChunkVerified(artifact Artifact, chunk Chunk, observed releaseinventory.Digest) (bool, error) {
	progress, exists := a.progress[artifact.id]
	if !exists || a.releaseState != releaseStateActive || progress.completed || int(chunk.index) >= len(artifact.chunks) ||
		artifact.chunks[chunk.index] != chunk || !observed.Equal(chunk.digest) {
		return false, ErrInvalidTransition
	}
	if _, exists := progress.verified[chunk.index]; exists {
		return false, nil
	}
	if len(progress.verified) != int(chunk.index) {
		return false, ErrInvalidTransition
	}
	progress.verified[chunk.index] = struct{}{}
	a.progress[artifact.id] = progress
	a.version++
	return true, nil
}

// InvalidateChunk removes stale retained evidence before a replacement fetch.
func (a *Aggregate) InvalidateChunk(artifact Artifact, chunk Chunk) (bool, error) {
	progress, exists := a.progress[artifact.id]
	if !exists || a.releaseState != releaseStateActive || progress.completed || int(chunk.index) >= len(artifact.chunks) || artifact.chunks[chunk.index] != chunk {
		return false, ErrInvalidTransition
	}
	if _, exists := progress.verified[chunk.index]; !exists {
		return false, nil
	}
	for index := range progress.verified {
		if index >= chunk.index {
			delete(progress.verified, index)
		}
	}
	a.progress[artifact.id] = progress
	a.version++
	return true, nil
}

// AuthorizePartial mints exact owned-partial authority.
func (a *Aggregate) AuthorizePartial(artifact Artifact) (PartialAuthorization, error) {
	progress, exists := a.progress[artifact.id]
	if !exists || a.releaseState != releaseStateActive || !progress.digest.Equal(artifact.digest) || progress.partialID != partialID(a.operationID, a.plan.digest, artifact) {
		return PartialAuthorization{}, ErrUnauthorizedPartial
	}
	return PartialAuthorization{partialID: progress.partialID, artifactID: artifact.id, digest: artifact.digest, size: artifact.size, contentKey: artifact.ContentKey()}, nil
}

// ResetInvalidPartial clears stale chunk evidence only after the adapter has
// securely reinitialized the same fully allocated owned partial. Ownership and
// consumed-capacity accounting are retained so retry cannot allocate outside
// the reservation.
func (a *Aggregate) ResetInvalidPartial(authorization PartialAuthorization) error {
	if !authorization.Valid() {
		return ErrUnauthorizedPartial
	}
	progress, exists := a.progress[authorization.artifactID]
	if !exists || a.releaseState != releaseStateActive || progress.completed || progress.partialID != authorization.partialID ||
		!progress.digest.Equal(authorization.digest) || !progress.reservationConsumed {
		return ErrUnauthorizedPartial
	}
	progress.verified = make(map[uint32]struct{})
	a.progress[authorization.artifactID] = progress
	a.version++
	return nil
}

// CompleteArtifact records exact final content only after every signed chunk.
func (a *Aggregate) CompleteArtifact(artifact Artifact, proof FinalProof) (bool, error) {
	progress, exists := a.progress[artifact.id]
	if !exists || a.releaseState != releaseStateActive || !progress.reservationConsumed || !progress.digest.Equal(artifact.digest) || !proof.digest.Equal(artifact.digest) || proof.size != artifact.size ||
		proof.contentKey != artifact.ContentKey() || len(progress.verified) != len(artifact.chunks) {
		return false, ErrInvalidTransition
	}
	if progress.completed {
		return false, nil
	}
	progress.completed = true
	a.progress[artifact.id] = progress
	a.version++
	return true, nil
}

// ArtifactCompleted reports exact final state.
func (a *Aggregate) ArtifactCompleted(artifact Artifact) bool {
	progress, exists := a.progress[artifact.id]
	return exists && progress.completed && progress.digest.Equal(artifact.digest)
}

// Snapshot returns deterministic immutable authenticated state.
func (a *Aggregate) Snapshot() Snapshot {
	result := Snapshot{SchemaVersion: aggregateSchemaVersion, OperationID: a.operationID, PlanDigest: a.plan.digest.Hex(), Version: a.version}
	if a.ReservationRequested() {
		result.ReservationID, result.ReservedBytes, result.FilesystemID = a.reservation.id, a.reservation.bytes, a.reservation.filesystemID
		result.ReleaseState, result.ReleaseReason = a.releaseState, string(a.releaseReason)
	}
	ids := make([]string, 0, len(a.progress))
	for id := range a.progress {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result.Progress = make([]ProgressSnapshot, 0, len(ids))
	for _, id := range ids {
		entry := a.progress[id]
		verified := make([]uint32, 0, len(entry.verified))
		for index := range entry.verified {
			verified = append(verified, index)
		}
		sort.Slice(verified, func(left, right int) bool { return verified[left] < verified[right] })
		result.Progress = append(result.Progress, ProgressSnapshot{
			ArtifactID: entry.artifactID, ArtifactDigest: entry.digest.Hex(), PartialID: entry.partialID,
			VerifiedChunks: verified, ReservationConsumed: entry.reservationConsumed, Completed: entry.completed,
		})
	}
	return result
}

// EvidenceDigest binds the complete deterministic aggregate snapshot. It is
// safe to expose across an application boundary because it contains no raw
// paths, source URLs, or reservation identifiers.
func (a *Aggregate) EvidenceDigest() releaseinventory.Digest {
	payload, err := json.Marshal(a.Snapshot())
	if err != nil {
		return releaseinventory.Digest{}
	}
	return releaseinventory.DigestBytes(payload)
}

func partialID(operationID string, planDigest releaseinventory.Digest, artifact Artifact) string {
	digest := sha256.Sum256([]byte("partial\x00" + operationID + "\x00" + planDigest.Hex() + "\x00" + artifact.digest.Hex()))
	return "p-" + releaseinventory.Digest(digest).Hex()
}

func contentKeyFor(digest releaseinventory.Digest) string {
	if digest.IsZero() {
		return ""
	}
	hexDigest := digest.Hex()
	return "sha256/" + hexDigest[:2] + "/" + hexDigest
}

func sameArtifact(left Artifact, right Artifact) bool {
	return left.id == right.id && left.digest.Equal(right.digest) && left.size == right.size &&
		left.expandedBytes == right.expandedBytes && len(left.chunks) == len(right.chunks)
}
