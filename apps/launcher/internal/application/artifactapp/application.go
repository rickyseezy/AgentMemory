package artifactapp

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

const reservationFinalizationTimeout = 15 * time.Second

// Dependencies are mandatory narrow clean-architecture boundaries.
type Dependencies struct {
	Repository  Repository
	Reservation ReservationPort
	Fetcher     Fetcher
	Store       Store
}

// Application coordinates exact capacity and verified acquisition.
type Application struct {
	repository  Repository
	reservation ReservationPort
	fetcher     Fetcher
	store       Store
}

// New rejects absent and typed-nil capabilities.
func New(dependencies Dependencies) (*Application, error) {
	if nilDependency(dependencies.Repository) || nilDependency(dependencies.Reservation) ||
		nilDependency(dependencies.Fetcher) || nilDependency(dependencies.Store) {
		return nil, appError(ErrorInvalidCommand, "configure")
	}
	return &Application{repository: dependencies.Repository, reservation: dependencies.Reservation, fetcher: dependencies.Fetcher, store: dependencies.Store}, nil
}

// Command binds one operation to one already verified signed plan.
type Command struct {
	OperationID string
	Plan        artifactacquisition.Plan
}

// ReserveResult reports durable reservation state.
type ReserveResult struct {
	Version       uint64
	ReservationID string
	ReservedBytes uint64
	Reused        bool
	// AggregateEvidence binds the exact durable reservation aggregate.
	AggregateEvidence releaseinventory.Digest
}

// AcquireResult reports only bounded counts and aggregate version.
type AcquireResult struct {
	Version            uint64
	CompletedArtifacts uint32
	DownloadedChunks   uint32
	RecoveredChunks    uint32
	// AggregateEvidence binds the exact fully verified durable aggregate.
	AggregateEvidence releaseinventory.Digest
	// VerifiedArtifacts contains only final objects reverified by Store.
	VerifiedArtifacts []VerifiedArtifact
	// ReservationRetained proves expansion, rollback, and safety headroom stays
	// owned until the parent saga durably activates or terminates the release.
	ReservationRetained bool
}

// ReleaseResult is durable evidence that explicit cancellation or rollback
// relinquished only aggregate-owned reservation resources.
type ReleaseResult struct {
	Version           uint64
	Reason            artifactacquisition.ReleaseReason
	Released          bool
	AggregateEvidence releaseinventory.Digest
}

// VerifiedArtifact is privacy-safe exact final-object evidence.
type VerifiedArtifact struct {
	ID         string
	Digest     releaseinventory.Digest
	Size       uint64
	ContentKey string
}

// ReserveSpace durably records exact local capacity before Fetch can run.
func (a *Application) ReserveSpace(ctx context.Context, command Command) (ReserveResult, error) {
	aggregate, err := a.loadOrCreate(ctx, command)
	if err != nil {
		return ReserveResult{}, err
	}
	if proof, exists := aggregate.Reservation(); exists {
		authorization, authorizationError := aggregate.AuthorizeReservationRevalidation()
		if authorizationError != nil {
			return ReserveResult{}, appError(ErrorIntegrity, "authorize-reservation-revalidation")
		}
		observed, reservationError := a.revalidate(ctx, authorization)
		if reservationError != nil {
			return ReserveResult{}, reservationError
		}
		if observed != proof {
			return ReserveResult{}, appError(ErrorIntegrity, "reservation-revalidation")
		}
		return ReserveResult{
			Version: aggregate.Version(), ReservationID: proof.ID(), ReservedBytes: proof.Bytes(), Reused: true,
			AggregateEvidence: aggregate.EvidenceDigest(),
		}, nil
	}
	if !aggregate.ReservationRequested() {
		previous := aggregate.Version()
		changed, requestError := aggregate.RequestReservation()
		if requestError != nil || !changed {
			return ReserveResult{}, appError(ErrorIntegrity, "request-reservation")
		}
		if saveError := a.repository.Save(ctx, previous, aggregate.Snapshot()); saveError != nil {
			return ReserveResult{}, appError(ErrorRepository, "persist-reservation-intent")
		}
	}
	authorization, err := aggregate.AuthorizeReservation()
	if err != nil {
		return ReserveResult{}, appError(ErrorIntegrity, "authorize-reservation")
	}
	proof, reservationError := a.reserve(ctx, command, authorization)
	if reservationError != nil {
		return ReserveResult{}, reservationError
	}
	previous := aggregate.Version()
	if _, err := aggregate.RecordReservation(proof); err != nil {
		return ReserveResult{}, appError(ErrorIntegrity, "record-reservation")
	}
	if err := a.repository.Save(ctx, previous, aggregate.Snapshot()); err != nil {
		return ReserveResult{}, appError(ErrorRepository, "persist-reservation")
	}
	return ReserveResult{
		Version: aggregate.Version(), ReservationID: proof.ID(), ReservedBytes: proof.Bytes(),
		AggregateEvidence: aggregate.EvidenceDigest(),
	}, nil
}

// Acquire verifies/reuses retained bytes, downloads only signed chunks, and
// atomically publishes each exact content-addressed artifact.
func (a *Application) Acquire(ctx context.Context, command Command) (AcquireResult, error) {
	if ctx == nil {
		return AcquireResult{}, appError(ErrorInvalidCommand, "validate")
	}
	if _, err := artifactacquisition.NewAggregate(command.OperationID, command.Plan); err != nil {
		return AcquireResult{}, appError(ErrorInvalidCommand, "validate")
	}
	snapshot, err := a.repository.Load(ctx, command.OperationID)
	if err != nil {
		return AcquireResult{}, mapRepository(err, "load")
	}
	aggregate, err := artifactacquisition.Restore(command.Plan, snapshot)
	if err != nil || aggregate.OperationID() != command.OperationID || !aggregate.Reserved() {
		return AcquireResult{}, appError(ErrorIntegrity, "restore")
	}
	authorization, err := aggregate.AuthorizeReservationRevalidation()
	if err != nil {
		return AcquireResult{}, appError(ErrorIntegrity, "authorize-reservation-revalidation")
	}
	observed, err := a.revalidate(ctx, authorization)
	proof, proofExists := aggregate.Reservation()
	if err != nil {
		return AcquireResult{}, err
	}
	if !proofExists || observed != proof {
		return AcquireResult{}, appError(ErrorIntegrity, "reservation-revalidation")
	}
	result := AcquireResult{}
	for _, artifact := range command.Plan.Artifacts() {
		if aggregate.ArtifactCompleted(artifact) {
			if _, err := a.store.InspectFinal(ctx, artifact); err != nil {
				return result, appError(ErrorIntegrity, "verify-completed")
			}
			result.CompletedArtifacts++
			result.VerifiedArtifacts = append(result.VerifiedArtifacts, verifiedArtifact(artifact))
			continue
		}
		if err := a.ensureArtifact(ctx, aggregate, artifact, &result); err != nil {
			return result, err
		}
		result.CompletedArtifacts++
		result.VerifiedArtifacts = append(result.VerifiedArtifacts, verifiedArtifact(artifact))
	}
	result.Version = aggregate.Version()
	result.AggregateEvidence = aggregate.EvidenceDigest()
	result.ReservationRetained = aggregate.ReservationActive()
	return result, nil
}

// ReleaseReservation explicitly settles owned capacity after user
// cancellation or saga rollback. It uses a fresh bounded context so cleanup
// is not skipped merely because the initiating operation was cancelled.
func (a *Application) ReleaseReservation(
	ctx context.Context,
	command Command,
	reason artifactacquisition.ReleaseReason,
) (ReleaseResult, error) {
	if ctx == nil || (reason != artifactacquisition.ReleaseReasonCancelled && reason != artifactacquisition.ReleaseReasonRollback) {
		return ReleaseResult{}, appError(ErrorInvalidCommand, "validate-release")
	}
	if _, err := artifactacquisition.NewAggregate(command.OperationID, command.Plan); err != nil {
		return ReleaseResult{}, appError(ErrorInvalidCommand, "validate-release")
	}
	cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), reservationFinalizationTimeout)
	defer cancel()
	snapshot, err := a.repository.Load(cleanupContext, command.OperationID)
	if err != nil {
		return ReleaseResult{}, mapRepository(err, "load-release")
	}
	aggregate, err := artifactacquisition.Restore(command.Plan, snapshot)
	if err != nil || aggregate.OperationID() != command.OperationID || !aggregate.ReservationRequested() {
		return ReleaseResult{}, appError(ErrorIntegrity, "restore-release")
	}
	if aggregate.ReservationReleased() {
		if aggregate.ReservationReleaseReason() != reason {
			return ReleaseResult{}, appError(ErrorIntegrity, "released-for-other-reason")
		}
		return releaseResult(aggregate), nil
	}
	if err := a.requestAndRelease(cleanupContext, aggregate, reason); err != nil {
		return ReleaseResult{}, err
	}
	return releaseResult(aggregate), nil
}

// ReleaseReservationIfPresent is the parent-saga settlement boundary. It is
// intentionally a no-op when the operation aggregate was never created or
// when no reservation intent was recorded. Once an intent exists it delegates
// to the same strict, journal-authorized release protocol as
// ReleaseReservation.
func (a *Application) ReleaseReservationIfPresent(
	ctx context.Context,
	command Command,
	reason artifactacquisition.ReleaseReason,
) (ReleaseResult, error) {
	if ctx == nil || (reason != artifactacquisition.ReleaseReasonCompleted &&
		reason != artifactacquisition.ReleaseReasonCancelled && reason != artifactacquisition.ReleaseReasonRollback) {
		return ReleaseResult{}, appError(ErrorInvalidCommand, "validate-optional-release")
	}
	pristine, err := artifactacquisition.NewAggregate(command.OperationID, command.Plan)
	if err != nil {
		return ReleaseResult{}, appError(ErrorInvalidCommand, "validate-optional-release")
	}
	cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), reservationFinalizationTimeout)
	defer cancel()
	snapshot, err := a.repository.Load(cleanupContext, command.OperationID)
	if errors.Is(err, ErrAggregateNotFound) {
		return ReleaseResult{Reason: reason}, nil
	}
	if err != nil {
		return ReleaseResult{}, mapRepository(err, "load-optional-release")
	}
	aggregate, err := artifactacquisition.Restore(command.Plan, snapshot)
	if err != nil || aggregate.OperationID() != command.OperationID {
		return ReleaseResult{}, appError(ErrorIntegrity, "restore-optional-release")
	}
	if !aggregate.ReservationRequested() {
		return ReleaseResult{
			Version: aggregate.Version(), Reason: reason, AggregateEvidence: pristine.EvidenceDigest(),
		}, nil
	}
	if aggregate.ReservationReleased() {
		return releaseResult(aggregate), nil
	}
	if err := a.requestAndRelease(cleanupContext, aggregate, reason); err != nil {
		return ReleaseResult{}, err
	}
	return releaseResult(aggregate), nil
}

func verifiedArtifact(artifact artifactacquisition.Artifact) VerifiedArtifact {
	return VerifiedArtifact{
		ID: artifact.ID(), Digest: artifact.Digest(), Size: artifact.Size(), ContentKey: artifact.ContentKey(),
	}
}

func (a *Application) ensureArtifact(
	ctx context.Context,
	aggregate *artifactacquisition.Aggregate,
	artifact artifactacquisition.Artifact,
	result *AcquireResult,
) error {
	previous := aggregate.Version()
	changed, err := aggregate.BeginArtifact(artifact)
	if err != nil {
		return appError(ErrorIntegrity, "begin-artifact")
	}
	if changed {
		if err := a.repository.Save(ctx, previous, aggregate.Snapshot()); err != nil {
			return appError(ErrorRepository, "persist-partial-ownership")
		}
	}
	if !aggregate.ReservationConsumed(artifact) {
		consumptionAuthorization, authorizationError := aggregate.AuthorizeConsumption(artifact)
		if authorizationError != nil {
			return appError(ErrorIntegrity, "authorize-consumption")
		}
		consumptionProof, consumeError := a.reservation.Consume(ctx, consumptionAuthorization)
		if consumeError != nil {
			return appError(ErrorReservation, "consume-reservation")
		}
		previous = aggregate.Version()
		consumed, recordError := aggregate.RecordConsumption(consumptionAuthorization, consumptionProof)
		if recordError != nil || !consumed {
			return appError(ErrorIntegrity, "record-consumption")
		}
		if saveError := a.repository.Save(ctx, previous, aggregate.Snapshot()); saveError != nil {
			return appError(ErrorRepository, "persist-consumption")
		}
	}
	authorization, err := aggregate.AuthorizePartial(artifact)
	if err != nil {
		return appError(ErrorIntegrity, "authorize-partial")
	}
	if finalProof, finalError := a.store.InspectFinal(ctx, artifact); finalError == nil {
		for _, chunk := range artifact.Chunks() {
			if err := a.recordChunk(ctx, aggregate, artifact, chunk, chunk.Digest()); err != nil {
				return err
			}
		}
		return a.complete(ctx, aggregate, artifact, finalProof)
	} else if !errors.Is(finalError, ErrArtifactNotFound) {
		return mapStore(finalError, "inspect-final")
	}

	for _, chunk := range artifact.Chunks() {
		retainedDigest, retainedError := a.store.VerifyChunk(ctx, authorization, chunk)
		if retainedError == nil && retainedDigest.Equal(chunk.Digest()) {
			if err := a.recordChunk(ctx, aggregate, artifact, chunk, retainedDigest); err != nil {
				return err
			}
			result.RecoveredChunks++
			continue
		}
		if retainedError != nil && !errors.Is(retainedError, ErrArtifactNotFound) && !errors.Is(retainedError, ErrStoreIntegrity) {
			return mapStore(retainedError, "verify-retained")
		}
		if aggregate.ChunkVerified(artifact, chunk) {
			previous := aggregate.Version()
			if _, err := aggregate.InvalidateChunk(artifact, chunk); err != nil {
				return appError(ErrorIntegrity, "invalidate-retained")
			}
			if err := a.repository.Save(ctx, previous, aggregate.Snapshot()); err != nil {
				return appError(ErrorRepository, "persist-invalidation")
			}
		}
		value, fetchError := a.fetchChunk(ctx, artifact, chunk)
		if fetchError != nil {
			return fetchError
		}
		if !chunk.VerifyBytes(value) {
			return appError(ErrorIntegrity, "verify-fetched-chunk")
		}
		if err := a.store.WriteChunk(ctx, authorization, chunk, value); err != nil {
			if errors.Is(err, ErrStoreIntegrity) {
				return a.compensateInvalid(ctx, aggregate, authorization)
			}
			return mapStore(err, "write-chunk")
		}
		observed, err := a.store.VerifyChunk(ctx, authorization, chunk)
		if err != nil || !observed.Equal(chunk.Digest()) {
			return a.compensateInvalid(ctx, aggregate, authorization)
		}
		if err := a.recordChunk(ctx, aggregate, artifact, chunk, observed); err != nil {
			return err
		}
		result.DownloadedChunks++
	}
	finalProof, err := a.store.Finalize(ctx, authorization, artifact)
	if err != nil {
		if errors.Is(err, ErrStoreIntegrity) {
			return a.compensateInvalid(ctx, aggregate, authorization)
		}
		return mapStore(err, "finalize")
	}
	return a.complete(ctx, aggregate, artifact, finalProof)
}

func (a *Application) reserve(
	ctx context.Context,
	command Command,
	authorization artifactacquisition.ReservationAuthorization,
) (artifactacquisition.ReservationProof, error) {
	reservationID, err := command.Plan.ReservationID(command.OperationID)
	if err != nil {
		return artifactacquisition.ReservationProof{}, appError(ErrorInvalidCommand, "reservation-id")
	}
	totals := command.Plan.Totals()
	proof, err := a.reservation.Reserve(ctx, ReservationRequest{
		Authorization: authorization,
		ReservationID: reservationID, PlanDigest: command.Plan.Digest(), RequiredBytes: totals.DownloadBytes(),
		DownloadBytes: totals.DownloadBytes(),
		Allocations:   authorization.Allocations(),
	})
	if err == nil {
		return proof, nil
	}
	failure := appError(ErrorReservation, "reserve")
	if errors.Is(err, ErrReservationUnsupported) {
		return artifactacquisition.ReservationProof{}, errors.Join(failure, ErrReservationUnsupported)
	}
	return artifactacquisition.ReservationProof{}, failure
}

func (a *Application) revalidate(
	ctx context.Context,
	authorization artifactacquisition.ReservationRevalidationAuthorization,
) (artifactacquisition.ReservationProof, error) {
	proof, err := a.reservation.Revalidate(ctx, authorization)
	if err != nil {
		return artifactacquisition.ReservationProof{}, appError(ErrorReservation, "revalidate-reservation")
	}
	return proof, nil
}

func (a *Application) requestAndRelease(
	ctx context.Context,
	aggregate *artifactacquisition.Aggregate,
	reason artifactacquisition.ReleaseReason,
) error {
	if aggregate.ReservationReleased() {
		if aggregate.ReservationReleaseReason() != reason {
			return appError(ErrorIntegrity, "release-reason")
		}
		return nil
	}
	if !aggregate.ReservationReleasePending() {
		previous := aggregate.Version()
		changed, err := aggregate.RequestReservationRelease(reason)
		if err != nil || !changed {
			return appError(ErrorIntegrity, "request-release")
		}
		if err := a.repository.Save(ctx, previous, aggregate.Snapshot()); err != nil {
			return appError(ErrorRepository, "persist-release-intent")
		}
	} else if aggregate.ReservationReleaseReason() != reason {
		return appError(ErrorIntegrity, "pending-release-reason")
	}
	authorization, err := aggregate.AuthorizeRelease()
	if err != nil {
		return appError(ErrorIntegrity, "authorize-release")
	}
	if err := a.reservation.Release(ctx, authorization); err != nil {
		return appError(ErrorCompensation, "release-reservation")
	}
	previous := aggregate.Version()
	changed, err := aggregate.RecordReleased(authorization)
	if err != nil || !changed {
		return appError(ErrorIntegrity, "record-release")
	}
	if err := a.repository.Save(ctx, previous, aggregate.Snapshot()); err != nil {
		return appError(ErrorCompensation, "persist-release")
	}
	return nil
}

func releaseResult(aggregate *artifactacquisition.Aggregate) ReleaseResult {
	return ReleaseResult{
		Version: aggregate.Version(), Reason: aggregate.ReservationReleaseReason(), Released: aggregate.ReservationReleased(),
		AggregateEvidence: aggregate.EvidenceDigest(),
	}
}

func (a *Application) fetchChunk(
	ctx context.Context,
	artifact artifactacquisition.Artifact,
	chunk artifactacquisition.Chunk,
) ([]byte, error) {
	for _, source := range artifact.Sources() {
		value, err := a.fetcher.Fetch(ctx, artifact, source, chunk)
		if err == nil {
			return append([]byte(nil), value...), nil
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, errors.Join(appError(ErrorSource, "fetch-cancelled"), err)
		}
		if errors.Is(err, ErrFetchIntegrity) {
			return nil, appError(ErrorIntegrity, "fetch-range")
		}
		if !errors.Is(err, ErrFetchUnavailable) {
			return nil, appError(ErrorSource, "fetch-range")
		}
	}
	return nil, appError(ErrorSource, "sources-exhausted")
}

func (a *Application) recordChunk(
	ctx context.Context,
	aggregate *artifactacquisition.Aggregate,
	artifact artifactacquisition.Artifact,
	chunk artifactacquisition.Chunk,
	digest releaseinventory.Digest,
) error {
	if aggregate.ChunkVerified(artifact, chunk) {
		return nil
	}
	previous := aggregate.Version()
	if _, err := aggregate.MarkChunkVerified(artifact, chunk, digest); err != nil {
		return appError(ErrorIntegrity, "record-chunk")
	}
	if err := a.repository.Save(ctx, previous, aggregate.Snapshot()); err != nil {
		return appError(ErrorRepository, "persist-chunk")
	}
	return nil
}

func (a *Application) complete(
	ctx context.Context,
	aggregate *artifactacquisition.Aggregate,
	artifact artifactacquisition.Artifact,
	proof artifactacquisition.FinalProof,
) error {
	previous := aggregate.Version()
	if _, err := aggregate.CompleteArtifact(artifact, proof); err != nil {
		return appError(ErrorIntegrity, "complete-artifact")
	}
	if err := a.repository.Save(ctx, previous, aggregate.Snapshot()); err != nil {
		return appError(ErrorRepository, "persist-completion")
	}
	return nil
}

func (a *Application) compensateInvalid(
	ctx context.Context,
	aggregate *artifactacquisition.Aggregate,
	authorization artifactacquisition.PartialAuthorization,
) error {
	if err := a.store.ResetInvalidPartial(ctx, authorization); err != nil {
		return appError(ErrorCompensation, "reset-invalid-partial")
	}
	previous := aggregate.Version()
	if err := aggregate.ResetInvalidPartial(authorization); err != nil {
		return appError(ErrorCompensation, "reset-invalid-evidence")
	}
	if err := a.repository.Save(ctx, previous, aggregate.Snapshot()); err != nil {
		return appError(ErrorCompensation, "persist-compensation")
	}
	return appError(ErrorIntegrity, "invalid-partial")
}

func (a *Application) loadOrCreate(ctx context.Context, command Command) (*artifactacquisition.Aggregate, error) {
	if ctx == nil {
		return nil, appError(ErrorInvalidCommand, "validate")
	}
	pristine, err := artifactacquisition.NewAggregate(command.OperationID, command.Plan)
	if err != nil {
		return nil, appError(ErrorInvalidCommand, "validate")
	}
	snapshot, err := a.repository.Load(ctx, command.OperationID)
	switch {
	case err == nil:
		aggregate, restoreError := artifactacquisition.Restore(command.Plan, snapshot)
		if restoreError != nil || aggregate.OperationID() != command.OperationID {
			return nil, appError(ErrorIntegrity, "restore")
		}
		return aggregate, nil
	case errors.Is(err, ErrAggregateNotFound):
		if saveError := a.repository.Save(ctx, 0, pristine.Snapshot()); saveError != nil {
			return nil, appError(ErrorRepository, "create")
		}
		return pristine, nil
	default:
		return nil, mapRepository(err, "load")
	}
}

func mapRepository(_ error, operation string) error { return appError(ErrorRepository, operation) }

func mapStore(err error, operation string) error {
	if errors.Is(err, ErrStoreIntegrity) {
		return appError(ErrorIntegrity, operation)
	}
	return appError(ErrorStore, operation)
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid, reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128, reflect.Array,
		reflect.String, reflect.Struct, reflect.UnsafePointer:
		return false
	}
	return false
}
