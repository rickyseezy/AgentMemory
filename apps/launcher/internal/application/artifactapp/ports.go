// Package artifactapp orchestrates reserve-before-download, resumable verified
// acquisition, and atomic content-addressed publication.
package artifactapp

import (
	"context"
	"errors"
	"io"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

var (
	// ErrAggregateNotFound means no authenticated operation state exists.
	ErrAggregateNotFound = errors.New("artifact acquisition aggregate not found")
	// ErrAggregateIntegrity means authentication, strict decoding, rollback
	// protection, or domain restoration failed.
	ErrAggregateIntegrity = errors.New("artifact acquisition aggregate integrity failure")
	// ErrAggregateConflict means optimistic CAS state changed.
	ErrAggregateConflict = errors.New("artifact acquisition aggregate conflict")
	// ErrAggregatePersistence means durable journal persistence failed.
	ErrAggregatePersistence = errors.New("artifact acquisition aggregate persistence failure")
	// ErrArtifactNotFound means no exact partial or final object exists.
	ErrArtifactNotFound = errors.New("artifact content not found")
	// ErrFetchUnavailable means an exact source was unavailable without an
	// integrity contradiction and another signed source may be attempted.
	ErrFetchUnavailable = errors.New("artifact source unavailable")
	// ErrFetchIntegrity means transport metadata or bytes contradicted the plan.
	ErrFetchIntegrity = errors.New("artifact fetch integrity failure")
	// ErrStoreIntegrity means retained or published bytes are invalid.
	ErrStoreIntegrity = errors.New("artifact store integrity failure")
	// ErrStoreOperation means a bounded local persistence operation failed.
	ErrStoreOperation = errors.New("artifact store operation failed")
	// ErrReservationUnsupported means safe local filesystem reservation cannot
	// be proven on this platform/filesystem.
	ErrReservationUnsupported = errors.New("safe local filesystem reservation unsupported")
	// ErrReservationOperation means exact reservation did not complete.
	ErrReservationOperation = errors.New("local filesystem reservation failed")
	// ErrExpandedTargetUnsupported means the signed plan does not explicitly
	// authorize a target representation kind and storage identity.
	ErrExpandedTargetUnsupported = errors.New("expanded target representation unsupported by signed plan")
	// ErrExpandedTargetOperation means an exact expanded-target mutation or
	// reconciliation could not be completed or proven.
	ErrExpandedTargetOperation = errors.New("expanded target operation failed")
)

// Repository stores complete authenticated snapshots with version CAS.
type Repository interface {
	Load(context.Context, string) (artifactacquisition.Snapshot, error)
	Save(context.Context, uint64, artifactacquisition.Snapshot) error
}

// ReservationRequest is a signed-plan-bound local capacity request.
type ReservationRequest struct {
	Authorization artifactacquisition.ReservationAuthorization
	ReservationID string
	PlanDigest    releaseinventory.Digest
	RequiredBytes uint64
	DownloadBytes uint64
	// Allocations are aggregate-derived artifact-sized slots whose sum must
	// equal DownloadBytes. They prevent transient double allocation.
	Allocations []artifactacquisition.ReservationAllocation
}

// ReservationPort durably reserves capacity on the same proven local
// filesystem used by the content store. Implementations must not accept NFS,
// SMB, synchronized folders, or a remote filesystem.
type ReservationPort interface {
	Reserve(context.Context, ReservationRequest) (artifactacquisition.ReservationProof, error)
	Revalidate(context.Context, artifactacquisition.ReservationRevalidationAuthorization) (artifactacquisition.ReservationProof, error)
	Consume(context.Context, artifactacquisition.ConsumptionAuthorization) (artifactacquisition.ConsumptionProof, error)
	Release(context.Context, artifactacquisition.ReleaseAuthorization) error
}

// Fetcher returns one exact signed range. Implementations own HTTP/bundle
// status, redirect, encoding, timeout, and bounded-read verification.
type Fetcher interface {
	Fetch(context.Context, artifactacquisition.Artifact, string, artifactacquisition.Chunk) ([]byte, error)
}

// Store owns exact partial and final bytes. InspectFinal must verify final size,
// final digest, and every signed chunk digest before returning success.
type Store interface {
	InspectFinal(context.Context, artifactacquisition.Artifact) (artifactacquisition.FinalProof, error)
	VerifyChunk(context.Context, artifactacquisition.PartialAuthorization, artifactacquisition.Chunk) (releaseinventory.Digest, error)
	WriteChunk(context.Context, artifactacquisition.PartialAuthorization, artifactacquisition.Chunk, []byte) error
	Finalize(context.Context, artifactacquisition.PartialAuthorization, artifactacquisition.Artifact) (artifactacquisition.FinalProof, error)
	ResetInvalidPartial(context.Context, artifactacquisition.PartialAuthorization) error
}

// VerifiedFinalReader opens one already-published CAS object through the same
// exact artifact authority used by InspectFinal. Implementations must verify
// the complete object before opening, require the consumer to read exactly to
// EOF, and revalidate descriptor/path identity plus digest when it closes.
// It is intentionally separate from Store so acquisition does not gain a read
// capability it does not need.
type VerifiedFinalReader interface {
	OpenFinal(context.Context, artifactacquisition.Artifact) (io.ReadCloser, error)
}

// VerifiedFinalMaterializer publishes one already-verified CAS object at an
// exact private local path. The private boundary and every descendant must be
// owner-only, local, non-link directories; an existing target is reusable only
// when its complete bytes still match the artifact authority.
type VerifiedFinalMaterializer interface {
	MaterializeFinal(
		context.Context,
		artifactacquisition.Artifact,
		string,
		string,
	) error
}
