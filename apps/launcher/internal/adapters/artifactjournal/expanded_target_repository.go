package artifactjournal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

// ExpandedTargetRepository persists each target lifecycle in a journal
// independent from both acquisition and capacity aggregates.
type ExpandedTargetRepository struct{ repository *Repository }

// NewExpandedTargetRepository constructs authenticated, rollback-protected target persistence.
func NewExpandedTargetRepository(provider JournalProvider, clock Clock) (*ExpandedTargetRepository, error) {
	base, err := New(provider, clock)
	if err != nil {
		return nil, err
	}
	return &ExpandedTargetRepository{repository: base}, nil
}

// LoadExpandedTarget loads and durability-confirms one exact lease journal.
func (r *ExpandedTargetRepository) LoadExpandedTarget(
	ctx context.Context,
	leaseID string,
) (artifactacquisition.ExpandedTargetSnapshot, error) {
	id, err := expandedTargetJournalID(leaseID)
	if err != nil {
		return artifactacquisition.ExpandedTargetSnapshot{}, artifactapp.ErrAggregateIntegrity
	}
	journal, err := r.repository.journal(ctx, id)
	if err != nil {
		return artifactacquisition.ExpandedTargetSnapshot{}, mapJournalError(err)
	}
	latest, err := journal.LoadLatest(ctx)
	if err != nil {
		return artifactacquisition.ExpandedTargetSnapshot{}, mapJournalError(err)
	}
	if latest.OperationID != id.String() || latest.Revision == 0 {
		return artifactacquisition.ExpandedTargetSnapshot{}, artifactapp.ErrAggregateIntegrity
	}
	snapshot, err := decodeExpandedTargetSnapshot(latest.Payload)
	if err != nil || snapshot.LeaseID != leaseID {
		return artifactacquisition.ExpandedTargetSnapshot{}, artifactapp.ErrAggregateIntegrity
	}
	if err := journal.ConfirmDurable(ctx, latest.OperationID, latest.Revision); err != nil {
		return artifactacquisition.ExpandedTargetSnapshot{}, mapJournalError(err)
	}
	return snapshot, nil
}

// SaveExpandedTarget appends exactly one lifecycle successor or confirms an exact replay.
func (r *ExpandedTargetRepository) SaveExpandedTarget(
	ctx context.Context,
	expected uint64,
	snapshot artifactacquisition.ExpandedTargetSnapshot,
) error {
	payload, id, err := encodeExpandedTargetSnapshot(snapshot)
	if err != nil {
		return artifactapp.ErrAggregateIntegrity
	}
	journal, err := r.repository.journal(ctx, id)
	if err != nil {
		return mapJournalError(err)
	}
	previousRevision := uint64(0)
	latest, loadError := journal.LoadLatest(ctx)
	switch {
	case loadError == nil:
		persisted, decodeError := decodeExpandedTargetSnapshot(latest.Payload)
		if decodeError != nil || latest.OperationID != id.String() || latest.Revision == 0 ||
			persisted.Version != expected || !sameExpandedTargetIdentity(persisted, snapshot) {
			return artifactapp.ErrAggregateConflict
		}
		persistedBytes, _, encodeError := encodeExpandedTargetSnapshot(persisted)
		if encodeError != nil {
			return artifactapp.ErrAggregateIntegrity
		}
		if snapshot.Version == expected && bytes.Equal(persistedBytes, payload) {
			return mapJournalError(journal.ConfirmDurable(ctx, latest.OperationID, latest.Revision))
		}
		if expected == ^uint64(0) || snapshot.Version != expected+1 || latest.Revision == ^uint64(0) {
			return artifactapp.ErrAggregateConflict
		}
		previousRevision = latest.Revision
	case errors.Is(loadError, installjournal.ErrNotFound):
		if expected != 0 || snapshot.Version != 0 {
			return artifactapp.ErrAggregateConflict
		}
	default:
		return mapJournalError(loadError)
	}
	now := r.repository.clock.Now().UTC()
	if now.IsZero() {
		return artifactapp.ErrAggregatePersistence
	}
	return mapJournalError(journal.Append(ctx, previousRevision, installjournal.Snapshot{
		OperationID: id.String(), Revision: previousRevision + 1, CapturedAt: now, Payload: payload,
	}))
}

func expandedTargetJournalID(leaseID string) (install.OperationID, error) {
	if !token(leaseID, "l-") {
		return install.OperationID{}, artifactapp.ErrAggregateIntegrity
	}
	digest := sha256.Sum256([]byte("expanded-target-journal\x00" + leaseID))
	return install.NewOperationID("expanded-" + releaseinventory.Digest(digest).Hex())
}

func encodeExpandedTargetSnapshot(
	snapshot artifactacquisition.ExpandedTargetSnapshot,
) ([]byte, install.OperationID, error) {
	if !validExpandedTargetSnapshot(snapshot) {
		return nil, install.OperationID{}, artifactapp.ErrAggregateIntegrity
	}
	id, err := expandedTargetJournalID(snapshot.LeaseID)
	if err != nil {
		return nil, install.OperationID{}, err
	}
	payload, err := json.Marshal(snapshot)
	if err != nil || len(payload) == 0 || len(payload) > maximumJournalBytes {
		return nil, install.OperationID{}, artifactapp.ErrAggregateIntegrity
	}
	return payload, id, nil
}

func decodeExpandedTargetSnapshot(payload []byte) (artifactacquisition.ExpandedTargetSnapshot, error) {
	if len(payload) == 0 || len(payload) > maximumJournalBytes || !json.Valid(payload) || duplicateKeys(payload) {
		return artifactacquisition.ExpandedTargetSnapshot{}, artifactapp.ErrAggregateIntegrity
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var snapshot artifactacquisition.ExpandedTargetSnapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return artifactacquisition.ExpandedTargetSnapshot{}, artifactapp.ErrAggregateIntegrity
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || !validExpandedTargetSnapshot(snapshot) {
		return artifactacquisition.ExpandedTargetSnapshot{}, artifactapp.ErrAggregateIntegrity
	}
	return snapshot, nil
}

func validExpandedTargetSnapshot(snapshot artifactacquisition.ExpandedTargetSnapshot) bool {
	if snapshot.SchemaVersion != 1 || snapshot.Version > 5 || !token(snapshot.LeaseID, "l-") ||
		!safeIdentifier(snapshot.ArtifactID) || !safeIdentifier(snapshot.PoolID) || !safeIdentifier(snapshot.PoolKind) ||
		snapshot.ReservedBytes == 0 || snapshot.ReservedBytes > uint64(1<<53-1) ||
		snapshot.ReservedAllocatedBytes < snapshot.ReservedBytes || snapshot.ReservedAllocatedBytes > uint64(1<<53-1) ||
		!safeIdentifier(snapshot.ReceiptToken) || !safeIdentifier(snapshot.InitialOwner) ||
		snapshot.SourceBytes == 0 || snapshot.SourceBytes > uint64(1<<53-1) ||
		!safeIdentifier(snapshot.TargetKind) || !safeRelativeTargetPath(snapshot.TargetStorageID) ||
		snapshot.TargetRoot == "" || len(snapshot.TargetRoot) > 4096 || strings.ContainsAny(snapshot.TargetRoot, "\x00\r\n") ||
		!safeIdentifier(snapshot.State) || snapshot.MeasuredBytes > snapshot.ReservedBytes ||
		snapshot.AllocatedBytes > snapshot.ReservedAllocatedBytes ||
		!safeIdentifier(snapshot.CurrentOwner) || !optionalCapacityIdentifier(snapshot.NewOwner) ||
		!optionalCapacityIdentifier(snapshot.ReleaseFrom) ||
		!optionalCapacityIdentifier(snapshot.CapacityReleaseFrom) ||
		!optionalCapacityIdentifier(snapshot.ReleaseKind) {
		return false
	}
	for _, digest := range []string{
		snapshot.PlanDigest, snapshot.SourceDigest, snapshot.TargetDigest, snapshot.TargetAuthorityDigest,
	} {
		if _, err := releaseinventory.ParseDigest(digest); err != nil {
			return false
		}
	}
	return true
}

func sameExpandedTargetIdentity(
	left artifactacquisition.ExpandedTargetSnapshot,
	right artifactacquisition.ExpandedTargetSnapshot,
) bool {
	return left.SchemaVersion == right.SchemaVersion && left.LeaseID == right.LeaseID &&
		left.ArtifactID == right.ArtifactID && left.PlanDigest == right.PlanDigest &&
		left.PoolID == right.PoolID && left.PoolKind == right.PoolKind &&
		left.ReservedBytes == right.ReservedBytes && left.ReservedAllocatedBytes == right.ReservedAllocatedBytes && left.ReceiptToken == right.ReceiptToken &&
		left.InitialOwner == right.InitialOwner && left.SourceDigest == right.SourceDigest &&
		left.SourceBytes == right.SourceBytes && left.TargetDigest == right.TargetDigest &&
		left.TargetKind == right.TargetKind && left.TargetStorageID == right.TargetStorageID &&
		left.TargetRoot == right.TargetRoot &&
		left.TargetAuthorityDigest == right.TargetAuthorityDigest
}

var _ artifactapp.ExpandedTargetRepository = (*ExpandedTargetRepository)(nil)
