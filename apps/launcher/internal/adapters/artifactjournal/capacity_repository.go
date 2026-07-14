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

// CapacityRepository persists capacity leases in a journal distinct from the
// download aggregate so each state has independent CAS/replay semantics.
type CapacityRepository struct{ repository *Repository }

// NewCapacityRepository creates an independently journaled capacity aggregate repository.
func NewCapacityRepository(provider JournalProvider, clock Clock) (*CapacityRepository, error) {
	base, err := New(provider, clock)
	if err != nil {
		return nil, err
	}
	return &CapacityRepository{repository: base}, nil
}

// LoadCapacity restores authenticated capacity state for one operation.
func (r *CapacityRepository) LoadCapacity(ctx context.Context, operationID string) (artifactacquisition.CapacityAggregateSnapshot, error) {
	id, err := capacityJournalID(operationID)
	if err != nil {
		return artifactacquisition.CapacityAggregateSnapshot{}, artifactapp.ErrAggregateIntegrity
	}
	journal, err := r.repository.journal(ctx, id)
	if err != nil {
		return artifactacquisition.CapacityAggregateSnapshot{}, mapJournalError(err)
	}
	latest, err := journal.LoadLatest(ctx)
	if err != nil {
		return artifactacquisition.CapacityAggregateSnapshot{}, mapJournalError(err)
	}
	if latest.OperationID != id.String() || latest.Revision == 0 {
		return artifactacquisition.CapacityAggregateSnapshot{}, artifactapp.ErrAggregateIntegrity
	}
	snapshot, err := decodeCapacitySnapshot(latest.Payload)
	if err != nil || snapshot.OperationID != operationID {
		return artifactacquisition.CapacityAggregateSnapshot{}, artifactapp.ErrAggregateIntegrity
	}
	if err := journal.ConfirmDurable(ctx, latest.OperationID, latest.Revision); err != nil {
		return artifactacquisition.CapacityAggregateSnapshot{}, mapJournalError(err)
	}
	return snapshot, nil
}

// SaveCapacity compare-and-swaps one exact aggregate successor and confirms durability.
func (r *CapacityRepository) SaveCapacity(ctx context.Context, expected uint64, snapshot artifactacquisition.CapacityAggregateSnapshot) error {
	payload, id, err := encodeCapacitySnapshot(snapshot)
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
		persisted, decodeError := decodeCapacitySnapshot(latest.Payload)
		if decodeError != nil || latest.OperationID != id.String() || persisted.OperationID != snapshot.OperationID || persisted.PlanDigest != snapshot.PlanDigest || persisted.Version != expected {
			return artifactapp.ErrAggregateConflict
		}
		persistedBytes, _, _ := encodeCapacitySnapshot(persisted)
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
	return mapJournalError(journal.Append(ctx, previousRevision, installjournal.Snapshot{OperationID: id.String(), Revision: previousRevision + 1, CapturedAt: now, Payload: payload}))
}

func capacityJournalID(operationID string) (install.OperationID, error) {
	if _, err := install.NewOperationID(operationID); err != nil {
		return install.OperationID{}, err
	}
	digest := sha256.Sum256([]byte("capacity-journal\x00" + operationID))
	return install.NewOperationID("capacity-" + releaseinventory.Digest(digest).Hex())
}

func encodeCapacitySnapshot(snapshot artifactacquisition.CapacityAggregateSnapshot) ([]byte, install.OperationID, error) {
	if !validCapacitySnapshot(snapshot) {
		return nil, install.OperationID{}, artifactapp.ErrAggregateIntegrity
	}
	id, err := capacityJournalID(snapshot.OperationID)
	if err != nil {
		return nil, install.OperationID{}, err
	}
	payload, err := json.Marshal(snapshot)
	if err != nil || len(payload) == 0 || len(payload) > maximumJournalBytes {
		return nil, install.OperationID{}, artifactapp.ErrAggregateIntegrity
	}
	return payload, id, nil
}

func decodeCapacitySnapshot(payload []byte) (artifactacquisition.CapacityAggregateSnapshot, error) {
	if len(payload) == 0 || len(payload) > maximumJournalBytes || !json.Valid(payload) || duplicateKeys(payload) {
		return artifactacquisition.CapacityAggregateSnapshot{}, artifactapp.ErrAggregateIntegrity
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var snapshot artifactacquisition.CapacityAggregateSnapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return artifactacquisition.CapacityAggregateSnapshot{}, artifactapp.ErrAggregateIntegrity
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return artifactacquisition.CapacityAggregateSnapshot{}, artifactapp.ErrAggregateIntegrity
	}
	if !validCapacitySnapshot(snapshot) {
		return artifactacquisition.CapacityAggregateSnapshot{}, artifactapp.ErrAggregateIntegrity
	}
	return snapshot, nil
}

func validCapacitySnapshot(snapshot artifactacquisition.CapacityAggregateSnapshot) bool {
	if snapshot.SchemaVersion != 6 || len(snapshot.Leases) == 0 || len(snapshot.Leases) > 8194 ||
		snapshot.ReleaseBatches > uint64(len(snapshot.Leases)) {
		return false
	}
	if _, err := install.NewOperationID(snapshot.OperationID); err != nil {
		return false
	}
	if _, err := releaseinventory.ParseDigest(snapshot.PlanDigest); err != nil {
		return false
	}
	seen := make(map[string]struct{}, len(snapshot.Leases))
	for _, lease := range snapshot.Leases {
		if !token(lease.LeaseID, "l-") || !safeIdentifier(lease.Purpose) || !safeIdentifier(lease.Owner) || !safeIdentifier(lease.PoolID) ||
			!safeIdentifier(lease.PoolKind) || lease.Bytes == 0 || lease.Bytes > uint64(1<<53-1) || lease.PlanDigest != snapshot.PlanDigest || !safeIdentifier(lease.State) {
			return false
		}
		if !optionalCapacityIdentifier(lease.ArtifactID) || !optionalCapacityIdentifier(lease.ResourcePurpose) ||
			!optionalCapacityIdentifier(lease.ProjectionInstallationID) ||
			!optionalCapacityIdentifier(lease.ProjectionReleaseID) ||
			!optionalCapacityIdentifier(lease.ProjectionGenerationID) ||
			!optionalCapacityIdentifier(lease.ReceiptToken) ||
			!optionalCapacityIdentifier(lease.NewOwner) || !optionalCapacityIdentifier(lease.ReleaseFrom) ||
			!optionalCapacityIdentifier(lease.ReleaseKind) || !optionalCapacityIdentifier(lease.ReleaseReceiptToken) ||
			lease.UsageBytes > lease.Bytes || lease.AllocatedBytes > lease.ReceiptAllocatedBytes ||
			!validOptionalReceiptAllocation(lease.Bytes, lease.ReceiptAllocatedBytes) || !optionalCapacityDigest(lease.SourceDigest) ||
			!optionalCapacityDigest(lease.ExpectedTargetDigest) || !optionalCapacityDigest(lease.TargetDigest) {
			return false
		}
		expanded := lease.Purpose == string(artifactacquisition.LeaseExpanded)
		projection := lease.Purpose == string(artifactacquisition.LeaseSecretProjection)
		if (expanded || projection) != (lease.ArtifactID != "") || projection != (lease.ResourcePurpose != "") ||
			projection != (lease.ProjectionInstallationID != "") || projection != (lease.ProjectionReleaseID != "") ||
			projection != (lease.ProjectionGenerationID != "") ||
			expanded != (lease.SourceDigest != "") ||
			expanded != (lease.SourceBytes > 0 && lease.SourceBytes <= uint64(1<<53-1)) ||
			expanded != (lease.ExpectedTargetDigest != "") || !safeTargetAuthorityForPurpose(lease, expanded) {
			return false
		}
		if _, duplicate := seen[lease.LeaseID]; duplicate {
			return false
		}
		seen[lease.LeaseID] = struct{}{}
	}
	return true
}

func validOptionalReceiptAllocation(bytes, allocated uint64) bool {
	return allocated == 0 || allocated >= bytes && allocated <= uint64(1<<53-1)
}

func safeTargetAuthorityForPurpose(lease artifactacquisition.CapacityLeaseSnapshot, expanded bool) bool {
	empty := lease.TargetKind == "" && lease.TargetStorageID == "" && lease.TargetAuthorityDigest == "" && lease.TargetRoot == ""
	if !expanded {
		return empty
	}
	if empty {
		return false
	}
	return safeIdentifier(lease.TargetKind) && safeRelativeTargetPath(lease.TargetStorageID) &&
		optionalCapacityDigest(lease.TargetAuthorityDigest) && lease.TargetAuthorityDigest != "" &&
		lease.TargetRoot != "" && len(lease.TargetRoot) <= 4096 && !strings.ContainsAny(lease.TargetRoot, "\x00\r\n")
}

func safeRelativeTargetPath(value string) bool {
	if value == "" || len(value) > 256 || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") ||
		strings.ContainsAny(value, "\x00\r\n\\") || strings.Contains(value, "//") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func optionalCapacityIdentifier(value string) bool { return value == "" || safeIdentifier(value) }

func optionalCapacityDigest(value string) bool {
	if value == "" {
		return true
	}
	_, err := releaseinventory.ParseDigest(value)
	return err == nil
}

var _ artifactapp.CapacityRepository = (*CapacityRepository)(nil)
