package filesystem

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"time"

	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeinstallapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const maximumRuntimeOwnershipRecordBytes = 128 * 1024

// RuntimeOwnershipRepository persists the pre-mutation and finalized runtime
// lifecycle authority in a purpose-separated protected journal.
type RuntimeOwnershipRepository struct {
	journalProvider OperationJournalProvider
	clock           OperationRepositoryClock
	fence           OperationStateFence
}

var _ runtimeinstallapp.RuntimeOwnershipRepository = (*RuntimeOwnershipRepository)(nil)

// NewRuntimeOwnershipRepository rejects an incomplete durability authority.
func NewRuntimeOwnershipRepository(
	journalProvider OperationJournalProvider,
	clock OperationRepositoryClock,
	fence OperationStateFence,
) (*RuntimeOwnershipRepository, error) {
	if nilInterface(journalProvider) || nilInterface(clock) || nilInterface(fence) {
		return nil, errors.New("runtime ownership repository dependencies are required")
	}
	return &RuntimeOwnershipRepository{journalProvider: journalProvider, clock: clock, fence: fence}, nil
}

// LoadRuntimeOwnership authenticates, strictly restores, and durability-confirms the latest record.
func (r *RuntimeOwnershipRepository) LoadRuntimeOwnership(
	ctx context.Context,
	operationID string,
) (runtimeinstall.RuntimeOwnershipRecord, error) {
	id, err := install.NewOperationID(operationID)
	if err != nil {
		return runtimeinstall.RuntimeOwnershipRecord{}, ownershipIntegrity(err)
	}
	var result runtimeinstall.RuntimeOwnershipRecord
	err = r.fence.WithExclusive(ctx, id, func() error {
		journal, journalError := r.journalFor(ctx, id)
		if journalError != nil {
			return mapOwnershipLoadError(journalError)
		}
		latest, loadError := journal.LoadLatest(ctx)
		if loadError != nil {
			return mapOwnershipLoadError(loadError)
		}
		if latest.OperationID != operationID || latest.Revision == 0 {
			return ownershipIntegrity(errors.New("runtime ownership journal identity is invalid"))
		}
		record, decodeError := decodeRuntimeOwnershipRecord(latest.Payload)
		if decodeError != nil || record.OperationID() != operationID {
			return ownershipIntegrity(errors.Join(errors.New("runtime ownership payload is invalid"), decodeError))
		}
		if confirmError := journal.ConfirmDurable(ctx, operationID, latest.Revision); confirmError != nil {
			return mapOwnershipMutationError(confirmError)
		}
		result = record
		return nil
	})
	return result, err
}

// SaveRuntimeOwnership applies monotonic record CAS and confirms exact replay durability.
func (r *RuntimeOwnershipRepository) SaveRuntimeOwnership(
	ctx context.Context,
	record runtimeinstall.RuntimeOwnershipRecord,
) error {
	restored, err := runtimeinstall.RestoreRuntimeOwnershipRecord(record.Snapshot())
	if err != nil {
		return ownershipIntegrity(err)
	}
	id, err := install.NewOperationID(restored.OperationID())
	if err != nil {
		return ownershipIntegrity(err)
	}
	return r.fence.WithExclusive(ctx, id, func() error {
		return r.saveUnfenced(ctx, id, restored)
	})
}

func (r *RuntimeOwnershipRepository) saveUnfenced(
	ctx context.Context,
	operationID install.OperationID,
	record runtimeinstall.RuntimeOwnershipRecord,
) error {
	payload, err := encodeRuntimeOwnershipRecord(record)
	if err != nil {
		return ownershipIntegrity(err)
	}
	journal, err := r.journalFor(ctx, operationID)
	if err != nil {
		return mapOwnershipMutationError(err)
	}
	previousRevision := uint64(0)
	latest, loadError := journal.LoadLatest(ctx)
	switch {
	case loadError == nil:
		if latest.OperationID != operationID.String() || latest.Revision == 0 {
			return ownershipIntegrity(errors.New("runtime ownership journal identity is invalid"))
		}
		current, decodeError := decodeRuntimeOwnershipRecord(latest.Payload)
		if decodeError != nil || current.OperationID() != operationID.String() {
			return ownershipIntegrity(errors.Join(errors.New("runtime ownership current record is invalid"), decodeError))
		}
		switch {
		case record.Revision() < current.Revision():
			return ownershipConflict(errors.New("runtime ownership record is stale"))
		case record.Revision() == current.Revision():
			if record.Digest() != current.Digest() || !bytes.Equal(payload, latest.Payload) {
				return ownershipConflict(errors.New("runtime ownership revision identifies different content"))
			}
			return mapOwnershipMutationError(
				journal.ConfirmDurable(ctx, operationID.String(), latest.Revision),
			)
		case !record.CanFollow(current):
			return ownershipIntegrity(errors.New("runtime ownership authority or evidence regressed"))
		}
		if latest.Revision == math.MaxUint64 {
			return ownershipConflict(errors.New("runtime ownership journal revision is exhausted"))
		}
		previousRevision = latest.Revision
	case errors.Is(loadError, journalport.ErrNotFound):
	case loadError != nil:
		return mapOwnershipLoadError(loadError)
	}
	now := r.clock.Now()
	if now.IsZero() || now.Location() != time.UTC {
		return ownershipIntegrity(errors.New("runtime ownership capture time must be UTC"))
	}
	nextRevision := previousRevision + 1
	if err := journal.Append(ctx, previousRevision, journalport.Snapshot{
		OperationID: operationID.String(), Revision: nextRevision, CapturedAt: now, Payload: payload,
	}); err != nil {
		return mapOwnershipMutationError(err)
	}
	return mapOwnershipMutationError(journal.ConfirmDurable(ctx, operationID.String(), nextRevision))
}

func (r *RuntimeOwnershipRepository) journalFor(
	ctx context.Context,
	operationID install.OperationID,
) (journalport.Journal, error) {
	if r == nil || ctx == nil || nilInterface(r.journalProvider) || nilInterface(r.clock) || nilInterface(r.fence) {
		return nil, ownershipIntegrity(errors.New("runtime ownership repository is incomplete"))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	journal, err := r.journalProvider.JournalFor(ctx, operationID)
	if err != nil {
		return nil, err
	}
	if nilInterface(journal) {
		return nil, ownershipIntegrity(errors.New("runtime ownership provider returned no journal"))
	}
	return journal, nil
}

func encodeRuntimeOwnershipRecord(record runtimeinstall.RuntimeOwnershipRecord) ([]byte, error) {
	restored, err := runtimeinstall.RestoreRuntimeOwnershipRecord(record.Snapshot())
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(restored.Snapshot())
	if err != nil || len(encoded) == 0 || len(encoded) > maximumRuntimeOwnershipRecordBytes {
		return nil, errors.New("encode runtime ownership record")
	}
	return encoded, nil
}

func decodeRuntimeOwnershipRecord(payload []byte) (runtimeinstall.RuntimeOwnershipRecord, error) {
	if len(payload) == 0 || len(payload) > maximumRuntimeOwnershipRecordBytes || rejectDuplicateJSONKeys(payload) != nil {
		return runtimeinstall.RuntimeOwnershipRecord{}, errors.New("runtime ownership JSON is malformed")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var snapshot runtimeinstall.RuntimeOwnershipRecordSnapshot
	if err := decoder.Decode(&snapshot); err != nil || requireJSONEnd(decoder) != nil {
		return runtimeinstall.RuntimeOwnershipRecord{}, errors.New("runtime ownership JSON violates its schema")
	}
	record, err := runtimeinstall.RestoreRuntimeOwnershipRecord(snapshot)
	if err != nil {
		return runtimeinstall.RuntimeOwnershipRecord{}, errors.New("runtime ownership record violates domain invariants")
	}
	canonical, err := json.Marshal(record.Snapshot())
	if err != nil || !bytes.Equal(canonical, payload) {
		return runtimeinstall.RuntimeOwnershipRecord{}, errors.New("runtime ownership JSON is not canonical")
	}
	return record, nil
}

type ownershipRepositoryError struct {
	category error
	cause    error
}

func (e *ownershipRepositoryError) Error() string   { return e.category.Error() }
func (e *ownershipRepositoryError) Unwrap() []error { return []error{e.category, e.cause} }

func ownershipIntegrity(cause error) error {
	return &ownershipRepositoryError{category: runtimeinstallapp.ErrOwnershipIntegrity, cause: cause}
}

func ownershipConflict(cause error) error {
	return &ownershipRepositoryError{category: runtimeinstallapp.ErrOwnershipConflict, cause: cause}
}

func mapOwnershipLoadError(err error) error {
	switch {
	case errors.Is(err, journalport.ErrNotFound):
		return runtimeinstallapp.ErrOwnershipNotFound
	case errors.Is(err, journalport.ErrConflict):
		return ownershipConflict(err)
	case errors.Is(err, journalport.ErrCorrupt), errors.Is(err, journalport.ErrInvalidSnapshot),
		errors.Is(err, journalport.ErrUnsafePermission):
		return ownershipIntegrity(err)
	default:
		return err
	}
}

func mapOwnershipMutationError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, journalport.ErrConflict):
		return ownershipConflict(err)
	case errors.Is(err, journalport.ErrNotFound), errors.Is(err, journalport.ErrCorrupt),
		errors.Is(err, journalport.ErrInvalidSnapshot), errors.Is(err, journalport.ErrUnsafePermission):
		return ownershipIntegrity(err)
	default:
		return err
	}
}
