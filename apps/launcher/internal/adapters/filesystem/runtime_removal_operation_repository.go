package filesystem

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"

	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeremovalapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeremoval"
)

const maximumRuntimeRemovalOperationBytes = 256 * 1024

// RuntimeRemovalOperationRepository stores the destructive saga in a
// purpose-separated authenticated journal namespace.
type RuntimeRemovalOperationRepository struct {
	journalProvider OperationJournalProvider
	clock           OperationRepositoryClock
	fence           OperationStateFence
}

var _ runtimeremovalapp.OperationRepository = (*RuntimeRemovalOperationRepository)(nil)

// NewRuntimeRemovalOperationRepository rejects incomplete durability authority.
func NewRuntimeRemovalOperationRepository(
	journalProvider OperationJournalProvider,
	clock OperationRepositoryClock,
	fence OperationStateFence,
) (*RuntimeRemovalOperationRepository, error) {
	if nilInterface(journalProvider) || nilInterface(clock) || nilInterface(fence) {
		return nil, errors.New("runtime removal repository dependencies are required")
	}
	return &RuntimeRemovalOperationRepository{
		journalProvider: journalProvider, clock: clock, fence: fence,
	}, nil
}

// Load authenticates and strictly restores the latest durable aggregate.
func (r *RuntimeRemovalOperationRepository) Load(
	ctx context.Context,
	operationID string,
) (*runtimeremoval.Operation, error) {
	id, err := install.NewOperationID(operationID)
	if err != nil {
		return nil, runtimeRemovalIntegrity(err)
	}
	var result *runtimeremoval.Operation
	err = r.fence.WithExclusive(ctx, id, func() error {
		journal, journalError := r.journalFor(ctx, id)
		if journalError != nil {
			return mapRuntimeRemovalLoadError(journalError)
		}
		latest, loadError := journal.LoadLatest(ctx)
		if loadError != nil {
			return mapRuntimeRemovalLoadError(loadError)
		}
		operation, decodeError := decodeRuntimeRemovalOperation(latest.Payload)
		if decodeError != nil || latest.OperationID != operationID || operation.ID() != id {
			return runtimeRemovalIntegrity(errors.Join(errors.New("runtime removal identity is invalid"), decodeError))
		}
		if durableError := journal.ConfirmDurable(ctx, latest.OperationID, latest.Revision); durableError != nil {
			return mapRuntimeRemovalMutationError(durableError)
		}
		result = operation
		return nil
	})
	return result, err
}

// Save applies aggregate-version CAS and confirms exact replay durability.
func (r *RuntimeRemovalOperationRepository) Save(
	ctx context.Context,
	snapshot runtimeremoval.OperationSnapshot,
) error {
	id, err := install.NewOperationID(snapshot.OperationID)
	if err != nil {
		return runtimeRemovalIntegrity(err)
	}
	return r.fence.WithExclusive(ctx, id, func() error {
		payload, encodeError := encodeRuntimeRemovalOperation(snapshot)
		if encodeError != nil {
			return runtimeRemovalIntegrity(encodeError)
		}
		journal, journalError := r.journalFor(ctx, id)
		if journalError != nil {
			return mapRuntimeRemovalMutationError(journalError)
		}
		previousRevision := uint64(0)
		latest, loadError := journal.LoadLatest(ctx)
		switch {
		case loadError == nil:
			current, decodeError := decodeRuntimeRemovalOperation(latest.Payload)
			if decodeError != nil || latest.OperationID != id.String() || current.ID() != id {
				return runtimeRemovalIntegrity(errors.Join(errors.New("runtime removal current state is invalid"), decodeError))
			}
			if current.PlanDigest() != snapshot.Plan.Digest {
				return runtimeRemovalIntegrity(errors.New("runtime removal plan authority changed"))
			}
			switch {
			case snapshot.Version < current.Version():
				return runtimeRemovalConflict(errors.New("runtime removal aggregate is stale"))
			case snapshot.Version == current.Version():
				if !bytes.Equal(latest.Payload, payload) {
					return runtimeRemovalConflict(errors.New("runtime removal version has divergent content"))
				}
				return mapRuntimeRemovalMutationError(journal.ConfirmDurable(ctx, id.String(), latest.Revision))
			case snapshot.Version != current.Version()+1:
				return runtimeRemovalConflict(errors.New("runtime removal aggregate skipped a version"))
			}
			if latest.Revision == math.MaxUint64 {
				return runtimeRemovalConflict(errors.New("runtime removal journal is exhausted"))
			}
			previousRevision = latest.Revision
		case errors.Is(loadError, journalport.ErrNotFound):
			if snapshot.Version != 0 {
				return runtimeRemovalConflict(errors.New("first runtime removal version must be zero"))
			}
		default:
			return mapRuntimeRemovalLoadError(loadError)
		}
		capturedAt := r.clock.Now().UTC()
		if capturedAt.IsZero() {
			return runtimeRemovalIntegrity(errors.New("runtime removal capture time is required"))
		}
		if appendError := journal.Append(ctx, previousRevision, journalport.Snapshot{
			OperationID: id.String(), Revision: previousRevision + 1, CapturedAt: capturedAt, Payload: payload,
		}); appendError != nil {
			return mapRuntimeRemovalMutationError(appendError)
		}
		return mapRuntimeRemovalMutationError(journal.ConfirmDurable(ctx, id.String(), previousRevision+1))
	})
}

func (r *RuntimeRemovalOperationRepository) journalFor(
	ctx context.Context,
	operationID install.OperationID,
) (journalport.Journal, error) {
	if r == nil || nilInterface(r.journalProvider) || nilInterface(r.clock) || nilInterface(r.fence) {
		return nil, runtimeRemovalIntegrity(errors.New("runtime removal repository is incomplete"))
	}
	journal, err := r.journalProvider.JournalFor(ctx, operationID)
	if err != nil {
		return nil, err
	}
	if nilInterface(journal) {
		return nil, runtimeRemovalIntegrity(errors.New("runtime removal provider returned no journal"))
	}
	return journal, nil
}

func encodeRuntimeRemovalOperation(snapshot runtimeremoval.OperationSnapshot) ([]byte, error) {
	operation, err := runtimeremoval.RestoreOperation(snapshot)
	if err != nil {
		return nil, errors.New("runtime removal snapshot violates domain invariants")
	}
	encoded, err := json.Marshal(operation.Snapshot())
	if err != nil || len(encoded) == 0 || len(encoded) > maximumRuntimeRemovalOperationBytes {
		return nil, errors.New("encode runtime removal operation")
	}
	return encoded, nil
}

func decodeRuntimeRemovalOperation(payload []byte) (*runtimeremoval.Operation, error) {
	if len(payload) == 0 || len(payload) > maximumRuntimeRemovalOperationBytes || rejectDuplicateJSONKeys(payload) != nil {
		return nil, errors.New("runtime removal JSON is malformed")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var snapshot runtimeremoval.OperationSnapshot
	if err := decoder.Decode(&snapshot); err != nil || requireJSONEnd(decoder) != nil {
		return nil, errors.New("runtime removal JSON violates its schema")
	}
	operation, err := runtimeremoval.RestoreOperation(snapshot)
	if err != nil {
		return nil, errors.New("runtime removal state violates domain invariants")
	}
	canonical, err := json.Marshal(operation.Snapshot())
	if err != nil || !bytes.Equal(canonical, payload) {
		return nil, errors.New("runtime removal JSON is not canonical")
	}
	return operation, nil
}

type runtimeRemovalRepositoryError struct {
	category error
	cause    error
}

func (e *runtimeRemovalRepositoryError) Error() string   { return e.category.Error() }
func (e *runtimeRemovalRepositoryError) Unwrap() []error { return []error{e.category, e.cause} }

func runtimeRemovalIntegrity(cause error) error {
	return &runtimeRemovalRepositoryError{category: runtimeremovalapp.ErrIntegrity, cause: cause}
}

func runtimeRemovalConflict(cause error) error {
	return &runtimeRemovalRepositoryError{category: runtimeremovalapp.ErrOperationConflict, cause: cause}
}

func mapRuntimeRemovalLoadError(err error) error {
	switch {
	case errors.Is(err, journalport.ErrNotFound):
		return runtimeremovalapp.ErrOperationNotFound
	case errors.Is(err, journalport.ErrConflict):
		return runtimeRemovalConflict(err)
	case errors.Is(err, journalport.ErrCorrupt), errors.Is(err, journalport.ErrInvalidSnapshot),
		errors.Is(err, journalport.ErrUnsafePermission):
		return runtimeRemovalIntegrity(err)
	default:
		return err
	}
}

func mapRuntimeRemovalMutationError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, journalport.ErrConflict) {
		return runtimeRemovalConflict(err)
	}
	if errors.Is(err, journalport.ErrNotFound) || errors.Is(err, journalport.ErrCorrupt) ||
		errors.Is(err, journalport.ErrInvalidSnapshot) || errors.Is(err, journalport.ErrUnsafePermission) {
		return runtimeRemovalIntegrity(err)
	}
	return err
}
