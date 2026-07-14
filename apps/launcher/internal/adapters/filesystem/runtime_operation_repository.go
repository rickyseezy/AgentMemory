package filesystem

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeinstallapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const runtimeOperationRepositorySchemaVersion = uint16(1)

// RuntimeOperationRepository stores the PF-006 child saga in a dedicated
// authenticated journal namespace. Its provider must be rooted separately
// from the parent PF-001 operation journal.
type RuntimeOperationRepository struct {
	journalProvider OperationJournalProvider
	clock           OperationRepositoryClock
	fence           OperationStateFence
}

var _ runtimeinstallapp.OperationRepository = (*RuntimeOperationRepository)(nil)

// NewRuntimeOperationRepository rejects a partial durability authority.
func NewRuntimeOperationRepository(
	journalProvider OperationJournalProvider,
	clock OperationRepositoryClock,
	fence OperationStateFence,
) (*RuntimeOperationRepository, error) {
	if nilInterface(journalProvider) || nilInterface(clock) || nilInterface(fence) {
		return nil, errors.New("runtime operation repository dependencies are required")
	}
	return &RuntimeOperationRepository{journalProvider: journalProvider, clock: clock, fence: fence}, nil
}

// Load authenticates the journal envelope, canonical payload, complete domain
// history, and durable publication before returning the aggregate.
func (r *RuntimeOperationRepository) Load(ctx context.Context, operationID string) (*runtimeinstall.Operation, error) {
	id, err := install.NewOperationID(operationID)
	if err != nil {
		return nil, runtimeOperationIntegrity(err)
	}
	var operation *runtimeinstall.Operation
	err = r.fence.WithExclusive(ctx, id, func() error {
		loaded, loadErr := r.loadUnfenced(ctx, id)
		operation = loaded
		return loadErr
	})
	return operation, err
}

func (r *RuntimeOperationRepository) loadUnfenced(
	ctx context.Context,
	operationID install.OperationID,
) (*runtimeinstall.Operation, error) {
	journal, err := r.journalFor(ctx, operationID)
	if err != nil {
		return nil, mapRuntimeJournalLoadError(err)
	}
	latest, err := journal.LoadLatest(ctx)
	if err != nil {
		return nil, mapRuntimeJournalLoadError(err)
	}
	if latest.OperationID != operationID.String() {
		return nil, runtimeOperationIntegrity(errors.New("runtime journal operation identity mismatch"))
	}
	operation, err := decodeRuntimeOperationSnapshot(latest.Payload)
	if err != nil || operation.ID() != latest.OperationID {
		if err == nil {
			err = errors.New("runtime payload operation identity mismatch")
		}
		return nil, runtimeOperationIntegrity(err)
	}
	if err := journal.ConfirmDurable(ctx, latest.OperationID, latest.Revision); err != nil {
		return nil, mapRuntimeJournalMutationError(err)
	}
	return operation, nil
}

// Save validates the whole snapshot and applies aggregate-version CAS. Exact
// replay confirms durability without creating another journal revision.
func (r *RuntimeOperationRepository) Save(ctx context.Context, snapshot runtimeinstall.OperationSnapshot) error {
	id, err := install.NewOperationID(snapshot.OperationID)
	if err != nil {
		return runtimeOperationIntegrity(err)
	}
	return r.fence.WithExclusive(ctx, id, func() error {
		return r.saveUnfenced(ctx, id, snapshot)
	})
}

func (r *RuntimeOperationRepository) saveUnfenced(
	ctx context.Context,
	operationID install.OperationID,
	snapshot runtimeinstall.OperationSnapshot,
) error {
	payload, encodedID, err := encodeRuntimeOperationSnapshot(snapshot)
	if err != nil || encodedID != operationID.String() {
		if err == nil {
			err = errors.New("runtime snapshot identity changed during validation")
		}
		return runtimeOperationIntegrity(err)
	}
	journal, err := r.journalFor(ctx, operationID)
	if err != nil {
		return mapRuntimeJournalMutationError(err)
	}
	previousRevision := uint64(0)
	latest, loadErr := journal.LoadLatest(ctx)
	switch {
	case loadErr == nil:
		if latest.OperationID != encodedID {
			return runtimeOperationConflict("runtime journal belongs to another operation")
		}
		current, decodeErr := decodeRuntimeOperationSnapshot(latest.Payload)
		if decodeErr != nil || current.ID() != latest.OperationID {
			if decodeErr == nil {
				decodeErr = errors.New("runtime journal envelope and payload identities differ")
			}
			return runtimeOperationIntegrity(decodeErr)
		}
		if current.PlanDigest() != snapshot.PlanDigest {
			return runtimeOperationIntegrity(errors.New("runtime snapshots use different plans"))
		}
		canonicalCurrent, _, encodeErr := encodeRuntimeOperationSnapshot(current.Snapshot())
		if encodeErr != nil {
			return runtimeOperationIntegrity(encodeErr)
		}
		switch {
		case snapshot.Version < current.Version():
			return runtimeOperationConflict("runtime aggregate snapshot is stale")
		case snapshot.Version == current.Version():
			if bytes.Equal(canonicalCurrent, payload) {
				return mapRuntimeJournalMutationError(
					journal.ConfirmDurable(ctx, latest.OperationID, latest.Revision),
				)
			}
			return runtimeOperationConflict("runtime aggregate version identifies different content")
		case snapshot.Version != current.Version()+1:
			return runtimeOperationConflict("runtime aggregate version skips a state mutation")
		}
		if latest.Revision == math.MaxUint64 {
			return runtimeOperationConflict("runtime journal revision is exhausted")
		}
		previousRevision = latest.Revision
	case errors.Is(loadErr, journalport.ErrNotFound):
		if snapshot.Version != 0 {
			return runtimeOperationConflict("first runtime aggregate version must be zero")
		}
	default:
		return mapRuntimeJournalLoadError(loadErr)
	}

	capturedAt := r.clock.Now().UTC()
	if capturedAt.IsZero() {
		return runtimeOperationIntegrity(errors.New("runtime snapshot capture time is required"))
	}
	if err := journal.Append(ctx, previousRevision, journalport.Snapshot{
		OperationID: encodedID,
		Revision:    previousRevision + 1,
		CapturedAt:  capturedAt,
		Payload:     payload,
	}); err != nil {
		return mapRuntimeJournalMutationError(err)
	}
	return nil
}

func (r *RuntimeOperationRepository) journalFor(
	ctx context.Context,
	operationID install.OperationID,
) (journalport.Journal, error) {
	if r == nil || nilInterface(r.journalProvider) || nilInterface(r.clock) || nilInterface(r.fence) {
		return nil, runtimeOperationIntegrity(errors.New("runtime operation repository is incomplete"))
	}
	journal, err := r.journalProvider.JournalFor(ctx, operationID)
	if err != nil {
		return nil, err
	}
	if nilInterface(journal) {
		return nil, runtimeOperationIntegrity(errors.New("runtime journal provider returned no journal"))
	}
	return journal, nil
}

type runtimeOperationSnapshotDTO struct {
	SchemaVersion uint16                         `json:"schema_version"`
	OperationID   string                         `json:"operation_id"`
	PlanDigest    string                         `json:"plan_digest"`
	State         string                         `json:"state"`
	CurrentPhase  string                         `json:"current_phase"`
	Attempt       uint32                         `json:"attempt"`
	Version       *uint64                        `json:"version"`
	Evidence      []runtimeTransitionEvidenceDTO `json:"evidence"`
	RebootReceipt *string                        `json:"reboot_receipt"`
}

type runtimeTransitionEvidenceDTO struct {
	Phase          string `json:"phase"`
	Attempt        uint32 `json:"attempt"`
	PlanDigest     string `json:"plan_digest"`
	InputDigest    string `json:"input_digest"`
	OutputDigest   string `json:"output_digest"`
	ArtifactDigest string `json:"artifact_digest"`
	Ownership      string `json:"ownership"`
}

func encodeRuntimeOperationSnapshot(snapshot runtimeinstall.OperationSnapshot) ([]byte, string, error) {
	operation, err := runtimeinstall.RestoreOperation(snapshot)
	if err != nil {
		return nil, "", fmt.Errorf("validate runtime operation snapshot: %w", err)
	}
	verified := operation.Snapshot()
	version := verified.Version
	document := runtimeOperationSnapshotDTO{
		SchemaVersion: runtimeOperationRepositorySchemaVersion,
		OperationID:   verified.OperationID,
		PlanDigest:    verified.PlanDigest.String(),
		State:         runtimeStateString(verified.State),
		CurrentPhase:  runtimePhaseString(verified.CurrentPhase),
		Attempt:       verified.Attempt,
		Version:       &version,
		Evidence:      make([]runtimeTransitionEvidenceDTO, 0, len(verified.Evidence)),
	}
	for _, evidence := range verified.Evidence {
		artifactDigest := ""
		if !evidence.ArtifactDigest.IsZero() {
			artifactDigest = evidence.ArtifactDigest.String()
		}
		document.Evidence = append(document.Evidence, runtimeTransitionEvidenceDTO{
			Phase: runtimePhaseString(evidence.Phase), Attempt: evidence.Attempt,
			PlanDigest: evidence.PlanDigest.String(), InputDigest: evidence.InputDigest.String(),
			OutputDigest: evidence.OutputDigest.String(), ArtifactDigest: artifactDigest,
			Ownership: runtimeOwnershipString(evidence.Ownership),
		})
	}
	if !verified.RebootReceipt.IsZero() {
		value := verified.RebootReceipt.String()
		document.RebootReceipt = &value
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, "", errors.New("encode runtime operation snapshot")
	}
	return encoded, document.OperationID, nil
}

func decodeRuntimeOperationSnapshot(payload []byte) (*runtimeinstall.Operation, error) {
	if len(payload) == 0 || rejectDuplicateJSONKeys(payload) != nil {
		return nil, errors.New("runtime operation snapshot JSON is malformed")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var document runtimeOperationSnapshotDTO
	if err := decoder.Decode(&document); err != nil || requireJSONEnd(decoder) != nil {
		return nil, errors.New("runtime operation snapshot JSON does not match its schema")
	}
	if document.SchemaVersion != runtimeOperationRepositorySchemaVersion ||
		document.Version == nil || document.Evidence == nil {
		return nil, errors.New("runtime operation snapshot schema is unsupported")
	}
	plan, err := runtimeinstall.ParseHash(document.PlanDigest)
	if err != nil {
		return nil, errors.New("runtime operation plan digest is invalid")
	}
	state := parseRuntimeState(document.State)
	phase := parseRuntimePhase(document.CurrentPhase)
	if state == runtimeinstall.OperationStateUnknown ||
		phase == runtimeinstall.PhaseUnknown && state != runtimeinstall.OperationStateReady {
		return nil, errors.New("runtime operation cursor is invalid")
	}
	evidence := make([]runtimeinstall.TransitionEvidence, 0, len(document.Evidence))
	for _, encoded := range document.Evidence {
		decoded, decodeErr := decodeRuntimeTransitionEvidence(encoded)
		if decodeErr != nil {
			return nil, decodeErr
		}
		evidence = append(evidence, decoded)
	}
	rebootReceipt := runtimeinstall.Hash{}
	if document.RebootReceipt != nil {
		rebootReceipt, err = runtimeinstall.ParseHash(*document.RebootReceipt)
		if err != nil || rebootReceipt.IsZero() {
			return nil, errors.New("runtime reboot receipt is invalid")
		}
	}
	operation, err := runtimeinstall.RestoreOperation(runtimeinstall.OperationSnapshot{
		SchemaVersion: runtimeOperationRepositorySchemaVersion,
		OperationID:   document.OperationID, PlanDigest: plan, State: state,
		CurrentPhase: phase, Attempt: document.Attempt, Version: *document.Version,
		Evidence: evidence, RebootReceipt: rebootReceipt,
	})
	if err != nil {
		return nil, errors.New("runtime operation snapshot violates domain invariants")
	}
	return operation, nil
}

func decodeRuntimeTransitionEvidence(document runtimeTransitionEvidenceDTO) (runtimeinstall.TransitionEvidence, error) {
	plan, planErr := runtimeinstall.ParseHash(document.PlanDigest)
	input, inputErr := runtimeinstall.ParseHash(document.InputDigest)
	output, outputErr := runtimeinstall.ParseHash(document.OutputDigest)
	artifact := runtimeinstall.Hash{}
	var artifactErr error
	if document.ArtifactDigest != "" {
		artifact, artifactErr = runtimeinstall.ParseHash(document.ArtifactDigest)
	}
	if planErr != nil || inputErr != nil || outputErr != nil || artifactErr != nil {
		return runtimeinstall.TransitionEvidence{}, errors.New("runtime transition digest is invalid")
	}
	ownership := parseRuntimeOwnership(document.Ownership)
	if ownership == runtimeinstall.OwnershipUnknown && document.Ownership != "unknown" {
		return runtimeinstall.TransitionEvidence{}, errors.New("runtime transition ownership is invalid")
	}
	evidence, err := runtimeinstall.NewTransitionEvidence(
		parseRuntimePhase(document.Phase), document.Attempt, plan, input, output, artifact,
		ownership,
	)
	if err != nil {
		return runtimeinstall.TransitionEvidence{}, errors.New("runtime transition evidence is invalid")
	}
	return evidence, nil
}

func runtimeStateString(state runtimeinstall.OperationState) string { return state.String() }

func parseRuntimeState(value string) runtimeinstall.OperationState {
	for _, state := range []runtimeinstall.OperationState{
		runtimeinstall.OperationStateRunning,
		runtimeinstall.OperationStateRebootPending,
		runtimeinstall.OperationStateReady,
		runtimeinstall.OperationStateCancelled,
		runtimeinstall.OperationStatePausedForAdministrator,
		runtimeinstall.OperationStateUnsupportedHost,
		runtimeinstall.OperationStateRuntimeConflict,
		runtimeinstall.OperationStateFailedRecoverable,
	} {
		if state.String() == value {
			return state
		}
	}
	return runtimeinstall.OperationStateUnknown
}

func runtimePhaseString(phase runtimeinstall.Phase) string { return phase.String() }

func parseRuntimePhase(value string) runtimeinstall.Phase {
	if value == runtimeinstall.PhaseUnknown.String() {
		return runtimeinstall.PhaseUnknown
	}
	for _, phase := range runtimeinstall.OrderedPhases() {
		if phase.String() == value {
			return phase
		}
	}
	return runtimeinstall.PhaseUnknown
}

func runtimeOwnershipString(value runtimeinstall.OwnershipDisposition) string {
	switch value {
	case runtimeinstall.OwnershipUnknown:
		return "unknown"
	case runtimeinstall.OwnershipReusedExternal:
		return "reused_external"
	case runtimeinstall.OwnershipProvisionedByAgentMemory:
		return "provisioned_by_agentmemory"
	default:
		return "invalid"
	}
}

func parseRuntimeOwnership(value string) runtimeinstall.OwnershipDisposition {
	switch value {
	case "unknown":
		return runtimeinstall.OwnershipUnknown
	case "reused_external":
		return runtimeinstall.OwnershipReusedExternal
	case "provisioned_by_agentmemory":
		return runtimeinstall.OwnershipProvisionedByAgentMemory
	default:
		return runtimeinstall.OwnershipUnknown
	}
}

type runtimeOperationIntegrityError struct{ cause error }

func (e *runtimeOperationIntegrityError) Error() string {
	return runtimeinstallapp.ErrOperationIntegrity.Error()
}
func (e *runtimeOperationIntegrityError) Unwrap() []error {
	return []error{runtimeinstallapp.ErrOperationIntegrity, e.cause}
}

func runtimeOperationIntegrity(cause error) error {
	if cause == nil {
		cause = errors.New("runtime operation integrity could not be proven")
	}
	return &runtimeOperationIntegrityError{cause: cause}
}

type runtimeOperationConflictError struct{ cause error }

func (e *runtimeOperationConflictError) Error() string {
	return runtimeinstallapp.ErrOperationConflict.Error()
}
func (e *runtimeOperationConflictError) Unwrap() []error {
	return []error{runtimeinstallapp.ErrOperationConflict, e.cause}
}

func runtimeOperationConflict(reason string) error {
	return &runtimeOperationConflictError{cause: journalport.NewError(
		journalport.ErrorConflict, "save runtime operation", errors.New(reason),
	)}
}

func mapRuntimeJournalLoadError(err error) error {
	switch {
	case errors.Is(err, journalport.ErrNotFound):
		return runtimeinstallapp.ErrOperationNotFound
	case errors.Is(err, journalport.ErrConflict):
		return &runtimeOperationConflictError{cause: err}
	case errors.Is(err, journalport.ErrCorrupt),
		errors.Is(err, journalport.ErrInvalidSnapshot),
		errors.Is(err, journalport.ErrUnsafePermission):
		return runtimeOperationIntegrity(err)
	default:
		return err
	}
}

func mapRuntimeJournalMutationError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, journalport.ErrConflict) {
		return &runtimeOperationConflictError{cause: err}
	}
	if errors.Is(err, journalport.ErrNotFound) || errors.Is(err, journalport.ErrCorrupt) ||
		errors.Is(err, journalport.ErrInvalidSnapshot) || errors.Is(err, journalport.ErrUnsafePermission) {
		return runtimeOperationIntegrity(err)
	}
	return err
}
