// Package filesystem provides owner-controlled, authenticated local
// persistence adapters for PF-001 installation state.
package filesystem

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const operationSnapshotSchemaVersion = 3

// OperationRepositoryClock supplies deterministic UTC capture times without
// coupling the repository to ambient wall-clock state.
type OperationRepositoryClock interface {
	Now() time.Time
}

// OperationJournalProvider resolves the authenticated journal dedicated to one
// operation. Implementations must derive a separate bootstrap location using
// a fixed collision-resistant digest/encoding of the opaque identity, never
// concatenate the raw ID into a path, and never fall back to a shared journal.
type OperationJournalProvider interface {
	JournalFor(context.Context, install.OperationID) (journalport.Journal, error)
}

// OperationStateFence serializes only authenticated operation-journal
// transactions across processes. It is independent of the long-lived machine
// mutation lock, allowing cancellation intent to race phases but never the
// aggregate compare-and-swap authority.
type OperationStateFence interface {
	WithExclusive(context.Context, install.OperationID, func() error) error
}

// InstallOperationRepository stores complete installation aggregates in an
// authenticated, append-only InstallJournal.
type InstallOperationRepository struct {
	journalProvider OperationJournalProvider
	clock           OperationRepositoryClock
	fence           OperationStateFence
}

var _ installapp.OperationRepository = (*InstallOperationRepository)(nil)
var _ installapp.CancellationIntentPort = (*InstallOperationRepository)(nil)

// NewInstallOperationRepository creates a journal-backed aggregate repository.
func NewInstallOperationRepository(
	journalProvider OperationJournalProvider,
	clock OperationRepositoryClock,
	fence OperationStateFence,
) (*InstallOperationRepository, error) {
	if nilInterface(journalProvider) {
		return nil, errors.New("install operation repository journal provider is required")
	}
	if nilInterface(clock) {
		return nil, errors.New("install operation repository clock is required")
	}
	if nilInterface(fence) {
		return nil, errors.New("install operation repository state fence is required")
	}
	return &InstallOperationRepository{journalProvider: journalProvider, clock: clock, fence: fence}, nil
}

// Load authenticates, strictly decodes, and domain-validates the latest
// operation snapshot before returning an executable aggregate.
func (r *InstallOperationRepository) Load(
	ctx context.Context,
	operationID install.OperationID,
) (*install.Operation, error) {
	var operation *install.Operation
	err := r.fence.WithExclusive(ctx, operationID, func() error {
		loaded, loadError := r.loadUnfenced(ctx, operationID)
		operation = loaded
		return loadError
	})
	return operation, err
}

func (r *InstallOperationRepository) loadUnfenced(
	ctx context.Context,
	operationID install.OperationID,
) (*install.Operation, error) {
	if operationID.IsZero() {
		return nil, operationIntegrity(errors.New("journal operation identity is absent"))
	}
	journal, providerError := r.journalFor(ctx, operationID)
	if providerError != nil {
		return nil, mapJournalLoadError(providerError)
	}
	latest, err := journal.LoadLatest(ctx)
	if err != nil {
		return nil, mapJournalLoadError(err)
	}
	if latest.OperationID != operationID.String() {
		return nil, operationIntegrity(errors.New("journal operation identity mismatch"))
	}

	operation, decodeError := decodeOperationSnapshot(latest.Payload)
	if decodeError != nil {
		return nil, operationIntegrity(decodeError)
	}
	if operation.ID().String() != latest.OperationID || operation.ID().String() != operationID.String() {
		return nil, operationIntegrity(errors.New("payload operation identity mismatch"))
	}
	if confirmError := journal.ConfirmDurable(ctx, latest.OperationID, latest.Revision); confirmError != nil {
		return nil, mapJournalMutationError(confirmError)
	}
	return operation, nil
}

// Save validates and appends a complete aggregate snapshot at the next journal
// revision. The journal remains the authority for optimistic-write conflicts.
func (r *InstallOperationRepository) Save(
	ctx context.Context,
	snapshot install.OperationSnapshot,
) error {
	return r.fence.WithExclusive(ctx, snapshot.OperationID(), func() error {
		return r.saveUnfenced(ctx, snapshot)
	})
}

func (r *InstallOperationRepository) saveUnfenced(
	ctx context.Context,
	snapshot install.OperationSnapshot,
) error {
	payload, operationID, err := encodeOperationSnapshot(snapshot)
	if err != nil {
		return operationIntegrity(err)
	}
	journal, providerError := r.journalFor(ctx, snapshot.OperationID())
	if providerError != nil {
		return mapJournalMutationError(providerError)
	}

	previousRevision := uint64(0)
	latest, loadError := journal.LoadLatest(ctx)
	switch {
	case loadError == nil:
		if latest.OperationID != operationID {
			return operationConflict("journal belongs to another operation")
		}
		latestOperation, decodeError := decodeOperationSnapshot(latest.Payload)
		if decodeError != nil {
			return operationIntegrity(decodeError)
		}
		if latestOperation.ID().String() != latest.OperationID {
			return operationIntegrity(errors.New("journal envelope and payload identities differ"))
		}
		if !latestOperation.PlanDigest().Equal(snapshot.PlanDigest()) {
			return operationIntegrity(errors.New("journal and incoming snapshots use different plans"))
		}
		latestPayload, _, encodeError := encodeOperationSnapshot(latestOperation.Snapshot())
		if encodeError != nil {
			return operationIntegrity(encodeError)
		}
		latestVersion := latestOperation.AggregateVersion()
		incomingVersion := snapshot.AggregateVersion()
		switch {
		case incomingVersion < latestVersion:
			return operationConflict("incoming aggregate snapshot is stale")
		case incomingVersion == latestVersion:
			if bytes.Equal(latestPayload, payload) {
				return mapJournalMutationError(
					journal.ConfirmDurable(ctx, latest.OperationID, latest.Revision),
				)
			}
			return operationConflict("aggregate version identifies different content")
		case incomingVersion != latestVersion+1:
			return operationConflict("incoming aggregate version skips a state mutation")
		}
		if latest.Revision == math.MaxUint64 {
			return operationConflict("journal revision is exhausted")
		}
		previousRevision = latest.Revision
	case errors.Is(loadError, journalport.ErrNotFound):
		if snapshot.AggregateVersion() != 0 {
			return operationConflict("first persisted aggregate version must be zero")
		}
		// The initial aggregate follows the journal's required zero predecessor.
	default:
		return mapJournalLoadError(loadError)
	}

	capturedAt := r.clock.Now().UTC()
	if capturedAt.IsZero() {
		return operationIntegrity(journalport.NewError(
			journalport.ErrorInvalidSnapshot,
			"save operation",
			errors.New("capture time is required"),
		))
	}

	appendError := journal.Append(ctx, previousRevision, journalport.Snapshot{
		OperationID: operationID,
		Revision:    previousRevision + 1,
		CapturedAt:  capturedAt,
		Payload:     payload,
	})
	if appendError != nil {
		return mapJournalMutationError(appendError)
	}
	return nil
}

func (r *InstallOperationRepository) journalFor(
	ctx context.Context,
	operationID install.OperationID,
) (journalport.Journal, error) {
	journal, err := r.journalProvider.JournalFor(ctx, operationID)
	if err != nil {
		return nil, err
	}
	if nilInterface(journal) {
		return nil, operationIntegrity(errors.New("install operation journal provider returned no journal"))
	}
	return journal, nil
}

type operationSnapshotDTO struct {
	SchemaVersion      uint32                 `json:"schema_version"`
	OperationID        string                 `json:"operation_id"`
	PlanDigest         string                 `json:"plan_digest"`
	AggregateVersion   *uint64                `json:"aggregate_version"`
	State              string                 `json:"state"`
	CurrentPhase       string                 `json:"current_phase"`
	Attempt            uint32                 `json:"attempt"`
	CompletedSteps     []stepEvidenceDTO      `json:"completed_steps"`
	RebootCheckpoint   *rebootCheckpointDTO   `json:"reboot_checkpoint"`
	CancellationIntent *cancellationIntentDTO `json:"cancellation_intent,omitempty"`
}

type stepEvidenceDTO struct {
	Phase                  string            `json:"phase"`
	Attempt                uint32            `json:"attempt"`
	PlanDigest             string            `json:"plan_digest"`
	InputDigest            string            `json:"input_digest"`
	OutputDigest           string            `json:"output_digest"`
	VerifiedArtifactDigest *string           `json:"verified_artifact_digest"`
	Facts                  []evidenceFactDTO `json:"facts"`
	RuntimeOwnership       string            `json:"runtime_ownership"`
	CompensationBoundary   string            `json:"compensation_boundary"`
	NextSafeAction         string            `json:"next_safe_action"`
	Fingerprint            string            `json:"fingerprint"`
}

type evidenceFactDTO struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type rebootCheckpointDTO struct {
	PlanDigest     string `json:"plan_digest"`
	Phase          string `json:"phase"`
	Attempt        uint32 `json:"attempt"`
	ReceiptDigest  string `json:"receipt_digest"`
	NextSafeAction string `json:"next_safe_action"`
}

type cancellationIntentDTO struct {
	RequestedAtVersion    uint64 `json:"requested_at_version"`
	AcknowledgedAtVersion uint64 `json:"acknowledged_at_version,omitempty"`
}

func encodeOperationSnapshot(snapshot install.OperationSnapshot) ([]byte, string, error) {
	checkpoint, hasCheckpoint := snapshot.RebootCheckpoint()
	restoreInput := install.RestoreInput{
		OperationID:      snapshot.OperationID(),
		PlanDigest:       snapshot.PlanDigest(),
		AggregateVersion: snapshot.AggregateVersion(),
		State:            snapshot.State(),
		CurrentPhase:     snapshot.CurrentPhase(),
		Attempt:          snapshot.Attempt(),
		Completed:        snapshot.CompletedEvidence(),
	}
	if hasCheckpoint {
		restoreInput.RebootCheckpoint = &checkpoint
	}
	if cancellation, hasCancellation := snapshot.CancellationIntent(); hasCancellation {
		restoreInput.CancellationIntent = &install.CancellationRestoreInput{
			RequestedAtVersion:    cancellation.RequestedAtVersion(),
			AcknowledgedAtVersion: cancellation.AcknowledgedAtVersion(),
		}
	}
	operation, err := install.RestoreOperation(restoreInput)
	if err != nil {
		return nil, "", fmt.Errorf("validate operation snapshot: %w", err)
	}

	verified := operation.Snapshot()
	aggregateVersion := verified.AggregateVersion()
	dto := operationSnapshotDTO{
		SchemaVersion:    operationSnapshotSchemaVersion,
		OperationID:      verified.OperationID().String(),
		PlanDigest:       verified.PlanDigest().String(),
		AggregateVersion: &aggregateVersion,
		State:            verified.State().String(),
		CurrentPhase:     verified.CurrentPhase().String(),
		Attempt:          verified.Attempt(),
		CompletedSteps:   make([]stepEvidenceDTO, 0, len(verified.CompletedEvidence())),
	}
	for _, evidence := range verified.CompletedEvidence() {
		dto.CompletedSteps = append(dto.CompletedSteps, encodeStepEvidence(evidence))
	}
	if restoredCheckpoint, exists := verified.RebootCheckpoint(); exists {
		dto.RebootCheckpoint = &rebootCheckpointDTO{
			PlanDigest:     restoredCheckpoint.PlanDigest().String(),
			Phase:          restoredCheckpoint.Phase().String(),
			Attempt:        restoredCheckpoint.Attempt(),
			ReceiptDigest:  restoredCheckpoint.ReceiptDigest().String(),
			NextSafeAction: restoredCheckpoint.NextSafeAction().String(),
		}
	}
	if cancellation, exists := verified.CancellationIntent(); exists {
		dto.CancellationIntent = &cancellationIntentDTO{
			RequestedAtVersion:    cancellation.RequestedAtVersion(),
			AcknowledgedAtVersion: cancellation.AcknowledgedAtVersion(),
		}
	}

	encoded, err := json.Marshal(dto)
	if err != nil {
		return nil, "", errors.New("encode operation snapshot")
	}
	return encoded, dto.OperationID, nil
}

func encodeStepEvidence(evidence install.StepEvidence) stepEvidenceDTO {
	facts := evidence.Facts()
	dtoFacts := make([]evidenceFactDTO, 0, len(facts))
	for _, fact := range facts {
		dtoFacts = append(dtoFacts, evidenceFactDTO{Name: fact.Name(), Value: fact.Value()})
	}

	var artifactDigest *string
	if artifact := evidence.VerifiedArtifactDigest(); !artifact.IsZero() {
		value := artifact.String()
		artifactDigest = &value
	}
	return stepEvidenceDTO{
		Phase:                  evidence.Phase().String(),
		Attempt:                evidence.Attempt(),
		PlanDigest:             evidence.PlanDigest().String(),
		InputDigest:            evidence.InputDigest().String(),
		OutputDigest:           evidence.OutputDigest().String(),
		VerifiedArtifactDigest: artifactDigest,
		Facts:                  dtoFacts,
		RuntimeOwnership:       evidence.RuntimeOwnership().String(),
		CompensationBoundary:   evidence.CompensationBoundary().String(),
		NextSafeAction:         evidence.NextSafeAction().String(),
		Fingerprint:            evidence.Fingerprint().String(),
	}
}

func decodeOperationSnapshot(payload []byte) (*install.Operation, error) {
	if err := rejectDuplicateJSONKeys(payload); err != nil {
		return nil, errors.New("operation snapshot JSON is malformed")
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var dto operationSnapshotDTO
	if err := decoder.Decode(&dto); err != nil {
		return nil, errors.New("operation snapshot JSON does not match its schema")
	}
	if err := requireJSONEnd(decoder); err != nil {
		return nil, errors.New("operation snapshot JSON contains trailing data")
	}
	if dto.SchemaVersion != 2 && dto.SchemaVersion != operationSnapshotSchemaVersion {
		return nil, errors.New("operation snapshot schema version is unsupported")
	}
	if dto.CompletedSteps == nil {
		return nil, errors.New("operation snapshot completed steps are absent")
	}
	if dto.AggregateVersion == nil {
		return nil, errors.New("operation snapshot aggregate version is absent")
	}

	operationID, err := install.NewOperationID(dto.OperationID)
	if err != nil {
		return nil, errors.New("operation snapshot identity is invalid")
	}
	planDigest, err := install.ParsePlanDigest(dto.PlanDigest)
	if err != nil {
		return nil, errors.New("operation snapshot plan digest is invalid")
	}
	state, err := decodeState(dto.State)
	if err != nil {
		return nil, err
	}
	currentPhase, err := decodePhase(dto.CurrentPhase)
	if err != nil {
		return nil, err
	}

	completed := make([]install.StepEvidence, 0, len(dto.CompletedSteps))
	for _, evidenceDTO := range dto.CompletedSteps {
		evidence, decodeError := decodeStepEvidence(evidenceDTO)
		if decodeError != nil {
			return nil, decodeError
		}
		completed = append(completed, evidence)
	}

	restoreInput := install.RestoreInput{
		OperationID:      operationID,
		PlanDigest:       planDigest,
		AggregateVersion: *dto.AggregateVersion,
		State:            state,
		CurrentPhase:     currentPhase,
		Attempt:          dto.Attempt,
		Completed:        completed,
	}
	if dto.RebootCheckpoint != nil {
		checkpoint, checkpointError := decodeRebootCheckpoint(*dto.RebootCheckpoint)
		if checkpointError != nil {
			return nil, checkpointError
		}
		restoreInput.RebootCheckpoint = &checkpoint
	}
	if dto.CancellationIntent != nil {
		restoreInput.CancellationIntent = &install.CancellationRestoreInput{
			RequestedAtVersion:    dto.CancellationIntent.RequestedAtVersion,
			AcknowledgedAtVersion: dto.CancellationIntent.AcknowledgedAtVersion,
		}
	}

	operation, err := install.RestoreOperation(restoreInput)
	if err != nil {
		return nil, errors.New("operation snapshot violates installation invariants")
	}
	return operation, nil
}

func decodeStepEvidence(dto stepEvidenceDTO) (install.StepEvidence, error) {
	if dto.Facts == nil {
		return install.StepEvidence{}, errors.New("step evidence facts are absent")
	}
	phase, err := decodePhase(dto.Phase)
	if err != nil {
		return install.StepEvidence{}, err
	}
	planDigest, err := install.ParsePlanDigest(dto.PlanDigest)
	if err != nil {
		return install.StepEvidence{}, errors.New("step evidence plan digest is invalid")
	}
	inputDigest, err := install.ParseDigest(dto.InputDigest)
	if err != nil {
		return install.StepEvidence{}, errors.New("step evidence input digest is invalid")
	}
	outputDigest, err := install.ParseDigest(dto.OutputDigest)
	if err != nil {
		return install.StepEvidence{}, errors.New("step evidence output digest is invalid")
	}

	artifactDigest := install.Digest{}
	if dto.VerifiedArtifactDigest != nil {
		artifactDigest, err = install.ParseDigest(*dto.VerifiedArtifactDigest)
		if err != nil {
			return install.StepEvidence{}, errors.New("step evidence artifact digest is invalid")
		}
	}
	ownership, err := decodeRuntimeOwnership(dto.RuntimeOwnership)
	if err != nil {
		return install.StepEvidence{}, err
	}
	boundary, err := install.NewCompensationBoundary(dto.CompensationBoundary)
	if err != nil {
		return install.StepEvidence{}, errors.New("step evidence compensation boundary is invalid")
	}
	nextAction, err := install.NewSafeAction(dto.NextSafeAction)
	if err != nil {
		return install.StepEvidence{}, errors.New("step evidence next action is invalid")
	}

	facts := make([]install.NonSecretFact, 0, len(dto.Facts))
	for _, factDTO := range dto.Facts {
		fact, factError := install.NewNonSecretFact(factDTO.Name, factDTO.Value)
		if factError != nil {
			return install.StepEvidence{}, errors.New("step evidence fact is invalid")
		}
		facts = append(facts, fact)
	}

	evidence, err := install.NewStepEvidence(install.StepEvidenceInput{
		Phase:                  phase,
		Attempt:                dto.Attempt,
		PlanDigest:             planDigest,
		InputDigest:            inputDigest,
		OutputDigest:           outputDigest,
		VerifiedArtifactDigest: artifactDigest,
		Facts:                  facts,
		RuntimeOwnership:       ownership,
		CompensationBoundary:   boundary,
		NextSafeAction:         nextAction,
	})
	if err != nil {
		return install.StepEvidence{}, errors.New("step evidence violates installation invariants")
	}
	persistedFingerprint, err := install.ParseDigest(dto.Fingerprint)
	if err != nil || !persistedFingerprint.Equal(evidence.Fingerprint()) {
		return install.StepEvidence{}, errors.New("step evidence fingerprint does not match its fields")
	}
	return evidence, nil
}

func decodeRebootCheckpoint(dto rebootCheckpointDTO) (install.RebootCheckpoint, error) {
	planDigest, err := install.ParsePlanDigest(dto.PlanDigest)
	if err != nil {
		return install.RebootCheckpoint{}, errors.New("reboot checkpoint plan digest is invalid")
	}
	phase, err := decodePhase(dto.Phase)
	if err != nil {
		return install.RebootCheckpoint{}, err
	}
	receiptDigest, err := install.ParseDigest(dto.ReceiptDigest)
	if err != nil {
		return install.RebootCheckpoint{}, errors.New("reboot checkpoint receipt digest is invalid")
	}
	nextAction, err := install.NewSafeAction(dto.NextSafeAction)
	if err != nil {
		return install.RebootCheckpoint{}, errors.New("reboot checkpoint next action is invalid")
	}
	checkpoint, err := install.NewRebootCheckpoint(planDigest, phase, dto.Attempt, receiptDigest, nextAction)
	if err != nil {
		return install.RebootCheckpoint{}, errors.New("reboot checkpoint violates installation invariants")
	}
	return checkpoint, nil
}

func decodePhase(value string) (install.Phase, error) {
	switch value {
	case "VerifyHost":
		return install.PhaseVerifyHost, nil
	case "EnsureContainerRuntime":
		return install.PhaseEnsureContainerRuntime, nil
	case "VerifyRelease":
		return install.PhaseVerifyRelease, nil
	case "ReserveSpace":
		return install.PhaseReserveSpace, nil
	case "EnsureDirectories":
		return install.PhaseEnsureDirectories, nil
	case "EnsureKeys":
		return install.PhaseEnsureKeys, nil
	case "EnsureComposeBundle":
		return install.PhaseEnsureComposeBundle, nil
	case "EnsureNetworkAndVolumes":
		return install.PhaseEnsureNetworkAndVolumes, nil
	case "RunMigrations":
		return install.PhaseRunMigrations, nil
	case "EnsureCoreAndGraph":
		return install.PhaseEnsureCoreAndGraph, nil
	case "BootstrapLocalBrain":
		return install.PhaseBootstrapLocalBrain, nil
	case "MergeAgentConfiguration":
		return install.PhaseMergeAgentConfiguration, nil
	case "VerifyReadiness":
		return install.PhaseVerifyReadiness, nil
	case "CommitActiveRelease":
		return install.PhaseCommitActiveRelease, nil
	default:
		return install.PhaseUnknown, errors.New("operation snapshot phase is unsupported")
	}
}

func decodeState(value string) (install.State, error) {
	switch value {
	case "Running":
		return install.StateRunning, nil
	case "RebootPending":
		return install.StateRebootPending, nil
	case "ResumeVerified":
		return install.StateResumeVerified, nil
	case "FailedRecoverable":
		return install.StateFailedRecoverable, nil
	case "PausedForAdministrator":
		return install.StatePausedForAdministrator, nil
	case "Cancelled":
		return install.StateCancelled, nil
	case "UnsupportedHost":
		return install.StateUnsupportedHost, nil
	case "RuntimeConflict":
		return install.StateRuntimeConflict, nil
	case "Ready":
		return install.StateReady, nil
	default:
		return install.StateUnknown, errors.New("operation snapshot state is unsupported")
	}
}

func decodeRuntimeOwnership(value string) (install.RuntimeOwnership, error) {
	switch value {
	case "undetermined":
		return install.RuntimeOwnershipUndetermined, nil
	case "reused_external":
		return install.RuntimeOwnershipReusedExternal, nil
	case "provisioned_by_agentmemory":
		return install.RuntimeOwnershipProvisionedByAgentMemory, nil
	case "not_applicable":
		return install.RuntimeOwnershipNotApplicable, nil
	default:
		return install.RuntimeOwnershipUnknown, errors.New("step evidence runtime ownership is unsupported")
	}
}

func rejectDuplicateJSONKeys(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	return requireJSONEnd(decoder)
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}

	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyError := decoder.Token()
			if keyError != nil {
				return keyError
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("JSON object contains a duplicate key")
			}
			seen[key] = struct{}{}
			if valueError := scanJSONValue(decoder); valueError != nil {
				return valueError
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if valueError := scanJSONValue(decoder); valueError != nil {
				return valueError
			}
		}
		_, err = decoder.Token()
		return err
	case '}', ']':
		return errors.New("JSON value starts with a closing delimiter")
	default:
		return errors.New("JSON value has an unsupported delimiter")
	}
}

func requireJSONEnd(decoder *json.Decoder) error {
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON contains trailing data")
		}
		return err
	}
	return nil
}

type operationIntegrityError struct {
	cause error
}

func (e *operationIntegrityError) Error() string {
	return installapp.ErrOperationIntegrity.Error()
}

func (e *operationIntegrityError) Unwrap() []error {
	return []error{installapp.ErrOperationIntegrity, e.cause}
}

func operationIntegrity(cause error) error {
	if cause == nil {
		cause = errors.New("operation snapshot integrity could not be proven")
	}
	return &operationIntegrityError{cause: cause}
}

func operationConflict(reason string) error {
	cause := journalport.NewError(
		journalport.ErrorConflict,
		"save operation",
		errors.New(reason),
	)
	return &operationConflictError{cause: cause}
}

type operationConflictError struct {
	cause error
}

func (e *operationConflictError) Error() string {
	return installapp.ErrOperationConflict.Error()
}

func (e *operationConflictError) Unwrap() []error {
	return []error{installapp.ErrOperationConflict, e.cause}
}

func mapJournalLoadError(err error) error {
	switch {
	case errors.Is(err, journalport.ErrNotFound):
		return installapp.ErrOperationNotFound
	case errors.Is(err, journalport.ErrConflict):
		return &operationConflictError{cause: err}
	case errors.Is(err, journalport.ErrCorrupt),
		errors.Is(err, journalport.ErrInvalidSnapshot),
		errors.Is(err, journalport.ErrUnsafePermission):
		return operationIntegrity(err)
	default:
		return err
	}
}

func mapJournalMutationError(err error) error {
	if errors.Is(err, journalport.ErrNotFound) {
		return operationIntegrity(err)
	}
	if errors.Is(err, journalport.ErrConflict) {
		return &operationConflictError{cause: err}
	}
	if errors.Is(err, journalport.ErrCorrupt) ||
		errors.Is(err, journalport.ErrUnsafePermission) ||
		errors.Is(err, journalport.ErrInvalidSnapshot) {
		return operationIntegrity(err)
	}
	return err
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid,
		reflect.Bool,
		reflect.Int,
		reflect.Int8,
		reflect.Int16,
		reflect.Int32,
		reflect.Int64,
		reflect.Uint,
		reflect.Uint8,
		reflect.Uint16,
		reflect.Uint32,
		reflect.Uint64,
		reflect.Uintptr,
		reflect.Float32,
		reflect.Float64,
		reflect.Complex64,
		reflect.Complex128,
		reflect.Array,
		reflect.String,
		reflect.Struct,
		reflect.UnsafePointer:
		return false
	}
	return false
}
