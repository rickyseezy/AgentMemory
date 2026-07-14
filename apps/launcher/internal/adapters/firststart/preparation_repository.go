package firststart

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/firststartapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const (
	preparationSchemaVersion = uint16(1)
	maximumPreparationBytes  = 32 * 1024
)

// PreparationJournalProvider supplies a purpose-separated authenticated and
// rollback-anchored journal for the pristine-start selection state.
type PreparationJournalProvider interface {
	JournalFor(context.Context, install.OperationID) (installjournal.Journal, error)
}

// PreparationClock supplies durable UTC capture times.
type PreparationClock interface{ Now() time.Time }

// PreparationRepository persists the crash-safe identifier and template
// selection before any installation plan can be published.
type PreparationRepository struct {
	journals PreparationJournalProvider
	clock    PreparationClock
}

// NewPreparationRepository rejects unprotected or incomplete composition.
func NewPreparationRepository(
	journals PreparationJournalProvider,
	clock PreparationClock,
) (*PreparationRepository, error) {
	if nilPreparationDependency(journals) || nilPreparationDependency(clock) {
		return nil, firststartapp.ErrIntegrity
	}
	return &PreparationRepository{journals: journals, clock: clock}, nil
}

// Load authenticates and confirms the current per-host preparation state.
func (r *PreparationRepository) Load(
	ctx context.Context,
	host agentconfigdomain.AgentHost,
) (firststartapp.Preparation, error) {
	journal, operationID, err := r.journal(ctx, host)
	if err != nil {
		return firststartapp.Preparation{}, err
	}
	snapshot, err := journal.LoadLatest(ctx)
	if err != nil {
		return firststartapp.Preparation{}, mapPreparationJournalError(err)
	}
	state, err := decodePreparation(snapshot, operationID, host)
	if err != nil {
		return firststartapp.Preparation{}, err
	}
	if err := journal.ConfirmDurable(ctx, operationID.String(), snapshot.Revision); err != nil {
		return firststartapp.Preparation{}, mapPreparationJournalError(err)
	}
	return state, nil
}

// Acquire atomically selects one winner and returns the already-selected
// winner to concurrent callers. A losing candidate is never merged.
func (r *PreparationRepository) Acquire(
	ctx context.Context,
	candidate firststartapp.Preparation,
) (firststartapp.Preparation, error) {
	if r == nil || ctx == nil || !candidate.Valid() || candidate.Confirmed() {
		return firststartapp.Preparation{}, firststartapp.ErrIntegrity
	}
	journal, operationID, err := r.journal(ctx, candidate.Host())
	if err != nil {
		return firststartapp.Preparation{}, err
	}
	if snapshot, loadErr := journal.LoadLatest(ctx); loadErr == nil {
		return r.confirmSnapshot(ctx, journal, snapshot, operationID, candidate.Host())
	} else if !errors.Is(loadErr, installjournal.ErrNotFound) {
		return firststartapp.Preparation{}, mapPreparationJournalError(loadErr)
	}
	payload, err := encodePreparation(candidate)
	if err != nil {
		return firststartapp.Preparation{}, err
	}
	snapshot, err := r.snapshot(operationID, 1, payload)
	if err != nil {
		return firststartapp.Preparation{}, err
	}
	appendErr := journal.Append(ctx, 0, snapshot)
	if appendErr == nil {
		if err = journal.ConfirmDurable(ctx, operationID.String(), 1); err != nil {
			return firststartapp.Preparation{}, mapPreparationJournalError(err)
		}
		return candidate, nil
	}
	// Append can lose a race or return an ambiguous post-commit error. Only an
	// authenticated winner read resolves either condition.
	observed, loadErr := journal.LoadLatest(ctx)
	if loadErr != nil {
		return firststartapp.Preparation{}, mapPreparationJournalError(appendErr)
	}
	return r.confirmSnapshot(ctx, journal, observed, operationID, candidate.Host())
}

// ConfirmPlan publishes the sole legal successor and rejects any changed
// preparation or plan digest.
func (r *PreparationRepository) ConfirmPlan(
	ctx context.Context,
	expected firststartapp.Preparation,
	digest install.PlanDigest,
) (firststartapp.Preparation, error) {
	if r == nil || ctx == nil || !expected.Valid() || expected.Confirmed() || digest.IsZero() {
		return firststartapp.Preparation{}, firststartapp.ErrIntegrity
	}
	journal, operationID, err := r.journal(ctx, expected.Host())
	if err != nil {
		return firststartapp.Preparation{}, err
	}
	currentSnapshot, err := journal.LoadLatest(ctx)
	if err != nil {
		return firststartapp.Preparation{}, mapPreparationJournalError(err)
	}
	current, err := decodePreparation(currentSnapshot, operationID, expected.Host())
	if err != nil {
		return firststartapp.Preparation{}, err
	}
	if !samePreparation(current, expected) {
		return firststartapp.Preparation{}, firststartapp.ErrConflict
	}
	confirmed, err := expected.WithConfirmedPlan(digest)
	if err != nil {
		return firststartapp.Preparation{}, err
	}
	payload, err := encodePreparation(confirmed)
	if err != nil {
		return firststartapp.Preparation{}, err
	}
	nextRevision := currentSnapshot.Revision + 1
	if nextRevision != 2 {
		return firststartapp.Preparation{}, firststartapp.ErrIntegrity
	}
	next, err := r.snapshot(operationID, nextRevision, payload)
	if err != nil {
		return firststartapp.Preparation{}, err
	}
	appendErr := journal.Append(ctx, currentSnapshot.Revision, next)
	if appendErr == nil {
		if err = journal.ConfirmDurable(ctx, operationID.String(), nextRevision); err != nil {
			return firststartapp.Preparation{}, mapPreparationJournalError(err)
		}
		return confirmed, nil
	}
	observed, loadErr := journal.LoadLatest(ctx)
	if loadErr != nil {
		return firststartapp.Preparation{}, mapPreparationJournalError(appendErr)
	}
	resolved, decodeErr := decodePreparation(observed, operationID, expected.Host())
	if decodeErr != nil || !samePreparation(resolved, confirmed) || !resolved.Confirmed() {
		return firststartapp.Preparation{}, firststartapp.ErrConflict
	}
	if err = journal.ConfirmDurable(ctx, operationID.String(), observed.Revision); err != nil {
		return firststartapp.Preparation{}, mapPreparationJournalError(err)
	}
	return resolved, nil
}

func (r *PreparationRepository) confirmSnapshot(
	ctx context.Context,
	journal installjournal.Journal,
	snapshot installjournal.Snapshot,
	operationID install.OperationID,
	host agentconfigdomain.AgentHost,
) (firststartapp.Preparation, error) {
	state, err := decodePreparation(snapshot, operationID, host)
	if err != nil {
		return firststartapp.Preparation{}, err
	}
	if err := journal.ConfirmDurable(ctx, operationID.String(), snapshot.Revision); err != nil {
		return firststartapp.Preparation{}, mapPreparationJournalError(err)
	}
	return state, nil
}

func (r *PreparationRepository) journal(
	ctx context.Context,
	host agentconfigdomain.AgentHost,
) (installjournal.Journal, install.OperationID, error) {
	if r == nil || ctx == nil || !host.Valid() || nilPreparationDependency(r.journals) {
		return nil, install.OperationID{}, firststartapp.ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, install.OperationID{}, err
	}
	operationID, err := preparationOperationID(host)
	if err != nil {
		return nil, install.OperationID{}, err
	}
	journal, err := r.journals.JournalFor(ctx, operationID)
	if err != nil {
		return nil, install.OperationID{}, mapPreparationJournalError(err)
	}
	if nilPreparationDependency(journal) {
		return nil, install.OperationID{}, firststartapp.ErrIntegrity
	}
	return journal, operationID, nil
}

func (r *PreparationRepository) snapshot(
	operationID install.OperationID,
	revision uint64,
	payload []byte,
) (installjournal.Snapshot, error) {
	capturedAt := r.clock.Now().UTC().Truncate(time.Microsecond)
	if capturedAt.IsZero() || revision == 0 || len(payload) == 0 {
		return installjournal.Snapshot{}, firststartapp.ErrIntegrity
	}
	return installjournal.Snapshot{
		OperationID: operationID.String(), Revision: revision,
		CapturedAt: capturedAt, Payload: append([]byte(nil), payload...),
	}, nil
}

func preparationOperationID(host agentconfigdomain.AgentHost) (install.OperationID, error) {
	if !host.Valid() {
		return install.OperationID{}, firststartapp.ErrIntegrity
	}
	operationID, err := install.NewOperationID("first-start-preparation-" + string(host) + "-v1")
	if err != nil {
		return install.OperationID{}, firststartapp.ErrIntegrity
	}
	return operationID, nil
}

type preparationDocument struct {
	SchemaVersion       uint16 `json:"schema_version"`
	Host                string `json:"host"`
	TemplateDigest      string `json:"template_digest"`
	OperationID         string `json:"operation_id"`
	InstallationID      string `json:"installation_id"`
	GenerationID        string `json:"generation_id"`
	BrainID             string `json:"brain_id"`
	OwnerPrincipalID    string `json:"owner_principal_id"`
	OwnerGrantID        string `json:"owner_grant_id"`
	AgentEntryID        string `json:"agent_entry_id"`
	SecurityEpoch       uint64 `json:"security_epoch"`
	ConfirmedPlanDigest string `json:"confirmed_plan_digest,omitempty"`
}

func encodePreparation(state firststartapp.Preparation) ([]byte, error) {
	if !state.Valid() {
		return nil, firststartapp.ErrIntegrity
	}
	document := preparationDocument{
		SchemaVersion: preparationSchemaVersion, Host: string(state.Host()),
		TemplateDigest: state.TemplateDigest().String(), OperationID: state.OperationID().String(),
		InstallationID: state.InstallationID(), GenerationID: state.GenerationID(), BrainID: state.BrainID(),
		OwnerPrincipalID: state.OwnerPrincipalID(), OwnerGrantID: state.OwnerGrantID(),
		AgentEntryID: state.AgentEntryID(), SecurityEpoch: state.SecurityEpoch(),
	}
	if state.Confirmed() {
		document.ConfirmedPlanDigest = state.ConfirmedPlanDigest().String()
	}
	payload, err := json.Marshal(document)
	if err != nil || len(payload) > maximumPreparationBytes {
		return nil, firststartapp.ErrIntegrity
	}
	return payload, nil
}

func decodePreparation(
	snapshot installjournal.Snapshot,
	operationID install.OperationID,
	host agentconfigdomain.AgentHost,
) (firststartapp.Preparation, error) {
	if snapshot.OperationID != operationID.String() || snapshot.Revision == 0 || snapshot.Revision > 2 ||
		snapshot.CapturedAt.IsZero() || len(snapshot.Payload) == 0 || len(snapshot.Payload) > maximumPreparationBytes {
		return firststartapp.Preparation{}, firststartapp.ErrIntegrity
	}
	var document preparationDocument
	decoder := json.NewDecoder(bytes.NewReader(snapshot.Payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil || decoder.More() {
		return firststartapp.Preparation{}, firststartapp.ErrIntegrity
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, snapshot.Payload) ||
		document.SchemaVersion != preparationSchemaVersion || document.Host != string(host) {
		return firststartapp.Preparation{}, firststartapp.ErrIntegrity
	}
	templateDigest, err := install.ParsePlanDigest(document.TemplateDigest)
	if err != nil {
		return firststartapp.Preparation{}, firststartapp.ErrIntegrity
	}
	selectedOperation, err := install.NewOperationID(document.OperationID)
	if err != nil {
		return firststartapp.Preparation{}, firststartapp.ErrIntegrity
	}
	state, err := firststartapp.NewPreparation(host, templateDigest, selectedOperation, []string{
		document.InstallationID, document.GenerationID, document.BrainID,
		document.OwnerPrincipalID, document.OwnerGrantID, document.AgentEntryID,
	}, document.SecurityEpoch)
	if err != nil {
		return firststartapp.Preparation{}, firststartapp.ErrIntegrity
	}
	if document.ConfirmedPlanDigest != "" {
		confirmed, parseErr := install.ParsePlanDigest(document.ConfirmedPlanDigest)
		if parseErr != nil {
			return firststartapp.Preparation{}, firststartapp.ErrIntegrity
		}
		state, err = state.WithConfirmedPlan(confirmed)
		if err != nil {
			return firststartapp.Preparation{}, firststartapp.ErrIntegrity
		}
	}
	if (snapshot.Revision == 1) != !state.Confirmed() {
		return firststartapp.Preparation{}, firststartapp.ErrIntegrity
	}
	return state, nil
}

func samePreparation(left, right firststartapp.Preparation) bool {
	leftBytes, leftErr := encodePreparation(left)
	rightBytes, rightErr := encodePreparation(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func mapPreparationJournalError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	switch {
	case errors.Is(err, installjournal.ErrNotFound):
		return firststartapp.ErrPreparationNotFound
	case errors.Is(err, installjournal.ErrConflict):
		return firststartapp.ErrConflict
	case errors.Is(err, installjournal.ErrCorrupt), errors.Is(err, installjournal.ErrUnsafePermission),
		errors.Is(err, installjournal.ErrInvalidSnapshot):
		return firststartapp.ErrIntegrity
	default:
		return firststartapp.ErrUnavailable
	}
}

func nilPreparationDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Every non-nilable concrete kind is a valid capability.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ firststartapp.PreparationRepository = (*PreparationRepository)(nil)
