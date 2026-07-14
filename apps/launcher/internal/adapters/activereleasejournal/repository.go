// Package activereleasejournal persists the crash-resumable activation saga
// and host active-release pointer in purpose-separated, authenticated,
// rollback-anchored journals.
package activereleasejournal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/activereleaseapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/activerelease"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const (
	activationSchema = uint16(1)
	pointerSchema    = uint16(1)
	maximumStateSize = 128 * 1024
)

// JournalProvider returns a protected journal from one purpose-specific
// namespace. Production composition supplies the native rollback-anchored
// operation journal provider, never a plain file store.
type JournalProvider interface {
	JournalFor(context.Context, install.OperationID) (installjournal.Journal, error)
}

// Clock supplies durable snapshot timestamps without ambient time access.
type Clock interface{ Now() time.Time }

// ActivationRepository stores the activation cursor. Its provider root must
// be distinct from install-operation and active-pointer journal roots.
type ActivationRepository struct {
	provider JournalProvider
	clock    Clock
}

// HostPointerRepository stores the monotonic host pointer. Its provider root
// must be distinct from the activation repository root.
type HostPointerRepository struct {
	provider JournalProvider
	clock    Clock
}

// NewActivationRepository creates a fail-closed activation repository.
func NewActivationRepository(provider JournalProvider, clock Clock) (*ActivationRepository, error) {
	if nilCapability(provider) || nilCapability(clock) {
		return nil, activereleaseapp.ErrActivationIntegrity
	}
	return &ActivationRepository{provider: provider, clock: clock}, nil
}

// NewHostPointerRepository creates a fail-closed host pointer repository.
func NewHostPointerRepository(provider JournalProvider, clock Clock) (*HostPointerRepository, error) {
	if nilCapability(provider) || nilCapability(clock) {
		return nil, activereleaseapp.ErrPointerIntegrity
	}
	return &HostPointerRepository{provider: provider, clock: clock}, nil
}

// Load restores one authenticated activation aggregate.
func (r *ActivationRepository) Load(
	ctx context.Context,
	operationID install.OperationID,
) (*activerelease.Activation, error) {
	if r == nil || ctx == nil || operationID.IsZero() {
		return nil, activereleaseapp.ErrActivationIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	journal, err := r.activationJournal(ctx, operationID)
	if err != nil {
		return nil, mapActivationJournalError(err)
	}
	snapshot, err := journal.LoadLatest(ctx)
	if err != nil {
		return nil, mapActivationJournalError(err)
	}
	activation, err := decodeActivation(snapshot, operationID)
	if err != nil {
		return nil, activereleaseapp.ErrActivationIntegrity
	}
	if err := journal.ConfirmDurable(ctx, snapshot.OperationID, snapshot.Revision); err != nil {
		return nil, mapActivationJournalError(err)
	}
	return activation, nil
}

// Save performs optimistic append by aggregate version. Exact replay only
// re-confirms durability; stale or skipped versions conflict.
func (r *ActivationRepository) Save(
	ctx context.Context,
	next activerelease.ActivationSnapshot,
) error {
	if r == nil || ctx == nil {
		return activereleaseapp.ErrActivationIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	operationID, err := install.NewOperationID(next.OperationID)
	if err != nil {
		return activereleaseapp.ErrActivationIntegrity
	}
	canonical, restored, err := encodeActivation(next)
	if err != nil || restored.OperationID() != operationID {
		return activereleaseapp.ErrActivationIntegrity
	}
	journal, err := r.activationJournal(ctx, operationID)
	if err != nil {
		return mapActivationJournalError(err)
	}
	expectedRevision := uint64(0)
	current, loadError := journal.LoadLatest(ctx)
	switch {
	case errors.Is(loadError, installjournal.ErrNotFound):
		if next.Version != 0 {
			return activereleaseapp.ErrActivationConflict
		}
	case loadError != nil:
		return mapActivationJournalError(loadError)
	default:
		persisted, decodeError := decodeActivation(current, operationID)
		if decodeError != nil {
			return activereleaseapp.ErrActivationIntegrity
		}
		persistedCanonical, _, encodeError := encodeActivation(persisted.Snapshot())
		if encodeError != nil {
			return activereleaseapp.ErrActivationIntegrity
		}
		if bytes.Equal(persistedCanonical, canonical) {
			return mapActivationJournalError(journal.ConfirmDurable(ctx, current.OperationID, current.Revision))
		}
		if current.Revision == ^uint64(0) || persisted.Version() == ^uint64(0) ||
			next.Version != persisted.Version()+1 || current.Revision != persisted.Version()+1 {
			return activereleaseapp.ErrActivationConflict
		}
		expectedRevision = current.Revision
	}
	capturedAt := r.clock.Now().UTC().Truncate(time.Microsecond)
	if capturedAt.IsZero() {
		return activereleaseapp.ErrActivationIntegrity
	}
	if err := journal.Append(ctx, expectedRevision, installjournal.Snapshot{
		OperationID: operationID.String(), Revision: next.Version + 1,
		CapturedAt: capturedAt, Payload: canonical,
	}); err != nil {
		return mapActivationJournalError(err)
	}
	return nil
}

func (r *ActivationRepository) activationJournal(
	ctx context.Context,
	operationID install.OperationID,
) (installjournal.Journal, error) {
	if nilCapability(r.provider) {
		return nil, activereleaseapp.ErrActivationIntegrity
	}
	journal, err := r.provider.JournalFor(ctx, operationID)
	if err != nil || nilCapability(journal) {
		if err == nil {
			err = activereleaseapp.ErrActivationIntegrity
		}
		return nil, err
	}
	return journal, nil
}

// Load restores and re-confirms the host pointer for one installation.
func (r *HostPointerRepository) Load(
	ctx context.Context,
	installationID string,
) (activerelease.Pointer, error) {
	operationID, err := pointerOperationID(installationID)
	if r == nil || ctx == nil || err != nil {
		return activerelease.Pointer{}, activereleaseapp.ErrPointerIntegrity
	}
	if err := ctx.Err(); err != nil {
		return activerelease.Pointer{}, err
	}
	journal, err := r.pointerJournal(ctx, operationID)
	if err != nil {
		return activerelease.Pointer{}, mapPointerJournalError(err)
	}
	snapshot, err := journal.LoadLatest(ctx)
	if err != nil {
		return activerelease.Pointer{}, mapPointerJournalError(err)
	}
	pointer, err := decodePointer(snapshot, operationID, installationID)
	if err != nil {
		return activerelease.Pointer{}, activereleaseapp.ErrPointerIntegrity
	}
	if err := journal.ConfirmDurable(ctx, snapshot.OperationID, snapshot.Revision); err != nil {
		return activerelease.Pointer{}, mapPointerJournalError(err)
	}
	return pointer, nil
}

// CompareAndSwap appends a monotonic successor only when the authenticated
// current digest exactly equals expected. A zero expected digest is first-write
// authority only.
func (r *HostPointerRepository) CompareAndSwap(
	ctx context.Context,
	expected install.Digest,
	next activerelease.Pointer,
) error {
	operationID, err := pointerOperationID(next.InstallationID())
	if r == nil || ctx == nil || err != nil || next.IsZero() {
		return activereleaseapp.ErrPointerIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	canonical, restored, err := encodePointer(next.Record())
	if err != nil || !restored.Digest().Equal(next.Digest()) {
		return activereleaseapp.ErrPointerIntegrity
	}
	journal, err := r.pointerJournal(ctx, operationID)
	if err != nil {
		return mapPointerJournalError(err)
	}
	expectedRevision := uint64(0)
	currentSnapshot, loadError := journal.LoadLatest(ctx)
	switch {
	case errors.Is(loadError, installjournal.ErrNotFound):
		if !expected.IsZero() {
			return activereleaseapp.ErrPointerConflict
		}
	case loadError != nil:
		return mapPointerJournalError(loadError)
	default:
		current, decodeError := decodePointer(currentSnapshot, operationID, next.InstallationID())
		if decodeError != nil {
			return activereleaseapp.ErrPointerIntegrity
		}
		if current.Digest().Equal(next.Digest()) && expected.Equal(current.Digest()) {
			return mapPointerJournalError(journal.ConfirmDurable(
				ctx, currentSnapshot.OperationID, currentSnapshot.Revision,
			))
		}
		if !current.Digest().Equal(expected) ||
			activerelease.DecideReplacement(current, next) != activerelease.DecisionActivate ||
			currentSnapshot.Revision == ^uint64(0) {
			return activereleaseapp.ErrPointerConflict
		}
		expectedRevision = currentSnapshot.Revision
	}
	capturedAt := r.clock.Now().UTC().Truncate(time.Microsecond)
	if capturedAt.IsZero() {
		return activereleaseapp.ErrPointerIntegrity
	}
	if err := journal.Append(ctx, expectedRevision, installjournal.Snapshot{
		OperationID: operationID.String(), Revision: expectedRevision + 1,
		CapturedAt: capturedAt, Payload: canonical,
	}); err != nil {
		return mapPointerJournalError(err)
	}
	return nil
}

// ConfirmDurable re-authenticates the exact current pointer and its rollback
// anchor after the compare-and-swap acknowledgement.
func (r *HostPointerRepository) ConfirmDurable(
	ctx context.Context,
	expected activerelease.Pointer,
) error {
	if expected.IsZero() {
		return activereleaseapp.ErrPointerIntegrity
	}
	if ctx == nil {
		return activereleaseapp.ErrPointerIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	current, err := r.Load(ctx, expected.InstallationID())
	if err != nil {
		return err
	}
	if !current.Digest().Equal(expected.Digest()) {
		return activereleaseapp.ErrPointerConflict
	}
	return nil
}

func (r *HostPointerRepository) pointerJournal(
	ctx context.Context,
	operationID install.OperationID,
) (installjournal.Journal, error) {
	if nilCapability(r.provider) {
		return nil, activereleaseapp.ErrPointerIntegrity
	}
	journal, err := r.provider.JournalFor(ctx, operationID)
	if err != nil || nilCapability(journal) {
		if err == nil {
			err = activereleaseapp.ErrPointerIntegrity
		}
		return nil, err
	}
	return journal, nil
}

type activationDocument struct {
	SchemaVersion      uint16          `json:"schema_version"`
	OperationID        string          `json:"operation_id"`
	PlanDigest         string          `json:"plan_digest"`
	ExpectedHostDigest string          `json:"expected_host_digest"`
	Target             pointerDocument `json:"target"`
	State              uint8           `json:"state"`
	CoreStageDigest    string          `json:"core_stage_digest"`
	Version            uint64          `json:"version"`
}

type pointerEnvelope struct {
	SchemaVersion uint16          `json:"schema_version"`
	Pointer       pointerDocument `json:"pointer"`
}

type pointerDocument struct {
	SchemaVersion            uint16 `json:"schema_version"`
	InstallationID           string `json:"installation_id"`
	ReleaseID                string `json:"release_id"`
	GenerationID             string `json:"generation_id"`
	ManifestDigest           string `json:"manifest_digest"`
	ComposeDigest            string `json:"compose_digest"`
	ReadinessReceiptDigest   string `json:"readiness_receipt_digest"`
	RuntimeEndpoint          string `json:"runtime_endpoint"`
	ReleaseSequence          uint64 `json:"release_sequence"`
	ResourceInventoryVersion uint64 `json:"resource_inventory_version"`
	ResourceInventoryDigest  string `json:"resource_inventory_digest"`
	SecurityEpoch            uint64 `json:"security_epoch"`
	ActivatedAt              string `json:"activated_at"`
	PointerDigest            string `json:"pointer_digest"`
}

func encodeActivation(snapshot activerelease.ActivationSnapshot) ([]byte, *activerelease.Activation, error) {
	restored, err := activerelease.RestoreActivation(snapshot)
	if err != nil {
		return nil, nil, err
	}
	verified := restored.Snapshot()
	document := activationDocument{
		SchemaVersion: activationSchema, OperationID: verified.OperationID, PlanDigest: verified.PlanDigest,
		ExpectedHostDigest: verified.ExpectedHostDigest, Target: pointerRecordToDocument(verified.Target),
		State: uint8(verified.State), CoreStageDigest: verified.CoreStageDigest, Version: verified.Version,
	}
	canonical, err := json.Marshal(document)
	if err != nil || len(canonical) == 0 || len(canonical) > maximumStateSize {
		return nil, nil, activereleaseapp.ErrActivationIntegrity
	}
	return canonical, restored, nil
}

func decodeActivation(
	snapshot installjournal.Snapshot,
	operationID install.OperationID,
) (*activerelease.Activation, error) {
	if snapshot.OperationID != operationID.String() || snapshot.Revision == 0 || snapshot.CapturedAt.IsZero() {
		return nil, activereleaseapp.ErrActivationIntegrity
	}
	var document activationDocument
	if err := decodeCanonical(snapshot.Payload, &document); err != nil || document.SchemaVersion != activationSchema ||
		document.OperationID != operationID.String() || document.Version == ^uint64(0) ||
		snapshot.Revision != document.Version+1 {
		return nil, activereleaseapp.ErrActivationIntegrity
	}
	return activerelease.RestoreActivation(activerelease.ActivationSnapshot{
		SchemaVersion: document.SchemaVersion, OperationID: document.OperationID, PlanDigest: document.PlanDigest,
		ExpectedHostDigest: document.ExpectedHostDigest, Target: pointerDocumentToRecord(document.Target),
		State: activerelease.State(document.State), CoreStageDigest: document.CoreStageDigest, Version: document.Version,
	})
}

func encodePointer(record activerelease.PointerRecord) ([]byte, activerelease.Pointer, error) {
	restored, err := activerelease.RestorePointer(record)
	if err != nil {
		return nil, activerelease.Pointer{}, err
	}
	canonical, err := json.Marshal(pointerEnvelope{
		SchemaVersion: pointerSchema, Pointer: pointerRecordToDocument(restored.Record()),
	})
	if err != nil || len(canonical) == 0 || len(canonical) > maximumStateSize {
		return nil, activerelease.Pointer{}, activereleaseapp.ErrPointerIntegrity
	}
	return canonical, restored, nil
}

func decodePointer(
	snapshot installjournal.Snapshot,
	operationID install.OperationID,
	installationID string,
) (activerelease.Pointer, error) {
	if snapshot.OperationID != operationID.String() || snapshot.Revision == 0 || snapshot.CapturedAt.IsZero() {
		return activerelease.Pointer{}, activereleaseapp.ErrPointerIntegrity
	}
	var envelope pointerEnvelope
	if err := decodeCanonical(snapshot.Payload, &envelope); err != nil || envelope.SchemaVersion != pointerSchema ||
		envelope.Pointer.InstallationID != installationID {
		return activerelease.Pointer{}, activereleaseapp.ErrPointerIntegrity
	}
	return activerelease.RestorePointer(pointerDocumentToRecord(envelope.Pointer))
}

func decodeCanonical(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > maximumStateSize || !json.Valid(raw) {
		return errors.New("active release journal payload is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("active release journal payload has trailing content")
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, raw) {
		return errors.New("active release journal payload is not canonical")
	}
	return nil
}

func pointerRecordToDocument(record activerelease.PointerRecord) pointerDocument {
	return pointerDocument{
		SchemaVersion: record.SchemaVersion, InstallationID: record.InstallationID, ReleaseID: record.ReleaseID,
		GenerationID: record.GenerationID, ManifestDigest: record.ManifestDigest, ComposeDigest: record.ComposeDigest,
		ReadinessReceiptDigest: record.ReadinessReceiptDigest, RuntimeEndpoint: record.RuntimeEndpoint,
		ReleaseSequence: record.ReleaseSequence, ResourceInventoryVersion: record.ResourceInventoryVersion,
		ResourceInventoryDigest: record.ResourceInventoryDigest, SecurityEpoch: record.SecurityEpoch,
		ActivatedAt: record.ActivatedAt, PointerDigest: record.PointerDigest,
	}
}

func pointerDocumentToRecord(document pointerDocument) activerelease.PointerRecord {
	return activerelease.PointerRecord{
		SchemaVersion: document.SchemaVersion, InstallationID: document.InstallationID, ReleaseID: document.ReleaseID,
		GenerationID: document.GenerationID, ManifestDigest: document.ManifestDigest, ComposeDigest: document.ComposeDigest,
		ReadinessReceiptDigest: document.ReadinessReceiptDigest, RuntimeEndpoint: document.RuntimeEndpoint,
		ReleaseSequence: document.ReleaseSequence, ResourceInventoryVersion: document.ResourceInventoryVersion,
		ResourceInventoryDigest: document.ResourceInventoryDigest, SecurityEpoch: document.SecurityEpoch,
		ActivatedAt: document.ActivatedAt, PointerDigest: document.PointerDigest,
	}
}

func pointerOperationID(installationID string) (install.OperationID, error) {
	return install.NewOperationID(installationID)
}

func mapActivationJournalError(err error) error {
	switch {
	case errors.Is(err, installjournal.ErrNotFound):
		return activereleaseapp.ErrActivationNotFound
	case errors.Is(err, installjournal.ErrConflict):
		return activereleaseapp.ErrActivationConflict
	case errors.Is(err, installjournal.ErrCorrupt), errors.Is(err, installjournal.ErrUnsafePermission),
		errors.Is(err, installjournal.ErrInvalidSnapshot), errors.Is(err, activereleaseapp.ErrActivationIntegrity):
		return activereleaseapp.ErrActivationIntegrity
	default:
		return err
	}
}

func mapPointerJournalError(err error) error {
	switch {
	case errors.Is(err, installjournal.ErrNotFound):
		return activereleaseapp.ErrPointerNotFound
	case errors.Is(err, installjournal.ErrConflict):
		return activereleaseapp.ErrPointerConflict
	case errors.Is(err, installjournal.ErrCorrupt), errors.Is(err, installjournal.ErrUnsafePermission),
		errors.Is(err, installjournal.ErrInvalidSnapshot), errors.Is(err, activereleaseapp.ErrPointerIntegrity):
		return activereleaseapp.ErrPointerIntegrity
	default:
		return err
	}
}

func nilCapability(value any) bool {
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

var (
	_ activereleaseapp.ActivationRepository  = (*ActivationRepository)(nil)
	_ activereleaseapp.HostPointerRepository = (*HostPointerRepository)(nil)
)
