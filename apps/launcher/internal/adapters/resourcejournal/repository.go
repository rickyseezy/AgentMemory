// Package resourcejournal persists managed Docker ownership in the existing
// HMAC-authenticated, rollback-anchored installation journal boundary.
package resourcejournal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"strings"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/resourceapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/resourceinventory"
)

const (
	repositorySchemaVersion = uint16(1)
	maximumInventoryBytes   = 1024 * 1024
)

// JournalProvider returns the owner-bound authenticated journal for the
// deterministic inventory operation identity. Production composition uses the
// rollback-anchored secure journal provider; unauthenticated journals violate
// this port contract.
type JournalProvider interface {
	JournalFor(context.Context, install.OperationID) (installjournal.Journal, error)
}

// Clock supplies deterministic UTC capture times.
type Clock interface {
	Now() time.Time
}

// Repository is a strict journal-backed resourceapp.Repository.
type Repository struct {
	provider JournalProvider
	clock    Clock
}

// New constructs an authenticated resource-inventory repository.
func New(provider JournalProvider, clock Clock) (*Repository, error) {
	if nilInterface(provider) || nilInterface(clock) {
		return nil, resourceapp.ErrInventoryPersistence
	}
	return &Repository{provider: provider, clock: clock}, nil
}

// Load authenticates the latest journal record, strictly decodes it, restores
// the domain aggregate, and confirms both journal and rollback-anchor durability.
func (r *Repository) Load(ctx context.Context, installationID string) (resourceinventory.Snapshot, error) {
	operationID, err := inventoryOperationID(installationID)
	if err != nil {
		return resourceinventory.Snapshot{}, resourceapp.ErrInventoryIntegrity
	}
	journal, err := r.journal(ctx, operationID)
	if err != nil {
		return resourceinventory.Snapshot{}, mapJournalError(err)
	}
	latest, err := journal.LoadLatest(ctx)
	if err != nil {
		return resourceinventory.Snapshot{}, mapJournalError(err)
	}
	if latest.OperationID != operationID.String() || latest.Revision == 0 {
		return resourceinventory.Snapshot{}, resourceapp.ErrInventoryIntegrity
	}
	snapshot, err := decodeSnapshot(latest.Payload)
	if err != nil || snapshot.InstallationID != installationID {
		return resourceinventory.Snapshot{}, resourceapp.ErrInventoryIntegrity
	}
	if err := journal.ConfirmDurable(ctx, latest.OperationID, latest.Revision); err != nil {
		return resourceinventory.Snapshot{}, mapJournalError(err)
	}
	return snapshot, nil
}

// Save validates a complete snapshot and durably appends exactly the next
// aggregate version under repository CAS. Exact same-version replay only
// confirms durability and never adds a second journal record.
func (r *Repository) Save(
	ctx context.Context,
	expectedVersion uint64,
	snapshot resourceinventory.Snapshot,
) error {
	canonical, operationID, err := encodeSnapshot(snapshot)
	if err != nil {
		return resourceapp.ErrInventoryIntegrity
	}
	journal, err := r.journal(ctx, operationID)
	if err != nil {
		return mapJournalError(err)
	}
	previousRevision := uint64(0)
	latest, loadError := journal.LoadLatest(ctx)
	switch {
	case loadError == nil:
		if latest.OperationID != operationID.String() || latest.Revision == 0 {
			return resourceapp.ErrInventoryIntegrity
		}
		persisted, decodeError := decodeSnapshot(latest.Payload)
		if decodeError != nil || persisted.InstallationID != snapshot.InstallationID {
			return resourceapp.ErrInventoryIntegrity
		}
		persistedCanonical, _, encodeError := encodeSnapshot(persisted)
		if encodeError != nil {
			return resourceapp.ErrInventoryIntegrity
		}
		if persisted.Version != expectedVersion {
			return resourceapp.ErrInventoryConflict
		}
		if snapshot.Version == expectedVersion && bytes.Equal(persistedCanonical, canonical) {
			return mapJournalError(journal.ConfirmDurable(ctx, latest.OperationID, latest.Revision))
		}
		if expectedVersion == math.MaxUint64 || snapshot.Version != expectedVersion+1 || latest.Revision == math.MaxUint64 {
			return resourceapp.ErrInventoryConflict
		}
		previousRevision = latest.Revision
	case errors.Is(loadError, installjournal.ErrNotFound):
		if expectedVersion != 0 || snapshot.Version != 0 {
			return resourceapp.ErrInventoryConflict
		}
	default:
		return mapJournalError(loadError)
	}
	capturedAt := r.clock.Now().UTC()
	if capturedAt.IsZero() {
		return resourceapp.ErrInventoryPersistence
	}
	if err := journal.Append(ctx, previousRevision, installjournal.Snapshot{
		OperationID: operationID.String(),
		Revision:    previousRevision + 1,
		CapturedAt:  capturedAt,
		Payload:     canonical,
	}); err != nil {
		return mapJournalError(err)
	}
	return nil
}

func (r *Repository) journal(ctx context.Context, operationID install.OperationID) (installjournal.Journal, error) {
	journal, err := r.provider.JournalFor(ctx, operationID)
	if err != nil {
		return nil, err
	}
	if nilInterface(journal) {
		return nil, resourceapp.ErrInventoryIntegrity
	}
	return journal, nil
}

type snapshotDocument struct {
	SchemaVersion  uint16          `json:"schema_version"`
	InstallationID string          `json:"installation_id"`
	Version        uint64          `json:"version"`
	Entries        []entryDocument `json:"entries"`
}

type entryDocument struct {
	Kind              string            `json:"kind"`
	Purpose           string            `json:"purpose"`
	Name              string            `json:"name"`
	Labels            map[string]string `json:"labels"`
	CreationOperation string            `json:"creation_operation"`
	State             string            `json:"state"`
	ObjectID          string            `json:"object_id"`
}

func encodeSnapshot(snapshot resourceinventory.Snapshot) ([]byte, install.OperationID, error) {
	inventory, err := resourceinventory.Restore(snapshot)
	if err != nil {
		return nil, install.OperationID{}, err
	}
	verified := inventory.Snapshot()
	operationID, err := inventoryOperationID(verified.InstallationID)
	if err != nil {
		return nil, install.OperationID{}, err
	}
	entries := make([]entryDocument, 0, len(verified.Entries))
	for _, entry := range verified.Entries {
		entries = append(entries, entryDocument{
			Kind: entry.Kind, Purpose: entry.Purpose, Name: entry.Name, Labels: cloneLabels(entry.Labels),
			CreationOperation: entry.CreationOperation, State: entry.State, ObjectID: entry.ObjectID,
		})
	}
	canonical, err := json.Marshal(snapshotDocument{
		SchemaVersion: repositorySchemaVersion, InstallationID: verified.InstallationID,
		Version: verified.Version, Entries: entries,
	})
	if err != nil || len(canonical) == 0 || len(canonical) > maximumInventoryBytes {
		return nil, install.OperationID{}, resourceapp.ErrInventoryIntegrity
	}
	return canonical, operationID, nil
}

func decodeSnapshot(payload []byte) (resourceinventory.Snapshot, error) {
	if len(payload) == 0 || len(payload) > maximumInventoryBytes || !json.Valid(payload) || duplicateKeys(payload) {
		return resourceinventory.Snapshot{}, resourceapp.ErrInventoryIntegrity
	}
	var rawDocument map[string]json.RawMessage
	if json.Unmarshal(payload, &rawDocument) != nil ||
		!exactObjectFields(rawDocument, "schema_version", "installation_id", "version", "entries") {
		return resourceinventory.Snapshot{}, resourceapp.ErrInventoryIntegrity
	}
	var rawEntries []json.RawMessage
	if json.Unmarshal(rawDocument["entries"], &rawEntries) != nil || rawEntries == nil {
		return resourceinventory.Snapshot{}, resourceapp.ErrInventoryIntegrity
	}
	for _, rawEntry := range rawEntries {
		var entryFields map[string]json.RawMessage
		if json.Unmarshal(rawEntry, &entryFields) != nil || !exactObjectFields(
			entryFields, "kind", "purpose", "name", "labels", "creation_operation", "state", "object_id",
		) {
			return resourceinventory.Snapshot{}, resourceapp.ErrInventoryIntegrity
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var document snapshotDocument
	if err := decoder.Decode(&document); err != nil {
		return resourceinventory.Snapshot{}, resourceapp.ErrInventoryIntegrity
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return resourceinventory.Snapshot{}, resourceapp.ErrInventoryIntegrity
	}
	if document.SchemaVersion != repositorySchemaVersion || document.Entries == nil {
		return resourceinventory.Snapshot{}, resourceapp.ErrInventoryIntegrity
	}
	entries := make([]resourceinventory.EntrySnapshot, 0, len(document.Entries))
	for _, entry := range document.Entries {
		entries = append(entries, resourceinventory.EntrySnapshot{
			Kind: entry.Kind, Purpose: entry.Purpose, Name: entry.Name, Labels: cloneLabels(entry.Labels),
			CreationOperation: entry.CreationOperation, State: entry.State, ObjectID: entry.ObjectID,
		})
	}
	snapshot := resourceinventory.Snapshot{
		SchemaVersion: repositorySchemaVersion, InstallationID: document.InstallationID,
		Version: document.Version, Entries: entries,
	}
	inventory, err := resourceinventory.Restore(snapshot)
	if err != nil {
		return resourceinventory.Snapshot{}, resourceapp.ErrInventoryIntegrity
	}
	return inventory.Snapshot(), nil
}

func exactObjectFields(document map[string]json.RawMessage, fields ...string) bool {
	if len(document) != len(fields) {
		return false
	}
	for _, field := range fields {
		if _, exists := document[field]; !exists {
			return false
		}
	}
	return true
}

func duplicateKeys(payload []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if consumeUnique(decoder) != nil {
		return true
	}
	_, err := decoder.Token()
	return !errors.Is(err, io.EOF)
}

func consumeUnique(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delimiter == '{' {
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyError := decoder.Token()
			if keyError != nil {
				return keyError
			}
			key, keyOK := keyToken.(string)
			if !keyOK {
				return resourceapp.ErrInventoryIntegrity
			}
			if _, exists := seen[key]; exists {
				return resourceapp.ErrInventoryIntegrity
			}
			seen[key] = struct{}{}
			if err := consumeUnique(decoder); err != nil {
				return err
			}
		}
		closing, closeError := decoder.Token()
		if closeError != nil || closing != json.Delim('}') {
			return resourceapp.ErrInventoryIntegrity
		}
		return nil
	}
	if delimiter == '[' {
		for decoder.More() {
			if err := consumeUnique(decoder); err != nil {
				return err
			}
		}
		closing, closeError := decoder.Token()
		if closeError != nil || closing != json.Delim(']') {
			return resourceapp.ErrInventoryIntegrity
		}
		return nil
	}
	return resourceapp.ErrInventoryIntegrity
}

func inventoryOperationID(installationID string) (install.OperationID, error) {
	if _, err := resourceinventory.New(installationID); err != nil {
		return install.OperationID{}, err
	}
	return install.NewOperationID("resource-inventory-" + strings.ReplaceAll(installationID, "-", ""))
}

func mapJournalError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, installjournal.ErrNotFound):
		return resourceapp.ErrInventoryNotFound
	case errors.Is(err, installjournal.ErrConflict):
		return resourceapp.ErrInventoryConflict
	case errors.Is(err, installjournal.ErrCorrupt), errors.Is(err, installjournal.ErrUnsafePermission),
		errors.Is(err, installjournal.ErrInvalidSnapshot):
		return resourceapp.ErrInventoryIntegrity
	default:
		return resourceapp.ErrInventoryPersistence
	}
}

func cloneLabels(labels map[string]string) map[string]string {
	copyOfLabels := make(map[string]string, len(labels))
	for key, value := range labels {
		copyOfLabels[key] = value
	}
	return copyOfLabels
}

func nilInterface(value any) bool {
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

var _ resourceapp.Repository = (*Repository)(nil)
