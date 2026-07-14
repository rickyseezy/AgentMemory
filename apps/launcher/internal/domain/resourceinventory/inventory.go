package resourceinventory

import (
	"errors"
	"sort"
)

const snapshotSchemaVersion = uint16(1)

// EntryState is the durable create lifecycle for one managed resource.
type EntryState string

const (
	// EntryPending is an authenticated pre-create intent without mutation authority.
	EntryPending EntryState = "pending"
	// EntryRecorded contains exact object identity and can authorize mutation.
	EntryRecorded EntryState = "recorded"
)

// Entry is an immutable view of one authenticated inventory member or intent.
type Entry struct {
	spec              Spec
	creationOperation string
	state             EntryState
	objectID          string
}

// Spec returns the immutable expected resource.
func (e Entry) Spec() Spec { return copySpec(e.spec) }

// CreationOperation returns the operation that durably declared the resource.
func (e Entry) CreationOperation() string { return e.creationOperation }

// State returns pending or recorded.
func (e Entry) State() EntryState { return e.state }

// ObjectID returns the exact Docker identity when recorded.
func (e Entry) ObjectID() string { return e.objectID }

// EntrySnapshot is the persistence-neutral representation of one entry.
type EntrySnapshot struct {
	Kind              string
	Purpose           string
	Name              string
	Labels            map[string]string
	CreationOperation string
	State             string
	ObjectID          string
}

// Snapshot is the complete authenticated resource-inventory aggregate.
type Snapshot struct {
	SchemaVersion  uint16
	InstallationID string
	Version        uint64
	Entries        []EntrySnapshot
}

// Inventory is the mutation authority for one installation. Persistence must
// HMAC-authenticate each complete Snapshot and enforce Version CAS.
type Inventory struct {
	installationID string
	version        uint64
	entries        map[string]Entry
}

// New creates an empty inventory for a canonical installation UUID.
func New(installationID string) (*Inventory, error) {
	if _, err := BuildPlan(installationID, "00000000-0000-7000-8000-000000000000", "initial"); err != nil {
		return nil, ErrInvalidResource
	}
	return &Inventory{installationID: installationID, entries: make(map[string]Entry)}, nil
}

// Restore verifies every authenticated field against the closed derived model.
func Restore(snapshot Snapshot) (*Inventory, error) {
	if snapshot.SchemaVersion != snapshotSchemaVersion {
		return nil, ErrInventoryIntegrity
	}
	inventory, err := New(snapshot.InstallationID)
	if err != nil {
		return nil, ErrInventoryIntegrity
	}
	if snapshot.Version < uint64(len(snapshot.Entries)) || len(snapshot.Entries) > 256 {
		return nil, ErrInventoryIntegrity
	}
	inventory.version = snapshot.Version
	seenObjectIDs := make(map[string]struct{}, len(snapshot.Entries))
	for _, persisted := range snapshot.Entries {
		kind, parseError := ParseKind(persisted.Kind)
		purpose := Purpose(persisted.Purpose)
		spec := Spec{kind: kind, purpose: purpose, name: persisted.Name, labels: cloneLabels(persisted.Labels)}
		if parseError != nil || !spec.validFor(snapshot.InstallationID) || !validOperation(persisted.CreationOperation) {
			return nil, ErrInventoryIntegrity
		}
		if _, duplicate := inventory.entries[spec.name]; duplicate {
			return nil, ErrInventoryIntegrity
		}
		entry := Entry{spec: spec, creationOperation: persisted.CreationOperation, state: EntryState(persisted.State), objectID: persisted.ObjectID}
		switch entry.state {
		case EntryPending:
			if entry.objectID != "" {
				return nil, ErrInventoryIntegrity
			}
		case EntryRecorded:
			observed, observedError := NewObserved(spec.kind, spec.name, entry.objectID, spec.labels)
			if observedError != nil || !observed.matches(spec) {
				return nil, ErrInventoryIntegrity
			}
			key := spec.kind.String() + ":" + entry.objectID
			if _, duplicate := seenObjectIDs[key]; duplicate {
				return nil, ErrInventoryIntegrity
			}
			seenObjectIDs[key] = struct{}{}
		default:
			return nil, ErrInventoryIntegrity
		}
		inventory.entries[spec.name] = entry
	}
	return inventory, nil
}

// InstallationID returns the canonical installation UUID.
func (i *Inventory) InstallationID() string { return i.installationID }

// Version returns the optimistic concurrency token.
func (i *Inventory) Version() uint64 { return i.version }

// Snapshot returns a deterministic immutable-by-copy aggregate view.
func (i *Inventory) Snapshot() Snapshot {
	names := make([]string, 0, len(i.entries))
	for name := range i.entries {
		names = append(names, name)
	}
	sort.Strings(names)
	entries := make([]EntrySnapshot, 0, len(names))
	for _, name := range names {
		entry := i.entries[name]
		entries = append(entries, EntrySnapshot{
			Kind:              entry.spec.kind.String(),
			Purpose:           string(entry.spec.purpose),
			Name:              entry.spec.name,
			Labels:            cloneLabels(entry.spec.labels),
			CreationOperation: entry.creationOperation,
			State:             string(entry.state),
			ObjectID:          entry.objectID,
		})
	}
	return Snapshot{SchemaVersion: snapshotSchemaVersion, InstallationID: i.installationID, Version: i.version, Entries: entries}
}

// Find returns an immutable entry by exact derived name.
func (i *Inventory) Find(name string) (Entry, bool) {
	entry, exists := i.entries[name]
	if !exists {
		return Entry{}, false
	}
	entry.spec = copySpec(entry.spec)
	return entry, true
}

// Begin records a durable create intent before Docker is inspected or mutated.
// A matching replay is idempotent; any disagreement fails closed.
func (i *Inventory) Begin(spec Spec, creationOperation string) (bool, error) {
	if !spec.validFor(i.installationID) || !validOperation(creationOperation) {
		return false, ErrInvalidResource
	}
	if existing, exists := i.entries[spec.name]; exists {
		if !existing.spec.equal(spec) || existing.creationOperation != creationOperation {
			return false, ErrInventoryConflict
		}
		return false, nil
	}
	i.entries[spec.name] = Entry{spec: copySpec(spec), creationOperation: creationOperation, state: EntryPending}
	i.version++
	return true, nil
}

// Record promotes the matching authenticated intent immediately after create
// or exact-label recovery. It never adopts a name without the prior intent.
func (i *Inventory) Record(spec Spec, creationOperation string, observed Observed) (bool, error) {
	entry, exists := i.entries[spec.name]
	if !exists || !entry.spec.equal(spec) || entry.creationOperation != creationOperation {
		return false, ErrInventoryConflict
	}
	if !observed.matches(spec) {
		return false, ErrInventoryIntegrity
	}
	if entry.state == EntryRecorded {
		if entry.objectID != observed.objectID {
			return false, ErrInventoryConflict
		}
		return false, nil
	}
	if entry.state != EntryPending || entry.objectID != "" {
		return false, ErrInventoryIntegrity
	}
	for name, candidate := range i.entries {
		if name != spec.name && candidate.state == EntryRecorded && candidate.spec.kind == spec.kind && candidate.objectID == observed.objectID {
			return false, ErrInventoryConflict
		}
	}
	entry.state = EntryRecorded
	entry.objectID = observed.objectID
	i.entries[spec.name] = entry
	i.version++
	return true, nil
}

// VerifyRecorded proves that Docker still exposes the exact inventoried object.
func (i *Inventory) VerifyRecorded(spec Spec, observed Observed) error {
	entry, exists := i.entries[spec.name]
	if !exists || entry.state != EntryRecorded || !entry.spec.equal(spec) ||
		entry.objectID != observed.objectID || !observed.matches(spec) {
		return ErrInventoryIntegrity
	}
	return nil
}

// AuthorizeRemoval mints a destructive token only from exact inventory
// membership plus exact currently observed ID and labels.
func (i *Inventory) AuthorizeRemoval(observed Observed) (RemovalAuthorization, error) {
	entry, exists := i.entries[observed.name]
	if !exists || entry.state != EntryRecorded || entry.objectID != observed.objectID || !observed.matches(entry.spec) {
		return RemovalAuthorization{}, ErrRemovalUnauthorized
	}
	return RemovalAuthorization{
		kind: entry.spec.kind, name: entry.spec.name, objectID: entry.objectID, labels: cloneLabels(entry.spec.labels),
	}, nil
}

// ConfirmRemoved deletes an entry only after an exact inventory-minted
// authorization has been successfully executed by the outbound adapter.
func (i *Inventory) ConfirmRemoved(authorization RemovalAuthorization) error {
	if !authorization.Valid() {
		return ErrRemovalUnauthorized
	}
	entry, exists := i.entries[authorization.name]
	if !exists || entry.state != EntryRecorded || entry.spec.kind != authorization.kind ||
		entry.objectID != authorization.objectID || !equalLabels(entry.spec.labels, authorization.labels) {
		return ErrRemovalUnauthorized
	}
	delete(i.entries, authorization.name)
	i.version++
	return nil
}

func copySpec(spec Spec) Spec {
	return Spec{kind: spec.kind, purpose: spec.purpose, name: spec.name, labels: cloneLabels(spec.labels)}
}

// IsIntegrityError reports fail-closed domain errors useful at application boundaries.
func IsIntegrityError(err error) bool {
	return errors.Is(err, ErrInventoryIntegrity) || errors.Is(err, ErrInventoryConflict) ||
		errors.Is(err, ErrRemovalUnauthorized) || errors.Is(err, ErrInvalidResource)
}
