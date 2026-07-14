package resourcejournal

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/resourceapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/resourceinventory"
)

const journalInstallation = "019f5f20-1234-4abc-8123-0123456789ab"

func TestPF001ResourceJournalRoundTripCASAndIdempotence(t *testing.T) {
	t.Parallel()
	journal := &memoryJournal{}
	repository := newRepository(t, journal)
	inventory, _ := resourceinventory.New(journalInstallation)
	if err := repository.Save(context.Background(), 0, inventory.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if len(journal.snapshots) != 1 || journal.snapshots[0].Revision != 1 {
		t.Fatalf("initial snapshots=%+v", journal.snapshots)
	}
	if err := repository.Save(context.Background(), 0, inventory.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if len(journal.snapshots) != 1 || journal.confirmed != 1 {
		t.Fatalf("idempotent append count=%d confirmed=%d", len(journal.snapshots), journal.confirmed)
	}
	plan, _ := resourceinventory.BuildPlan(journalInstallation, "019f5f20-1234-7abc-8123-0123456789ab", "0.1.0")
	_, _ = inventory.Begin(plan[0], "install-1")
	if err := repository.Save(context.Background(), 0, inventory.Snapshot()); err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.Load(context.Background(), journalInstallation)
	if err != nil || loaded.Version != 1 || len(loaded.Entries) != 1 || journal.confirmed != 2 {
		t.Fatalf("Load()=(%+v,%v) confirmed=%d", loaded, err, journal.confirmed)
	}
	if err := repository.Save(context.Background(), 0, inventory.Snapshot()); !errors.Is(err, resourceapp.ErrInventoryConflict) {
		t.Fatalf("stale CAS error=%v", err)
	}
}

func TestPF001ResourceJournalStrictlyRejectsTampering(t *testing.T) {
	t.Parallel()
	inventory, _ := resourceinventory.New(journalInstallation)
	canonical, operationID, err := encodeSnapshot(inventory.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		payload []byte
		op      string
	}{
		{name: "duplicate", payload: []byte(strings.Replace(string(canonical), `"version":0`, `"version":0,"version":0`, 1)), op: operationID.String()},
		{name: "unknown", payload: []byte(strings.Replace(string(canonical), `"entries":[]`, `"future":true,"entries":[]`, 1)), op: operationID.String()},
		{name: "missing required", payload: []byte(strings.Replace(string(canonical), `"version":0,`, "", 1)), op: operationID.String()},
		{name: "schema", payload: []byte(strings.Replace(string(canonical), `"schema_version":1`, `"schema_version":2`, 1)), op: operationID.String()},
		{name: "cross installation", payload: canonical, op: "resource-inventory-other"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			journal := &memoryJournal{snapshots: []installjournal.Snapshot{{OperationID: test.op, Revision: 1, CapturedAt: time.Now(), Payload: test.payload}}}
			_, err := newRepository(t, journal).Load(context.Background(), journalInstallation)
			if !errors.Is(err, resourceapp.ErrInventoryIntegrity) {
				t.Fatalf("Load() error=%v", err)
			}
		})
	}
}

func TestPF001ResourceJournalMapsBoundariesWithoutDiagnostics(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err  error
		want error
	}{
		{installjournal.ErrNotFound, resourceapp.ErrInventoryNotFound},
		{installjournal.ErrConflict, resourceapp.ErrInventoryConflict},
		{installjournal.ErrCorrupt, resourceapp.ErrInventoryIntegrity},
		{installjournal.ErrUnsafePermission, resourceapp.ErrInventoryIntegrity},
		{installjournal.ErrInvalidSnapshot, resourceapp.ErrInventoryIntegrity},
		{installjournal.ErrIO, resourceapp.ErrInventoryPersistence},
	}
	for _, test := range tests {
		journal := &memoryJournal{loadErr: test.err}
		_, err := newRepository(t, journal).Load(context.Background(), journalInstallation)
		if !errors.Is(err, test.want) {
			t.Fatalf("error=%v want=%v", err, test.want)
		}
	}
	journal := &memoryJournal{}
	repository, _ := New(&journalProvider{journal: journal}, fixedClock{})
	inventory, _ := resourceinventory.New(journalInstallation)
	journal.appendErr = installjournal.ErrIO
	if err := repository.Save(context.Background(), 0, inventory.Snapshot()); !errors.Is(err, resourceapp.ErrInventoryPersistence) {
		t.Fatalf("append error=%v", err)
	}
}

func TestPF001ResourceJournalRejectsInvalidCompositionInputsAndClock(t *testing.T) {
	t.Parallel()
	var nilProvider *journalProvider
	var nilClock *pointerClock
	for _, input := range []struct {
		provider JournalProvider
		clock    Clock
	}{
		{nil, fixedClock{}},
		{nilProvider, fixedClock{}},
		{&journalProvider{journal: &memoryJournal{}}, nilClock},
	} {
		if _, err := New(input.provider, input.clock); err == nil {
			t.Fatal("New accepted nil dependency")
		}
	}
	repository, _ := New(&journalProvider{journal: &memoryJournal{}}, zeroClock{})
	inventory, _ := resourceinventory.New(journalInstallation)
	if err := repository.Save(context.Background(), 0, inventory.Snapshot()); !errors.Is(err, resourceapp.ErrInventoryPersistence) {
		t.Fatalf("zero clock error=%v", err)
	}
	if _, err := repository.Load(context.Background(), "bad"); !errors.Is(err, resourceapp.ErrInventoryIntegrity) {
		t.Fatalf("invalid identity error=%v", err)
	}
}

func TestPF001ResourceJournalDecoderRejectsOversizeAndMalformedJSON(t *testing.T) {
	t.Parallel()
	for _, payload := range [][]byte{
		nil,
		[]byte(`{"schema_version":1}`),
		[]byte(`{"a":[1,2}`),
		make([]byte, maximumInventoryBytes+1),
	} {
		if _, err := decodeSnapshot(payload); err == nil {
			t.Fatalf("decode accepted %d bytes", len(payload))
		}
	}
	if duplicateKeys([]byte(`{"a":[{"b":1}],"c":true}`)) {
		t.Fatal("duplicate detector rejected valid nested JSON")
	}
	if !duplicateKeys([]byte(`{"a":{"b":1,"b":2}}`)) {
		t.Fatal("duplicate detector accepted nested duplicate")
	}
}

func TestPF001ResourceJournalFailsClosedAcrossProviderDurabilityAndCASBoundaries(t *testing.T) {
	t.Parallel()
	providerFailure, _ := New(&journalProvider{err: installjournal.ErrIO}, fixedClock{})
	if _, err := providerFailure.Load(context.Background(), journalInstallation); !errors.Is(err, resourceapp.ErrInventoryPersistence) {
		t.Fatalf("provider error=%v", err)
	}
	nilJournal, _ := New(&journalProvider{}, fixedClock{})
	if _, err := nilJournal.Load(context.Background(), journalInstallation); !errors.Is(err, resourceapp.ErrInventoryPersistence) {
		t.Fatalf("nil journal error=%v", err)
	}

	inventory, _ := resourceinventory.New(journalInstallation)
	canonical, operationID, _ := encodeSnapshot(inventory.Snapshot())
	confirmFailure := &memoryJournal{
		snapshots:  []installjournal.Snapshot{{OperationID: operationID.String(), Revision: 1, Payload: canonical}},
		confirmErr: installjournal.ErrIO,
	}
	if _, err := newRepository(t, confirmFailure).Load(context.Background(), journalInstallation); !errors.Is(err, resourceapp.ErrInventoryPersistence) {
		t.Fatalf("confirmation error=%v", err)
	}

	tests := []struct {
		name     string
		latest   installjournal.Snapshot
		expected uint64
		snapshot resourceinventory.Snapshot
		want     error
	}{
		{name: "identity", latest: installjournal.Snapshot{OperationID: "wrong", Revision: 1, Payload: canonical}, snapshot: inventory.Snapshot(), want: resourceapp.ErrInventoryIntegrity},
		{name: "revision", latest: installjournal.Snapshot{OperationID: operationID.String(), Revision: 0, Payload: canonical}, snapshot: inventory.Snapshot(), want: resourceapp.ErrInventoryIntegrity},
		{name: "payload", latest: installjournal.Snapshot{OperationID: operationID.String(), Revision: 1, Payload: []byte("bad")}, snapshot: inventory.Snapshot(), want: resourceapp.ErrInventoryIntegrity},
		{name: "skipped initial", snapshot: func() resourceinventory.Snapshot {
			value := inventory.Snapshot()
			value.Version = 1
			return value
		}(), want: resourceapp.ErrInventoryConflict},
		{name: "version overflow", latest: func() installjournal.Snapshot {
			value := inventory.Snapshot()
			value.Version = math.MaxUint64
			// A structurally impossible domain snapshot is deliberately rejected
			// before it can ever reach repository CAS.
			payload, _, _ := encodeSnapshot(value)
			return installjournal.Snapshot{OperationID: operationID.String(), Revision: 1, Payload: payload}
		}(), expected: math.MaxUint64, snapshot: inventory.Snapshot(), want: resourceapp.ErrInventoryConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			journal := &memoryJournal{}
			if test.latest.OperationID != "" {
				journal.snapshots = []installjournal.Snapshot{test.latest}
			}
			err := newRepository(t, journal).Save(context.Background(), test.expected, test.snapshot)
			if !errors.Is(err, test.want) {
				t.Fatalf("error=%v want=%v", err, test.want)
			}
		})
	}
}

func TestPF001ResourceJournalStrictDecoderRejectsEntryShapesAndTrailingData(t *testing.T) {
	t.Parallel()
	inventory, _ := resourceinventory.New(journalInstallation)
	canonical, _, _ := encodeSnapshot(inventory.Snapshot())
	invalid := [][]byte{
		[]byte(strings.Replace(string(canonical), `"entries":[]`, `"entries":null`, 1)),
		[]byte(strings.Replace(string(canonical), `"entries":[]`, `"entries":[1]`, 1)),
		[]byte(strings.Replace(string(canonical), `"entries":[]`, `"entries":[{"kind":"volume"}]`, 1)),
		append(append([]byte(nil), canonical...), []byte(` {}`)...),
	}
	for index, payload := range invalid {
		if _, err := decodeSnapshot(payload); !errors.Is(err, resourceapp.ErrInventoryIntegrity) {
			t.Fatalf("payload %d error=%v", index, err)
		}
	}
	if exactObjectFields(map[string]json.RawMessage{"a": nil}, "a", "b") ||
		duplicateKeys([]byte(`[]`)) || duplicateKeys([]byte(`1`)) || !duplicateKeys([]byte(`{"a":1} trailing`)) {
		t.Fatal("strict JSON shape classification changed")
	}
	if _, _, err := encodeSnapshot(resourceinventory.Snapshot{}); err == nil {
		t.Fatal("empty domain snapshot encoded")
	}
	var nilMap map[string]string
	if nilInterface(0) || !nilInterface(nilMap) {
		t.Fatal("nil interface classification changed")
	}

	inventory, _ = resourceinventory.New(journalInstallation)
	canonical, operationID, _ := encodeSnapshot(inventory.Snapshot())
	replay := &memoryJournal{
		snapshots:  []installjournal.Snapshot{{OperationID: operationID.String(), Revision: 1, Payload: canonical}},
		confirmErr: installjournal.ErrIO,
	}
	if err := newRepository(t, replay).Save(context.Background(), 0, inventory.Snapshot()); !errors.Is(err, resourceapp.ErrInventoryPersistence) {
		t.Fatalf("replay confirmation error=%v", err)
	}
	providerFailure, _ := New(&journalProvider{err: installjournal.ErrIO}, fixedClock{})
	if err := providerFailure.Save(context.Background(), 0, inventory.Snapshot()); !errors.Is(err, resourceapp.ErrInventoryPersistence) {
		t.Fatalf("save provider error=%v", err)
	}
	loadFailure := &memoryJournal{loadErr: installjournal.ErrIO}
	if err := newRepository(t, loadFailure).Save(context.Background(), 0, inventory.Snapshot()); !errors.Is(err, resourceapp.ErrInventoryPersistence) {
		t.Fatalf("save load error=%v", err)
	}
	if duplicateKeys([]byte(`[1,{"a":2}]`)) || !duplicateKeys([]byte(`[1,}`)) {
		t.Fatal("array scanner classification changed")
	}
}

func newRepository(t *testing.T, journal *memoryJournal) *Repository {
	t.Helper()
	repository, err := New(&journalProvider{journal: journal}, fixedClock{})
	if err != nil {
		t.Fatal(err)
	}
	return repository
}

type journalProvider struct {
	journal installjournal.Journal
	err     error
}

func (p *journalProvider) JournalFor(_ context.Context, _ install.OperationID) (installjournal.Journal, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.journal, nil
}

type memoryJournal struct {
	snapshots  []installjournal.Snapshot
	loadErr    error
	appendErr  error
	confirmErr error
	confirmed  int
}

func (j *memoryJournal) Append(_ context.Context, expected uint64, snapshot installjournal.Snapshot) error {
	if j.appendErr != nil {
		return j.appendErr
	}
	if uint64(len(j.snapshots)) != expected || snapshot.Revision != expected+1 || !json.Valid(snapshot.Payload) {
		return installjournal.ErrConflict
	}
	snapshot.Payload = append([]byte(nil), snapshot.Payload...)
	j.snapshots = append(j.snapshots, snapshot)
	return nil
}

func (j *memoryJournal) LoadLatest(context.Context) (installjournal.Snapshot, error) {
	if j.loadErr != nil {
		return installjournal.Snapshot{}, j.loadErr
	}
	if len(j.snapshots) == 0 {
		return installjournal.Snapshot{}, installjournal.ErrNotFound
	}
	latest := j.snapshots[len(j.snapshots)-1]
	latest.Payload = append([]byte(nil), latest.Payload...)
	return latest, nil
}

func (j *memoryJournal) ConfirmDurable(_ context.Context, _ string, _ uint64) error {
	j.confirmed++
	return j.confirmErr
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC) }

type zeroClock struct{}

func (zeroClock) Now() time.Time { return time.Time{} }

type pointerClock struct{}

func (*pointerClock) Now() time.Time { return time.Now() }
