package artifactjournal

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001ArtifactJournalRoundTripCASAndIdempotence(t *testing.T) {
	t.Parallel()
	journal := &memoryJournal{}
	repository := newRepository(t, journal)
	snapshot := pristineSnapshot(t)
	if err := repository.Save(context.Background(), 0, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(context.Background(), 0, snapshot); err != nil || len(journal.snapshots) != 1 || journal.confirmed != 1 {
		t.Fatalf("replay err=%v snapshots=%d confirmed=%d", err, len(journal.snapshots), journal.confirmed)
	}
	id := "r-" + strings.Repeat("a", 64)
	snapshot.Version = 1
	snapshot.ReservationID, snapshot.ReservedBytes, snapshot.ReleaseState = id, 10, "allocating"
	if err := repository.Save(context.Background(), 0, snapshot); err != nil {
		t.Fatal(err)
	}
	snapshot.Version = 2
	snapshot.FilesystemID = "localfs-1"
	snapshot.ReleaseState = "active"
	if err := repository.Save(context.Background(), 1, snapshot); err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.Load(context.Background(), snapshot.OperationID)
	if err != nil || loaded.Version != 2 || loaded.ReservationID != id || journal.confirmed != 2 {
		t.Fatalf("Load()=(%+v,%v) confirmed=%d", loaded, err, journal.confirmed)
	}
	if err := repository.Save(context.Background(), 0, snapshot); !errors.Is(err, artifactapp.ErrAggregateConflict) {
		t.Fatalf("stale error=%v", err)
	}
}

func TestPF001ArtifactJournalRejectsDuplicateUnknownMissingAndContradictoryFields(t *testing.T) {
	t.Parallel()
	canonical, journalID, _ := encodeSnapshot(pristineSnapshot(t))
	mutations := [][]byte{
		[]byte(strings.Replace(string(canonical), `"version":0`, `"version":0,"version":0`, 1)),
		[]byte(strings.Replace(string(canonical), `"progress":[]`, `"future":true,"progress":[]`, 1)),
		[]byte(strings.Replace(string(canonical), `"plan_digest":`, `"missing":`, 1)),
		[]byte(strings.Replace(string(canonical), `"schema_version":2`, `"schema_version":3`, 1)),
	}
	for index, payload := range mutations {
		journal := &memoryJournal{snapshots: []installjournal.Snapshot{{OperationID: journalID.String(), Revision: 1, CapturedAt: time.Now(), Payload: payload}}}
		_, err := newRepository(t, journal).Load(context.Background(), "install-1")
		if !errors.Is(err, artifactapp.ErrAggregateIntegrity) {
			t.Fatalf("mutation %d error=%v", index, err)
		}
	}
}

func TestPF001ArtifactJournalMapsSecureJournalErrors(t *testing.T) {
	t.Parallel()
	tests := []struct{ source, target error }{
		{installjournal.ErrNotFound, artifactapp.ErrAggregateNotFound},
		{installjournal.ErrConflict, artifactapp.ErrAggregateConflict},
		{installjournal.ErrCorrupt, artifactapp.ErrAggregateIntegrity},
		{installjournal.ErrUnsafePermission, artifactapp.ErrAggregateIntegrity},
		{installjournal.ErrIO, artifactapp.ErrAggregatePersistence},
	}
	for _, test := range tests {
		journal := &memoryJournal{loadErr: test.source}
		_, err := newRepository(t, journal).Load(context.Background(), "install-1")
		if !errors.Is(err, test.target) {
			t.Fatalf("error=%v want=%v", err, test.target)
		}
	}
	journal := &memoryJournal{appendErr: installjournal.ErrIO}
	if err := newRepository(t, journal).Save(context.Background(), 0, pristineSnapshot(t)); !errors.Is(err, artifactapp.ErrAggregatePersistence) {
		t.Fatalf("append error=%v", err)
	}
}

func TestPF001ArtifactJournalRejectsInvalidCompositionClockAndSnapshot(t *testing.T) {
	t.Parallel()
	var nilProvider *provider
	var nilClock *pointerClock
	if _, err := New(nilProvider, fixedClock{}); err == nil {
		t.Fatal("nil provider accepted")
	}
	if _, err := New(&provider{journal: &memoryJournal{}}, nilClock); err == nil {
		t.Fatal("nil clock accepted")
	}
	repository, _ := New(&provider{journal: &memoryJournal{}}, zeroClock{})
	if err := repository.Save(context.Background(), 0, pristineSnapshot(t)); !errors.Is(err, artifactapp.ErrAggregatePersistence) {
		t.Fatalf("zero clock error=%v", err)
	}
	snapshot := pristineSnapshot(t)
	snapshot.PlanDigest = "bad"
	if err := newRepository(t, &memoryJournal{}).Save(context.Background(), 0, snapshot); !errors.Is(err, artifactapp.ErrAggregateIntegrity) {
		t.Fatalf("bad snapshot error=%v", err)
	}
}

func TestPF001ArtifactJournalJSONScannerHandlesNestedValues(t *testing.T) {
	t.Parallel()
	if duplicateKeys([]byte(`{"a":[{"b":1}],"c":true}`)) || !duplicateKeys([]byte(`{"a":{"b":1,"b":2}}`)) {
		t.Fatal("duplicate scanner classification changed")
	}
	if _, err := decodeSnapshot(make([]byte, maximumJournalBytes+1)); err == nil {
		t.Fatal("oversize payload accepted")
	}
}

func TestPF001ArtifactJournalValidatesEveryPersistedIdentityAndPrefix(t *testing.T) {
	t.Parallel()
	valid := pristineSnapshot(t)
	valid.ReservationID = "r-" + strings.Repeat("a", 64)
	valid.ReservedBytes = 5
	valid.FilesystemID = "localfs-1"
	valid.ReleaseState = "active"
	valid.Progress = []artifactacquisition.ProgressSnapshot{{
		ArtifactID:     "artifact",
		ArtifactDigest: releaseinventory.DigestBytes([]byte("abc")).Hex(),
		PartialID:      "p-" + strings.Repeat("b", 64),
		VerifiedChunks: []uint32{},
	}}
	if !validSnapshot(valid) {
		t.Fatal("valid snapshot rejected")
	}

	tests := []struct {
		name   string
		mutate func(*artifactacquisition.Snapshot)
	}{
		{"schema", func(snapshot *artifactacquisition.Snapshot) { snapshot.SchemaVersion++ }},
		{"operation", func(snapshot *artifactacquisition.Snapshot) { snapshot.OperationID = "" }},
		{"plan-digest", func(snapshot *artifactacquisition.Snapshot) { snapshot.PlanDigest = "bad" }},
		{"partial-reservation", func(snapshot *artifactacquisition.Snapshot) { snapshot.ReservationID = "" }},
		{"reservation-token", func(snapshot *artifactacquisition.Snapshot) { snapshot.ReservationID = "r-bad" }},
		{"reservation-zero", func(snapshot *artifactacquisition.Snapshot) { snapshot.ReservedBytes = 0 }},
		{"reservation-overflow", func(snapshot *artifactacquisition.Snapshot) { snapshot.ReservedBytes = uint64(1 << 53) }},
		{"filesystem", func(snapshot *artifactacquisition.Snapshot) { snapshot.FilesystemID = "unsafe/path" }},
		{"progress-without-reservation", func(snapshot *artifactacquisition.Snapshot) {
			snapshot.ReservationID, snapshot.ReservedBytes, snapshot.FilesystemID = "", 0, ""
		}},
		{"artifact-id", func(snapshot *artifactacquisition.Snapshot) { snapshot.Progress[0].ArtifactID = "" }},
		{"artifact-digest", func(snapshot *artifactacquisition.Snapshot) { snapshot.Progress[0].ArtifactDigest = "bad" }},
		{"partial-id", func(snapshot *artifactacquisition.Snapshot) { snapshot.Progress[0].PartialID = "p-bad" }},
		{"nil-prefix", func(snapshot *artifactacquisition.Snapshot) { snapshot.Progress[0].VerifiedChunks = nil }},
		{"gap-prefix", func(snapshot *artifactacquisition.Snapshot) { snapshot.Progress[0].VerifiedChunks = []uint32{0, 2} }},
		{"unsorted-prefix", func(snapshot *artifactacquisition.Snapshot) { snapshot.Progress[0].VerifiedChunks = []uint32{1, 0} }},
		{"duplicate-artifact", func(snapshot *artifactacquisition.Snapshot) {
			snapshot.Progress = append(snapshot.Progress, snapshot.Progress[0])
		}},
		{"progress-limit", func(snapshot *artifactacquisition.Snapshot) {
			snapshot.Progress = make([]artifactacquisition.ProgressSnapshot, 4097)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := valid
			snapshot.Progress = append([]artifactacquisition.ProgressSnapshot(nil), valid.Progress...)
			snapshot.Progress[0].VerifiedChunks = append([]uint32(nil), valid.Progress[0].VerifiedChunks...)
			test.mutate(&snapshot)
			if validSnapshot(snapshot) {
				t.Fatal("invalid snapshot accepted")
			}
		})
	}
}

func TestPF001ArtifactJournalFailsClosedAcrossProviderAndCASBoundaries(t *testing.T) {
	t.Parallel()
	if _, err := artifactJournalID(""); err == nil {
		t.Fatal("invalid operation accepted")
	}
	if safeIdentifier("") || safeIdentifier(strings.Repeat("a", 129)) || safeIdentifier("unsafe/path") || !safeIdentifier("localfs-1_A") {
		t.Fatal("safe identifier classification changed")
	}
	if token("r-bad", "r-") || token("x-"+strings.Repeat("a", 64), "r-") || !token("r-"+strings.Repeat("f", 64), "r-") {
		t.Fatal("token classification changed")
	}

	providerFailure, err := New(&provider{err: installjournal.ErrIO}, fixedClock{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := providerFailure.Load(context.Background(), "install-1"); !errors.Is(err, artifactapp.ErrAggregatePersistence) {
		t.Fatalf("provider error=%v", err)
	}
	nilJournal, _ := New(&provider{}, fixedClock{})
	if _, err := nilJournal.Load(context.Background(), "install-1"); !errors.Is(err, artifactapp.ErrAggregatePersistence) {
		t.Fatalf("nil journal error=%v", err)
	}
	if _, err := newRepository(t, &memoryJournal{}).Load(context.Background(), ""); !errors.Is(err, artifactapp.ErrAggregateIntegrity) {
		t.Fatalf("invalid load operation error=%v", err)
	}

	snapshot := pristineSnapshot(t)
	canonical, journalID, _ := encodeSnapshot(snapshot)
	wrongIdentity := &memoryJournal{snapshots: []installjournal.Snapshot{{OperationID: "wrong", Revision: 1, Payload: canonical}}}
	if _, err := newRepository(t, wrongIdentity).Load(context.Background(), snapshot.OperationID); !errors.Is(err, artifactapp.ErrAggregateIntegrity) {
		t.Fatalf("wrong journal identity error=%v", err)
	}
	zeroRevision := &memoryJournal{snapshots: []installjournal.Snapshot{{OperationID: journalID.String(), Revision: 0, Payload: canonical}}}
	if _, err := newRepository(t, zeroRevision).Load(context.Background(), snapshot.OperationID); !errors.Is(err, artifactapp.ErrAggregateIntegrity) {
		t.Fatalf("zero revision error=%v", err)
	}
	confirmFailure := &memoryJournal{snapshots: []installjournal.Snapshot{{OperationID: journalID.String(), Revision: 1, Payload: canonical}}, confirmErr: installjournal.ErrIO}
	if _, err := newRepository(t, confirmFailure).Load(context.Background(), snapshot.OperationID); !errors.Is(err, artifactapp.ErrAggregatePersistence) {
		t.Fatalf("durability confirmation error=%v", err)
	}
	if err := newRepository(t, &memoryJournal{}).Save(context.Background(), 0, func() artifactacquisition.Snapshot {
		value := snapshot
		value.Version = 1
		return value
	}()); !errors.Is(err, artifactapp.ErrAggregateConflict) {
		t.Fatalf("skipped initial version error=%v", err)
	}
}

func TestPF001ArtifactJournalRejectsEveryContradictoryCASReplay(t *testing.T) {
	t.Parallel()
	snapshot := pristineSnapshot(t)
	canonical, journalID, _ := encodeSnapshot(snapshot)
	tests := []struct {
		name     string
		latest   installjournal.Snapshot
		expected uint64
		mutate   func(*artifactacquisition.Snapshot)
		want     error
	}{
		{name: "latest identity", latest: installjournal.Snapshot{OperationID: "wrong", Revision: 1, Payload: canonical}, want: artifactapp.ErrAggregateIntegrity},
		{name: "latest revision", latest: installjournal.Snapshot{OperationID: journalID.String(), Revision: 0, Payload: canonical}, want: artifactapp.ErrAggregateIntegrity},
		{name: "latest payload", latest: installjournal.Snapshot{OperationID: journalID.String(), Revision: 1, Payload: []byte("bad")}, want: artifactapp.ErrAggregateIntegrity},
		{name: "plan contradiction", latest: installjournal.Snapshot{OperationID: journalID.String(), Revision: 1, Payload: canonical}, mutate: func(value *artifactacquisition.Snapshot) {
			value.PlanDigest = releaseinventory.DigestBytes([]byte("other")).Hex()
		}, want: artifactapp.ErrAggregateIntegrity},
		{name: "version overflow", latest: func() installjournal.Snapshot {
			persisted := snapshot
			persisted.Version = math.MaxUint64
			payload, _, _ := encodeSnapshot(persisted)
			return installjournal.Snapshot{OperationID: journalID.String(), Revision: 1, Payload: payload}
		}(), expected: math.MaxUint64, want: artifactapp.ErrAggregateConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := snapshot
			if test.mutate != nil {
				test.mutate(&candidate)
			}
			journal := &memoryJournal{snapshots: []installjournal.Snapshot{test.latest}}
			err := newRepository(t, journal).Save(context.Background(), test.expected, candidate)
			if !errors.Is(err, test.want) {
				t.Fatalf("error=%v want=%v", err, test.want)
			}
		})
	}
}

func TestPF001ArtifactJournalStrictDecoderRejectsMalformedShapes(t *testing.T) {
	t.Parallel()
	canonical, _, _ := encodeSnapshot(pristineSnapshot(t))
	invalid := [][]byte{
		nil,
		[]byte("not-json"),
		[]byte(strings.Replace(string(canonical), `"progress":[]`, `"progress":null`, 1)),
		[]byte(strings.Replace(string(canonical), `"progress":[]`, `"progress":[1]`, 1)),
		[]byte(strings.Replace(string(canonical), `"progress":[]`, `"progress":[{"artifact_id":"x"}]`, 1)),
		append(append([]byte(nil), canonical...), []byte(` {}`)...),
	}
	for index, payload := range invalid {
		if _, err := decodeSnapshot(payload); !errors.Is(err, artifactapp.ErrAggregateIntegrity) {
			t.Fatalf("payload %d error=%v", index, err)
		}
	}
	if duplicateKeys([]byte(`[]`)) || duplicateKeys([]byte(`1`)) || !duplicateKeys([]byte(`{"a":1} trailing`)) {
		t.Fatal("strict duplicate scanner classification changed")
	}
}

func TestPF001ArtifactJournalRoundTripsConsumptionAndReleaseLifecycleStates(t *testing.T) {
	t.Parallel()
	id := "r-" + strings.Repeat("a", 64)
	partial := "p-" + strings.Repeat("b", 64)
	digest := releaseinventory.DigestBytes([]byte("abc")).Hex()
	for _, snapshot := range []artifactacquisition.Snapshot{
		func() artifactacquisition.Snapshot {
			value := pristineSnapshot(t)
			value.Version, value.ReservationID, value.ReservedBytes, value.ReleaseState = 1, id, 5, "allocating"
			return value
		}(),
		func() artifactacquisition.Snapshot {
			value := pristineSnapshot(t)
			value.Version, value.ReservationID, value.ReservedBytes = 2, id, 5
			value.ReleaseState, value.ReleaseReason = "pending", "cancelled"
			return value
		}(),
		func() artifactacquisition.Snapshot {
			value := pristineSnapshot(t)
			value.Version, value.ReservationID, value.ReservedBytes, value.FilesystemID = 7, id, 5, "localfs-1"
			value.ReleaseState, value.ReleaseReason = "released", "completed"
			value.Progress = []artifactacquisition.ProgressSnapshot{{
				ArtifactID: "artifact", ArtifactDigest: digest, PartialID: partial,
				VerifiedChunks: []uint32{0}, ReservationConsumed: true, Completed: true,
			}}
			return value
		}(),
	} {
		encoded, _, err := encodeSnapshot(snapshot)
		if err != nil {
			t.Fatalf("encode lifecycle %+v: %v", snapshot, err)
		}
		decoded, err := decodeSnapshot(encoded)
		if err != nil || !reflect.DeepEqual(decoded, snapshot) {
			t.Fatalf("roundtrip decoded=%+v want=%+v err=%v", decoded, snapshot, err)
		}
	}
}

func TestPF001ArtifactJournalRejectsContradictoryLifecycleShapes(t *testing.T) {
	t.Parallel()
	id := "r-" + strings.Repeat("a", 64)
	base := pristineSnapshot(t)
	base.Version, base.ReservationID, base.ReservedBytes, base.ReleaseState = 1, id, 5, "allocating"
	tests := []func(*artifactacquisition.Snapshot){
		func(value *artifactacquisition.Snapshot) { value.ReleaseState = "" },
		func(value *artifactacquisition.Snapshot) { value.FilesystemID = "localfs-1" },
		func(value *artifactacquisition.Snapshot) { value.ReleaseReason = "cancelled" },
		func(value *artifactacquisition.Snapshot) { value.ReleaseState = "unknown" },
		func(value *artifactacquisition.Snapshot) {
			value.ReleaseState, value.FilesystemID, value.ReleaseReason = "active", "", ""
		},
		func(value *artifactacquisition.Snapshot) {
			value.ReleaseState, value.FilesystemID, value.ReleaseReason = "active", "localfs-1", "rollback"
		},
		func(value *artifactacquisition.Snapshot) {
			value.ReleaseState, value.ReleaseReason = "pending", "other"
		},
		func(value *artifactacquisition.Snapshot) {
			value.Progress = []artifactacquisition.ProgressSnapshot{{
				ArtifactID: "artifact", ArtifactDigest: releaseinventory.DigestBytes([]byte("abc")).Hex(),
				PartialID: "p-" + strings.Repeat("b", 64), VerifiedChunks: []uint32{},
			}}
		},
		func(value *artifactacquisition.Snapshot) {
			value.ReleaseState, value.FilesystemID = "active", "localfs-1"
			value.Progress = []artifactacquisition.ProgressSnapshot{{
				ArtifactID: "artifact", ArtifactDigest: releaseinventory.DigestBytes([]byte("abc")).Hex(),
				PartialID: "p-" + strings.Repeat("b", 64), VerifiedChunks: []uint32{0}, Completed: true,
			}}
		},
	}
	for index, mutate := range tests {
		candidate := base
		mutate(&candidate)
		if validSnapshot(candidate) {
			t.Fatalf("lifecycle mutation %d accepted: %+v", index, candidate)
		}
		if _, _, err := encodeSnapshot(candidate); !errors.Is(err, artifactapp.ErrAggregateIntegrity) {
			t.Fatalf("lifecycle mutation %d encode error=%v", index, err)
		}
	}
}

func pristineSnapshot(t *testing.T) artifactacquisition.Snapshot {
	t.Helper()
	plan, err := artifactacquisition.NewPlan(artifactacquisition.PlanInput{
		PlanDigest: releaseinventory.DigestBytes([]byte("plan")),
		ProxyMode:  artifactacquisition.ProxyModeSystem,
		Artifacts: []artifactacquisition.ArtifactInput{{
			ID: "artifact", Digest: releaseinventory.DigestBytes([]byte("abc")), Size: 3,
			Sources: []string{"bundle://artifact"},
			Chunks:  []artifactacquisition.ChunkInput{{Offset: 0, Size: 3, Digest: releaseinventory.DigestBytes([]byte("abc"))}},
		}},
		Totals: artifactacquisition.TotalsInput{DownloadBytes: 3, RollbackHeadroomBytes: 1, SafetyHeadroomBytes: 1, RequiredBytes: 5},
	})
	if err != nil {
		t.Fatal(err)
	}
	aggregate, _ := artifactacquisition.NewAggregate("install-1", plan)
	return aggregate.Snapshot()
}

func newRepository(t *testing.T, journal *memoryJournal) *Repository {
	t.Helper()
	repository, err := New(&provider{journal: journal}, fixedClock{})
	if err != nil {
		t.Fatal(err)
	}
	return repository
}

type provider struct {
	journal installjournal.Journal
	err     error
}

func (p *provider) JournalFor(context.Context, install.OperationID) (installjournal.Journal, error) {
	return p.journal, p.err
}

type memoryJournal struct {
	snapshots  []installjournal.Snapshot
	loadErr    error
	appendErr  error
	confirmErr error
	confirmed  int
}

func (j *memoryJournal) LoadLatest(context.Context) (installjournal.Snapshot, error) {
	if j.loadErr != nil {
		return installjournal.Snapshot{}, j.loadErr
	}
	if len(j.snapshots) == 0 {
		return installjournal.Snapshot{}, installjournal.ErrNotFound
	}
	return j.snapshots[len(j.snapshots)-1], nil
}

func (j *memoryJournal) Append(_ context.Context, expected uint64, snapshot installjournal.Snapshot) error {
	if j.appendErr != nil {
		return j.appendErr
	}
	if uint64(len(j.snapshots)) != expected || snapshot.Revision != expected+1 || !json.Valid(snapshot.Payload) {
		return installjournal.ErrConflict
	}
	j.snapshots = append(j.snapshots, snapshot)
	return nil
}

func (j *memoryJournal) ConfirmDurable(context.Context, string, uint64) error {
	j.confirmed++
	return j.confirmErr
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC) }

type zeroClock struct{}

func (zeroClock) Now() time.Time { return time.Time{} }

type pointerClock struct{}

func (*pointerClock) Now() time.Time { return time.Now() }
