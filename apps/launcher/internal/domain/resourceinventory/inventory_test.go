package resourceinventory

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
)

const (
	testInstallation = "019f5f20-1234-4abc-8123-0123456789ab"
	testGeneration   = "019f5f20-1234-7abc-8123-0123456789ab"
)

func TestPF001BuildPlanIsClosedAndUUIDDerived(t *testing.T) {
	t.Parallel()
	plan, err := BuildPlan(testInstallation, testGeneration, "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	wantPurposes := []Purpose{PurposeInternal, PurposeState, PurposeArtifacts, PurposeNeo4j, PurposeJournal, PurposeModels, PurposeTelemetry}
	if len(plan) != len(wantPurposes) {
		t.Fatalf("plan length=%d", len(plan))
	}
	for index, spec := range plan {
		if spec.Purpose() != wantPurposes[index] || len(spec.Labels()) != 5 {
			t.Fatalf("resource %d=%+v labels=%v", index, spec, spec.Labels())
		}
		if strings.Contains(spec.Name(), "project") || spec.Labels()[composeplan.LabelInstallation] != testInstallation {
			t.Fatalf("unsafe derivation: %q", spec.Name())
		}
		generation := testGeneration
		if index >= 4 {
			generation = stableGeneration
		}
		if spec.Labels()[composeplan.LabelGeneration] != generation {
			t.Fatalf("generation=%q want=%q", spec.Labels()[composeplan.LabelGeneration], generation)
		}
	}
	for _, invalid := range []struct{ installation, generation, release string }{
		{"bad", testGeneration, "0.1.0"},
		{testInstallation, "bad", "0.1.0"},
		{testInstallation, testGeneration, "../bad"},
	} {
		if _, err := BuildPlan(invalid.installation, invalid.generation, invalid.release); !errors.Is(err, ErrInvalidResource) {
			t.Fatalf("BuildPlan(%+v) error=%v", invalid, err)
		}
	}
}

func TestPF001InventoryRequiresIntentThenExactObservation(t *testing.T) {
	t.Parallel()
	inventory := newInventory(t)
	spec := mustPlan(t)[0]
	if _, err := inventory.Record(spec, "install-1", observedFor(t, spec)); !errors.Is(err, ErrInventoryConflict) {
		t.Fatalf("record without intent error=%v", err)
	}
	changed, err := inventory.Begin(spec, "install-1")
	if err != nil || !changed || inventory.Version() != 1 {
		t.Fatalf("Begin()=(%v,%v) version=%d", changed, err, inventory.Version())
	}
	changed, err = inventory.Begin(spec, "install-1")
	if err != nil || changed || inventory.Version() != 1 {
		t.Fatalf("idempotent Begin()=(%v,%v) version=%d", changed, err, inventory.Version())
	}
	foreign := observedFor(t, spec)
	labels := foreign.Labels()
	labels[composeplan.LabelInstallation] = "119f5f20-1234-4abc-8123-0123456789ab"
	foreign, _ = NewObserved(spec.Kind(), spec.Name(), foreign.ObjectID(), labels)
	if _, err := inventory.Record(spec, "install-1", foreign); !errors.Is(err, ErrInventoryIntegrity) {
		t.Fatalf("foreign labels error=%v", err)
	}
	changed, err = inventory.Record(spec, "install-1", observedFor(t, spec))
	if err != nil || !changed || inventory.Version() != 2 {
		t.Fatalf("Record()=(%v,%v) version=%d", changed, err, inventory.Version())
	}
	changed, err = inventory.Record(spec, "install-1", observedFor(t, spec))
	if err != nil || changed || inventory.Version() != 2 {
		t.Fatalf("idempotent Record()=(%v,%v) version=%d", changed, err, inventory.Version())
	}
}

func TestPF001RemovalRequiresInventoryIDAndExactLabels(t *testing.T) {
	t.Parallel()
	inventory := newInventory(t)
	spec := mustPlan(t)[1]
	observed := observedFor(t, spec)
	_, _ = inventory.Begin(spec, "install-1")
	if _, err := inventory.AuthorizeRemoval(observed); !errors.Is(err, ErrRemovalUnauthorized) {
		t.Fatalf("pending authorization error=%v", err)
	}
	_, _ = inventory.Record(spec, "install-1", observed)
	authorization, err := inventory.AuthorizeRemoval(observed)
	if err != nil || !authorization.Valid() {
		t.Fatalf("AuthorizeRemoval()=(%+v,%v)", authorization, err)
	}
	labels := observed.Labels()
	labels[composeplan.LabelRelease] = "0.2.0"
	foreign, _ := NewObserved(spec.Kind(), spec.Name(), spec.Name(), labels)
	if _, err := inventory.AuthorizeRemoval(foreign); !errors.Is(err, ErrRemovalUnauthorized) {
		t.Fatalf("label mismatch error=%v", err)
	}
	if err := inventory.ConfirmRemoved(authorization); err != nil {
		t.Fatal(err)
	}
	if _, exists := inventory.Find(spec.Name()); exists {
		t.Fatal("confirmed removal retained entry")
	}
	if err := inventory.ConfirmRemoved(authorization); !errors.Is(err, ErrRemovalUnauthorized) {
		t.Fatalf("replay removal error=%v", err)
	}
}

func TestPF001SnapshotRoundTripDefensiveCopiesAndRejectsTampering(t *testing.T) {
	t.Parallel()
	inventory := newInventory(t)
	for _, spec := range mustPlan(t) {
		_, _ = inventory.Begin(spec, "install-1")
		_, _ = inventory.Record(spec, "install-1", observedFor(t, spec))
	}
	snapshot := inventory.Snapshot()
	restored, err := Restore(snapshot)
	if err != nil || !reflect.DeepEqual(snapshot, restored.Snapshot()) {
		t.Fatalf("roundtrip err=%v\n got=%+v\nwant=%+v", err, restored.Snapshot(), snapshot)
	}
	snapshot.Entries[0].Labels[composeplan.LabelManaged] = "false"
	if restored.Snapshot().Entries[0].Labels[composeplan.LabelManaged] != "true" {
		t.Fatal("snapshot labels alias aggregate")
	}

	pristine := inventory.Snapshot()
	mutations := []func(*Snapshot){
		func(s *Snapshot) { s.SchemaVersion++ },
		func(s *Snapshot) { s.InstallationID = "bad" },
		func(s *Snapshot) { s.Version = 0 },
		func(s *Snapshot) { s.Entries[0].Name = "foreign" },
		func(s *Snapshot) { s.Entries[0].Labels[composeplan.LabelPurpose] = "other" },
		func(s *Snapshot) { s.Entries[0].CreationOperation = "bad operation" },
		func(s *Snapshot) { s.Entries[0].State = "future" },
		func(s *Snapshot) { s.Entries = append(s.Entries, s.Entries[0]) },
	}
	for index, mutate := range mutations {
		candidate := cloneSnapshot(pristine)
		mutate(&candidate)
		if _, err := Restore(candidate); !errors.Is(err, ErrInventoryIntegrity) {
			t.Fatalf("mutation %d error=%v", index, err)
		}
	}
}

func TestPF001ObservedValidation(t *testing.T) {
	t.Parallel()
	specs := mustPlan(t)
	if _, err := NewObserved(KindVolume, specs[1].Name(), "different", specs[1].Labels()); !errors.Is(err, ErrInvalidResource) {
		t.Fatalf("volume object ID error=%v", err)
	}
	if _, err := NewObserved(KindNetwork, specs[0].Name(), strings.Repeat("A", 64), specs[0].Labels()); !errors.Is(err, ErrInvalidResource) {
		t.Fatalf("network object ID error=%v", err)
	}
	if kind, err := ParseKind("future"); kind != KindUnknown || !errors.Is(err, ErrInvalidResource) {
		t.Fatalf("ParseKind()=(%v,%v)", kind, err)
	}
}

func TestPF001InventoryViewsAndVerificationRemainExact(t *testing.T) {
	t.Parallel()
	inventory := newInventory(t)
	spec := mustPlan(t)[0]
	observed := observedFor(t, spec)
	_, _ = inventory.Begin(spec, "install-1")
	_, _ = inventory.Record(spec, "install-1", observed)
	entry, exists := inventory.Find(spec.Name())
	if !exists || entry.CreationOperation() != "install-1" || entry.State() != EntryRecorded ||
		entry.ObjectID() != observed.ObjectID() || !entry.Spec().equal(spec) ||
		inventory.InstallationID() != testInstallation {
		t.Fatalf("entry=%+v exists=%v installation=%q", entry, exists, inventory.InstallationID())
	}
	if observed.Kind() != spec.Kind() || observed.Name() != spec.Name() {
		t.Fatalf("observation=%+v", observed)
	}
	if err := inventory.VerifyRecorded(spec, observed); err != nil {
		t.Fatal(err)
	}
	labels := observed.Labels()
	labels[composeplan.LabelManaged] = "false"
	foreign, _ := NewObserved(observed.Kind(), observed.Name(), observed.ObjectID(), labels)
	if err := inventory.VerifyRecorded(spec, foreign); !errors.Is(err, ErrInventoryIntegrity) {
		t.Fatalf("foreign verification error=%v", err)
	}
	authorization, _ := inventory.AuthorizeRemoval(observed)
	if authorization.Kind() != spec.Kind() || authorization.Name() != spec.Name() ||
		authorization.ObjectID() != observed.ObjectID() || authorization.Labels()[composeplan.LabelManaged] != "true" {
		t.Fatalf("authorization=%+v", authorization)
	}
	if !IsIntegrityError(ErrInventoryConflict) || IsIntegrityError(errors.New("external")) {
		t.Fatal("IsIntegrityError classification is incorrect")
	}
}

func TestPF001InventoryRejectsConflictingIntentAndMalformedObservations(t *testing.T) {
	t.Parallel()
	inventory := newInventory(t)
	spec := mustPlan(t)[1]
	_, _ = inventory.Begin(spec, "install-1")
	if _, err := inventory.Begin(spec, "install-2"); !errors.Is(err, ErrInventoryConflict) {
		t.Fatalf("conflicting intent error=%v", err)
	}
	for _, candidate := range []struct {
		kind     Kind
		name     string
		objectID string
		labels   map[string]string
	}{
		{KindUnknown, spec.Name(), spec.Name(), spec.Labels()},
		{KindVolume, "Bad", "Bad", spec.Labels()},
		{KindVolume, spec.Name(), spec.Name(), map[string]string{}},
	} {
		if _, err := NewObserved(candidate.kind, candidate.name, candidate.objectID, candidate.labels); !errors.Is(err, ErrInvalidResource) {
			t.Fatalf("NewObserved(%+v) error=%v", candidate, err)
		}
	}
	if Kind(99).String() != "unknown" || KindUnknown.String() != "unknown" {
		t.Fatal("unknown kind string changed")
	}
}

func newInventory(t *testing.T) *Inventory {
	t.Helper()
	inventory, err := New(testInstallation)
	if err != nil {
		t.Fatal(err)
	}
	return inventory
}

func mustPlan(t *testing.T) []Spec {
	t.Helper()
	plan, err := BuildPlan(testInstallation, testGeneration, "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func observedFor(t *testing.T, spec Spec) Observed {
	t.Helper()
	objectID := spec.Name()
	if spec.Kind() == KindNetwork {
		objectID = strings.Repeat("a", 64)
	}
	observed, err := NewObserved(spec.Kind(), spec.Name(), objectID, spec.Labels())
	if err != nil {
		t.Fatal(err)
	}
	return observed
}

func cloneSnapshot(snapshot Snapshot) Snapshot {
	copyOfSnapshot := snapshot
	copyOfSnapshot.Entries = append([]EntrySnapshot(nil), snapshot.Entries...)
	for index := range copyOfSnapshot.Entries {
		copyOfSnapshot.Entries[index].Labels = cloneLabels(snapshot.Entries[index].Labels)
	}
	return copyOfSnapshot
}
