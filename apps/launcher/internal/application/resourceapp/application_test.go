package resourceapp

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/resourceinventory"
)

const (
	installationID = "019f5f20-1234-4abc-8123-0123456789ab"
	generationID   = "019f5f20-1234-7abc-8123-0123456789ab"
)

func TestPF001EnsureCreatesOneAtATimeAndPersistsImmediately(t *testing.T) {
	t.Parallel()
	repository := newMemoryRepository()
	engine := newFakeEngine(t)
	application := newApplication(t, repository, engine)
	result, err := application.EnsureNetworkAndVolumes(context.Background(), validCommand(t))
	if err != nil {
		t.Fatal(err)
	}
	if result.Created != 7 || result.Recovered != 0 || result.Verified != 0 || result.InventoryVersion != 14 || result.InventoryDigest.IsZero() {
		t.Fatalf("result=%+v", result)
	}
	if repository.saveCount != 15 { // initial + intent and object for seven resources
		t.Fatalf("saves=%d", repository.saveCount)
	}
	wantPrefix := []string{"inspect:internal", "create:internal", "inspect:state", "create:state"}
	if !reflect.DeepEqual(engine.events[:4], wantPrefix) {
		t.Fatalf("events=%v", engine.events)
	}
	for index := 0; index < len(engine.events); index += 2 {
		if !strings.HasPrefix(engine.events[index], "inspect:") || !strings.HasPrefix(engine.events[index+1], "create:") {
			t.Fatalf("non-sequential events=%v", engine.events)
		}
	}
}

func TestPF001EnsureReplayVerifiesExactObjectsWithoutMutation(t *testing.T) {
	t.Parallel()
	repository := newMemoryRepository()
	engine := newFakeEngine(t)
	application := newApplication(t, repository, engine)
	first, err := application.EnsureNetworkAndVolumes(context.Background(), validCommand(t))
	if err != nil {
		t.Fatal(err)
	}
	engine.events = nil
	second, err := application.EnsureNetworkAndVolumes(context.Background(), validCommand(t))
	if err != nil {
		t.Fatal(err)
	}
	if second.Created != 0 || second.Verified != 7 || second.InventoryVersion != first.InventoryVersion ||
		!second.InventoryDigest.Equal(first.InventoryDigest) {
		t.Fatalf("replay=%+v first=%+v", second, first)
	}
	for _, event := range engine.events {
		if !strings.HasPrefix(event, "inspect:") {
			t.Fatalf("replay mutation event=%q", event)
		}
	}
}

func TestPF001PendingIntentRecoversOnlyExactResource(t *testing.T) {
	t.Parallel()
	command := validCommand(t)
	plan, _ := resourceinventory.BuildPlan(command.InstallationID, command.GenerationID, command.Release)
	inventory, _ := resourceinventory.New(command.InstallationID)
	_, _ = inventory.Begin(plan[0], command.CreationOperation)
	repository := newMemoryRepository()
	repository.snapshot = inventory.Snapshot()
	repository.exists = true
	engine := newFakeEngine(t)
	engine.objects[plan[0].Name()] = fakeObserved(t, plan[0])
	result, err := newApplication(t, repository, engine).EnsureNetworkAndVolumes(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if result.Recovered != 1 || result.Created != 6 {
		t.Fatalf("result=%+v", result)
	}

	inventory, _ = resourceinventory.New(command.InstallationID)
	_, _ = inventory.Begin(plan[0], command.CreationOperation)
	repository = newMemoryRepository()
	repository.snapshot, repository.exists = inventory.Snapshot(), true
	engine = newFakeEngine(t)
	foreignLabels := plan[0].Labels()
	foreignLabels["io.agentmemory.release"] = "9.9.9"
	foreign, _ := resourceinventory.NewObserved(plan[0].Kind(), plan[0].Name(), strings.Repeat("a", 64), foreignLabels)
	engine.objects[plan[0].Name()] = foreign
	_, err = newApplication(t, repository, engine).EnsureNetworkAndVolumes(context.Background(), command)
	var applicationError *Error
	if !errors.As(err, &applicationError) || applicationError.Code != ErrorOwnership || len(engine.created) != 0 {
		t.Fatalf("foreign recovery err=%v created=%v", err, engine.created)
	}
}

func TestPF001FailureCompensatesOnlyCreatedAndRecordedResources(t *testing.T) {
	t.Parallel()
	repository := newMemoryRepository()
	engine := newFakeEngine(t)
	engine.failCreatePurpose = resourceinventory.PurposeArtifacts
	_, err := newApplication(t, repository, engine).EnsureNetworkAndVolumes(context.Background(), validCommand(t))
	var applicationError *Error
	if !errors.As(err, &applicationError) || applicationError.Code != ErrorEngine {
		t.Fatalf("error=%v", err)
	}
	if !reflect.DeepEqual(engine.removed, []resourceinventory.Purpose{resourceinventory.PurposeState, resourceinventory.PurposeInternal}) {
		t.Fatalf("removed=%v", engine.removed)
	}
	restored, restoreError := resourceinventory.Restore(repository.snapshot)
	if restoreError != nil {
		t.Fatal(restoreError)
	}
	plan, _ := resourceinventory.BuildPlan(installationID, generationID, "0.1.0")
	if _, exists := restored.Find(plan[0].Name()); exists {
		t.Fatal("compensated internal network retained ownership")
	}
	entry, exists := restored.Find(plan[2].Name())
	if !exists || entry.State() != resourceinventory.EntryPending {
		t.Fatalf("failed resource intent=%+v exists=%v", entry, exists)
	}
}

func TestPF001RecordSaveFailurePreservesPendingForSafeRecovery(t *testing.T) {
	t.Parallel()
	repository := newMemoryRepository()
	repository.failAtSave = 3 // initial, first intent, first object record
	engine := newFakeEngine(t)
	_, err := newApplication(t, repository, engine).EnsureNetworkAndVolumes(context.Background(), validCommand(t))
	var applicationError *Error
	if !errors.As(err, &applicationError) || applicationError.Code != ErrorInventory || len(engine.removed) != 0 {
		t.Fatalf("err=%v removed=%v", err, engine.removed)
	}
	restored, restoreError := resourceinventory.Restore(repository.snapshot)
	if restoreError != nil {
		t.Fatal(restoreError)
	}
	plan, _ := resourceinventory.BuildPlan(installationID, generationID, "0.1.0")
	entry, exists := restored.Find(plan[0].Name())
	if !exists || entry.State() != resourceinventory.EntryPending {
		t.Fatalf("entry=%+v exists=%v", entry, exists)
	}
}

func TestPF001EnsureRejectsInvalidCompositionCommandAndRepositoryState(t *testing.T) {
	t.Parallel()
	var nilRepository *memoryRepository
	var nilEngine *fakeEngine
	for _, dependencies := range []Dependencies{
		{},
		{Repository: nilRepository, Engine: newFakeEngine(t)},
		{Repository: newMemoryRepository(), Engine: nilEngine},
	} {
		if _, err := New(dependencies); err == nil {
			t.Fatalf("New(%+v) succeeded", dependencies)
		}
	}
	application := newApplication(t, newMemoryRepository(), newFakeEngine(t))
	for _, command := range []Command{{}, func() Command { c := validCommand(t); c.CreationOperation = "bad op"; return c }()} {
		_, err := application.EnsureNetworkAndVolumes(context.Background(), command)
		var applicationError *Error
		if !errors.As(err, &applicationError) || applicationError.Code != ErrorInvalidCommand {
			t.Fatalf("command=%+v err=%v", command, err)
		}
	}
	repository := newMemoryRepository()
	repository.loadErr = ErrInventoryIntegrity
	_, err := newApplication(t, repository, newFakeEngine(t)).EnsureNetworkAndVolumes(context.Background(), validCommand(t))
	var applicationError *Error
	if !errors.As(err, &applicationError) || applicationError.Code != ErrorInventory {
		t.Fatalf("repository err=%v", err)
	}
}

func TestPF001CompensationFailureIsExplicitAndDoesNotForgetOwnership(t *testing.T) {
	t.Parallel()
	repository := newMemoryRepository()
	engine := newFakeEngine(t)
	engine.failCreatePurpose = resourceinventory.PurposeState
	engine.failRemove = true
	_, err := newApplication(t, repository, engine).EnsureNetworkAndVolumes(context.Background(), validCommand(t))
	var applicationError *Error
	if !errors.As(err, &applicationError) || applicationError.Code != ErrorCompensation {
		t.Fatalf("error=%v", err)
	}
	restored, restoreError := resourceinventory.Restore(repository.snapshot)
	if restoreError != nil {
		t.Fatal(restoreError)
	}
	plan, _ := resourceinventory.BuildPlan(installationID, generationID, "0.1.0")
	entry, exists := restored.Find(plan[0].Name())
	if !exists || entry.State() != resourceinventory.EntryRecorded {
		t.Fatal("failed compensation forgot resource ownership")
	}
}

func TestPF001ApplicationErrorsAreStableAndInitialSaveFailsClosed(t *testing.T) {
	t.Parallel()
	repository := newMemoryRepository()
	repository.failAtSave = 1
	_, err := newApplication(t, repository, newFakeEngine(t)).EnsureNetworkAndVolumes(context.Background(), validCommand(t))
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != ErrorInventory || typed.Error() == "" ||
		!errors.Is(typed, &Error{Code: ErrorInventory}) || errors.Is(typed, &Error{Code: ErrorEngine}) {
		t.Fatalf("stable error=%v", err)
	}
	var nilError *Error
	if nilError.Error() != "<nil>" {
		t.Fatalf("nil error=%q", nilError.Error())
	}
	application := newApplication(t, newMemoryRepository(), newFakeEngine(t))
	var absentContext context.Context
	if _, err := application.EnsureNetworkAndVolumes(absentContext, validCommand(t)); err == nil {
		t.Fatal("nil context succeeded")
	}
}

func TestPF001ResourceApplicationFailsClosedAtEveryPersistenceAndEngineBoundary(t *testing.T) {
	t.Parallel()
	command := validCommand(t)
	for _, failAt := range []int{2, 7} {
		repository := newMemoryRepository()
		repository.failAtSave = failAt
		engine := newFakeEngine(t)
		if failAt == 7 {
			engine.failCreatePurpose = resourceinventory.PurposeArtifacts
		}
		_, err := newApplication(t, repository, engine).EnsureNetworkAndVolumes(context.Background(), command)
		var typed *Error
		if !errors.As(err, &typed) || (failAt == 2 && typed.Code != ErrorInventory) || (failAt == 7 && typed.Code != ErrorCompensation) {
			t.Fatalf("save %d error=%v", failAt, err)
		}
	}

	for _, engineError := range []error{
		containerengine.ErrManagedResourceOperation,
		containerengine.ErrManagedResourceCollision,
		containerengine.ErrManagedResourceResponse,
	} {
		engine := newFakeEngine(t)
		engine.inspectError = engineError
		_, err := newApplication(t, newMemoryRepository(), engine).EnsureNetworkAndVolumes(context.Background(), command)
		var typed *Error
		if !errors.As(err, &typed) {
			t.Fatalf("engine error=%v", err)
		}
		want := ErrorEngine
		if errors.Is(engineError, containerengine.ErrManagedResourceCollision) || errors.Is(engineError, containerengine.ErrManagedResourceResponse) {
			want = ErrorOwnership
		}
		if typed.Code != want {
			t.Fatalf("engine error code=%s want=%s", typed.Code, want)
		}
	}

	repository := newMemoryRepository()
	repository.exists = true
	repository.snapshot = resourceinventory.Snapshot{SchemaVersion: 999, InstallationID: command.InstallationID}
	_, err := newApplication(t, repository, newFakeEngine(t)).EnsureNetworkAndVolumes(context.Background(), command)
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != ErrorInventory {
		t.Fatalf("invalid restored inventory error=%v", err)
	}
	if validCreationOperation("install-1", nil) {
		t.Fatal("empty creation plan accepted")
	}
	for _, value := range []any{0, struct{}{}, "configured"} {
		if nilDependency(value) {
			t.Fatalf("non-nil value rejected: %T", value)
		}
	}
}

func validCommand(t *testing.T) Command {
	t.Helper()
	endpoint, err := containerengine.NewEndpoint("unix:///var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	return Command{InstallationID: installationID, GenerationID: generationID, Release: "0.1.0", CreationOperation: "install-1", Endpoint: endpoint}
}

func newApplication(t *testing.T, repository Repository, engine containerengine.ManagedResourcePort) *Application {
	t.Helper()
	application, err := New(Dependencies{Repository: repository, Engine: engine})
	if err != nil {
		t.Fatal(err)
	}
	return application
}

type memoryRepository struct {
	exists     bool
	snapshot   resourceinventory.Snapshot
	saveCount  int
	failAtSave int
	loadErr    error
}

func newMemoryRepository() *memoryRepository { return &memoryRepository{} }

func (r *memoryRepository) Load(_ context.Context, installation string) (resourceinventory.Snapshot, error) {
	if r.loadErr != nil {
		return resourceinventory.Snapshot{}, r.loadErr
	}
	if !r.exists {
		return resourceinventory.Snapshot{}, ErrInventoryNotFound
	}
	if r.snapshot.InstallationID != installation {
		return resourceinventory.Snapshot{}, ErrInventoryIntegrity
	}
	return cloneSnapshot(r.snapshot), nil
}

func (r *memoryRepository) Save(_ context.Context, expected uint64, snapshot resourceinventory.Snapshot) error {
	r.saveCount++
	if r.failAtSave == r.saveCount {
		return ErrInventoryPersistence
	}
	if r.exists && r.snapshot.Version != expected {
		return ErrInventoryConflict
	}
	if !r.exists && (expected != 0 || snapshot.Version != 0) {
		return ErrInventoryConflict
	}
	r.snapshot, r.exists = cloneSnapshot(snapshot), true
	return nil
}

type fakeEngine struct {
	t                 *testing.T
	objects           map[string]resourceinventory.Observed
	events            []string
	created           []resourceinventory.Purpose
	removed           []resourceinventory.Purpose
	failCreatePurpose resourceinventory.Purpose
	failRemove        bool
	inspectError      error
}

func newFakeEngine(t *testing.T) *fakeEngine {
	return &fakeEngine{t: t, objects: make(map[string]resourceinventory.Observed)}
}

func (e *fakeEngine) Inspect(_ context.Context, _ containerengine.Endpoint, spec resourceinventory.Spec) (resourceinventory.Observed, error) {
	e.events = append(e.events, "inspect:"+string(spec.Purpose()))
	if e.inspectError != nil {
		return resourceinventory.Observed{}, e.inspectError
	}
	observed, exists := e.objects[spec.Name()]
	if !exists {
		return resourceinventory.Observed{}, containerengine.ErrManagedResourceNotFound
	}
	return observed, nil
}

func (e *fakeEngine) Create(_ context.Context, _ containerengine.Endpoint, spec resourceinventory.Spec) (resourceinventory.Observed, error) {
	e.events = append(e.events, "create:"+string(spec.Purpose()))
	if spec.Purpose() == e.failCreatePurpose {
		return resourceinventory.Observed{}, containerengine.ErrManagedResourceOperation
	}
	observed := fakeObserved(e.t, spec)
	e.objects[spec.Name()] = observed
	e.created = append(e.created, spec.Purpose())
	return observed, nil
}

func (e *fakeEngine) Remove(_ context.Context, _ containerengine.Endpoint, authorization resourceinventory.RemovalAuthorization) error {
	if e.failRemove {
		return containerengine.ErrManagedResourceOperation
	}
	observed, exists := e.objects[authorization.Name()]
	if !exists || observed.ObjectID() != authorization.ObjectID() {
		return containerengine.ErrManagedResourceCollision
	}
	delete(e.objects, authorization.Name())
	e.removed = append(e.removed, resourceinventory.Purpose(authorization.Labels()["io.agentmemory.purpose"]))
	return nil
}

func fakeObserved(t *testing.T, spec resourceinventory.Spec) resourceinventory.Observed {
	t.Helper()
	objectID := spec.Name()
	if spec.Kind() == resourceinventory.KindNetwork {
		objectID = strings.Repeat("a", 64)
	}
	observed, err := resourceinventory.NewObserved(spec.Kind(), spec.Name(), objectID, spec.Labels())
	if err != nil {
		t.Fatal(err)
	}
	return observed
}

func cloneSnapshot(snapshot resourceinventory.Snapshot) resourceinventory.Snapshot {
	copyOfSnapshot := snapshot
	copyOfSnapshot.Entries = append([]resourceinventory.EntrySnapshot(nil), snapshot.Entries...)
	for index := range copyOfSnapshot.Entries {
		labels := make(map[string]string, len(snapshot.Entries[index].Labels))
		for key, value := range snapshot.Entries[index].Labels {
			labels[key] = value
		}
		copyOfSnapshot.Entries[index].Labels = labels
	}
	return copyOfSnapshot
}
