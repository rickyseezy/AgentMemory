package activereleasejournal

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/activereleaseapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/activerelease"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001ActivationRepositoryPersistsReplaysAndRestoresEveryCursor(t *testing.T) {
	t.Parallel()
	provider := newMemoryJournalProvider()
	repository, err := NewActivationRepository(provider, fixedClock{now: repositoryTime()})
	if err != nil {
		t.Fatal(err)
	}
	operationID, plan, pointer := repositoryIdentities(t, 1)
	activation, err := activerelease.NewActivation(operationID, plan, install.Digest{}, pointer)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(context.Background(), activation.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(context.Background(), activation.Snapshot()); err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}
	restored, err := repository.Load(context.Background(), operationID)
	if err != nil || restored.State() != activerelease.StateCreated || restored.Version() != 0 {
		t.Fatalf("Load() = %#v/%v", restored, err)
	}
	stage := install.DigestBytes([]byte("Core stage"))
	if err := restored.RecordCorePrepared(stage); err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(context.Background(), restored.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if err := restored.RecordHostCommitted(pointer.Digest()); err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(context.Background(), restored.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if err := restored.RecordCoreCommitted(stage, pointer.Digest()); err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(context.Background(), restored.Snapshot()); err != nil {
		t.Fatal(err)
	}
	committed, err := repository.Load(context.Background(), operationID)
	journal := provider.journal(operationID)
	if err != nil || committed.State() != activerelease.StateCommitted || committed.Version() != 3 ||
		journal.snapshot.Revision != 4 || journal.confirms < 3 {
		t.Fatalf("committed = %#v/%v; revision/confirms=%d/%d", committed, err, journal.snapshot.Revision, journal.confirms)
	}
}

func TestPF001ActivationRepositoryRejectsMissingStaleTamperedAndUnavailableState(t *testing.T) {
	t.Parallel()
	provider := newMemoryJournalProvider()
	repository, _ := NewActivationRepository(provider, fixedClock{now: repositoryTime()})
	operationID, plan, pointer := repositoryIdentities(t, 1)
	if _, err := repository.Load(context.Background(), operationID); !errors.Is(err, activereleaseapp.ErrActivationNotFound) {
		t.Fatalf("missing load error = %v", err)
	}
	activation, _ := activerelease.NewActivation(operationID, plan, install.Digest{}, pointer)
	if err := activation.RecordCorePrepared(install.DigestBytes([]byte("stage"))); err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(context.Background(), activation.Snapshot()); !errors.Is(err, activereleaseapp.ErrActivationConflict) {
		t.Fatalf("skipped first version error = %v", err)
	}
	initial, _ := activerelease.NewActivation(operationID, plan, install.Digest{}, pointer)
	if err := repository.Save(context.Background(), initial.Snapshot()); err != nil {
		t.Fatal(err)
	}
	otherOperation, otherPlan, _ := repositoryIdentities(t, 2)
	foreign, _ := activerelease.NewActivation(otherOperation, otherPlan, install.Digest{}, pointer)
	if err := repository.Save(context.Background(), foreign.Snapshot()); err != nil {
		t.Fatal(err)
	}
	provider.journal(operationID).snapshot.Payload = append([]byte(" "), provider.journal(operationID).snapshot.Payload...)
	if _, err := repository.Load(context.Background(), operationID); !errors.Is(err, activereleaseapp.ErrActivationIntegrity) {
		t.Fatalf("noncanonical load error = %v", err)
	}
	provider.err = errors.New("private infrastructure")
	if _, err := repository.Load(context.Background(), otherOperation); !errors.Is(err, provider.err) {
		t.Fatalf("provider error = %v", err)
	}
}

func TestPF001HostPointerRepositoryUsesAuthenticatedMonotonicCAS(t *testing.T) {
	t.Parallel()
	provider := newMemoryJournalProvider()
	repository, err := NewHostPointerRepository(provider, fixedClock{now: repositoryTime()})
	if err != nil {
		t.Fatal(err)
	}
	_, _, first := repositoryIdentities(t, 1)
	if _, err := repository.Load(context.Background(), first.InstallationID()); !errors.Is(err, activereleaseapp.ErrPointerNotFound) {
		t.Fatalf("missing pointer error = %v", err)
	}
	if err := repository.CompareAndSwap(context.Background(), install.Digest{}, first); err != nil {
		t.Fatal(err)
	}
	if err := repository.ConfirmDurable(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.Load(context.Background(), first.InstallationID())
	if err != nil || !loaded.Digest().Equal(first.Digest()) {
		t.Fatalf("Load() = %#v/%v", loaded, err)
	}
	second := successorPointer(t, first)
	if err := repository.CompareAndSwap(context.Background(), first.Digest(), second); err != nil {
		t.Fatal(err)
	}
	if err := repository.CompareAndSwap(context.Background(), second.Digest(), second); err != nil {
		t.Fatalf("exact current confirmation: %v", err)
	}
	if err := repository.CompareAndSwap(context.Background(), first.Digest(), second); !errors.Is(err, activereleaseapp.ErrPointerConflict) {
		t.Fatalf("stale CAS error = %v", err)
	}
	if err := repository.ConfirmDurable(context.Background(), first); !errors.Is(err, activereleaseapp.ErrPointerConflict) {
		t.Fatalf("foreign confirm error = %v", err)
	}
	operationID, _ := pointerOperationID(first.InstallationID())
	journal := provider.journal(operationID)
	if journal.snapshot.Revision != 2 || journal.confirms < 3 {
		t.Fatalf("revision/confirms = %d/%d", journal.snapshot.Revision, journal.confirms)
	}
}

func TestPF001HostPointerRepositoryRejectsRollbackTamperAndJournalFailures(t *testing.T) {
	t.Parallel()
	provider := newMemoryJournalProvider()
	repository, _ := NewHostPointerRepository(provider, fixedClock{now: repositoryTime()})
	_, _, first := repositoryIdentities(t, 1)
	if err := repository.CompareAndSwap(context.Background(), install.DigestBytes([]byte("missing")), first); !errors.Is(err, activereleaseapp.ErrPointerConflict) {
		t.Fatalf("nonzero first expected error = %v", err)
	}
	if err := repository.CompareAndSwap(context.Background(), install.Digest{}, first); err != nil {
		t.Fatal(err)
	}
	rollback := pointerWithSequence(t, first, 1, 3)
	if err := repository.CompareAndSwap(context.Background(), first.Digest(), rollback); !errors.Is(err, activereleaseapp.ErrPointerConflict) {
		t.Fatalf("same-sequence equivocation error = %v", err)
	}
	operationID, _ := pointerOperationID(first.InstallationID())
	journal := provider.journal(operationID)
	journal.snapshot.Payload = append(journal.snapshot.Payload, '\n')
	if _, err := repository.Load(context.Background(), first.InstallationID()); !errors.Is(err, activereleaseapp.ErrPointerIntegrity) {
		t.Fatalf("tamper error = %v", err)
	}
	journal.loadErr = installjournal.ErrCorrupt
	if _, err := repository.Load(context.Background(), first.InstallationID()); !errors.Is(err, activereleaseapp.ErrPointerIntegrity) {
		t.Fatalf("corrupt journal error = %v", err)
	}
	journal.loadErr = nil
	journal.appendErr = installjournal.ErrConflict
	journal.snapshot = installjournal.Snapshot{}
	if err := repository.CompareAndSwap(context.Background(), install.Digest{}, first); !errors.Is(err, activereleaseapp.ErrPointerConflict) {
		t.Fatalf("append conflict error = %v", err)
	}
}

func TestPF001ActiveReleaseRepositoriesRejectInvalidCompositionAndInputs(t *testing.T) {
	t.Parallel()
	provider := newMemoryJournalProvider()
	clock := fixedClock{now: repositoryTime()}
	if _, err := NewActivationRepository(nil, clock); !errors.Is(err, activereleaseapp.ErrActivationIntegrity) {
		t.Fatalf("nil activation provider error = %v", err)
	}
	if _, err := NewHostPointerRepository(provider, nil); !errors.Is(err, activereleaseapp.ErrPointerIntegrity) {
		t.Fatalf("nil pointer clock error = %v", err)
	}
	var typedNilProvider *memoryJournalProvider
	if _, err := NewActivationRepository(typedNilProvider, clock); err == nil {
		t.Fatal("typed nil provider was accepted")
	}
	operationID, _, pointer := repositoryIdentities(t, 1)
	if _, err := (*ActivationRepository)(nil).Load(context.Background(), operationID); err == nil {
		t.Fatal("nil activation repository loaded")
	}
	if err := (*ActivationRepository)(nil).Save(context.Background(), activerelease.ActivationSnapshot{}); err == nil {
		t.Fatal("nil activation repository saved")
	}
	if _, err := (*HostPointerRepository)(nil).Load(context.Background(), pointer.InstallationID()); err == nil {
		t.Fatal("nil pointer repository loaded")
	}
	if err := (*HostPointerRepository)(nil).CompareAndSwap(context.Background(), install.Digest{}, pointer); err == nil {
		t.Fatal("nil pointer repository mutated")
	}
	if err := (*HostPointerRepository)(nil).ConfirmDurable(context.Background(), activerelease.Pointer{}); err == nil {
		t.Fatal("nil pointer repository confirmed")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	repository, _ := NewHostPointerRepository(provider, clock)
	if _, err := repository.Load(cancelled, pointer.InstallationID()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled load error = %v", err)
	}
}

func TestPF001ActiveReleaseCanonicalDecodersRejectContradictoryDocuments(t *testing.T) {
	t.Parallel()
	operationID, plan, pointer := repositoryIdentities(t, 1)
	activation, _ := activerelease.NewActivation(operationID, plan, install.Digest{}, pointer)
	raw, _, err := encodeActivation(activation.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	base := installjournal.Snapshot{OperationID: operationID.String(), Revision: 1, CapturedAt: repositoryTime(), Payload: raw}
	mutations := []func(*installjournal.Snapshot){
		func(value *installjournal.Snapshot) { value.OperationID = "019f5f23-5678-7def-9123-abcdef012399" },
		func(value *installjournal.Snapshot) { value.Revision = 2 },
		func(value *installjournal.Snapshot) { value.CapturedAt = time.Time{} },
		func(value *installjournal.Snapshot) { value.Payload = []byte(`{"schema_version":1}`) },
		func(value *installjournal.Snapshot) { value.Payload = append(value.Payload, value.Payload...) },
	}
	for index, mutate := range mutations {
		candidate := base
		candidate.Payload = append([]byte(nil), base.Payload...)
		mutate(&candidate)
		if _, err := decodeActivation(candidate, operationID); err == nil {
			t.Fatalf("activation mutation %d was accepted", index)
		}
	}
	pointerRaw, _, err := encodePointer(pointer.Record())
	if err != nil {
		t.Fatal(err)
	}
	pointerSnapshot := installjournal.Snapshot{
		OperationID: pointer.InstallationID(), Revision: 1, CapturedAt: repositoryTime(), Payload: pointerRaw,
	}
	if _, err := decodePointer(pointerSnapshot, operationID, "019f5f20-5678-7def-9123-abcdef012399"); err == nil {
		t.Fatal("foreign pointer installation was accepted")
	}
	var document map[string]any
	if err := json.Unmarshal(pointerRaw, &document); err != nil {
		t.Fatal(err)
	}
	document["unknown"] = true
	noncanonical, _ := json.Marshal(document)
	if err := decodeCanonical(noncanonical, &pointerEnvelope{}); err == nil {
		t.Fatal("unknown pointer envelope field was accepted")
	}
}

type memoryJournalProvider struct {
	mu       sync.Mutex
	journals map[string]*memoryJournal
	err      error
	nilNext  bool
}

func newMemoryJournalProvider() *memoryJournalProvider {
	return &memoryJournalProvider{journals: make(map[string]*memoryJournal)}
}

func (p *memoryJournalProvider) JournalFor(_ context.Context, operationID install.OperationID) (installjournal.Journal, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return nil, p.err
	}
	if p.nilNext {
		return nil, nil
	}
	journal, found := p.journals[operationID.String()]
	if !found {
		journal = &memoryJournal{}
		p.journals[operationID.String()] = journal
	}
	return journal, nil
}

func (p *memoryJournalProvider) journal(operationID install.OperationID) *memoryJournal {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.journals[operationID.String()]
}

type memoryJournal struct {
	mu         sync.Mutex
	snapshot   installjournal.Snapshot
	loadErr    error
	appendErr  error
	confirmErr error
	confirms   int
}

func (j *memoryJournal) Append(_ context.Context, previous uint64, snapshot installjournal.Snapshot) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.appendErr != nil {
		return j.appendErr
	}
	if j.snapshot.Revision != previous {
		return installjournal.ErrConflict
	}
	snapshot.Payload = append([]byte(nil), snapshot.Payload...)
	j.snapshot = snapshot
	return nil
}

func (j *memoryJournal) LoadLatest(context.Context) (installjournal.Snapshot, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.loadErr != nil {
		return installjournal.Snapshot{}, j.loadErr
	}
	if j.snapshot.Revision == 0 {
		return installjournal.Snapshot{}, installjournal.ErrNotFound
	}
	result := j.snapshot
	result.Payload = append([]byte(nil), j.snapshot.Payload...)
	return result, nil
}

func (j *memoryJournal) ConfirmDurable(_ context.Context, operationID string, revision uint64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.confirmErr != nil {
		return j.confirmErr
	}
	if j.snapshot.OperationID != operationID || j.snapshot.Revision != revision {
		return installjournal.ErrCorrupt
	}
	j.confirms++
	return nil
}

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func repositoryTime() time.Time {
	return time.Date(2026, 7, 13, 12, 30, 0, 123456000, time.UTC)
}

func repositoryIdentities(t testing.TB, suffix int) (install.OperationID, install.PlanDigest, activerelease.Pointer) {
	t.Helper()
	operationText := "019f5f23-5678-7def-9123-abcdef012347"
	installationID := "019f5f20-5678-7def-9123-abcdef012345"
	if suffix == 2 {
		operationText = "019f5f24-5678-7def-9123-abcdef012348"
		installationID = "019f5f25-5678-7def-9123-abcdef012349"
	}
	operationID, err := install.NewOperationID(operationText)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := install.BindPlan([]byte("canonical plan " + operationText))
	if err != nil {
		t.Fatal(err)
	}
	pointer, err := activerelease.NewPointer(activerelease.PointerInput{
		InstallationID: installationID, ReleaseID: "agentmemory-1.0.0",
		GenerationID:   "019f5f21-5678-7def-9123-abcdef012346",
		ManifestDigest: install.DigestBytes([]byte("manifest")), ComposeDigest: install.DigestBytes([]byte("compose")),
		ReadinessReceiptDigest: install.DigestBytes([]byte("readiness")), RuntimeEndpoint: "unix:///var/run/docker.sock",
		ReleaseSequence: 2, ResourceInventoryVersion: 1, ResourceInventoryDigest: install.DigestBytes([]byte("inventory")),
		SecurityEpoch: 1, ActivatedAt: repositoryTime(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return operationID, plan, pointer
}

func successorPointer(t testing.TB, current activerelease.Pointer) activerelease.Pointer {
	t.Helper()
	return pointerWithSequence(t, current, current.ReleaseSequence()+1, current.ResourceInventoryVersion()+1)
}

func pointerWithSequence(t testing.TB, current activerelease.Pointer, sequence, inventoryVersion uint64) activerelease.Pointer {
	t.Helper()
	pointer, err := activerelease.NewPointer(activerelease.PointerInput{
		InstallationID: current.InstallationID(), ReleaseID: "agentmemory-1.0.1",
		GenerationID:   "019f5f26-5678-7def-9123-abcdef012350",
		ManifestDigest: install.DigestBytes([]byte("manifest-next")), ComposeDigest: install.DigestBytes([]byte("compose-next")),
		ReadinessReceiptDigest: install.DigestBytes([]byte("readiness-next")), RuntimeEndpoint: current.RuntimeEndpoint(),
		ReleaseSequence: sequence, ResourceInventoryVersion: inventoryVersion,
		ResourceInventoryDigest: install.DigestBytes([]byte("inventory-next")), SecurityEpoch: current.SecurityEpoch(),
		ActivatedAt: current.ActivatedAt().Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	return pointer
}
