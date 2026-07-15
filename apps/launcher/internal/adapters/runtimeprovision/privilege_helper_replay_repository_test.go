package runtimeprovision

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF006PrivilegeHelperReplayRepositoryPersistsPendingAndCompletedRequest(t *testing.T) {
	t.Parallel()
	_, _, request, receipt := privilegeCodecFixture(t)
	provider := newPrivilegeHelperReplayProvider(t)
	clock := &privilegeHelperClockStub{now: request.IssuedAt().Add(time.Second)}
	repository, err := NewAnchoredPrivilegeHelperReplayRepository(provider, clock)
	if err != nil {
		t.Fatal(err)
	}

	if cached, complete, beginError := repository.BeginPrivilegeRequest(t.Context(), request); beginError != nil || complete || !cached.Digest().IsZero() {
		t.Fatalf("first begin cached=%x complete=%t error=%v", cached.Digest(), complete, beginError)
	}
	if cached, complete, beginError := repository.BeginPrivilegeRequest(t.Context(), request); beginError != nil || complete || !cached.Digest().IsZero() {
		t.Fatalf("pending replay cached=%x complete=%t error=%v", cached.Digest(), complete, beginError)
	}
	if completeError := repository.CompletePrivilegeRequest(t.Context(), request, receipt); completeError != nil {
		t.Fatal(completeError)
	}
	if completeError := repository.CompletePrivilegeRequest(t.Context(), request, receipt); completeError != nil {
		t.Fatalf("idempotent completion error=%v", completeError)
	}

	restarted, _ := NewAnchoredPrivilegeHelperReplayRepository(provider, clock)
	cached, complete, err := restarted.BeginPrivilegeRequest(t.Context(), request)
	if err != nil || !complete || cached.Digest() != receipt.Digest() ||
		!bytes.Equal(cached.Signature(), receipt.Signature()) {
		t.Fatalf("restart cached=%x complete=%t error=%v", cached.Digest(), complete, err)
	}
	operation, _ := install.NewOperationID(request.OperationID())
	journal, _ := provider.JournalFor(t.Context(), operation)
	snapshot, err := journal.LoadLatest(t.Context())
	document, decodeError := decodePrivilegeHelperReplay(snapshot.Payload)
	if err != nil || decodeError != nil || snapshot.Revision != 2 || document.Revision != 2 ||
		len(document.Entries) != 1 || document.Entries[0].Status != privilegeHelperReplayComplete {
		t.Fatalf("snapshot=%+v document=%+v errors=%v/%v", snapshot, document, err, decodeError)
	}
}

func TestPF006PrivilegeHelperReplayRepositoryRejectsNonceSubstitutionAndUnsafeStorage(t *testing.T) {
	t.Parallel()
	_, _, request, receipt := privilegeCodecFixture(t)
	clock := &privilegeHelperClockStub{now: request.IssuedAt().Add(time.Second)}
	provider := newPrivilegeHelperReplayProvider(t)
	repository, _ := NewAnchoredPrivilegeHelperReplayRepository(provider, clock)
	if _, _, err := repository.BeginPrivilegeRequest(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	substitutedInput := request.TransportInput()
	substitutedInput.Attempt++
	substituted, err := runtimeport.NewPrivilegeRequest(substitutedInput)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := repository.BeginPrivilegeRequest(t.Context(), substituted); !errors.Is(err, runtimeport.ErrPrivilegeIntegrity) {
		t.Fatalf("nonce substitution error=%v", err)
	}
	if err := repository.CompletePrivilegeRequest(t.Context(), request, receipt); err != nil {
		t.Fatal(err)
	}
	foreignInput := receipt.TransportInput()
	foreignInput.Signature[0] ^= 1
	foreign, err := runtimeport.NewPrivilegeReceipt(foreignInput)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.CompletePrivilegeRequest(t.Context(), request, foreign); !errors.Is(err, runtimeport.ErrPrivilegeIntegrity) {
		t.Fatalf("receipt substitution error=%v", err)
	}

	unprotected, _ := NewAnchoredPrivilegeHelperReplayRepository(
		privilegeHelperReplayStaticProvider{journal: &privilegeHelperReplayMemoryJournal{}}, clock,
	)
	if _, _, err := unprotected.BeginPrivilegeRequest(t.Context(), request); !errors.Is(err, runtimeport.ErrPrivilegeIntegrity) {
		t.Fatalf("unprotected journal error=%v", err)
	}
	for name, construct := range map[string]func() (*AnchoredPrivilegeHelperReplayRepository, error){
		"nil provider": func() (*AnchoredPrivilegeHelperReplayRepository, error) {
			return NewAnchoredPrivilegeHelperReplayRepository(nil, clock)
		},
		"nil clock": func() (*AnchoredPrivilegeHelperReplayRepository, error) {
			return NewAnchoredPrivilegeHelperReplayRepository(provider, nil)
		},
	} {
		if candidate, constructError := construct(); constructError == nil || candidate != nil {
			t.Fatalf("%s accepted", name)
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := repository.BeginPrivilegeRequest(cancelled, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
}

func TestPF006PrivilegeHelperReplayCodecRejectsDamagedOrNoncanonicalState(t *testing.T) {
	t.Parallel()
	_, _, request, _ := privilegeCodecFixture(t)
	document := privilegeHelperReplayDocument{
		SchemaVersion: privilegeHelperReplaySchemaVersion,
		OperationID:   request.OperationID(),
		Revision:      1,
		Entries:       []privilegeHelperReplayEntry{newPrivilegeHelperReplayEntry(request)},
	}
	payload, err := encodePrivilegeHelperReplay(document)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodePrivilegeHelperReplay(payload)
	if err != nil || decoded.Revision != 1 {
		t.Fatalf("decoded=%+v error=%v", decoded, err)
	}
	for name, damaged := range map[string][]byte{
		"empty":      nil,
		"malformed":  []byte(`{"schema_version":`),
		"unknown":    append(bytes.Clone(bytes.TrimSuffix(payload, []byte("}"))), []byte(`,"unknown":true}`)...),
		"trailing":   append(bytes.Clone(payload), []byte(` {}`)...),
		"whitespace": append([]byte(" "), payload...),
		"oversized":  bytes.Repeat([]byte("x"), maximumPrivilegeHelperReplayBytes+1),
	} {
		if _, decodeError := decodePrivilegeHelperReplay(damaged); decodeError == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	invalid := document
	invalid.Entries[0].Status = "foreign"
	if _, err := encodePrivilegeHelperReplay(invalid); err == nil {
		t.Fatal("foreign status accepted")
	}
}

type privilegeHelperReplayProvider struct {
	mu       sync.Mutex
	owner    install.OwnerBinding
	keys     *bootstrapadapter.MemoryOperationKeySource
	anchors  *bootstrapadapter.MemoryRollbackAnchorStore
	journals map[string]*bootstrapadapter.AnchoredJournal
}

func newPrivilegeHelperReplayProvider(t testing.TB) *privilegeHelperReplayProvider {
	t.Helper()
	owner, err := install.BindOwner("helper-replay-machine", "helper-replay-root")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := bootstrapadapter.NewMemoryOperationKeySource(bytes.NewReader(bytes.Repeat([]byte{0x6d}, 4096)))
	if err != nil {
		t.Fatal(err)
	}
	anchors, err := bootstrapadapter.NewMemoryRollbackAnchorStore(keys)
	if err != nil {
		t.Fatal(err)
	}
	return &privilegeHelperReplayProvider{
		owner: owner, keys: keys, anchors: anchors,
		journals: make(map[string]*bootstrapadapter.AnchoredJournal),
	}
}

func (p *privilegeHelperReplayProvider) JournalFor(
	ctx context.Context,
	operation install.OperationID,
) (journalport.Journal, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if existing := p.journals[operation.String()]; existing != nil {
		return existing, nil
	}
	key, err := p.keys.Ensure(ctx, operation, p.owner)
	if err != nil {
		return nil, err
	}
	journal, err := bootstrapadapter.NewAnchoredJournal(
		&privilegeHelperReplayMemoryJournal{}, p.anchors, key, operation, p.owner,
	)
	if err != nil {
		return nil, err
	}
	p.journals[operation.String()] = journal
	return journal, nil
}

type privilegeHelperReplayStaticProvider struct{ journal journalport.Journal }

func (p privilegeHelperReplayStaticProvider) JournalFor(
	context.Context,
	install.OperationID,
) (journalport.Journal, error) {
	return p.journal, nil
}

type privilegeHelperReplayMemoryJournal struct {
	mu       sync.Mutex
	snapshot journalport.Snapshot
}

func (j *privilegeHelperReplayMemoryJournal) Append(
	_ context.Context,
	expected uint64,
	snapshot journalport.Snapshot,
) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.snapshot.Revision != expected || snapshot.Revision != expected+1 {
		return journalport.ErrConflict
	}
	snapshot.Payload = bytes.Clone(snapshot.Payload)
	j.snapshot = snapshot
	return nil
}

func (j *privilegeHelperReplayMemoryJournal) LoadLatest(context.Context) (journalport.Snapshot, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.snapshot.Revision == 0 {
		return journalport.Snapshot{}, journalport.ErrNotFound
	}
	snapshotCopy := j.snapshot
	snapshotCopy.Payload = bytes.Clone(j.snapshot.Payload)
	return snapshotCopy, nil
}

func (j *privilegeHelperReplayMemoryJournal) ConfirmDurable(
	_ context.Context,
	operationID string,
	revision uint64,
) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.snapshot.OperationID != operationID || j.snapshot.Revision != revision {
		return journalport.ErrConflict
	}
	return nil
}
