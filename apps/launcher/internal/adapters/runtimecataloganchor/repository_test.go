package runtimecataloganchor

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
)

func TestPF001CatalogAnchorRepositoryPersistsNamespacesAndRestoresSuccessors(t *testing.T) {
	t.Parallel()
	repository, journal := repositoryFixture(t)
	first := testAnchor(t, "docker.desktop", 41, "first")
	if err := repository.CompareAndSwapCatalogAnchor(t.Context(), nil, first); err != nil {
		t.Fatal(err)
	}
	secondNamespace := testAnchor(t, "docker.engine", 7, "engine")
	if err := repository.CompareAndSwapCatalogAnchor(t.Context(), nil, secondNamespace); err != nil {
		t.Fatal(err)
	}
	next := testAnchor(t, "docker.desktop", 42, "next")
	if err := repository.CompareAndSwapCatalogAnchor(t.Context(), &first, next); err != nil {
		t.Fatal(err)
	}
	for _, want := range []runtimecatalogapp.CatalogAnchor{next, secondNamespace} {
		got, err := repository.LoadCatalogAnchor(t.Context(), want.CatalogID())
		if err != nil || !sameAnchor(got, want) {
			t.Fatalf("anchor %q=%+v error=%v", want.CatalogID(), got, err)
		}
	}
	if journal.confirmations != 3 {
		t.Fatalf("durable confirmations=%d", journal.confirmations)
	}
}

func TestPF001CatalogAnchorRepositoryEnforcesCASAndMonotonicity(t *testing.T) {
	t.Parallel()
	repository, _ := repositoryFixture(t)
	first := testAnchor(t, "docker.desktop", 7, "first")
	if err := repository.CompareAndSwapCatalogAnchor(t.Context(), nil, first); err != nil {
		t.Fatal(err)
	}
	stale := testAnchor(t, "docker.desktop", 6, "stale")
	for name, test := range map[string]struct {
		expected *runtimecatalogapp.CatalogAnchor
		next     runtimecatalogapp.CatalogAnchor
		want     error
	}{
		"second create": {nil, testAnchor(t, "docker.desktop", 8, "next"), runtimecatalogapp.ErrCatalogAnchorConflict},
		"stale CAS":     {&stale, testAnchor(t, "docker.desktop", 8, "next"), runtimecatalogapp.ErrCatalogAnchorConflict},
		"same sequence": {&first, testAnchor(t, "docker.desktop", 7, "equivocation"), runtimecatalogapp.ErrCatalogAnchorIntegrity},
		"other catalog": {&first, testAnchor(t, "docker.engine", 8, "other"), runtimecatalogapp.ErrCatalogAnchorIntegrity},
	} {
		if err := repository.CompareAndSwapCatalogAnchor(t.Context(), test.expected, test.next); !errors.Is(err, test.want) {
			t.Fatalf("%s error=%v", name, err)
		}
	}
	missing, _ := repositoryFixture(t)
	if _, err := missing.LoadCatalogAnchor(t.Context(), "docker.desktop"); !errors.Is(err, runtimecatalogapp.ErrCatalogAnchorNotFound) {
		t.Fatalf("missing load error=%v", err)
	}
	if err := missing.CompareAndSwapCatalogAnchor(t.Context(), &first, testAnchor(t, "docker.desktop", 8, "next")); !errors.Is(err, runtimecatalogapp.ErrCatalogAnchorConflict) {
		t.Fatalf("missing predecessor error=%v", err)
	}
}

func TestPF001CatalogAnchorRepositorySerializesRacingSuccessors(t *testing.T) {
	t.Parallel()
	repository, _ := repositoryFixture(t)
	first := testAnchor(t, "docker.desktop", 10, "first")
	if err := repository.CompareAndSwapCatalogAnchor(t.Context(), nil, first); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, next := range []runtimecatalogapp.CatalogAnchor{
		testAnchor(t, "docker.desktop", 11, "a"), testAnchor(t, "docker.desktop", 12, "b"),
	} {
		next := next
		go func() { <-start; results <- repository.CompareAndSwapCatalogAnchor(t.Context(), &first, next) }()
	}
	close(start)
	var successes, conflicts int
	for range 2 {
		switch err := <-results; {
		case err == nil:
			successes++
		case errors.Is(err, runtimecatalogapp.ErrCatalogAnchorConflict):
			conflicts++
		default:
			t.Fatalf("race error=%v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes/conflicts=%d/%d", successes, conflicts)
	}
}

func TestPF001CatalogAnchorSnapshotRejectsTamperingAndNonCanonicalState(t *testing.T) {
	t.Parallel()
	anchor := testAnchor(t, "docker.desktop", 1, "manifest")
	payload, err := encodeAnchors(anchorSet{anchor.CatalogID(): anchor})
	if err != nil {
		t.Fatal(err)
	}
	base := installjournal.Snapshot{OperationID: catalogAnchorOperationID, Revision: 1, CapturedAt: time.Unix(1, 0).UTC(), Payload: payload}
	if got, decodeError := decodeSnapshot(base); decodeError != nil || !sameAnchor(got[anchor.CatalogID()], anchor) {
		t.Fatalf("decode=%+v error=%v", got, decodeError)
	}
	for name, mutate := range map[string]func(*installjournal.Snapshot){
		"operation": func(value *installjournal.Snapshot) { value.OperationID = "other" },
		"revision":  func(value *installjournal.Snapshot) { value.Revision = 0 },
		"time":      func(value *installjournal.Snapshot) { value.CapturedAt = time.Time{} },
		"invalid":   func(value *installjournal.Snapshot) { value.Payload = []byte("{") },
		"oversize": func(value *installjournal.Snapshot) {
			value.Payload = bytes.Repeat([]byte(" "), maximumSnapshotBytes+1)
		},
		"whitespace": func(value *installjournal.Snapshot) {
			value.Payload = append([]byte(" "), value.Payload...)
		},
		"unknown": func(value *installjournal.Snapshot) {
			value.Payload = bytes.Replace(value.Payload, []byte("}"), []byte(",\"unknown\":true}"), 1)
		},
		"schema": func(value *installjournal.Snapshot) {
			value.Payload = bytes.Replace(value.Payload, []byte("\"schema_version\":1"), []byte("\"schema_version\":2"), 1)
		},
		"zero sequence": func(value *installjournal.Snapshot) {
			value.Payload = bytes.Replace(value.Payload, []byte("\"sequence\":1"), []byte("\"sequence\":0"), 1)
		},
		"digest": func(value *installjournal.Snapshot) {
			value.Payload = bytes.Replace(value.Payload, []byte(anchor.ManifestDigest().Hex()), []byte("invalid"), 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			candidate.Payload = append([]byte(nil), base.Payload...)
			mutate(&candidate)
			if _, decodeError := decodeSnapshot(candidate); !errors.Is(decodeError, runtimecatalogapp.ErrCatalogAnchorIntegrity) {
				t.Fatalf("decode error=%v", decodeError)
			}
		})
	}
}

func TestPF001CatalogAnchorRepositoryRejectsIncompleteOrUnprotectedAuthority(t *testing.T) {
	t.Parallel()
	clock := fixedClock{at: time.Unix(1000, 0).UTC()}
	anchored := newAnchoredTestJournal(t, &memoryJournal{})
	provider := &anchorProvider{journal: anchored}
	repository, err := NewRepositoryFromProvider(t.Context(), provider, clock)
	if err != nil || repository == nil || provider.operation.String() != catalogAnchorOperationID {
		t.Fatalf("repository=%+v error=%v provider=%+v", repository, err, provider)
	}
	for name, candidate := range map[string]anchoredJournalProvider{
		"nil": nil, "typed nil": (*anchorProvider)(nil),
		"plain":   &anchorProvider{journal: &memoryJournal{}},
		"failure": &anchorProvider{err: installjournal.ErrUnsafePermission},
	} {
		got, resolveError := NewRepositoryFromProvider(t.Context(), candidate, clock)
		if got != nil || resolveError == nil {
			t.Fatalf("%s accepted: repository=%+v error=%v", name, got, resolveError)
		}
	}
	if got, constructError := NewRepository(nil, clock); got != nil || !errors.Is(constructError, runtimecatalogapp.ErrCatalogAnchorIntegrity) {
		t.Fatalf("nil journal accepted: repository=%+v error=%v", got, constructError)
	}
	zeroClock, constructError := NewRepository(anchored, fixedClock{})
	if constructError != nil {
		t.Fatal(constructError)
	}
	if err := zeroClock.CompareAndSwapCatalogAnchor(t.Context(), nil, testAnchor(t, "docker.desktop", 1, "one")); !errors.Is(err, runtimecatalogapp.ErrDependencyUnavailable) {
		t.Fatalf("zero clock error=%v", err)
	}
	var absent *Repository
	if _, err := absent.LoadCatalogAnchor(t.Context(), "docker.desktop"); !errors.Is(err, runtimecatalogapp.ErrCatalogAnchorIntegrity) {
		t.Fatalf("nil repository error=%v", err)
	}
	for _, test := range []struct{ input, load, write error }{
		{installjournal.ErrNotFound, runtimecatalogapp.ErrCatalogAnchorNotFound, runtimecatalogapp.ErrDependencyUnavailable},
		{installjournal.ErrCorrupt, runtimecatalogapp.ErrCatalogAnchorIntegrity, runtimecatalogapp.ErrCatalogAnchorIntegrity},
		{installjournal.ErrConflict, runtimecatalogapp.ErrDependencyUnavailable, runtimecatalogapp.ErrCatalogAnchorConflict},
		{installjournal.ErrIO, runtimecatalogapp.ErrDependencyUnavailable, runtimecatalogapp.ErrDependencyUnavailable},
		{context.Canceled, context.Canceled, context.Canceled},
	} {
		if !errors.Is(mapLoadError(test.input), test.load) || !errors.Is(mapMutationError(test.input), test.write) {
			t.Fatalf("mapping %v failed", test.input)
		}
	}
}

func repositoryFixture(t *testing.T) (*Repository, *memoryJournal) {
	t.Helper()
	inner := &memoryJournal{}
	repository, err := NewRepository(newAnchoredTestJournal(t, inner), fixedClock{at: time.Unix(1000, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	return repository, inner
}

func newAnchoredTestJournal(t *testing.T, inner *memoryJournal) *bootstrapadapter.AnchoredJournal {
	t.Helper()
	operationID, _ := install.NewOperationID(catalogAnchorOperationID)
	owner, _ := install.BindOwner("test-machine", "test-principal")
	keys, err := bootstrapadapter.NewMemoryOperationKeySource(bytes.NewReader(bytes.Repeat([]byte{7}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	keyRef, err := keys.Ensure(t.Context(), operationID, owner)
	if err != nil {
		t.Fatal(err)
	}
	anchors, err := bootstrapadapter.NewMemoryRollbackAnchorStore(keys)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := bootstrapadapter.NewAnchoredJournal(inner, anchors, keyRef, operationID, owner)
	if err != nil {
		t.Fatal(err)
	}
	return journal
}

func testAnchor(t *testing.T, catalogID string, sequence uint64, content string) runtimecatalogapp.CatalogAnchor {
	t.Helper()
	anchor, err := runtimecatalogapp.NewCatalogAnchor(catalogID, sequence, runtimecatalog.DigestBytes([]byte(content)))
	if err != nil {
		t.Fatal(err)
	}
	return anchor
}

type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

type anchorProvider struct {
	journal   installjournal.Journal
	err       error
	operation install.OperationID
}

func (p *anchorProvider) JournalFor(_ context.Context, operationID install.OperationID) (installjournal.Journal, error) {
	p.operation = operationID
	return p.journal, p.err
}

type memoryJournal struct {
	mu            sync.Mutex
	snapshot      installjournal.Snapshot
	confirmations int
}

func (j *memoryJournal) Append(ctx context.Context, expected uint64, snapshot installjournal.Snapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.snapshot.Revision != expected || snapshot.Revision != expected+1 {
		return installjournal.ErrConflict
	}
	snapshot.Payload = append([]byte(nil), snapshot.Payload...)
	j.snapshot = snapshot
	return nil
}

func (j *memoryJournal) LoadLatest(ctx context.Context) (installjournal.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return installjournal.Snapshot{}, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.snapshot.Revision == 0 {
		return installjournal.Snapshot{}, installjournal.ErrNotFound
	}
	result := j.snapshot
	result.Payload = append([]byte(nil), result.Payload...)
	return result, nil
}

func (j *memoryJournal) ConfirmDurable(ctx context.Context, operationID string, revision uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.snapshot.OperationID != operationID || j.snapshot.Revision != revision {
		return installjournal.ErrConflict
	}
	j.confirmations++
	return nil
}
