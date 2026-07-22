package provideradapterjournal

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/provideradapterapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/provideradapter"
)

func TestPRO002JournalCommitsFindsAndConfirmsExactReplay(t *testing.T) {
	t.Parallel()
	journal := &journalStub{}
	provider := &providerStub{journal: journal}
	repository, err := New(provider, fixedClock{})
	if err != nil {
		t.Fatal(err)
	}
	result := journalResult(t)
	ctx := context.WithValue(context.Background(), contextKey{}, "exact-context")
	if err := repository.Commit(ctx, result); err != nil {
		t.Fatal(err)
	}
	if journal.appendContext != ctx || journal.appendExpectedRevision != 0 ||
		journal.snapshot.CapturedAt != (fixedClock{}).Now() || provider.context != ctx ||
		!strings.HasPrefix(provider.operationID.String(), "provider-adapter-") {
		t.Fatalf("commit authority was altered: provider=%#v journal=%#v", provider, journal)
	}
	loaded, found, err := repository.Find(ctx, result.OperationID())
	if err != nil || !found || loaded != result || journal.confirms != 1 ||
		journal.loadContext != ctx || journal.confirmContext != ctx ||
		journal.confirmOperationID != provider.operationID.String() || journal.confirmRevision != 1 {
		t.Fatalf("find = %#v %t %v", loaded, found, err)
	}
	if err := repository.Commit(ctx, result); err != nil || journal.confirms != 2 || journal.confirmContext != ctx {
		t.Fatalf("replay = %v confirms=%d", err, journal.confirms)
	}
}

func TestPRO002JournalFailsClosedOnConflictCorruptionAndStorageFailure(t *testing.T) {
	t.Parallel()
	result := journalResult(t)
	tests := []struct {
		name    string
		journal *journalStub
		commit  bool
		want    error
	}{
		{"corrupt", &journalStub{snapshot: installjournal.Snapshot{OperationID: "wrong", Revision: 1, Payload: []byte(`{}`)}}, false, provideradapterapp.ErrStorage},
		{"load", &journalStub{loadErr: errors.New("disk")}, false, provideradapterapp.ErrStorage},
		{"append", &journalStub{loadErr: installjournal.ErrNotFound, appendErr: installjournal.ErrIO}, true, provideradapterapp.ErrStorage},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			repository, _ := New(&providerStub{journal: test.journal}, fixedClock{})
			if test.commit {
				if err := repository.Commit(context.Background(), result); !errors.Is(err, test.want) {
					t.Fatalf("commit=%v", err)
				}
			} else {
				if _, _, err := repository.Find(context.Background(), result.OperationID()); !errors.Is(err, test.want) {
					t.Fatalf("find=%v", err)
				}
			}
		})
	}
}

func TestPRO002JournalCoversMissingReplayAndDependencyBoundaries(t *testing.T) {
	t.Parallel()
	result := journalResult(t)
	if _, err := New(nil, fixedClock{}); !errors.Is(err, provideradapterapp.ErrStorage) {
		t.Fatalf("nil provider=%v", err)
	}
	if _, err := New(&providerStub{}, nil); !errors.Is(err, provideradapterapp.ErrStorage) {
		t.Fatalf("nil clock=%v", err)
	}
	repository, _ := New(&providerStub{journal: &journalStub{}}, fixedClock{})
	if _, found, err := repository.Find(context.Background(), result.OperationID()); err != nil || found {
		t.Fatalf("missing=%t %v", found, err)
	}
	if err := repository.Commit(context.Background(), provideradapterapp.InstallResult{}); !errors.Is(err, provideradapterapp.ErrStorage) {
		t.Fatalf("zero result=%v", err)
	}

	existing := &journalStub{}
	repository, _ = New(&providerStub{journal: existing}, fixedClock{})
	if err := repository.Commit(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	existing.snapshot.Payload = []byte(`{"different":true}`)
	if err := repository.Commit(context.Background(), result); !errors.Is(err, provideradapterapp.ErrConflict) {
		t.Fatalf("different replay=%v", err)
	}

	confirm := &journalStub{confirmErr: installjournal.ErrIO}
	repository, _ = New(&providerStub{journal: confirm}, fixedClock{})
	if err := repository.Commit(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repository.Find(context.Background(), result.OperationID()); !errors.Is(err, provideradapterapp.ErrStorage) {
		t.Fatalf("confirm=%v", err)
	}

	repository, _ = New(&providerStub{journal: &journalStub{}, providerErr: errors.New("provider")}, fixedClock{})
	if _, _, err := repository.Find(context.Background(), result.OperationID()); !errors.Is(err, provideradapterapp.ErrStorage) {
		t.Fatalf("provider=%v", err)
	}
	repository, _ = New(&providerStub{journal: &journalStub{}}, zeroClock{})
	if err := repository.Commit(context.Background(), result); !errors.Is(err, provideradapterapp.ErrStorage) {
		t.Fatalf("clock=%v", err)
	}
	conflict := &journalStub{appendErr: installjournal.ErrConflict}
	repository, _ = New(&providerStub{journal: conflict}, fixedClock{})
	if err := repository.Commit(context.Background(), result); !errors.Is(err, provideradapterapp.ErrConflict) {
		t.Fatalf("append conflict=%v", err)
	}
}

func TestPRO002JournalRejectsEveryAuthenticatedSnapshotMutation(t *testing.T) {
	t.Parallel()
	result := journalResult(t)
	seed := &journalStub{}
	repository, _ := New(&providerStub{journal: seed}, fixedClock{})
	if err := repository.Commit(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	valid := seed.snapshot

	tests := []struct {
		name   string
		mutate func(*installjournal.Snapshot)
	}{
		{"operation-id", func(snapshot *installjournal.Snapshot) { snapshot.OperationID = "wrong" }},
		{"revision", func(snapshot *installjournal.Snapshot) { snapshot.Revision = 2 }},
		{"empty-payload", func(snapshot *installjournal.Snapshot) { snapshot.Payload = nil }},
		{"unknown-field", func(snapshot *installjournal.Snapshot) {
			snapshot.Payload = append(snapshot.Payload[:len(snapshot.Payload)-1], []byte(`,"unknown":true}`)...)
		}},
		{"trailing-document", func(snapshot *installjournal.Snapshot) { snapshot.Payload = append(snapshot.Payload, []byte(` {}`)...) }},
		{"wrong-schema", func(snapshot *installjournal.Snapshot) {
			snapshot.Payload = []byte(strings.Replace(string(snapshot.Payload), `"schema_version":1`, `"schema_version":2`, 1))
		}},
		{"operation-substitution", func(snapshot *installjournal.Snapshot) {
			snapshot.Payload = []byte(strings.Replace(string(snapshot.Payload), `"operation_id":"install-provider-1"`, `"operation_id":"install-provider-2"`, 1))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			snapshot := valid
			snapshot.Payload = append([]byte(nil), valid.Payload...)
			test.mutate(&snapshot)
			candidate, _ := New(&providerStub{journal: &journalStub{snapshot: snapshot}}, fixedClock{})
			if _, _, err := candidate.Find(context.Background(), result.OperationID()); !errors.Is(err, provideradapterapp.ErrStorage) {
				t.Fatalf("mutation accepted: %v", err)
			}
		})
	}

	t.Run("oversized-payload", func(t *testing.T) {
		snapshot := valid
		snapshot.Payload = make([]byte, 64*1024+1)
		candidate, _ := New(&providerStub{journal: &journalStub{snapshot: snapshot}}, fixedClock{})
		if _, _, err := candidate.Find(context.Background(), result.OperationID()); !errors.Is(err, provideradapterapp.ErrStorage) {
			t.Fatalf("oversized payload accepted: %v", err)
		}
	})
}

func TestPRO002JournalRejectsEveryDigestSubstitutionAndBoundary(t *testing.T) {
	t.Parallel()
	result := journalResult(t)
	payload, err := encodeResult(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"request_digest", "manifest_digest", "plan_digest", "attestation_digest"} {
		t.Run(field+"-invalid", func(t *testing.T) {
			corrupt := strings.Replace(string(payload), `"`+field+`":"`, `"`+field+`":"not-a-digest`, 1)
			if _, err := decodeResult([]byte(corrupt)); !errors.Is(err, provideradapterapp.ErrStorage) {
				t.Fatalf("invalid digest accepted: %v", err)
			}
		})
	}
	loaded, err := decodeResult(payload)
	if err != nil || loaded != result {
		t.Fatalf("digest order changed: %#v %v", loaded, err)
	}
	if _, err := decodeResult(make([]byte, 64*1024)); !errors.Is(err, provideradapterapp.ErrStorage) {
		t.Fatalf("64 KiB invalid document accepted: %v", err)
	}
	if _, err := decodeResult(make([]byte, 64*1024+1)); !errors.Is(err, provideradapterapp.ErrStorage) {
		t.Fatalf("oversized document accepted: %v", err)
	}
}

func TestPRO002JournalRejectsEveryReplayAndAuthorityFailure(t *testing.T) {
	t.Parallel()
	result := journalResult(t)
	seed := &journalStub{}
	repository, _ := New(&providerStub{journal: seed}, fixedClock{})
	if err := repository.Commit(context.Background(), result); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*journalStub)
		want   error
	}{
		{"operation-id", func(j *journalStub) { j.snapshot.OperationID = "wrong" }, provideradapterapp.ErrConflict},
		{"revision", func(j *journalStub) { j.snapshot.Revision = 2 }, provideradapterapp.ErrConflict},
		{"payload", func(j *journalStub) { j.snapshot.Payload = []byte(`{}`) }, provideradapterapp.ErrConflict},
		{"durability", func(j *journalStub) { j.confirmErr = installjournal.ErrIO }, provideradapterapp.ErrStorage},
		{"load", func(j *journalStub) { j.loadErr = installjournal.ErrIO }, provideradapterapp.ErrStorage},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidateJournal := &journalStub{snapshot: seed.snapshot}
			candidateJournal.snapshot.Payload = append([]byte(nil), seed.snapshot.Payload...)
			test.mutate(candidateJournal)
			candidate, _ := New(&providerStub{journal: candidateJournal}, fixedClock{})
			if err := candidate.Commit(context.Background(), result); !errors.Is(err, test.want) {
				t.Fatalf("replay failure = %v", err)
			}
		})
	}

	var nilRepository *Repository
	if _, _, err := nilRepository.Find(context.Background(), result.OperationID()); !errors.Is(err, provideradapterapp.ErrStorage) {
		t.Fatalf("nil repository=%v", err)
	}
	var nilContext context.Context
	if _, _, err := repository.Find(nilContext, result.OperationID()); !errors.Is(err, provideradapterapp.ErrStorage) {
		t.Fatalf("nil context=%v", err)
	}
	if _, _, err := repository.Find(context.Background(), "invalid operation id"); !errors.Is(err, provideradapterapp.ErrStorage) {
		t.Fatalf("invalid operation=%v", err)
	}
	var nilJournal *journalStub
	candidate, _ := New(&providerStub{journal: nilJournal}, fixedClock{})
	if _, _, err := candidate.Find(context.Background(), result.OperationID()); !errors.Is(err, provideradapterapp.ErrStorage) {
		t.Fatalf("typed nil journal=%v", err)
	}
	var nilProvider *providerStub
	if _, err := New(nilProvider, fixedClock{}); !errors.Is(err, provideradapterapp.ErrStorage) {
		t.Fatalf("typed nil provider=%v", err)
	}
	var nilClock *clockPointerStub
	if _, err := New(&providerStub{}, nilClock); !errors.Is(err, provideradapterapp.ErrStorage) {
		t.Fatalf("typed nil clock=%v", err)
	}
}

func journalResult(t testing.TB) provideradapterapp.InstallResult {
	t.Helper()
	digest := func(value string) provideradapter.Digest { return provideradapter.DigestBytes([]byte(value)) }
	result, err := provideradapterapp.RestoreInstallResult("install-provider-1", "python-reference", "custom-provider-runtime",
		digest("request"), digest("manifest"), digest("plan"), digest("attestation"), provideradapterapp.StatusActive)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

type providerStub struct {
	journal     installjournal.Journal
	providerErr error
	context     context.Context
	operationID install.OperationID
}

func (p *providerStub) JournalFor(ctx context.Context, operationID install.OperationID) (installjournal.Journal, error) {
	p.context = ctx
	p.operationID = operationID
	return p.journal, p.providerErr
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Date(2026, 7, 22, 8, 0, 0, 0, time.UTC) }

type zeroClock struct{}

func (zeroClock) Now() time.Time { return time.Time{} }

type clockPointerStub struct{}

func (*clockPointerStub) Now() time.Time { return time.Now() }

type contextKey struct{}

type journalStub struct {
	snapshot               installjournal.Snapshot
	loadErr, appendErr     error
	confirms               int
	confirmErr             error
	loadContext            context.Context
	appendContext          context.Context
	confirmContext         context.Context
	appendExpectedRevision uint64
	confirmOperationID     string
	confirmRevision        uint64
}

func (j *journalStub) Append(ctx context.Context, expectedRevision uint64, snapshot installjournal.Snapshot) error {
	j.appendContext = ctx
	j.appendExpectedRevision = expectedRevision
	if j.appendErr != nil {
		return j.appendErr
	}
	j.snapshot = snapshot
	j.loadErr = nil
	return nil
}
func (j *journalStub) LoadLatest(ctx context.Context) (installjournal.Snapshot, error) {
	j.loadContext = ctx
	if j.loadErr != nil {
		return installjournal.Snapshot{}, j.loadErr
	}
	if j.snapshot.Revision == 0 {
		return installjournal.Snapshot{}, installjournal.ErrNotFound
	}
	return j.snapshot, nil
}
func (j *journalStub) ConfirmDurable(ctx context.Context, operationID string, revision uint64) error {
	j.confirms++
	j.confirmContext = ctx
	j.confirmOperationID = operationID
	j.confirmRevision = revision
	return j.confirmErr
}
