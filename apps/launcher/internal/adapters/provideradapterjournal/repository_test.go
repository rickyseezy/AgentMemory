package provideradapterjournal

import (
	"context"
	"errors"
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
	repository, err := New(&providerStub{journal: journal}, fixedClock{})
	if err != nil {
		t.Fatal(err)
	}
	result := journalResult(t)
	if err := repository.Commit(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := repository.Find(context.Background(), result.OperationID())
	if err != nil || !found || loaded.AttestationDigest() != result.AttestationDigest() || journal.confirms != 1 {
		t.Fatalf("find = %#v %t %v", loaded, found, err)
	}
	if err := repository.Commit(context.Background(), result); err != nil || journal.confirms != 2 {
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
}

func (p *providerStub) JournalFor(context.Context, install.OperationID) (installjournal.Journal, error) {
	return p.journal, p.providerErr
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Date(2026, 7, 22, 8, 0, 0, 0, time.UTC) }

type zeroClock struct{}

func (zeroClock) Now() time.Time { return time.Time{} }

type journalStub struct {
	snapshot           installjournal.Snapshot
	loadErr, appendErr error
	confirms           int
	confirmErr         error
}

func (j *journalStub) Append(_ context.Context, _ uint64, snapshot installjournal.Snapshot) error {
	if j.appendErr != nil {
		return j.appendErr
	}
	j.snapshot = snapshot
	j.loadErr = nil
	return nil
}
func (j *journalStub) LoadLatest(context.Context) (installjournal.Snapshot, error) {
	if j.loadErr != nil {
		return installjournal.Snapshot{}, j.loadErr
	}
	if j.snapshot.Revision == 0 {
		return installjournal.Snapshot{}, installjournal.ErrNotFound
	}
	return j.snapshot, nil
}
func (j *journalStub) ConfirmDurable(context.Context, string, uint64) error {
	j.confirms++
	return j.confirmErr
}
