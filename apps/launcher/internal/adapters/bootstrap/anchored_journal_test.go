package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001AnchoredJournalRecoversJournalAheadByOneAfterAmbiguousAppend(t *testing.T) {
	t.Parallel()
	fixture := newAnchoredJournalFixture(t, "ambiguous-append")
	innerError := journalport.NewError(journalport.ErrorIO, "append", errors.New("crash after rename"))
	fixture.inner.appendError = innerError
	snapshot := anchoredSnapshot(fixture.operationID, 1, `{"state":"running"}`)

	if err := fixture.journal.Append(context.Background(), 0, snapshot); !errors.Is(err, journalport.ErrIO) {
		t.Fatalf("ambiguous Append() error = %v", err)
	}
	if _, err := fixture.anchors.Load(context.Background(), fixture.keyRef, fixture.operationID, fixture.owner); !errors.Is(err, bootstrapport.ErrNotFound) {
		t.Fatalf("anchor advanced despite ambiguous journal append: %v", err)
	}
	fixture.inner.confirmError = journalport.NewError(
		journalport.ErrorIO,
		"confirm",
		errors.New("journal directory is not durable"),
	)
	if _, err := fixture.journal.LoadLatest(context.Background()); !errors.Is(err, journalport.ErrIO) {
		t.Fatalf("recovery ignored journal durability failure: %v", err)
	}
	if _, err := fixture.anchors.Load(context.Background(), fixture.keyRef, fixture.operationID, fixture.owner); !errors.Is(err, bootstrapport.ErrNotFound) {
		t.Fatalf("anchor advanced before journal durability was confirmed: %v", err)
	}
	fixture.inner.confirmError = nil
	loaded, err := fixture.journal.LoadLatest(context.Background())
	if err != nil || loaded.Revision != 1 || !bytes.Equal(loaded.Payload, snapshot.Payload) {
		t.Fatalf("recovered snapshot = %#v, %v", loaded, err)
	}
	anchor, err := fixture.anchors.Load(context.Background(), fixture.keyRef, fixture.operationID, fixture.owner)
	if err != nil || anchor.Sequence() != 1 {
		t.Fatalf("reconciled anchor = %#v, %v", anchor, err)
	}
	if err := fixture.journal.ConfirmDurable(context.Background(), fixture.operationID.String(), 1); err != nil {
		t.Fatalf("ConfirmDurable() after ambiguity = %v", err)
	}
}

func TestPF001AnchoredJournalRejectsAnchorAheadBehindAndSameSequenceMismatch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		journalRevision  uint64
		anchorRevisions  []uint64
		wrongFinalDigest bool
	}{
		{name: "anchor ahead", journalRevision: 1, anchorRevisions: []uint64{1, 2}},
		{name: "anchor behind by more than crash window", journalRevision: 3, anchorRevisions: []uint64{1}},
		{name: "anchor absent behind revision one", journalRevision: 2},
		{name: "same sequence different state", journalRevision: 1, anchorRevisions: []uint64{1}, wrongFinalDigest: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newAnchoredJournalFixture(t, "mismatch-"+strings.ReplaceAll(test.name, " ", "-"))
			latest := anchoredSnapshot(fixture.operationID, test.journalRevision, `{"state":"latest"}`)
			fixture.inner.snapshot = cloneJournalSnapshot(latest)
			for _, revision := range test.anchorRevisions {
				state := anchoredSnapshot(fixture.operationID, revision, `{"state":"anchor"}`)
				digest, err := journalSnapshotDigest(state)
				if err != nil {
					t.Fatal(err)
				}
				if revision == test.journalRevision && !test.wrongFinalDigest {
					digest, err = journalSnapshotDigest(latest)
					if err != nil {
						t.Fatal(err)
					}
				}
				anchor, err := install.NewRollbackAnchor(fixture.operationID, fixture.owner, revision, digest)
				if err != nil {
					t.Fatal(err)
				}
				if err := fixture.anchors.Advance(context.Background(), fixture.keyRef, revision-1, anchor); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := fixture.journal.LoadLatest(context.Background()); !errors.Is(err, journalport.ErrCorrupt) {
				t.Fatalf("LoadLatest() mismatch error = %v", err)
			}
		})
	}
}

func TestPF001AnchoredJournalRejectsDeletedJournalWhenAnchorExists(t *testing.T) {
	t.Parallel()
	fixture := newAnchoredJournalFixture(t, "deleted-journal")
	snapshot := anchoredSnapshot(fixture.operationID, 1, `{"state":"durable"}`)
	if err := fixture.journal.Append(context.Background(), 0, snapshot); err != nil {
		t.Fatal(err)
	}
	fixture.inner.mu.Lock()
	fixture.inner.snapshot = journalport.Snapshot{}
	fixture.inner.mu.Unlock()
	if _, err := fixture.journal.LoadLatest(context.Background()); !errors.Is(err, journalport.ErrCorrupt) {
		t.Fatalf("deleted journal error = %v", err)
	}
}

func TestPF001AnchoredJournalResolvesAmbiguousAnchorAdvanceOnlyWhenExact(t *testing.T) {
	t.Parallel()
	fixture := newAnchoredJournalFixture(t, "ambiguous-anchor")
	ambiguous := &ambiguousAdvanceAnchorStore{
		RollbackAnchorStore: fixture.anchors,
		err:                 errors.New("crash after anchor replace"),
	}
	journal, err := NewAnchoredJournal(
		fixture.inner,
		ambiguous,
		fixture.keyRef,
		fixture.operationID,
		fixture.owner,
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := anchoredSnapshot(fixture.operationID, 1, `{"state":"running"}`)
	if err := journal.Append(context.Background(), 0, snapshot); err != nil {
		t.Fatalf("exact post-error anchor was not accepted: %v", err)
	}
	anchor, err := fixture.anchors.Load(context.Background(), fixture.keyRef, fixture.operationID, fixture.owner)
	if err != nil || anchor.Sequence() != 1 {
		t.Fatalf("ambiguous anchor = %#v, %v", anchor, err)
	}
}

func TestPF001AnchoredJournalMapsProtectedAnchorFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		anchorErr error
		want      error
	}{
		{name: "integrity", anchorErr: bootstrapport.ErrIntegrity, want: journalport.ErrCorrupt},
		{name: "conflict", anchorErr: bootstrapport.ErrConflict, want: journalport.ErrConflict},
		{name: "io", anchorErr: errors.New("anchor unavailable"), want: journalport.ErrIO},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newAnchoredJournalFixture(t, "anchor-error-"+test.name)
			fixture.inner.snapshot = anchoredSnapshot(fixture.operationID, 1, `{"state":"running"}`)
			journal, err := NewAnchoredJournal(
				fixture.inner,
				failingAnchorStore{err: test.anchorErr},
				fixture.keyRef,
				fixture.operationID,
				fixture.owner,
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := journal.LoadLatest(context.Background()); !errors.Is(err, test.want) {
				t.Fatalf("anchor failure = %v, want %v", err, test.want)
			}
		})
	}
}

func TestPF001AnchoredJournalFailsClosedAtConstructionAndSnapshotBinding(t *testing.T) {
	t.Parallel()
	fixture := newAnchoredJournalFixture(t, "boundaries")
	if _, err := NewAnchoredJournal(nil, fixture.anchors, fixture.keyRef, fixture.operationID, fixture.owner); err == nil {
		t.Fatal("nil inner journal was accepted")
	}
	if _, err := NewAnchoredJournal(fixture.inner, nil, fixture.keyRef, fixture.operationID, fixture.owner); err == nil {
		t.Fatal("nil anchor store was accepted")
	}
	otherID, _ := install.NewOperationID("other-operation")
	wrongID := anchoredSnapshot(otherID, 1, `{"state":"running"}`)
	if err := fixture.journal.Append(context.Background(), 0, wrongID); !errors.Is(err, journalport.ErrInvalidSnapshot) {
		t.Fatalf("cross-operation Append() error = %v", err)
	}
	skipped := anchoredSnapshot(fixture.operationID, 2, `{"state":"running"}`)
	if err := fixture.journal.Append(context.Background(), 0, skipped); !errors.Is(err, journalport.ErrInvalidSnapshot) {
		t.Fatalf("skipped revision Append() error = %v", err)
	}
}

type anchoredJournalFixture struct {
	inner       *scriptedJournal
	anchors     *MemoryRollbackAnchorStore
	journal     journalport.Journal
	operationID install.OperationID
	owner       install.OwnerBinding
	keyRef      install.BootstrapKeyRef
}

func newAnchoredJournalFixture(t *testing.T, operation string) anchoredJournalFixture {
	t.Helper()
	operationID, err := install.NewOperationID(operation)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := install.BindOwner("machine", "linux:uid:1000")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := NewMemoryOperationKeySource(bytes.NewReader(bytes.Repeat([]byte{0xd4}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	keyRef, err := keys.Ensure(context.Background(), operationID, owner)
	if err != nil {
		t.Fatal(err)
	}
	anchors, err := NewMemoryRollbackAnchorStore(keys)
	if err != nil {
		t.Fatal(err)
	}
	inner := &scriptedJournal{appendStoresBeforeError: true}
	journal, err := NewAnchoredJournal(inner, anchors, keyRef, operationID, owner)
	if err != nil {
		t.Fatal(err)
	}
	return anchoredJournalFixture{
		inner:       inner,
		anchors:     anchors,
		journal:     journal,
		operationID: operationID,
		owner:       owner,
		keyRef:      keyRef,
	}
}

func anchoredSnapshot(operationID install.OperationID, revision uint64, payload string) journalport.Snapshot {
	return journalport.Snapshot{
		OperationID: operationID.String(),
		Revision:    revision,
		CapturedAt:  time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC),
		Payload:     json.RawMessage(payload),
	}
}

type scriptedJournal struct {
	mu                      sync.Mutex
	snapshot                journalport.Snapshot
	appendError             error
	appendStoresBeforeError bool
	confirmError            error
}

type ambiguousAdvanceAnchorStore struct {
	bootstrapport.RollbackAnchorStore
	err error
}

func (s *ambiguousAdvanceAnchorStore) Advance(
	ctx context.Context,
	keyRef install.BootstrapKeyRef,
	expectedSequence uint64,
	next install.RollbackAnchor,
) error {
	if err := s.RollbackAnchorStore.Advance(ctx, keyRef, expectedSequence, next); err != nil {
		return err
	}
	return s.err
}

type failingAnchorStore struct{ err error }

func (s failingAnchorStore) Load(
	context.Context,
	install.BootstrapKeyRef,
	install.OperationID,
	install.OwnerBinding,
) (install.RollbackAnchor, error) {
	return install.RollbackAnchor{}, s.err
}

func (s failingAnchorStore) Advance(
	context.Context,
	install.BootstrapKeyRef,
	uint64,
	install.RollbackAnchor,
) error {
	return s.err
}

func (s failingAnchorStore) ConfirmDurable(
	context.Context,
	install.BootstrapKeyRef,
	install.RollbackAnchor,
) error {
	return s.err
}

func (j *scriptedJournal) Append(
	_ context.Context,
	expectedPreviousRevision uint64,
	snapshot journalport.Snapshot,
) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	currentRevision := j.snapshot.Revision
	if currentRevision != expectedPreviousRevision {
		return journalport.ErrConflict
	}
	if j.appendError == nil || j.appendStoresBeforeError {
		j.snapshot = cloneJournalSnapshot(snapshot)
	}
	return j.appendError
}

func (j *scriptedJournal) LoadLatest(context.Context) (journalport.Snapshot, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.snapshot.Revision == 0 {
		return journalport.Snapshot{}, journalport.ErrNotFound
	}
	return cloneJournalSnapshot(j.snapshot), nil
}

func (j *scriptedJournal) ConfirmDurable(_ context.Context, operationID string, revision uint64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.confirmError != nil {
		return j.confirmError
	}
	if j.snapshot.OperationID != operationID || j.snapshot.Revision != revision {
		return journalport.ErrConflict
	}
	return nil
}

func cloneJournalSnapshot(snapshot journalport.Snapshot) journalport.Snapshot {
	snapshot.Payload = append(json.RawMessage(nil), snapshot.Payload...)
	return snapshot
}
