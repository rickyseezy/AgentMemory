package bootstrap

import (
	"context"
	"errors"
	"testing"

	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001AnchoredJournalRejectsStaleAppendAndMissingPredecessor(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	stale := newAnchoredJournalFixture(t, "stale-append")
	first := anchoredSnapshot(stale.operationID, 1, `{"state":"durable"}`)
	if err := stale.journal.Append(ctx, 0, first); err != nil {
		t.Fatal(err)
	}
	if err := stale.journal.Append(ctx, 0, first); !errors.Is(err, journalport.ErrConflict) {
		t.Fatalf("stale Append() error = %v", err)
	}

	missing := newAnchoredJournalFixture(t, "missing-predecessor")
	second := anchoredSnapshot(missing.operationID, 2, `{"state":"running"}`)
	if err := missing.journal.Append(ctx, 1, second); !errors.Is(err, journalport.ErrConflict) {
		t.Fatalf("missing-predecessor Append() error = %v", err)
	}

	loadFailure := errors.New("authenticated journal read failed")
	failingJournal, err := NewAnchoredJournal(
		journalFailureStub{loadError: loadFailure},
		missing.anchors,
		missing.keyRef,
		missing.operationID,
		missing.owner,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := failingJournal.Append(ctx, 0, anchoredSnapshot(missing.operationID, 1, `{"state":"running"}`)); !errors.Is(err, loadFailure) {
		t.Fatalf("journal read failure was not preserved: %v", err)
	}
}

func TestPF001AnchoredJournalConfirmationFailsClosed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newAnchoredJournalFixture(t, "confirmation-failures")
	snapshot := anchoredSnapshot(fixture.operationID, 1, `{"state":"durable"}`)
	if err := fixture.journal.Append(ctx, 0, snapshot); err != nil {
		t.Fatal(err)
	}

	if err := fixture.journal.ConfirmDurable(ctx, "different-operation", 1); !errors.Is(err, journalport.ErrInvalidSnapshot) {
		t.Fatalf("cross-operation ConfirmDurable() error = %v", err)
	}
	if err := fixture.journal.ConfirmDurable(ctx, fixture.operationID.String(), 2); !errors.Is(err, journalport.ErrConflict) {
		t.Fatalf("changed-revision ConfirmDurable() error = %v", err)
	}
	confirmFailure := journalport.NewError(journalport.ErrorIO, "confirm", errors.New("directory flush failed"))
	fixture.inner.confirmError = confirmFailure
	if err := fixture.journal.ConfirmDurable(ctx, fixture.operationID.String(), 1); !errors.Is(err, journalport.ErrIO) {
		t.Fatalf("journal durability failure = %v", err)
	}
}

func TestPF001AnchoredJournalRejectsInvalidPersistedSnapshotAndAnchorReadFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	invalid := newAnchoredJournalFixture(t, "invalid-persisted-snapshot")
	invalid.inner.snapshot = anchoredSnapshot(invalid.operationID, 1, `{"state":"running"}`)
	invalid.inner.snapshot.Payload = nil
	if _, err := invalid.journal.LoadLatest(ctx); !errors.Is(err, journalport.ErrCorrupt) {
		t.Fatalf("non-canonical persisted snapshot error = %v", err)
	}

	anchorFailure := errors.New("protected anchor unavailable")
	journal, err := NewAnchoredJournal(
		journalFailureStub{loadError: journalport.ErrNotFound},
		scriptedRollbackAnchorStore{loadError: anchorFailure},
		invalid.keyRef,
		invalid.operationID,
		invalid.owner,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.LoadLatest(ctx); !errors.Is(err, journalport.ErrIO) {
		t.Fatalf("protected anchor read failure = %v", err)
	}
}

func TestPF001AnchoredJournalRejectsAnchorIdentityDriftAndDurabilityFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newAnchoredJournalFixture(t, "anchor-failure-paths")
	snapshot := anchoredSnapshot(fixture.operationID, 1, `{"state":"running"}`)
	digest, err := journalSnapshotDigest(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := install.NewRollbackAnchor(fixture.operationID, fixture.owner, 1, digest)
	if err != nil {
		t.Fatal(err)
	}

	wrongOwner, _ := install.BindOwner("different-machine", "linux:uid:1000")
	wrongIdentity, _ := install.NewRollbackAnchor(fixture.operationID, wrongOwner, 1, digest)
	identityJournal := anchoredJournalWithStore(t, fixture, scriptedRollbackAnchorStore{loaded: wrongIdentity})
	if err := identityJournal.reconcileSnapshot(ctx, snapshot); !errors.Is(err, journalport.ErrCorrupt) {
		t.Fatalf("anchor identity drift error = %v", err)
	}

	confirmFailure := errors.New("anchor flush failed")
	reconcileJournal := anchoredJournalWithStore(t, fixture, scriptedRollbackAnchorStore{
		loaded:       expected,
		confirmError: confirmFailure,
	})
	if err := reconcileJournal.reconcileSnapshot(ctx, snapshot); !errors.Is(err, journalport.ErrIO) {
		t.Fatalf("reconciled anchor durability error = %v", err)
	}

	wrongDigest, _ := install.NewRollbackAnchor(
		fixture.operationID,
		fixture.owner,
		1,
		install.DigestBytes([]byte("different state")),
	)
	exactJournal := anchoredJournalWithStore(t, fixture, scriptedRollbackAnchorStore{loaded: wrongDigest})
	if err := exactJournal.requireExactAnchor(ctx, snapshot); !errors.Is(err, journalport.ErrCorrupt) {
		t.Fatalf("changed anchor during confirmation error = %v", err)
	}

	missingJournal := anchoredJournalWithStore(t, fixture, scriptedRollbackAnchorStore{loadError: bootstrapport.ErrNotFound})
	if err := missingJournal.requireExactAnchor(ctx, snapshot); !errors.Is(err, journalport.ErrCorrupt) {
		t.Fatalf("deleted anchor during confirmation error = %v", err)
	}

	durableJournal := anchoredJournalWithStore(t, fixture, scriptedRollbackAnchorStore{
		loaded:       expected,
		confirmError: confirmFailure,
	})
	if err := durableJournal.requireExactAnchor(ctx, snapshot); !errors.Is(err, journalport.ErrIO) {
		t.Fatalf("exact anchor durability error = %v", err)
	}
}

func TestPF001AnchoredJournalResolvesAmbiguousAnchorAdvanceOnlyAfterDurability(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixture := newAnchoredJournalFixture(t, "ambiguous-anchor-failures")
	snapshot := anchoredSnapshot(fixture.operationID, 1, `{"state":"running"}`)
	digest, err := journalSnapshotDigest(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	next, err := install.NewRollbackAnchor(fixture.operationID, fixture.owner, 1, digest)
	if err != nil {
		t.Fatal(err)
	}

	postCommit := errors.New("anchor replace returned an ambiguous error")
	confirmFailure := errors.New("anchor directory flush failed")
	journal := anchoredJournalWithStore(t, fixture, scriptedRollbackAnchorStore{
		loaded:       next,
		advanceError: postCommit,
		confirmError: confirmFailure,
	})
	if err := journal.advanceAnchor(ctx, 0, next); !errors.Is(err, journalport.ErrIO) {
		t.Fatalf("ambiguous write without durability error = %v", err)
	}

	different, _ := install.NewRollbackAnchor(
		fixture.operationID,
		fixture.owner,
		1,
		install.DigestBytes([]byte("different anchor")),
	)
	conflicting := anchoredJournalWithStore(t, fixture, scriptedRollbackAnchorStore{
		loaded:       different,
		advanceError: bootstrapport.ErrConflict,
	})
	if err := conflicting.advanceAnchor(ctx, 0, next); !errors.Is(err, journalport.ErrConflict) {
		t.Fatalf("ambiguous non-exact anchor error = %v", err)
	}
}

func TestPF001AnchoredJournalCanonicalizationFailsClosed(t *testing.T) {
	t.Parallel()
	fixture := newAnchoredJournalFixture(t, "canonicalization-failures")
	invalid := anchoredSnapshot(fixture.operationID, 1, `{"state":`)
	if _, err := journalSnapshotDigest(invalid); err == nil {
		t.Fatal("invalid journal payload was canonicalized")
	}
	if _, err := fixture.journal.(*AnchoredJournal).anchorForSnapshot(invalid); !errors.Is(err, journalport.ErrInvalidSnapshot) {
		t.Fatalf("invalid rollback snapshot error = %v", err)
	}
	valid := anchoredSnapshot(fixture.operationID, 1, `{"state":"running"}`)
	if _, err := (&AnchoredJournal{}).anchorForSnapshot(valid); !errors.Is(err, journalport.ErrInvalidSnapshot) {
		t.Fatalf("zero rollback binding error = %v", err)
	}
}

func anchoredJournalWithStore(
	t *testing.T,
	fixture anchoredJournalFixture,
	store bootstrapport.RollbackAnchorStore,
) *AnchoredJournal {
	t.Helper()
	journal, err := NewAnchoredJournal(
		fixture.inner,
		store,
		fixture.keyRef,
		fixture.operationID,
		fixture.owner,
	)
	if err != nil {
		t.Fatal(err)
	}
	return journal
}

type journalFailureStub struct {
	loadError error
}

func (s journalFailureStub) Append(context.Context, uint64, journalport.Snapshot) error {
	return nil
}

func (s journalFailureStub) LoadLatest(context.Context) (journalport.Snapshot, error) {
	return journalport.Snapshot{}, s.loadError
}

func (s journalFailureStub) ConfirmDurable(context.Context, string, uint64) error {
	return nil
}

type scriptedRollbackAnchorStore struct {
	loaded       install.RollbackAnchor
	loadError    error
	advanceError error
	confirmError error
}

func (s scriptedRollbackAnchorStore) Load(
	context.Context,
	install.BootstrapKeyRef,
	install.OperationID,
	install.OwnerBinding,
) (install.RollbackAnchor, error) {
	return s.loaded, s.loadError
}

func (s scriptedRollbackAnchorStore) Advance(
	context.Context,
	install.BootstrapKeyRef,
	uint64,
	install.RollbackAnchor,
) error {
	return s.advanceError
}

func (s scriptedRollbackAnchorStore) ConfirmDurable(
	context.Context,
	install.BootstrapKeyRef,
	install.RollbackAnchor,
) error {
	return s.confirmError
}
