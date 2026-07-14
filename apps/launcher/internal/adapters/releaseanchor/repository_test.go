package releaseanchor

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001ReleaseAnchorRepositoryPersistsAndRestoresExactSuccessors(t *testing.T) {
	t.Parallel()
	repository, journal := releaseAnchorFixture(t)
	first := testReleaseAnchor(t, 41, "first")
	if err := repository.CompareAndSwapReleaseAnchor(context.Background(), nil, first); err != nil {
		t.Fatal(err)
	}
	observed, err := repository.LoadReleaseAnchor(context.Background(), releaseinventory.ReleaseChannelStable)
	if err != nil || !sameAnchor(observed, first) {
		t.Fatalf("LoadReleaseAnchor()=%+v error=%v", observed, err)
	}
	second := testReleaseAnchor(t, 42, "second")
	if err := repository.CompareAndSwapReleaseAnchor(context.Background(), &first, second); err != nil {
		t.Fatal(err)
	}
	observed, err = repository.LoadReleaseAnchor(context.Background(), releaseinventory.ReleaseChannelStable)
	if err != nil || !sameAnchor(observed, second) || journal.confirmations < 2 {
		t.Fatalf("successor=%+v error=%v confirmations=%d", observed, err, journal.confirmations)
	}
}

func TestPF001ReleaseAnchorRepositoryNamespacesHighWaterMarksByChannel(t *testing.T) {
	t.Parallel()
	repository, _ := releaseAnchorFixture(t)
	stable := testChannelReleaseAnchor(t, releaseinventory.ReleaseChannelStable, 7, "stable")
	nightly := testChannelReleaseAnchor(t, releaseinventory.ReleaseChannelNightly, 900, "nightly")
	for _, anchor := range []releaseverify.ReleaseAnchor{stable, nightly} {
		if err := repository.CompareAndSwapReleaseAnchor(context.Background(), nil, anchor); err != nil {
			t.Fatalf("create %s anchor: %v", anchor.Channel(), err)
		}
	}
	for _, want := range []releaseverify.ReleaseAnchor{stable, nightly} {
		got, err := repository.LoadReleaseAnchor(context.Background(), want.Channel())
		if err != nil || !sameAnchor(got, want) {
			t.Fatalf("load %s anchor=%+v error=%v", want.Channel(), got, err)
		}
	}
	if _, err := repository.LoadReleaseAnchor(
		context.Background(), releaseinventory.ReleaseChannelBeta,
	); !errors.Is(err, releaseverify.ErrReleaseAnchorNotFound) {
		t.Fatalf("missing beta anchor error=%v", err)
	}
	nextStable := testChannelReleaseAnchor(t, releaseinventory.ReleaseChannelStable, 8, "stable-next")
	if err := repository.CompareAndSwapReleaseAnchor(context.Background(), &stable, nextStable); err != nil {
		t.Fatal(err)
	}
	gotNightly, err := repository.LoadReleaseAnchor(context.Background(), releaseinventory.ReleaseChannelNightly)
	if err != nil || !sameAnchor(gotNightly, nightly) {
		t.Fatalf("stable mutation changed nightly anchor=%+v error=%v", gotNightly, err)
	}
}

func TestPF001ReleaseAnchorRepositoryCASRejectsStaleMissingAndNonMonotonicWrites(t *testing.T) {
	t.Parallel()
	repository, _ := releaseAnchorFixture(t)
	first := testReleaseAnchor(t, 7, "first")
	if err := repository.CompareAndSwapReleaseAnchor(context.Background(), nil, first); err != nil {
		t.Fatal(err)
	}
	if err := repository.CompareAndSwapReleaseAnchor(
		context.Background(), nil, testReleaseAnchor(t, 8, "unexpected"),
	); !errors.Is(err, releaseverify.ErrReleaseAnchorConflict) {
		t.Fatalf("second create error=%v", err)
	}
	stale := testReleaseAnchor(t, 6, "stale")
	if err := repository.CompareAndSwapReleaseAnchor(
		context.Background(), &stale, testReleaseAnchor(t, 8, "next"),
	); !errors.Is(err, releaseverify.ErrReleaseAnchorConflict) {
		t.Fatalf("stale CAS error=%v", err)
	}
	if err := repository.CompareAndSwapReleaseAnchor(
		context.Background(), &first, testReleaseAnchor(t, first.Sequence(), "same-sequence"),
	); !errors.Is(err, releaseverify.ErrReleaseAnchorIntegrity) {
		t.Fatalf("non-monotonic CAS error=%v", err)
	}

	emptyRepository, _ := releaseAnchorFixture(t)
	if _, err := emptyRepository.LoadReleaseAnchor(
		context.Background(), releaseinventory.ReleaseChannelStable,
	); !errors.Is(err, releaseverify.ErrReleaseAnchorNotFound) {
		t.Fatalf("missing load error=%v", err)
	}
	if err := emptyRepository.CompareAndSwapReleaseAnchor(
		context.Background(), &first, testReleaseAnchor(t, 8, "next"),
	); !errors.Is(err, releaseverify.ErrReleaseAnchorConflict) {
		t.Fatalf("missing predecessor error=%v", err)
	}
}

func TestPF001ReleaseAnchorRepositorySerializesRacingSuccessors(t *testing.T) {
	t.Parallel()
	repository, _ := releaseAnchorFixture(t)
	first := testReleaseAnchor(t, 10, "first")
	if err := repository.CompareAndSwapReleaseAnchor(context.Background(), nil, first); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errorsSeen := make(chan error, 2)
	for _, next := range []releaseverify.ReleaseAnchor{
		testReleaseAnchor(t, 11, "next-a"),
		testReleaseAnchor(t, 12, "next-b"),
	} {
		next := next
		go func() {
			<-start
			errorsSeen <- repository.CompareAndSwapReleaseAnchor(context.Background(), &first, next)
		}()
	}
	close(start)
	var successes, conflicts int
	for range 2 {
		err := <-errorsSeen
		switch {
		case err == nil:
			successes++
		case errors.Is(err, releaseverify.ErrReleaseAnchorConflict):
			conflicts++
		default:
			t.Fatalf("race error=%v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("race successes/conflicts=%d/%d", successes, conflicts)
	}
}

func TestPF001ReleaseAnchorSnapshotDecoderRejectsNonCanonicalAndTamperedState(t *testing.T) {
	t.Parallel()
	anchor := testReleaseAnchor(t, 1, "release")
	payload, err := encodeAnchors(anchorSet{anchor.Channel(): anchor})
	if err != nil {
		t.Fatal(err)
	}
	base := installjournal.Snapshot{
		OperationID: releaseAnchorOperationID,
		Revision:    1,
		CapturedAt:  time.Unix(1, 0).UTC(),
		Payload:     payload,
	}
	if observed, err := decodeSnapshot(base); err != nil || !sameAnchor(observed[anchor.Channel()], anchor) {
		t.Fatalf("valid decode=%+v error=%v", observed, err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*installjournal.Snapshot)
	}{
		{name: "operation", mutate: func(value *installjournal.Snapshot) { value.OperationID = "other" }},
		{name: "revision", mutate: func(value *installjournal.Snapshot) { value.Revision = 0 }},
		{name: "time", mutate: func(value *installjournal.Snapshot) { value.CapturedAt = time.Time{} }},
		{name: "invalid JSON", mutate: func(value *installjournal.Snapshot) { value.Payload = []byte("{") }},
		{name: "oversize", mutate: func(value *installjournal.Snapshot) { value.Payload = bytes.Repeat([]byte(" "), 8193) }},
		{name: "whitespace", mutate: func(value *installjournal.Snapshot) { value.Payload = append([]byte(" "), value.Payload...) }},
		{name: "unknown", mutate: func(value *installjournal.Snapshot) {
			value.Payload = bytes.Replace(value.Payload, []byte("}"), []byte(",\"unknown\":true}"), 1)
		}},
		{name: "trailing", mutate: func(value *installjournal.Snapshot) { value.Payload = append(value.Payload, []byte("{}")...) }},
		{name: "schema", mutate: func(value *installjournal.Snapshot) {
			value.Payload = bytes.Replace(value.Payload, []byte("\"schema_version\":1"), []byte("\"schema_version\":2"), 1)
		}},
		{name: "zero sequence", mutate: func(value *installjournal.Snapshot) {
			value.Payload = bytes.Replace(value.Payload, []byte("\"sequence\":1"), []byte("\"sequence\":0"), 1)
		}},
		{name: "unsafe sequence", mutate: func(value *installjournal.Snapshot) {
			value.Payload = bytes.Replace(value.Payload, []byte("\"sequence\":1"), []byte("\"sequence\":9007199254740992"), 1)
		}},
		{name: "digest", mutate: func(value *installjournal.Snapshot) {
			value.Payload = bytes.Replace(value.Payload, []byte(anchor.ManifestDigest().Hex()), []byte("not-a-digest"), 1)
		}},
		{name: "release ID", mutate: func(value *installjournal.Snapshot) {
			value.Payload = bytes.Replace(value.Payload, []byte("\"release_id\":\"release\""), []byte("\"release_id\":\"unsafe/id\""), 1)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			candidate.Payload = append([]byte(nil), base.Payload...)
			test.mutate(&candidate)
			if _, err := decodeSnapshot(candidate); !errors.Is(err, releaseverify.ErrReleaseAnchorIntegrity) {
				t.Fatalf("decode error=%v", err)
			}
		})
	}
}

func TestPF001ReleaseAnchorRepositoryRejectsIncompleteCompositionAndMapsBoundaries(t *testing.T) {
	t.Parallel()
	clock := fixedClock{at: time.Unix(1, 0).UTC()}
	if repository, err := NewRepository(nil, clock); !errors.Is(err, releaseverify.ErrReleaseAnchorIntegrity) || repository != nil {
		t.Fatalf("nil journal repository=%+v error=%v", repository, err)
	}
	journal := newAnchoredTestJournal(t, &memoryJournal{})
	var typedNil *fixedClock
	if repository, err := NewRepository(journal, typedNil); !errors.Is(err, releaseverify.ErrReleaseAnchorIntegrity) || repository != nil {
		t.Fatalf("typed-nil clock repository=%+v error=%v", repository, err)
	}
	zeroClockRepository, err := NewRepository(journal, fixedClock{})
	if err != nil {
		t.Fatal(err)
	}
	if err := zeroClockRepository.CompareAndSwapReleaseAnchor(
		context.Background(), nil, testReleaseAnchor(t, 1, "release"),
	); !errors.Is(err, releaseverify.ErrDependencyUnavailable) {
		t.Fatalf("zero clock error=%v", err)
	}
	var absent *Repository
	//lint:ignore SA1012 Deliberate nil-context security regression fixture; owner=security expiry=2027-07-14.
	//nolint:staticcheck // SA1012: deliberate nil-context security regression fixture; owner=security expiry=2027-07-14.
	_, nilContextError := absent.LoadReleaseAnchor(nil, releaseinventory.ReleaseChannelStable)
	if !errors.Is(nilContextError, releaseverify.ErrReleaseAnchorIntegrity) {
		t.Fatalf("nil repository load error=%v", nilContextError)
	}
	if err := absent.CompareAndSwapReleaseAnchor(context.Background(), nil, releaseverify.ReleaseAnchor{}); !errors.Is(err, releaseverify.ErrReleaseAnchorIntegrity) {
		t.Fatalf("nil repository mutation error=%v", err)
	}

	for _, test := range []struct {
		input error
		load  error
		write error
	}{
		{input: installjournal.ErrNotFound, load: releaseverify.ErrReleaseAnchorNotFound, write: releaseverify.ErrDependencyUnavailable},
		{input: installjournal.ErrCorrupt, load: releaseverify.ErrReleaseAnchorIntegrity, write: releaseverify.ErrReleaseAnchorIntegrity},
		{input: installjournal.ErrUnsafePermission, load: releaseverify.ErrReleaseAnchorIntegrity, write: releaseverify.ErrReleaseAnchorIntegrity},
		{input: installjournal.ErrInvalidSnapshot, load: releaseverify.ErrReleaseAnchorIntegrity, write: releaseverify.ErrReleaseAnchorIntegrity},
		{input: installjournal.ErrConflict, load: releaseverify.ErrDependencyUnavailable, write: releaseverify.ErrReleaseAnchorConflict},
		{input: installjournal.ErrIO, load: releaseverify.ErrDependencyUnavailable, write: releaseverify.ErrDependencyUnavailable},
		{input: context.Canceled, load: context.Canceled, write: context.Canceled},
		{input: context.DeadlineExceeded, load: context.DeadlineExceeded, write: context.DeadlineExceeded},
	} {
		if observed := mapLoadError(test.input); !errors.Is(observed, test.load) {
			t.Fatalf("mapLoadError(%v)=%v", test.input, observed)
		}
		if observed := mapMutationError(test.input); !errors.Is(observed, test.write) {
			t.Fatalf("mapMutationError(%v)=%v", test.input, observed)
		}
	}
}

func releaseAnchorFixture(t *testing.T) (*Repository, *memoryJournal) {
	t.Helper()
	inner := &memoryJournal{}
	journal := newAnchoredTestJournal(t, inner)
	repository, err := NewRepository(journal, fixedClock{at: time.Unix(1_000, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	return repository, inner
}

func newAnchoredTestJournal(t *testing.T, inner *memoryJournal) *bootstrapadapter.AnchoredJournal {
	t.Helper()
	operationID, err := install.NewOperationID(releaseAnchorOperationID)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := install.BindOwner("test-machine", "test-principal")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := bootstrapadapter.NewMemoryOperationKeySource(bytes.NewReader(bytes.Repeat([]byte{7}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	keyRef, err := keys.Ensure(context.Background(), operationID, owner)
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

func testReleaseAnchor(t *testing.T, sequence uint64, releaseID string) releaseverify.ReleaseAnchor {
	t.Helper()
	return testChannelReleaseAnchor(t, releaseinventory.ReleaseChannelStable, sequence, releaseID)
}

func testChannelReleaseAnchor(
	t *testing.T,
	channel releaseinventory.ReleaseChannel,
	sequence uint64,
	releaseID string,
) releaseverify.ReleaseAnchor {
	t.Helper()
	anchor, err := releaseverify.NewReleaseAnchor(
		channel,
		sequence,
		releaseinventory.DigestBytes([]byte(releaseID)),
		releaseID,
	)
	if err != nil {
		t.Fatal(err)
	}
	return anchor
}

type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

type memoryJournal struct {
	mu            sync.Mutex
	snapshot      installjournal.Snapshot
	confirmations int
}

func (j *memoryJournal) Append(
	ctx context.Context,
	expectedPreviousRevision uint64,
	snapshot installjournal.Snapshot,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.snapshot.Revision != expectedPreviousRevision || snapshot.Revision != expectedPreviousRevision+1 {
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

var _ installjournal.Journal = (*memoryJournal)(nil)
var _ bootstrapport.OperationKeySource = (*bootstrapadapter.MemoryOperationKeySource)(nil)
