package artifactapp

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001ArtifactApplicationReservesBeforeAnyFetch(t *testing.T) {
	t.Parallel()
	repository := newMemoryRepository()
	events := []string{}
	reservation := &fakeReservation{events: &events}
	fetcher := &fakeFetcher{events: &events}
	store := newMemoryStore(&events)
	application := newApplication(t, repository, reservation, fetcher, store)
	command := testCommand(t)

	if _, err := application.Acquire(context.Background(), command); err == nil || fetcher.calls != 0 {
		t.Fatalf("Acquire before reserve error=%v fetches=%d", err, fetcher.calls)
	}
	reserved, err := application.ReserveSpace(context.Background(), command)
	if err != nil || reserved.ReservedBytes != 6 || reserved.Reused || reserved.AggregateEvidence.IsZero() ||
		!strings.HasPrefix(reserved.ReservationID, "r-") {
		t.Fatalf("ReserveSpace()=(%+v,%v)", reserved, err)
	}
	replayed, err := application.ReserveSpace(context.Background(), command)
	if err != nil || !replayed.Reused || reservation.calls != 1 || reservation.revalidateCalls != 1 {
		t.Fatalf("replay=(%+v,%v) calls=%d revalidations=%d", replayed, err, reservation.calls, reservation.revalidateCalls)
	}
	result, err := application.Acquire(context.Background(), command)
	if err != nil || result.CompletedArtifacts != 1 || result.DownloadedChunks != 2 || result.RecoveredChunks != 0 ||
		result.AggregateEvidence.IsZero() || !result.ReservationRetained || len(result.VerifiedArtifacts) != 1 ||
		result.VerifiedArtifacts[0].ID != "core" || !result.VerifiedArtifacts[0].Digest.Equal(command.Plan.Artifacts()[0].Digest()) ||
		reservation.revalidateCalls != 2 {
		t.Fatalf("Acquire()=(%+v,%v)", result, err)
	}
	firstFetch := -1
	for index, event := range events {
		if strings.HasPrefix(event, "fetch:") {
			firstFetch = index
			break
		}
	}
	if firstFetch < 1 || events[0] != "reserve" {
		t.Fatalf("events=%v", events)
	}
	if fetcher.sources[0] != "bundle://release/core.bin" || fetcher.sources[1] != "https://releases.agentmemory.dev/artifacts/core.bin" {
		t.Fatalf("signed source order=%v", fetcher.sources)
	}
}

func TestPF001ArtifactAcquirePhysicallyRevalidatesEveryRetainedReservationLayout(t *testing.T) {
	t.Parallel()
	repository := newMemoryRepository()
	reservation := &fakeReservation{}
	application := newApplication(t, repository, reservation, &fakeFetcher{}, newMemoryStore(nil))
	command := testCommand(t)
	if _, err := application.ReserveSpace(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	reservation.revalidateError = ErrReservationOperation
	if _, err := application.Acquire(context.Background(), command); err == nil || reservation.consumeCalls != 0 {
		t.Fatalf("missing physical reservation advanced acquisition: error=%v consumes=%d", err, reservation.consumeCalls)
	}
	reservation.revalidateError = nil
	reservationID, _ := command.Plan.ReservationID(command.OperationID)
	reservation.revalidateProof, _ = artifactacquisition.NewReservationProof(
		reservationID, command.Plan.Totals().DownloadBytes(), "localfs-substituted",
	)
	if _, err := application.Acquire(context.Background(), command); err == nil {
		t.Fatal("substituted physical reservation proof advanced acquisition")
	}
}

func TestPF001ArtifactApplicationRevalidatesARecordedReservationBeforeReuse(t *testing.T) {
	t.Parallel()
	repository := newMemoryRepository()
	reservation := &fakeReservation{}
	application := newApplication(t, repository, reservation, &fakeFetcher{}, newMemoryStore(nil))
	command := testCommand(t)
	first, err := application.ReserveSpace(context.Background(), command)
	if err != nil || first.Reused || reservation.calls != 1 {
		t.Fatalf("first reservation=(%+v,%v) calls=%d", first, err, reservation.calls)
	}

	reservation.revalidateError = ErrReservationOperation
	if reused, err := application.ReserveSpace(context.Background(), command); err == nil || reused.Reused || reservation.revalidateCalls != 1 {
		t.Fatalf("lost reservation reuse=(%+v,%v) revalidations=%d", reused, err, reservation.revalidateCalls)
	}

	reservation.revalidateError = nil
	foreign, _ := artifactacquisition.NewReservationProof(
		first.ReservationID, first.ReservedBytes, "localfs-substituted",
	)
	reservation.revalidateProof = foreign
	if _, err := application.ReserveSpace(context.Background(), command); err == nil {
		t.Fatal("substituted filesystem receipt was reused")
	}
}

func TestPF001ArtifactAcquireReplayVerifiesFinalWithoutNetwork(t *testing.T) {
	t.Parallel()
	repository, reservation, fetcher, store := preparedApplicationState(t)
	application := newApplication(t, repository, reservation, fetcher, store)
	command := testCommand(t)
	if _, err := application.Acquire(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	before := fetcher.calls
	result, err := application.Acquire(context.Background(), command)
	if err != nil || result.CompletedArtifacts != 1 || fetcher.calls != before || store.inspectFinalCalls < 2 {
		t.Fatalf("replay=(%+v,%v) fetches=%d/%d final=%d", result, err, fetcher.calls, before, store.inspectFinalCalls)
	}
	store.inspectError = ErrStoreOperation
	if _, err := application.Acquire(context.Background(), command); err == nil {
		t.Fatal("completed artifact inspection failure succeeded")
	}
}

func TestPF001ArtifactAcquireRevalidatesRetainedChunks(t *testing.T) {
	t.Parallel()
	repository := newMemoryRepository()
	events := []string{}
	reservation := &fakeReservation{events: &events}
	fetcher := &fakeFetcher{events: &events}
	store := newMemoryStore(&events)
	application := newApplication(t, repository, reservation, fetcher, store)
	command := testCommand(t)
	_, _ = application.ReserveSpace(context.Background(), command)

	// Simulate a crash after a valid WriteChunk but before aggregate Mark/Save.
	snapshot, _ := repository.Load(context.Background(), command.OperationID)
	aggregate, _ := artifactacquisition.Restore(command.Plan, snapshot)
	artifact := command.Plan.Artifacts()[0]
	previous := aggregate.Version()
	_, _ = aggregate.BeginArtifact(artifact)
	_ = repository.Save(context.Background(), previous, aggregate.Snapshot())
	authorization, _ := aggregate.AuthorizePartial(artifact)
	chunk := artifact.Chunks()[0]
	_ = store.WriteChunk(context.Background(), authorization, chunk, []byte("abc"))

	result, err := application.Acquire(context.Background(), command)
	if err != nil || result.RecoveredChunks != 1 || result.DownloadedChunks != 1 {
		t.Fatalf("recovery=(%+v,%v)", result, err)
	}
	if fetcher.chunkCalls[0] != 0 || fetcher.chunkCalls[1] != 2 {
		t.Fatalf("fetch chunk calls=%v", fetcher.chunkCalls)
	}
}

func TestPF001ArtifactAcquireInvalidatesCorruptRetainedChunk(t *testing.T) {
	t.Parallel()
	repository := newMemoryRepository()
	events := []string{}
	application := newApplication(t, repository, &fakeReservation{events: &events}, &fakeFetcher{events: &events}, newMemoryStore(&events))
	command := testCommand(t)
	_, _ = application.ReserveSpace(context.Background(), command)
	// Normal acquisition covers replacement of a non-existent retained range;
	// the integrity-specific cleanup path is exercised below.
	application.store.(*memoryStore).writeIntegrity = true
	_, err := application.Acquire(context.Background(), command)
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != ErrorIntegrity || application.store.(*memoryStore).removed != 1 {
		t.Fatalf("error=%v removed=%d", err, application.store.(*memoryStore).removed)
	}
	loaded, _ := repository.Load(context.Background(), command.OperationID)
	if len(loaded.Progress) != 1 || !loaded.Progress[0].ReservationConsumed || len(loaded.Progress[0].VerifiedChunks) != 0 {
		t.Fatalf("invalid partial capacity was not safely retained: %+v", loaded.Progress)
	}
}

func TestPF001ArtifactFetchIntegrityAndCancellationNeverDeleteValidOwnedPartial(t *testing.T) {
	t.Parallel()
	for _, fetchError := range []error{ErrFetchIntegrity, context.Canceled} {
		repository := newMemoryRepository()
		events := []string{}
		reservation := &fakeReservation{events: &events}
		fetcher := &fakeFetcher{events: &events, forcedError: fetchError}
		store := newMemoryStore(&events)
		application := newApplication(t, repository, reservation, fetcher, store)
		command := testCommand(t)
		_, _ = application.ReserveSpace(context.Background(), command)
		_, err := application.Acquire(context.Background(), command)
		if err == nil || store.removed != 0 {
			t.Fatalf("fetch error=%v result=%v removed=%d", fetchError, err, store.removed)
		}
		loaded, _ := repository.Load(context.Background(), command.OperationID)
		if len(loaded.Progress) != 1 {
			t.Fatalf("owned resumable partial was forgotten: %+v", loaded.Progress)
		}
	}
}

func TestPF001ArtifactApplicationRejectsNilDependenciesAndInvalidCommands(t *testing.T) {
	t.Parallel()
	var nilRepository *memoryRepository
	var nilReservation *fakeReservation
	var nilFetcher *fakeFetcher
	var nilStore *memoryStore
	for _, dependencies := range []Dependencies{
		{},
		{Repository: nilRepository, Reservation: &fakeReservation{}, Fetcher: &fakeFetcher{}, Store: &memoryStore{}},
		{Repository: newMemoryRepository(), Reservation: nilReservation, Fetcher: &fakeFetcher{}, Store: &memoryStore{}},
		{Repository: newMemoryRepository(), Reservation: &fakeReservation{}, Fetcher: nilFetcher, Store: &memoryStore{}},
		{Repository: newMemoryRepository(), Reservation: &fakeReservation{}, Fetcher: &fakeFetcher{}, Store: nilStore},
	} {
		if _, err := New(dependencies); err == nil {
			t.Fatal("New accepted nil dependency")
		}
	}
	application := newApplication(t, newMemoryRepository(), &fakeReservation{}, &fakeFetcher{}, newMemoryStore(nil))
	if _, err := application.ReserveSpace(context.Background(), Command{}); err == nil {
		t.Fatal("invalid reserve succeeded")
	}
	if _, err := application.Acquire(context.Background(), Command{}); err == nil {
		t.Fatal("invalid acquire succeeded")
	}
	var absent context.Context
	if _, err := application.Acquire(absent, testCommand(t)); err == nil {
		t.Fatal("nil-context acquire succeeded")
	}
}

func TestPF001ArtifactRepositoryFailuresAreSanitized(t *testing.T) {
	t.Parallel()
	repository := newMemoryRepository()
	repository.loadErr = errors.New("raw path and URL")
	application := newApplication(t, repository, &fakeReservation{}, &fakeFetcher{}, newMemoryStore(nil))
	_, err := application.ReserveSpace(context.Background(), testCommand(t))
	if err == nil || strings.Contains(err.Error(), "raw path") {
		t.Fatalf("error=%v", err)
	}
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != ErrorRepository || typed.Error() == "" ||
		!errors.Is(typed, &Error{Code: ErrorRepository}) || errors.Is(typed, &Error{Code: ErrorStore}) {
		t.Fatalf("stable error=%v", err)
	}
	var nilError *Error
	if nilError.Error() != "<nil>" {
		t.Fatalf("nil error=%q", nilError.Error())
	}
}

func TestPF001ArtifactApplicationMapsReservationStoreAndCompensationFailures(t *testing.T) {
	t.Parallel()
	command := testCommand(t)
	repository := newMemoryRepository()
	application := newApplication(t, repository, &fakeReservation{forcedError: ErrReservationUnsupported}, &fakeFetcher{}, newMemoryStore(nil))
	if _, err := application.ReserveSpace(context.Background(), command); err == nil {
		t.Fatal("reservation failure succeeded")
	}

	tests := []struct {
		name      string
		configure func(*memoryStore)
		code      ErrorCode
	}{
		{name: "inspect", configure: func(store *memoryStore) { store.inspectError = ErrStoreOperation }, code: ErrorStore},
		{name: "verify", configure: func(store *memoryStore) { store.verifyError = ErrStoreOperation }, code: ErrorStore},
		{name: "finalize", configure: func(store *memoryStore) { store.finalizeError = ErrStoreOperation }, code: ErrorStore},
		{name: "remove", configure: func(store *memoryStore) { store.writeIntegrity = true; store.removeError = ErrStoreOperation }, code: ErrorCompensation},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := newMemoryRepository()
			store := newMemoryStore(nil)
			test.configure(store)
			application := newApplication(t, repository, &fakeReservation{}, &fakeFetcher{}, store)
			_, _ = application.ReserveSpace(context.Background(), command)
			_, err := application.Acquire(context.Background(), command)
			var typed *Error
			if !errors.As(err, &typed) || typed.Code != test.code {
				t.Fatalf("error=%v want=%s", err, test.code)
			}
		})
	}
	var integrityError *Error
	var storeError *Error
	if !errors.As(mapStore(ErrStoreIntegrity, "test"), &integrityError) || integrityError.Code != ErrorIntegrity ||
		!errors.As(mapStore(ErrStoreOperation, "test"), &storeError) || storeError.Code != ErrorStore {
		t.Fatal("store error mapping changed")
	}
}

func TestPF001ArtifactApplicationPreservesUnsupportedReservationClassification(t *testing.T) {
	t.Parallel()
	application := newApplication(t, newMemoryRepository(), &fakeReservation{forcedError: ErrReservationUnsupported}, &fakeFetcher{}, newMemoryStore(nil))
	_, err := application.ReserveSpace(context.Background(), testCommand(t))
	if !errors.Is(err, ErrReservationUnsupported) {
		t.Fatalf("unsupported reservation classification lost: %v", err)
	}
}

func TestPF001ArtifactApplicationAcceptsAlreadyVerifiedFinal(t *testing.T) {
	t.Parallel()
	repository := newMemoryRepository()
	store := newMemoryStore(nil)
	command := testCommand(t)
	artifact := command.Plan.Artifacts()[0]
	store.finals[artifact.ContentKey()] = []byte("abcdef")
	application := newApplication(t, repository, &fakeReservation{}, &fakeFetcher{}, store)
	_, _ = application.ReserveSpace(context.Background(), command)
	result, err := application.Acquire(context.Background(), command)
	if err != nil || result.CompletedArtifacts != 1 || result.DownloadedChunks != 0 {
		t.Fatalf("Acquire()=(%+v,%v)", result, err)
	}
}

func TestPF001ArtifactApplicationFailsClosedOnSourceAndPersistenceBoundaries(t *testing.T) {
	t.Parallel()
	command := testCommand(t)
	artifact := command.Plan.Artifacts()[0]
	chunk := artifact.Chunks()[0]

	for _, fetchError := range []error{ErrFetchUnavailable, errors.New("unexpected")} {
		application := newApplication(t, newMemoryRepository(), &fakeReservation{}, &fakeFetcher{forcedError: fetchError}, newMemoryStore(nil))
		if _, err := application.fetchChunk(context.Background(), artifact, chunk); err == nil {
			t.Fatalf("source error %v succeeded", fetchError)
		}
	}
	for _, networkError := range []error{
		ErrFetchProxyConfiguration, ErrFetchProxyAuthentication, ErrFetchTLSInterception, ErrFetchNetworkInterception,
	} {
		application := newApplication(t, newMemoryRepository(), &fakeReservation{}, &fakeFetcher{
			forcedError: errors.Join(ErrFetchUnavailable, networkError),
		}, newMemoryStore(nil))
		_, err := application.fetchChunk(context.Background(), artifact, chunk)
		if !errors.Is(err, networkError) {
			t.Fatalf("network error %v was not preserved: %v", networkError, err)
		}
	}

	createFailure := newMemoryRepository()
	createFailure.saveErr = errors.New("raw repository failure")
	application := newApplication(t, createFailure, &fakeReservation{}, &fakeFetcher{}, newMemoryStore(nil))
	if _, err := application.ReserveSpace(context.Background(), command); err == nil {
		t.Fatal("aggregate creation failure succeeded")
	}

	for _, value := range []any{0, struct{}{}, "configured"} {
		if nilDependency(value) {
			t.Fatalf("non-nil dependency value rejected: %T", value)
		}
	}
	var nilMap map[string]string
	if !nilDependency(nilMap) {
		t.Fatal("typed nil map accepted")
	}
}

func TestPF001ArtifactApplicationPersistsEveryTransitionOrFailsClosed(t *testing.T) {
	t.Parallel()
	command := testCommand(t)
	tests := []struct {
		name       string
		failSaveAt int
		code       ErrorCode
	}{
		{name: "partial ownership", failSaveAt: 4, code: ErrorRepository},
		{name: "first chunk", failSaveAt: 6, code: ErrorRepository},
		{name: "second chunk", failSaveAt: 7, code: ErrorRepository},
		{name: "completion", failSaveAt: 8, code: ErrorRepository},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := newMemoryRepository()
			application := newApplication(t, repository, &fakeReservation{}, &fakeFetcher{}, newMemoryStore(nil))
			if _, err := application.ReserveSpace(context.Background(), command); err != nil {
				t.Fatal(err)
			}
			repository.failSaveAt = test.failSaveAt
			_, err := application.Acquire(context.Background(), command)
			var typed *Error
			if !errors.As(err, &typed) || typed.Code != test.code {
				t.Fatalf("error=%v want=%s", err, test.code)
			}
		})
	}

	repository := newMemoryRepository()
	application := newApplication(t, repository, &fakeReservation{}, &fakeFetcher{}, newMemoryStore(nil))
	if _, err := application.ReserveSpace(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	repository.failSaveAt = 3
	if _, err := application.ReserveSpace(context.Background(), command); err != nil {
		t.Fatalf("reused reservation unexpectedly persisted: %v", err)
	}
}

func TestPF001ArtifactApplicationRejectsInvalidBytesAndPersistsInvalidation(t *testing.T) {
	t.Parallel()
	command := testCommand(t)

	for _, configure := range []func(*fakeFetcher, *memoryStore){
		func(fetcher *fakeFetcher, _ *memoryStore) { fetcher.forcedValue = []byte("bad") },
		func(_ *fakeFetcher, store *memoryStore) { store.writeError = ErrStoreOperation },
		func(_ *fakeFetcher, store *memoryStore) { store.verifyWrong = true },
	} {
		repository := newMemoryRepository()
		fetcher := &fakeFetcher{}
		store := newMemoryStore(nil)
		configure(fetcher, store)
		application := newApplication(t, repository, &fakeReservation{}, fetcher, store)
		_, _ = application.ReserveSpace(context.Background(), command)
		if _, err := application.Acquire(context.Background(), command); err == nil {
			t.Fatal("invalid acquisition boundary succeeded")
		}
	}

	repository := newMemoryRepository()
	store := newMemoryStore(nil)
	application := newApplication(t, repository, &fakeReservation{}, &fakeFetcher{}, store)
	_, _ = application.ReserveSpace(context.Background(), command)
	snapshot, _ := repository.Load(context.Background(), command.OperationID)
	aggregate, _ := artifactacquisition.Restore(command.Plan, snapshot)
	artifact := command.Plan.Artifacts()[0]
	previous := aggregate.Version()
	_, _ = aggregate.BeginArtifact(artifact)
	_ = repository.Save(context.Background(), previous, aggregate.Snapshot())
	previous = aggregate.Version()
	_, _ = aggregate.MarkChunkVerified(artifact, artifact.Chunks()[0], artifact.Chunks()[0].Digest())
	_ = repository.Save(context.Background(), previous, aggregate.Snapshot())
	result, err := application.Acquire(context.Background(), command)
	if err != nil || result.DownloadedChunks != 2 {
		t.Fatalf("invalidated recovery=(%+v,%v)", result, err)
	}
}

func TestPF001ArtifactApplicationRejectsContradictoryProofsAndPersistence(t *testing.T) {
	t.Parallel()
	command := testCommand(t)

	repository := newMemoryRepository()
	repository.failSaveAt = 2
	application := newApplication(t, repository, &fakeReservation{}, &fakeFetcher{}, newMemoryStore(nil))
	if _, err := application.ReserveSpace(context.Background(), command); err == nil {
		t.Fatal("reservation persistence failure succeeded")
	}

	wrongID := "r-" + strings.Repeat("a", 64)
	wrongProof, _ := artifactacquisition.NewReservationProof(wrongID, command.Plan.Totals().DownloadBytes(), "localfs-1")
	application = newApplication(t, newMemoryRepository(), &fakeReservation{proof: wrongProof}, &fakeFetcher{}, newMemoryStore(nil))
	if _, err := application.ReserveSpace(context.Background(), command); err == nil {
		t.Fatal("contradictory reservation proof succeeded")
	}

	repository = newMemoryRepository()
	store := newMemoryStore(nil)
	application = newApplication(t, repository, &fakeReservation{}, &fakeFetcher{}, store)
	_, _ = application.ReserveSpace(context.Background(), command)
	repository.failSaveAt = 6
	store.writeIntegrity = true
	_, err := application.Acquire(context.Background(), command)
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != ErrorCompensation {
		t.Fatalf("compensation persistence error=%v", err)
	}

	repository = newMemoryRepository()
	store = newMemoryStore(nil)
	application = newApplication(t, repository, &fakeReservation{}, &fakeFetcher{}, store)
	_, _ = application.ReserveSpace(context.Background(), command)
	other := releaseinventory.DigestBytes([]byte("other-final"))
	store.finalizeProof, _ = artifactacquisition.NewFinalProof(other, 11, "sha256/"+other.Hex()[:2]+"/"+other.Hex())
	store.overrideFinalizeProof = true
	_, err = application.Acquire(context.Background(), command)
	if !errors.As(err, &typed) || typed.Code != ErrorIntegrity {
		t.Fatalf("contradictory final proof error=%v", err)
	}
}

func preparedApplicationState(t *testing.T) (*memoryRepository, *fakeReservation, *fakeFetcher, *memoryStore) {
	t.Helper()
	repository := newMemoryRepository()
	events := []string{}
	reservation := &fakeReservation{events: &events}
	fetcher := &fakeFetcher{events: &events}
	store := newMemoryStore(&events)
	application := newApplication(t, repository, reservation, fetcher, store)
	_, _ = application.ReserveSpace(context.Background(), testCommand(t))
	return repository, reservation, fetcher, store
}

func newApplication(t *testing.T, repository Repository, reservation ReservationPort, fetcher Fetcher, store Store) *Application {
	t.Helper()
	application, err := New(Dependencies{Repository: repository, Reservation: reservation, Fetcher: fetcher, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	return application
}

func testCommand(t *testing.T) Command {
	t.Helper()
	digest := releaseinventory.DigestBytes([]byte("abcdef"))
	target, targetErr := releaseinventory.NewReleaseExpandedTarget(digest, 6, releaseinventory.ReleaseExpandedTargetInput{
		Kind: releaseinventory.ExpandedTargetComposeBundle, StorageID: "compose/compose.yaml", Digest: digest, Bytes: 6,
	})
	if targetErr != nil {
		t.Fatal(targetErr)
	}
	plan, err := artifactacquisition.NewPlan(artifactacquisition.PlanInput{
		PlanDigest: releaseinventory.DigestBytes([]byte("signed-plan")),
		ProxyMode:  artifactacquisition.ProxyModeSystem,
		Artifacts: []artifactacquisition.ArtifactInput{{
			ID: "core", Digest: digest, Size: 6, ExpandedBytes: 6, ExpandedDigest: digest,
			TargetKind: target.Kind(), TargetStorageID: target.StorageID(), TargetAuthorityDigest: target.AuthorityDigest(),
			Sources: []string{"https://releases.agentmemory.dev/artifacts/core.bin", "bundle://release/core.bin"},
			Chunks: []artifactacquisition.ChunkInput{
				{Offset: 0, Size: 3, Digest: releaseinventory.DigestBytes([]byte("abc"))},
				{Offset: 3, Size: 3, Digest: releaseinventory.DigestBytes([]byte("def"))},
			},
		}},
		Totals: artifactacquisition.TotalsInput{DownloadBytes: 6, ExpandedBytes: 6, RollbackHeadroomBytes: 20, SafetyHeadroomBytes: 30, RequiredBytes: 62},
	})
	if err != nil {
		t.Fatal(err)
	}
	return Command{OperationID: "install-1", Plan: plan}
}

type memoryRepository struct {
	exists     bool
	snapshot   artifactacquisition.Snapshot
	loadErr    error
	saveErr    error
	failSaveAt int
	saveCount  int
}

func newMemoryRepository() *memoryRepository { return &memoryRepository{} }

func (r *memoryRepository) Load(_ context.Context, operationID string) (artifactacquisition.Snapshot, error) {
	if r.loadErr != nil {
		return artifactacquisition.Snapshot{}, r.loadErr
	}
	if !r.exists {
		return artifactacquisition.Snapshot{}, ErrAggregateNotFound
	}
	if r.snapshot.OperationID != operationID {
		return artifactacquisition.Snapshot{}, ErrAggregateIntegrity
	}
	return cloneSnapshot(r.snapshot), nil
}

func (r *memoryRepository) Save(_ context.Context, expected uint64, snapshot artifactacquisition.Snapshot) error {
	r.saveCount++
	if r.saveErr != nil || (r.failSaveAt > 0 && r.saveCount == r.failSaveAt) {
		if r.saveErr == nil {
			return ErrAggregatePersistence
		}
		return r.saveErr
	}
	if r.exists && r.snapshot.Version != expected {
		return ErrAggregateConflict
	}
	if !r.exists && (expected != 0 || snapshot.Version != 0) {
		return ErrAggregateConflict
	}
	r.snapshot, r.exists = cloneSnapshot(snapshot), true
	return nil
}

type fakeReservation struct {
	events          *[]string
	calls           int
	revalidateCalls int
	consumeCalls    int
	releaseCalls    int
	forcedError     error
	revalidateError error
	consumeError    error
	releaseError    error
	proof           artifactacquisition.ReservationProof
	revalidateProof artifactacquisition.ReservationProof
}

func (r *fakeReservation) Reserve(_ context.Context, request ReservationRequest) (artifactacquisition.ReservationProof, error) {
	r.calls++
	if r.events != nil {
		*r.events = append(*r.events, "reserve")
	}
	if r.forcedError != nil {
		return artifactacquisition.ReservationProof{}, r.forcedError
	}
	if r.proof.ID() != "" {
		return r.proof, nil
	}
	return artifactacquisition.NewReservationProof(request.ReservationID, request.RequiredBytes, "localfs-1")
}

func (r *fakeReservation) Revalidate(
	_ context.Context,
	authorization artifactacquisition.ReservationRevalidationAuthorization,
) (artifactacquisition.ReservationProof, error) {
	r.revalidateCalls++
	if r.events != nil {
		*r.events = append(*r.events, "revalidate")
	}
	if r.revalidateError != nil {
		return artifactacquisition.ReservationProof{}, r.revalidateError
	}
	if r.revalidateProof.ID() != "" {
		return r.revalidateProof, nil
	}
	return authorization.Reservation(), nil
}

func (r *fakeReservation) Consume(
	_ context.Context,
	authorization artifactacquisition.ConsumptionAuthorization,
) (artifactacquisition.ConsumptionProof, error) {
	r.consumeCalls++
	if r.consumeError != nil {
		return artifactacquisition.ConsumptionProof{}, r.consumeError
	}
	return artifactacquisition.NewConsumptionProof(
		authorization.ReservationID(), authorization.PartialID(), authorization.Bytes(), authorization.FilesystemID(),
	)
}

func (r *fakeReservation) Release(_ context.Context, _ artifactacquisition.ReleaseAuthorization) error {
	r.releaseCalls++
	return r.releaseError
}

type fakeFetcher struct {
	events      *[]string
	calls       int
	sources     []string
	chunkCalls  map[uint32]int
	forcedError error
	forcedValue []byte
}

func (f *fakeFetcher) Fetch(_ context.Context, _ artifactacquisition.Artifact, source string, chunk artifactacquisition.Chunk) ([]byte, error) {
	f.calls++
	if f.chunkCalls == nil {
		f.chunkCalls = make(map[uint32]int)
	}
	f.chunkCalls[chunk.Index()]++
	f.sources = append(f.sources, source)
	if f.events != nil {
		*f.events = append(*f.events, "fetch:"+source)
	}
	if f.forcedError != nil {
		return nil, f.forcedError
	}
	if f.forcedValue != nil {
		return append([]byte(nil), f.forcedValue...), nil
	}
	if strings.HasPrefix(source, "bundle://") {
		return nil, ErrFetchUnavailable
	}
	if chunk.Index() == 0 {
		return []byte("abc"), nil
	}
	return []byte("def"), nil
}

type memoryStore struct {
	events                *[]string
	partials              map[string][]byte
	finals                map[string][]byte
	removed               int
	writeIntegrity        bool
	inspectFinalCalls     int
	inspectError          error
	verifyError           error
	finalizeError         error
	removeError           error
	writeError            error
	verifyWrong           bool
	finalizeProof         artifactacquisition.FinalProof
	overrideFinalizeProof bool
}

func newMemoryStore(events *[]string) *memoryStore {
	return &memoryStore{events: events, partials: make(map[string][]byte), finals: make(map[string][]byte)}
}

func (s *memoryStore) InspectFinal(_ context.Context, artifact artifactacquisition.Artifact) (artifactacquisition.FinalProof, error) {
	s.inspectFinalCalls++
	if s.inspectError != nil {
		return artifactacquisition.FinalProof{}, s.inspectError
	}
	value, exists := s.finals[artifact.ContentKey()]
	if !exists {
		return artifactacquisition.FinalProof{}, ErrArtifactNotFound
	}
	if uint64(len(value)) != artifact.Size() || !releaseinventory.DigestBytes(value).Equal(artifact.Digest()) {
		return artifactacquisition.FinalProof{}, ErrStoreIntegrity
	}
	for _, chunk := range artifact.Chunks() {
		if !chunk.VerifyBytes(value[chunk.Offset() : chunk.Offset()+chunk.Size()]) {
			return artifactacquisition.FinalProof{}, ErrStoreIntegrity
		}
	}
	return artifactacquisition.NewFinalProof(artifact.Digest(), artifact.Size(), artifact.ContentKey())
}

func (s *memoryStore) VerifyChunk(_ context.Context, authorization artifactacquisition.PartialAuthorization, chunk artifactacquisition.Chunk) (releaseinventory.Digest, error) {
	if s.verifyError != nil {
		return releaseinventory.Digest{}, s.verifyError
	}
	if s.verifyWrong {
		return releaseinventory.DigestBytes([]byte("wrong")), nil
	}
	value, exists := s.partials[authorization.PartialID()]
	if !exists || uint64(len(value)) < chunk.Offset()+chunk.Size() {
		return releaseinventory.Digest{}, ErrArtifactNotFound
	}
	return releaseinventory.DigestBytes(value[chunk.Offset() : chunk.Offset()+chunk.Size()]), nil
}

func (s *memoryStore) WriteChunk(_ context.Context, authorization artifactacquisition.PartialAuthorization, chunk artifactacquisition.Chunk, value []byte) error {
	if s.writeIntegrity {
		return ErrStoreIntegrity
	}
	if s.writeError != nil {
		return s.writeError
	}
	partial := s.partials[authorization.PartialID()]
	requiredSize := chunk.Offset() + chunk.Size()
	if requiredSize > math.MaxInt {
		return ErrStoreIntegrity
	}
	required := int(requiredSize) // #nosec G115 -- math.MaxInt bound is proven above.
	if len(partial) < required {
		partial = append(partial, make([]byte, required-len(partial))...)
	}
	copy(partial[chunk.Offset():], value)
	s.partials[authorization.PartialID()] = partial
	return nil
}

func (s *memoryStore) Finalize(_ context.Context, authorization artifactacquisition.PartialAuthorization, artifact artifactacquisition.Artifact) (artifactacquisition.FinalProof, error) {
	if s.finalizeError != nil {
		return artifactacquisition.FinalProof{}, s.finalizeError
	}
	if s.overrideFinalizeProof {
		return s.finalizeProof, nil
	}
	value := s.partials[authorization.PartialID()]
	if uint64(len(value)) != artifact.Size() || !releaseinventory.DigestBytes(value).Equal(artifact.Digest()) {
		return artifactacquisition.FinalProof{}, ErrStoreIntegrity
	}
	s.finals[artifact.ContentKey()] = append([]byte(nil), value...)
	delete(s.partials, authorization.PartialID())
	return artifactacquisition.NewFinalProof(artifact.Digest(), artifact.Size(), artifact.ContentKey())
}

func (s *memoryStore) ResetInvalidPartial(_ context.Context, authorization artifactacquisition.PartialAuthorization) error {
	if s.removeError != nil {
		return s.removeError
	}
	s.partials[authorization.PartialID()] = make([]byte, authorization.Size())
	s.removed++
	return nil
}

func cloneSnapshot(snapshot artifactacquisition.Snapshot) artifactacquisition.Snapshot {
	copyOfSnapshot := snapshot
	copyOfSnapshot.Progress = append([]artifactacquisition.ProgressSnapshot(nil), snapshot.Progress...)
	for index := range copyOfSnapshot.Progress {
		copyOfSnapshot.Progress[index].VerifiedChunks = append([]uint32(nil), snapshot.Progress[index].VerifiedChunks...)
	}
	return copyOfSnapshot
}
