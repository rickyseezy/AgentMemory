package artifactapp

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
)

func TestPF001ReservationIntentSurvivesCrashBeforeProofAndReplayCompletes(t *testing.T) {
	t.Parallel()
	repository := newMemoryRepository()
	repository.failSaveAt = 3 // adapter succeeded; proof journal save lost to the simulated crash.
	reservation := &fakeReservation{}
	application := newApplication(t, repository, reservation, &fakeFetcher{}, newMemoryStore(nil))
	command := testCommand(t)
	if _, err := application.ReserveSpace(context.Background(), command); err == nil {
		t.Fatal("reservation proof persistence failure succeeded")
	}
	if !repository.exists || repository.snapshot.ReleaseState != "allocating" || repository.snapshot.FilesystemID != "" ||
		reservation.calls != 1 {
		t.Fatalf("intent snapshot=%+v calls=%d", repository.snapshot, reservation.calls)
	}
	repository.failSaveAt = 0
	result, err := application.ReserveSpace(context.Background(), command)
	if err != nil || result.ReservedBytes != command.Plan.Totals().DownloadBytes() || reservation.calls != 2 {
		t.Fatalf("replay result=%+v error=%v calls=%d", result, err, reservation.calls)
	}
}

func TestPF001ExplicitCancelReleasesAllocatingReservationWithFreshContext(t *testing.T) {
	t.Parallel()
	repository := newMemoryRepository()
	reservation := &fakeReservation{forcedError: ErrReservationOperation}
	application := newApplication(t, repository, reservation, &fakeFetcher{}, newMemoryStore(nil))
	command := testCommand(t)
	if _, err := application.ReserveSpace(context.Background(), command); err == nil {
		t.Fatal("forced allocation interruption succeeded")
	}
	if repository.snapshot.ReleaseState != "allocating" {
		t.Fatalf("allocation intent not durable: %+v", repository.snapshot)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := application.ReleaseReservation(cancelled, command, artifactacquisition.ReleaseReasonCancelled)
	if err != nil || !result.Released || result.Reason != artifactacquisition.ReleaseReasonCancelled || reservation.releaseCalls != 1 {
		t.Fatalf("ReleaseReservation()=(%+v,%v) calls=%d", result, err, reservation.releaseCalls)
	}
	if !errors.Is(cancelled.Err(), context.Canceled) || repository.snapshot.ReleaseState != "released" {
		t.Fatalf("cancel/release state=%v/%+v", cancelled.Err(), repository.snapshot)
	}
}

func TestPF001OptionalSettlementNoOpsBeforeReservationAndCleansAllocatingCrash(t *testing.T) {
	t.Parallel()
	command := testCommand(t)
	validationApplication := newApplication(t, newMemoryRepository(), &fakeReservation{}, &fakeFetcher{}, newMemoryStore(nil))
	var absentContext context.Context
	for _, test := range []struct {
		ctx     context.Context
		command Command
		reason  artifactacquisition.ReleaseReason
	}{
		{ctx: absentContext, command: command, reason: artifactacquisition.ReleaseReasonCancelled},
		{ctx: context.Background(), command: command, reason: artifactacquisition.ReleaseReason("unknown")},
		{ctx: context.Background(), command: Command{}, reason: artifactacquisition.ReleaseReasonRollback},
	} {
		if _, err := validationApplication.ReleaseReservationIfPresent(test.ctx, test.command, test.reason); err == nil {
			t.Fatalf("invalid optional settlement accepted: %+v", test)
		}
	}
	loadFailure := newMemoryRepository()
	loadFailure.loadErr = errors.New("private repository detail")
	validationApplication = newApplication(t, loadFailure, &fakeReservation{}, &fakeFetcher{}, newMemoryStore(nil))
	if _, err := validationApplication.ReleaseReservationIfPresent(
		context.Background(), command, artifactacquisition.ReleaseReasonRollback,
	); err == nil {
		t.Fatal("optional settlement repository failure succeeded")
	}
	corrupt := newMemoryRepository()
	corrupt.exists = true
	corrupt.snapshot.OperationID = "other-operation"
	validationApplication = newApplication(t, corrupt, &fakeReservation{}, &fakeFetcher{}, newMemoryStore(nil))
	if _, err := validationApplication.ReleaseReservationIfPresent(
		context.Background(), command, artifactacquisition.ReleaseReasonRollback,
	); err == nil {
		t.Fatal("optional settlement corrupt aggregate succeeded")
	}
	for _, setup := range []string{"absent", "pristine"} {
		repository := newMemoryRepository()
		if setup == "pristine" {
			aggregate, _ := artifactacquisition.NewAggregate(command.OperationID, command.Plan)
			_ = repository.Save(context.Background(), 0, aggregate.Snapshot())
		}
		reservation := &fakeReservation{}
		application := newApplication(t, repository, reservation, &fakeFetcher{}, newMemoryStore(nil))
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		result, err := application.ReleaseReservationIfPresent(
			cancelled, command, artifactacquisition.ReleaseReasonCancelled,
		)
		if err != nil || result.Released || result.Reason != artifactacquisition.ReleaseReasonCancelled || reservation.releaseCalls != 0 {
			t.Fatalf("%s optional settlement=(%+v,%v) release calls=%d", setup, result, err, reservation.releaseCalls)
		}
	}

	repository := newMemoryRepository()
	reservation := &fakeReservation{forcedError: ErrReservationOperation}
	application := newApplication(t, repository, reservation, &fakeFetcher{}, newMemoryStore(nil))
	_, _ = application.ReserveSpace(context.Background(), command)
	result, err := application.ReleaseReservationIfPresent(
		context.Background(), command, artifactacquisition.ReleaseReasonRollback,
	)
	if err != nil || !result.Released || reservation.releaseCalls != 1 || repository.snapshot.ReleaseState != "released" {
		t.Fatalf("allocating optional settlement=(%+v,%v) calls=%d snapshot=%+v", result, err, reservation.releaseCalls, repository.snapshot)
	}

	completedRepository := newMemoryRepository()
	completedReservation := &fakeReservation{}
	application = newApplication(t, completedRepository, completedReservation, &fakeFetcher{}, newMemoryStore(nil))
	_, _ = application.ReserveSpace(context.Background(), command)
	completed, err := application.Acquire(context.Background(), command)
	if err != nil || !completed.ReservationRetained || completedReservation.releaseCalls != 0 {
		t.Fatal(err)
	}
	settled, err := application.ReleaseReservationIfPresent(
		context.Background(), command, artifactacquisition.ReleaseReasonCompleted,
	)
	if err != nil || !settled.Released || settled.Reason != artifactacquisition.ReleaseReasonCompleted || completedReservation.releaseCalls != 1 {
		t.Fatalf("completed optional settlement=(%+v,%v) calls=%d", settled, err, completedReservation.releaseCalls)
	}
}

func TestPF001AcquireRetainsHeadroomUntilParentSettlement(t *testing.T) {
	t.Parallel()
	command := testCommand(t)
	repository := newMemoryRepository()
	reservation := &fakeReservation{releaseError: ErrReservationOperation}
	application := newApplication(t, repository, reservation, &fakeFetcher{}, newMemoryStore(nil))
	_, _ = application.ReserveSpace(context.Background(), command)
	result, err := application.Acquire(context.Background(), command)
	if err != nil || !result.ReservationRetained || repository.snapshot.ReleaseState != "active" ||
		reservation.releaseCalls != 0 {
		t.Fatalf("completed result=%+v error=%v snapshot=%+v calls=%d", result, err, repository.snapshot, reservation.releaseCalls)
	}
}

func TestPF001AcquireRejectsAllocationIntentBeforeAnyStoreOrNetworkMutation(t *testing.T) {
	t.Parallel()
	repository := newMemoryRepository()
	reservation := &fakeReservation{forcedError: ErrReservationOperation}
	fetcher := &fakeFetcher{}
	store := newMemoryStore(nil)
	application := newApplication(t, repository, reservation, fetcher, store)
	command := testCommand(t)
	_, _ = application.ReserveSpace(context.Background(), command)
	_, err := application.Acquire(context.Background(), command)
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != ErrorIntegrity || fetcher.calls != 0 || reservation.consumeCalls != 0 ||
		len(store.partials) != 0 {
		t.Fatalf("Acquire() error=%v fetches=%d consumes=%d partials=%d", err, fetcher.calls, reservation.consumeCalls, len(store.partials))
	}
}

func TestPF001ExplicitReleaseValidatesReplayConflictAndPersistenceBoundaries(t *testing.T) {
	t.Parallel()
	command := testCommand(t)
	application := newApplication(t, newMemoryRepository(), &fakeReservation{}, &fakeFetcher{}, newMemoryStore(nil))
	var absent context.Context
	for _, test := range []struct {
		ctx     context.Context
		command Command
		reason  artifactacquisition.ReleaseReason
	}{
		{ctx: absent, command: command, reason: artifactacquisition.ReleaseReasonCancelled},
		{ctx: context.Background(), command: command, reason: artifactacquisition.ReleaseReasonCompleted},
		{ctx: context.Background(), command: Command{}, reason: artifactacquisition.ReleaseReasonRollback},
	} {
		if _, err := application.ReleaseReservation(test.ctx, test.command, test.reason); err == nil {
			t.Fatalf("invalid release accepted: %+v", test)
		}
	}

	loadFailure := newMemoryRepository()
	loadFailure.loadErr = errors.New("private path")
	application = newApplication(t, loadFailure, &fakeReservation{}, &fakeFetcher{}, newMemoryStore(nil))
	if _, err := application.ReleaseReservation(context.Background(), command, artifactacquisition.ReleaseReasonRollback); err == nil {
		t.Fatal("release load failure succeeded")
	}
	pristine := newMemoryRepository()
	aggregate, _ := artifactacquisition.NewAggregate(command.OperationID, command.Plan)
	_ = pristine.Save(context.Background(), 0, aggregate.Snapshot())
	application = newApplication(t, pristine, &fakeReservation{}, &fakeFetcher{}, newMemoryStore(nil))
	if _, err := application.ReleaseReservation(context.Background(), command, artifactacquisition.ReleaseReasonRollback); err == nil {
		t.Fatal("unrequested release succeeded")
	}

	repository := newMemoryRepository()
	reservation := &fakeReservation{}
	application = newApplication(t, repository, reservation, &fakeFetcher{}, newMemoryStore(nil))
	_, _ = application.ReserveSpace(context.Background(), command)
	first, err := application.ReleaseReservation(context.Background(), command, artifactacquisition.ReleaseReasonCancelled)
	if err != nil || !first.Released {
		t.Fatal(err)
	}
	replayed, err := application.ReleaseReservation(context.Background(), command, artifactacquisition.ReleaseReasonCancelled)
	if err != nil || replayed.AggregateEvidence != first.AggregateEvidence || reservation.releaseCalls != 1 {
		t.Fatalf("release replay=%+v err=%v calls=%d", replayed, err, reservation.releaseCalls)
	}
	if _, err := application.ReleaseReservation(context.Background(), command, artifactacquisition.ReleaseReasonRollback); err == nil {
		t.Fatal("released reason substitution succeeded")
	}

	pendingRepository := newMemoryRepository()
	pendingReservation := &fakeReservation{releaseError: ErrReservationOperation}
	application = newApplication(t, pendingRepository, pendingReservation, &fakeFetcher{}, newMemoryStore(nil))
	_, _ = application.ReserveSpace(context.Background(), command)
	_, _ = application.ReleaseReservation(context.Background(), command, artifactacquisition.ReleaseReasonCancelled)
	if _, err := application.ReleaseReservation(context.Background(), command, artifactacquisition.ReleaseReasonRollback); err == nil {
		t.Fatal("pending reason substitution succeeded")
	}
	pendingReservation.releaseError = nil
	if result, err := application.ReleaseReservation(context.Background(), command, artifactacquisition.ReleaseReasonCancelled); err != nil || !result.Released {
		t.Fatalf("pending replay result=%+v err=%v", result, err)
	}

	for _, failAt := range []int{4, 5} {
		repository := newMemoryRepository()
		application := newApplication(t, repository, &fakeReservation{}, &fakeFetcher{}, newMemoryStore(nil))
		_, _ = application.ReserveSpace(context.Background(), command)
		repository.failSaveAt = failAt
		if _, err := application.ReleaseReservation(context.Background(), command, artifactacquisition.ReleaseReasonRollback); err == nil {
			t.Fatalf("release persistence failure %d succeeded", failAt)
		}
	}
}

func TestPF001InvalidPartialResetRetainsConsumedCapacityAndRetrySucceeds(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"write-integrity", "post-verify"} {
		t.Run(mode, func(t *testing.T) {
			repository := newMemoryRepository()
			reservation := &fakeReservation{}
			store := newMemoryStore(nil)
			if mode == "write-integrity" {
				store.writeIntegrity = true
			} else {
				store.verifyWrong = true
			}
			application := newApplication(t, repository, reservation, &fakeFetcher{}, store)
			command := testCommand(t)
			_, _ = application.ReserveSpace(context.Background(), command)
			if _, err := application.Acquire(context.Background(), command); err == nil || store.removed != 1 {
				t.Fatalf("first corrupt acquisition error=%v resets=%d", err, store.removed)
			}
			snapshot, _ := repository.Load(context.Background(), command.OperationID)
			if len(snapshot.Progress) != 1 || !snapshot.Progress[0].ReservationConsumed || len(snapshot.Progress[0].VerifiedChunks) != 0 {
				t.Fatalf("reset snapshot=%+v", snapshot)
			}
			store.writeIntegrity, store.verifyWrong = false, false
			result, err := application.Acquire(context.Background(), command)
			if err != nil || !result.ReservationRetained || result.CompletedArtifacts != 1 || reservation.consumeCalls != 1 {
				t.Fatalf("retry result=%+v error=%v consumes=%d", result, err, reservation.consumeCalls)
			}
		})
	}
}
