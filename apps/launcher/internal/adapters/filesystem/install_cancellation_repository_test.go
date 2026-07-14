package filesystem

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001CancellationIntentUsesOperationAggregateAuthority(t *testing.T) {
	t.Parallel()

	journal := &repositoryJournalStub{}
	repository := mustOperationRepository(t, journal)
	operation, plan := repositoryTestOperation(t, "aggregate-cancellation")
	if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}
	intent, err := repository.Request(context.Background(), installapp.CancellationRequest{
		OperationID: operation.ID(), PlanDigest: plan,
		ObservedAggregateVersion: operation.AggregateVersion(),
	})
	if err != nil || intent.Status != installapp.CancellationIntentRequested {
		t.Fatalf("Request()=(%+v,%v)", intent, err)
	}
	loaded := mustRepositoryLoad(t, repository, operation.ID())
	if loaded.AggregateVersion() != intent.Revision {
		t.Fatalf("request revision=%d aggregate=%d", intent.Revision, loaded.AggregateVersion())
	}
	if err := loaded.Cancel(plan); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if saveErr := repository.Save(context.Background(), loaded.Snapshot()); saveErr != nil {
		t.Fatalf("persist cancellation: %v", saveErr)
	}
	acknowledged, err := repository.Acknowledge(context.Background(), intent, install.StateCancelled)
	if err != nil || acknowledged.Status != installapp.CancellationIntentAcknowledged {
		t.Fatalf("Acknowledge()=(%+v,%v)", acknowledged, err)
	}
	replayed, err := repository.Acknowledge(context.Background(), intent, install.StateCancelled)
	if err != nil || replayed.Revision != acknowledged.Revision {
		t.Fatalf("Acknowledge() replay=(%+v,%v)", replayed, err)
	}
	foreign, _ := install.BindPlan([]byte("foreign"))
	if _, err := repository.Observe(context.Background(), operation.ID(), foreign); !errors.Is(err, installapp.ErrCancellationIntentIntegrity) {
		t.Fatalf("foreign Observe() error=%v", err)
	}
}

func TestPF001CancellationRequestAndReadyCASAreMutuallyExclusive(t *testing.T) {
	t.Parallel()

	for iteration := range 40 {
		journal := &repositoryJournalStub{}
		repository := mustOperationRepository(t, journal)
		operation, plan := repositoryTestOperation(t, fmt.Sprintf("ready-cancel-race-%d", iteration))
		if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
			t.Fatal(err)
		}
		phases := install.OrderedPhases()
		for index, phase := range phases[:len(phases)-1] {
			if err := operation.CompleteStep(repositoryEvidence(t, phase, operation.Attempt(), plan, false, index)); err != nil {
				t.Fatal(err)
			}
			if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
				t.Fatal(err)
			}
		}
		readyCandidate := mustRepositoryLoad(t, repository, operation.ID())
		finalPhase := phases[len(phases)-1]
		if err := readyCandidate.CompleteStep(repositoryEvidence(t, finalPhase, 1, plan, true, len(phases)-1)); err != nil {
			t.Fatal(err)
		}
		observedVersion := readyCandidate.AggregateVersion() - 1
		start := make(chan struct{})
		var readyError, requestError error
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			readyError = repository.Save(context.Background(), readyCandidate.Snapshot())
		}()
		go func() {
			defer wait.Done()
			<-start
			_, requestError = repository.Request(context.Background(), installapp.CancellationRequest{
				OperationID: operation.ID(), PlanDigest: plan, ObservedAggregateVersion: observedVersion,
			})
		}()
		close(start)
		wait.Wait()
		if (readyError == nil) == (requestError == nil) {
			t.Fatalf("iteration %d Ready/Request errors=%v/%v, want exactly one winner", iteration, readyError, requestError)
		}
		durable := mustRepositoryLoad(t, repository, operation.ID())
		_, hasIntent := durable.CancellationIntent()
		if durable.State() == install.StateReady && hasIntent {
			t.Fatalf("iteration %d persisted forbidden Ready+pending intent", iteration)
		}
		if readyError == nil && durable.State() != install.StateReady {
			t.Fatalf("iteration %d Ready won but durable state=%s", iteration, durable.State())
		}
		if requestError == nil && (durable.State() == install.StateReady || !hasIntent) {
			t.Fatalf("iteration %d Request won but durable state/intent=%s/%v", iteration, durable.State(), hasIntent)
		}
	}
}

func TestPF001CancellationWaitHonorsContextWithoutBackgroundWorker(t *testing.T) {
	t.Parallel()

	repository := mustOperationRepository(t, &repositoryJournalStub{})
	operation, plan := repositoryTestOperation(t, "wait-cancel")
	if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := repository.Wait(ctx, operation.ID(), plan)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 250*time.Millisecond {
		t.Fatalf("Wait() error/elapsed=%v/%s", err, time.Since(started))
	}
}

func TestPF001CancellationRepositoryFailsClosedAtEveryPublicBoundary(t *testing.T) {
	t.Parallel()
	repository := mustOperationRepository(t, &repositoryJournalStub{})
	operation, plan := repositoryTestOperation(t, "cancellation-boundaries")
	foreign, _ := install.BindPlan([]byte("foreign cancellation plan"))
	validRequest := installapp.CancellationRequest{
		OperationID: operation.ID(), PlanDigest: plan, ObservedAggregateVersion: operation.AggregateVersion(),
	}
	//lint:ignore SA1012 Deliberate absent-context boundary tests.
	if _, err := repository.Request(nil, validRequest); !errors.Is(err, installapp.ErrCancellationIntentIntegrity) { //nolint:staticcheck
		t.Fatalf("nil Request context error=%v", err)
	}
	if _, err := repository.Request(t.Context(), installapp.CancellationRequest{}); !errors.Is(err, installapp.ErrCancellationIntentIntegrity) {
		t.Fatalf("empty Request error=%v", err)
	}
	if _, err := repository.Request(t.Context(), validRequest); !errors.Is(err, installapp.ErrCancellationIntentNotFound) {
		t.Fatalf("missing Request error=%v", err)
	}
	if err := repository.Save(t.Context(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Observe(t.Context(), operation.ID(), plan); !errors.Is(err, installapp.ErrCancellationIntentNotFound) {
		t.Fatalf("pristine Observe error=%v", err)
	}
	stale := validRequest
	stale.ObservedAggregateVersion += 10
	if _, err := repository.Request(t.Context(), stale); !errors.Is(err, installapp.ErrCancellationIntentIntegrity) {
		t.Fatalf("future Request error=%v", err)
	}
	wrongPlan := validRequest
	wrongPlan.PlanDigest = foreign
	if _, err := repository.Request(t.Context(), wrongPlan); !errors.Is(err, installapp.ErrCancellationIntentIntegrity) {
		t.Fatalf("foreign Request error=%v", err)
	}
	intent, err := repository.Request(t.Context(), validRequest)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := repository.Request(t.Context(), validRequest)
	if err != nil || replayed != intent {
		t.Fatalf("Request replay=(%+v,%v)", replayed, err)
	}
	if _, err := repository.Acknowledge(t.Context(), intent, install.StateRunning); !errors.Is(err, installapp.ErrCancellationIntentIntegrity) {
		t.Fatalf("premature Acknowledge error=%v", err)
	}
	if _, err := repository.Acknowledge(t.Context(), intent, install.StateCancelled); !errors.Is(err, installapp.ErrCancellationIntentIntegrity) {
		t.Fatalf("uncancelled Acknowledge error=%v", err)
	}
	invalidIntent := intent
	invalidIntent.Revision = 0
	if _, err := repository.Acknowledge(t.Context(), invalidIntent, install.StateCancelled); !errors.Is(err, installapp.ErrCancellationIntentIntegrity) {
		t.Fatalf("invalid Acknowledge error=%v", err)
	}
	//lint:ignore SA1012 Deliberate absent-context boundary tests.
	if _, err := repository.Observe(nil, operation.ID(), plan); !errors.Is(err, installapp.ErrCancellationIntentIntegrity) { //nolint:staticcheck
		t.Fatalf("nil Observe context error=%v", err)
	}
	//lint:ignore SA1012 Deliberate absent-context boundary tests.
	if _, err := repository.Wait(nil, operation.ID(), plan); !errors.Is(err, installapp.ErrCancellationIntentIntegrity) { //nolint:staticcheck
		t.Fatalf("nil Wait context error=%v", err)
	}
	if _, err := cancellationIntentFromOperation(nil); !errors.Is(err, installapp.ErrCancellationIntentIntegrity) {
		t.Fatalf("nil aggregate intent error=%v", err)
	}
}

func TestPF001CancellationRepositoryMapsOnlyClosedAuthorityErrors(t *testing.T) {
	t.Parallel()
	private := errors.New("private")
	for _, test := range []struct {
		input error
		want  error
	}{
		{installapp.ErrCancellationIntentNotFound, installapp.ErrCancellationIntentNotFound},
		{installapp.ErrCancellationIntentIntegrity, installapp.ErrCancellationIntentIntegrity},
		{installapp.ErrCancellationIntentConflict, installapp.ErrCancellationIntentConflict},
		{installapp.ErrOperationNotFound, installapp.ErrCancellationIntentNotFound},
		{installapp.ErrOperationIntegrity, installapp.ErrCancellationIntentIntegrity},
		{installapp.ErrOperationConflict, installapp.ErrCancellationIntentConflict},
		{private, private},
	} {
		if observed := mapCancellationRepositoryError(test.input); !errors.Is(observed, test.want) {
			t.Fatalf("map(%v)=%v want=%v", test.input, observed, test.want)
		}
	}
}
