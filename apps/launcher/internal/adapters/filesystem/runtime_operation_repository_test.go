package filesystem

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeinstallapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF001RuntimeOperationRepositoryImplementsApplicationPort(t *testing.T) {
	t.Parallel()
	var repository runtimeinstallapp.OperationRepository = &RuntimeOperationRepository{}
	_ = repository
}

func TestPF001RuntimeOperationRepositoryRoundTripsCompleteSaga(t *testing.T) {
	t.Parallel()
	journal := &repositoryJournalStub{}
	repository := mustRuntimeOperationRepository(t, journal)
	operation, plan := runtimeRepositoryOperation(t, "runtime-roundtrip")

	if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}
	for index, phase := range runtimeinstall.OrderedPhases() {
		evidence := runtimeRepositoryEvidence(t, phase, operation.Attempt(), plan, index)
		if err := operation.Complete(phase, evidence); err != nil {
			t.Fatalf("complete %s: %v", phase, err)
		}
		if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
			t.Fatalf("save %s: %v", phase, err)
		}
		operation = mustRuntimeRepositoryLoad(t, repository, operation.ID())
	}

	if operation.State() != runtimeinstall.OperationStateReady ||
		journal.latest.Revision != uint64(len(runtimeinstall.OrderedPhases())+1) {
		t.Fatalf("state/revision = %s/%d", operation.State(), journal.latest.Revision)
	}
	if !journal.latest.CapturedAt.Equal(repositoryFixedTime.UTC()) {
		t.Fatalf("captured at = %s", journal.latest.CapturedAt)
	}
	for _, forbidden := range []string{"private_key", "secret", repositoryTestKey} {
		if strings.Contains(string(journal.latest.Payload), forbidden) {
			t.Fatalf("payload contains forbidden value %q", forbidden)
		}
	}
}

func TestPF001RuntimeOperationRepositoryRestoresRebootAndPauseStates(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(*runtimeinstall.Operation) error
		state  runtimeinstall.OperationState
	}{
		{name: "reboot", mutate: func(*runtimeinstall.Operation) error { return nil }, state: runtimeinstall.OperationStateRebootPending},
		{name: "administrator", mutate: func(operation *runtimeinstall.Operation) error {
			return operation.Pause(runtimeinstall.OperationStatePausedForAdministrator)
		}, state: runtimeinstall.OperationStatePausedForAdministrator},
		{name: "recoverable", mutate: func(operation *runtimeinstall.Operation) error {
			return operation.Pause(runtimeinstall.OperationStateFailedRecoverable)
		}, state: runtimeinstall.OperationStateFailedRecoverable},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			repository := mustRuntimeOperationRepository(t, &repositoryJournalStub{})
			operation, _ := runtimeRepositoryOperation(t, "runtime-state-"+test.name)
			if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
				t.Fatal(err)
			}
			if test.name == "reboot" {
				for _, phase := range runtimeinstall.OrderedPhases()[:6] {
					if err := operation.Complete(phase, runtimeRepositoryEvidence(t, phase, operation.Attempt(), operation.PlanDigest(), int(phase))); err != nil {
						t.Fatal(err)
					}
					if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
						t.Fatal(err)
					}
				}
				if err := operation.RequireReboot(runtimeinstall.Sum([]byte("reboot-receipt"))); err != nil {
					t.Fatal(err)
				}
			} else if err := test.mutate(operation); err != nil {
				t.Fatal(err)
			}
			if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
				t.Fatal(err)
			}
			loaded := mustRuntimeRepositoryLoad(t, repository, operation.ID())
			if loaded.State() != test.state || loaded.Version() != operation.Version() ||
				loaded.CurrentPhase() != operation.CurrentPhase() || loaded.Attempt() != operation.Attempt() {
				t.Fatalf("restored operation differs: %+v", loaded.Snapshot())
			}
		})
	}
}

func TestPF001RuntimeOperationRepositoryEnforcesAggregateCASAndIdempotency(t *testing.T) {
	t.Parallel()
	journal := &repositoryJournalStub{}
	repository := mustRuntimeOperationRepository(t, journal)
	operation, _ := runtimeRepositoryOperation(t, "runtime-cas")
	initial := operation.Snapshot()
	if err := repository.Save(context.Background(), initial); err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(context.Background(), initial); err != nil {
		t.Fatalf("idempotent save: %v", err)
	}
	if journal.latest.Revision != 1 || len(journal.appends) != 1 || journal.confirms != 1 {
		t.Fatalf("revision/appends/confirms = %d/%d/%d", journal.latest.Revision, len(journal.appends), journal.confirms)
	}

	first := mustRuntimeRepositoryLoad(t, repository, operation.ID())
	second := mustRuntimeRepositoryLoad(t, repository, operation.ID())
	if err := first.Pause(runtimeinstall.OperationStateFailedRecoverable); err != nil {
		t.Fatal(err)
	}
	if err := second.Pause(runtimeinstall.OperationStateCancelled); err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(context.Background(), first.Snapshot()); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []runtimeinstall.OperationSnapshot{initial, second.Snapshot()} {
		err := repository.Save(context.Background(), candidate)
		if !errors.Is(err, runtimeinstallapp.ErrOperationConflict) || !errors.Is(err, journalport.ErrConflict) {
			t.Fatalf("conflict = %T %v", err, err)
		}
	}
	if journal.latest.Revision != 2 || len(journal.appends) != 2 {
		t.Fatalf("conflicts mutated journal: %d/%d", journal.latest.Revision, len(journal.appends))
	}
}

func TestPF001RuntimeOperationRepositoryRejectsUntrustedJournalState(t *testing.T) {
	t.Parallel()
	operation, _ := runtimeRepositoryOperation(t, "runtime-untrusted")
	valid, operationID, err := encodeRuntimeOperationSnapshot(operation.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var document runtimeOperationSnapshotDTO
	if err := json.Unmarshal(valid, &document); err != nil {
		t.Fatal(err)
	}
	wrongPlan := document
	wrongPlan.PlanDigest = runtimeinstall.Sum([]byte("substituted-plan")).String()
	wrongPayload, _ := json.Marshal(wrongPlan)

	for _, test := range []struct {
		name     string
		snapshot journalport.Snapshot
	}{
		{name: "envelope identity", snapshot: journalport.Snapshot{OperationID: "other", Revision: 1, Payload: valid}},
		{name: "payload identity", snapshot: journalport.Snapshot{OperationID: operationID, Revision: 1, Payload: []byte(strings.Replace(string(valid), operationID, "runtime-other", 1))}},
		{name: "unknown field", snapshot: repositoryRuntimeJournalSnapshot(operationID, append(valid[:len(valid)-1], []byte(`,"extra":true}`)...))},
		{name: "duplicate key", snapshot: repositoryRuntimeJournalSnapshot(operationID, []byte(strings.Replace(string(valid), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)))},
		{name: "trailing data", snapshot: repositoryRuntimeJournalSnapshot(operationID, append(valid, []byte(`{}`)...))},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			journal := &repositoryJournalStub{latest: test.snapshot}
			journal.exists = true
			repository := mustRuntimeOperationRepository(t, journal)
			_, err := repository.Load(context.Background(), operationID)
			if !errors.Is(err, runtimeinstallapp.ErrOperationIntegrity) {
				t.Fatalf("Load() error = %T %v", err, err)
			}
		})
	}
	journal := &repositoryJournalStub{exists: true, latest: repositoryRuntimeJournalSnapshot(operationID, wrongPayload)}
	repository := mustRuntimeOperationRepository(t, journal)
	if err := repository.Save(context.Background(), operation.Snapshot()); !errors.Is(err, runtimeinstallapp.ErrOperationIntegrity) {
		t.Fatalf("plan-substitution Save() error = %T %v", err, err)
	}
}

func TestPF001RuntimeOperationRepositoryMapsJournalErrorsAndRejectsPartialComposition(t *testing.T) {
	t.Parallel()
	operation, _ := runtimeRepositoryOperation(t, "runtime-errors")
	for _, test := range []struct {
		name string
		err  error
		want error
	}{
		{name: "missing", err: journalport.ErrNotFound, want: runtimeinstallapp.ErrOperationNotFound},
		{name: "corrupt", err: journalport.ErrCorrupt, want: runtimeinstallapp.ErrOperationIntegrity},
		{name: "permissions", err: journalport.ErrUnsafePermission, want: runtimeinstallapp.ErrOperationIntegrity},
		{name: "conflict", err: journalport.ErrConflict, want: runtimeinstallapp.ErrOperationConflict},
		{name: "io", err: journalport.ErrIO, want: journalport.ErrIO},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			repository := mustRuntimeOperationRepository(t, &repositoryJournalStub{loadError: test.err})
			_, err := repository.Load(context.Background(), operation.ID())
			if !errors.Is(err, test.want) {
				t.Fatalf("Load() error = %T %v, want %v", err, err, test.want)
			}
		})
	}

	typedNilProvider := (*repositoryJournalProviderStub)(nil)
	typedNilClock := (*repositoryClockStub)(nil)
	typedNilFence := (*repositoryFenceStub)(nil)
	for index, dependencies := range []struct {
		provider OperationJournalProvider
		clock    OperationRepositoryClock
		fence    OperationStateFence
	}{
		{provider: nil, clock: repositoryClockStub{now: repositoryFixedTime}, fence: &repositoryFenceStub{}},
		{provider: typedNilProvider, clock: repositoryClockStub{now: repositoryFixedTime}, fence: &repositoryFenceStub{}},
		{provider: &repositoryJournalProviderStub{}, clock: nil, fence: &repositoryFenceStub{}},
		{provider: &repositoryJournalProviderStub{}, clock: typedNilClock, fence: &repositoryFenceStub{}},
		{provider: &repositoryJournalProviderStub{}, clock: repositoryClockStub{now: repositoryFixedTime}, fence: nil},
		{provider: &repositoryJournalProviderStub{}, clock: repositoryClockStub{now: repositoryFixedTime}, fence: typedNilFence},
	} {
		if repository, err := NewRuntimeOperationRepository(dependencies.provider, dependencies.clock, dependencies.fence); err == nil || repository != nil {
			t.Fatalf("case %d accepted partial dependencies", index)
		}
	}
}

func mustRuntimeOperationRepository(t testing.TB, journal journalport.Journal) *RuntimeOperationRepository {
	t.Helper()
	repository, err := NewRuntimeOperationRepository(
		&repositoryJournalProviderStub{journal: journal},
		repositoryClockStub{now: repositoryFixedTime},
		&repositoryFenceStub{},
	)
	if err != nil {
		t.Fatal(err)
	}
	return repository
}

func runtimeRepositoryOperation(t testing.TB, id string) (*runtimeinstall.Operation, runtimeinstall.Hash) {
	t.Helper()
	plan := runtimeinstall.Sum([]byte("runtime-plan:" + id))
	operation, err := runtimeinstall.NewOperation(id, plan)
	if err != nil {
		t.Fatal(err)
	}
	return operation, plan
}

func runtimeRepositoryEvidence(
	t testing.TB,
	phase runtimeinstall.Phase,
	attempt uint32,
	plan runtimeinstall.Hash,
	index int,
) runtimeinstall.TransitionEvidence {
	t.Helper()
	artifact := runtimeinstall.Hash{}
	if phase >= runtimeinstall.PhaseVerifyRuntimeArtifact {
		artifact = runtimeinstall.Sum([]byte(fmt.Sprintf("artifact:%d", index)))
	}
	ownership := runtimeinstall.OwnershipUnknown
	if phase == runtimeinstall.PhaseVerifyRuntimeCapabilities {
		ownership = runtimeinstall.OwnershipProvisionedByAgentMemory
	}
	evidence, err := runtimeinstall.NewTransitionEvidence(
		phase,
		attempt,
		plan,
		runtimeinstall.Sum([]byte(fmt.Sprintf("input:%d", index))),
		runtimeinstall.Sum([]byte(fmt.Sprintf("output:%d", index))),
		artifact,
		ownership,
	)
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func mustRuntimeRepositoryLoad(t testing.TB, repository *RuntimeOperationRepository, operationID string) *runtimeinstall.Operation {
	t.Helper()
	operation, err := repository.Load(context.Background(), operationID)
	if err != nil {
		var integrity *runtimeOperationIntegrityError
		if errors.As(err, &integrity) {
			t.Fatalf("%v: %v", err, integrity.cause)
		}
		t.Fatal(err)
	}
	return operation
}

func repositoryRuntimeJournalSnapshot(operationID string, payload []byte) journalport.Snapshot {
	return journalport.Snapshot{OperationID: operationID, Revision: 1, CapturedAt: repositoryFixedTime, Payload: payload}
}
