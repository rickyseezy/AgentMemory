package filesystem

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001InstallOperationRepositoryImplementsApplicationPort(t *testing.T) {
	t.Parallel()
	var repository installapp.OperationRepository = &InstallOperationRepository{}
	_ = repository
}

func TestPF001InstallOperationRepositoryRoundTripsEveryPhaseAndReady(t *testing.T) {
	t.Parallel()
	journal := &repositoryJournalStub{}
	repository := mustOperationRepository(t, journal)
	operation, plan := repositoryTestOperation(t, "roundtrip-phases")

	if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatalf("save initial operation: %v", err)
	}
	assertRepositoryOperationEqual(t, mustRepositoryLoad(t, repository, operation.ID()), operation)

	for index, phase := range install.OrderedPhases() {
		evidence := repositoryEvidence(t, phase, operation.Attempt(), plan, index%2 == 0, index)
		if err := operation.CompleteStep(evidence); err != nil {
			t.Fatalf("complete %s: %v", phase, err)
		}
		if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
			t.Fatalf("save after %s: %v", phase, err)
		}
		operation = mustRepositoryLoad(t, repository, operation.ID())
		if got := len(operation.CompletedEvidence()); got != index+1 {
			t.Fatalf("after %s evidence count = %d, want %d", phase, got, index+1)
		}
	}

	if operation.State() != install.StateReady || journal.latest.Revision != uint64(len(install.OrderedPhases())+1) {
		t.Fatalf("state = %s, revision = %d", operation.State(), journal.latest.Revision)
	}
	if !journal.latest.CapturedAt.Equal(repositoryFixedTime.UTC()) {
		t.Fatalf("capture time = %s", journal.latest.CapturedAt)
	}
	payload := string(journal.latest.Payload)
	for _, forbidden := range []string{"hmac", "secret", "private_key", repositoryTestKey} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("payload contains forbidden material %q", forbidden)
		}
	}
}

func TestPF001InstallOperationRepositoryIsolatesTerminalAndFreshOperations(t *testing.T) {
	t.Parallel()
	journals := make(map[string]*repositoryJournalStub)
	provider := &repositoryJournalProviderStub{
		selectJournal: func(operationID install.OperationID) (journalport.Journal, error) {
			key := operationID.String()
			journal, exists := journals[key]
			if !exists {
				journal = &repositoryJournalStub{}
				journals[key] = journal
			}
			return journal, nil
		},
	}
	repository := mustOperationRepositoryWithProvider(t, provider)
	terminal, terminalPlan := repositoryTestOperation(t, "terminal-operation-a")
	fresh, _ := repositoryTestOperation(t, "fresh-operation-b")

	if err := repository.Save(context.Background(), terminal.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if err := terminal.Cancel(terminalPlan); err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(context.Background(), terminal.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(context.Background(), fresh.Snapshot()); err != nil {
		t.Fatalf("save fresh operation after terminal operation: %v", err)
	}

	restoredTerminal := mustRepositoryLoad(t, repository, terminal.ID())
	restoredFresh := mustRepositoryLoad(t, repository, fresh.ID())
	if restoredTerminal.State() != install.StateCancelled || restoredFresh.State() != install.StateRunning {
		t.Fatalf("isolated states = terminal %s, fresh %s", restoredTerminal.State(), restoredFresh.State())
	}
	terminalJournal := journals[terminal.ID().String()]
	freshJournal := journals[fresh.ID().String()]
	if terminalJournal == freshJournal || terminalJournal.latest.Revision != 2 || freshJournal.latest.Revision != 1 {
		t.Fatalf(
			"journal isolation = same:%t terminal revision:%d fresh revision:%d",
			terminalJournal == freshJournal,
			terminalJournal.latest.Revision,
			freshJournal.latest.Revision,
		)
	}
}

func TestPF001InstallOperationRepositoryRejectsStaleAndDivergentAggregateVersions(t *testing.T) {
	t.Parallel()
	journal := &repositoryJournalStub{}
	repository := mustOperationRepository(t, journal)
	operation, plan := repositoryTestOperation(t, "aggregate-cas")
	initial := operation.Snapshot()

	if err := repository.Save(context.Background(), initial); err != nil {
		t.Fatal(err)
	}
	firstWriter := mustRepositoryLoad(t, repository, operation.ID())
	secondWriter := mustRepositoryLoad(t, repository, operation.ID())
	if err := firstWriter.FailRecoverable(plan); err != nil {
		t.Fatal(err)
	}
	if err := secondWriter.Cancel(plan); err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(context.Background(), firstWriter.Snapshot()); err != nil {
		t.Fatal(err)
	}

	staleError := repository.Save(context.Background(), initial)
	assertRepositoryConflict(t, staleError)
	if staleError.Error() != installapp.ErrOperationConflict.Error() {
		t.Fatalf("conflict exposed internal state: %q", staleError)
	}
	assertRepositoryConflict(t, repository.Save(context.Background(), secondWriter.Snapshot()))
	if journal.latest.Revision != 2 || len(journal.appends) != 2 {
		t.Fatalf("conflicting saves mutated journal: revision=%d appends=%d", journal.latest.Revision, len(journal.appends))
	}
	if restored := mustRepositoryLoad(t, repository, operation.ID()); restored.State() != install.StateFailedRecoverable {
		t.Fatalf("winning state = %s", restored.State())
	}
}

func TestPF001InstallOperationRepositoryMakesIdenticalAggregateSaveIdempotent(t *testing.T) {
	t.Parallel()
	journal := &repositoryJournalStub{}
	repository := mustOperationRepository(t, journal)
	operation, _ := repositoryTestOperation(t, "aggregate-idempotency")
	snapshot := operation.Snapshot()

	if err := repository.Save(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	var persisted operationSnapshotDTO
	if err := json.Unmarshal(journal.latest.Payload, &persisted); err != nil {
		t.Fatal(err)
	}
	indented, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	journal.latest.Payload = indented
	if err := repository.Save(context.Background(), snapshot); err != nil {
		t.Fatalf("save identical snapshot: %v", err)
	}
	loaded := mustRepositoryLoad(t, repository, operation.ID())
	if err := repository.Save(context.Background(), loaded.Snapshot()); err != nil {
		t.Fatalf("save semantically identical restored snapshot: %v", err)
	}
	if journal.latest.Revision != 1 || len(journal.appends) != 1 {
		t.Fatalf("idempotent saves appended: revision=%d appends=%d", journal.latest.Revision, len(journal.appends))
	}
	if journal.confirms != 3 {
		t.Fatalf("durability confirmations = %d, want 3", journal.confirms)
	}
}

func TestPF001InstallOperationRepositoryDoesNotAssumeEqualPayloadIsDurable(t *testing.T) {
	t.Parallel()
	journal := &repositoryJournalStub{}
	repository := mustOperationRepository(t, journal)
	operation, _ := repositoryTestOperation(t, "aggregate-confirmation")
	if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}

	journal.confirmError = journalport.NewError(journalport.ErrorIO, "confirm", errors.New("parent sync failed"))
	err := repository.Save(context.Background(), operation.Snapshot())
	assertRepositoryErrorIs(t, err, journalport.ErrIO)
	if len(journal.appends) != 1 || journal.confirms != 1 {
		t.Fatalf("appends/confirms = %d/%d, want 1/1", len(journal.appends), journal.confirms)
	}
}

func TestPF001InstallOperationRepositoryMapsVanishedDurableRevisionToIntegrity(t *testing.T) {
	t.Parallel()
	journal := &repositoryJournalStub{}
	repository := mustOperationRepository(t, journal)
	operation, _ := repositoryTestOperation(t, "vanished-durable-revision")
	if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}

	journal.confirmError = journalport.ErrNotFound
	err := repository.Save(context.Background(), operation.Snapshot())
	assertRepositoryErrorIs(t, err, journalport.ErrNotFound)
	assertRepositoryErrorIs(t, err, installapp.ErrOperationIntegrity)
}

func TestPF001InstallOperationRepositoryLoadConfirmsVisibleRevisionDurability(t *testing.T) {
	t.Parallel()
	journal := &repositoryJournalStub{}
	repository := mustOperationRepository(t, journal)
	operation, _ := repositoryTestOperation(t, "load-durability-confirmation")
	if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Load(context.Background(), operation.ID()); err != nil {
		t.Fatal(err)
	}
	if journal.confirms != 1 {
		t.Fatalf("load durability confirmations = %d, want 1", journal.confirms)
	}

	journal.confirmError = journalport.ErrNotFound
	_, err := repository.Load(context.Background(), operation.ID())
	assertRepositoryErrorIs(t, err, journalport.ErrNotFound)
	assertRepositoryErrorIs(t, err, installapp.ErrOperationIntegrity)
}

func TestPF001InstallOperationRepositoryRejectsSkippedAggregateVersion(t *testing.T) {
	t.Parallel()
	journal := &repositoryJournalStub{}
	repository := mustOperationRepository(t, journal)
	operation, plan := repositoryTestOperation(t, "aggregate-version-gap")
	if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}

	skipped, err := install.RestoreOperation(install.RestoreInput{
		OperationID:      operation.ID(),
		PlanDigest:       plan,
		AggregateVersion: operation.AggregateVersion() + 2,
		State:            operation.State(),
		CurrentPhase:     operation.CurrentPhase(),
		Attempt:          operation.Attempt(),
		Completed:        operation.CompletedEvidence(),
	})
	if err != nil {
		t.Fatal(err)
	}
	assertRepositoryConflict(t, repository.Save(context.Background(), skipped.Snapshot()))

	emptyRepository := mustOperationRepository(t, &repositoryJournalStub{})
	assertRepositoryConflict(t, emptyRepository.Save(context.Background(), skipped.Snapshot()))
}

func TestPF001InstallOperationRepositoryRoundTripsPausedAndTerminalStates(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		transition func(*install.Operation, install.PlanDigest) error
		want       install.State
	}{
		{name: "failed recoverable", transition: (*install.Operation).FailRecoverable, want: install.StateFailedRecoverable},
		{name: "administrator", transition: (*install.Operation).PauseForAdministrator, want: install.StatePausedForAdministrator},
		{name: "cancelled", transition: (*install.Operation).Cancel, want: install.StateCancelled},
		{name: "unsupported host", transition: (*install.Operation).MarkUnsupportedHost, want: install.StateUnsupportedHost},
		{name: "runtime conflict", transition: (*install.Operation).MarkRuntimeConflict, want: install.StateRuntimeConflict},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			journal := &repositoryJournalStub{}
			repository := mustOperationRepository(t, journal)
			operation, plan := repositoryTestOperation(t, "state-"+strings.ReplaceAll(test.name, " ", "-"))
			if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
				t.Fatal(err)
			}
			if err := test.transition(operation, plan); err != nil {
				t.Fatal(err)
			}
			if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
				t.Fatal(err)
			}
			restored := mustRepositoryLoad(t, repository, operation.ID())
			if restored.State() != test.want {
				t.Fatalf("state = %s, want %s", restored.State(), test.want)
			}
		})
	}
}

func TestPF001InstallOperationRepositoryRoundTripsRebootAndVerifiedResume(t *testing.T) {
	t.Parallel()
	journal := &repositoryJournalStub{}
	repository := mustOperationRepository(t, journal)
	operation, plan := repositoryTestOperation(t, "reboot-roundtrip")
	if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if err := operation.CompleteStep(repositoryEvidence(t, install.PhaseVerifyHost, 1, plan, false, 0)); err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}
	receipt := install.DigestBytes([]byte("one-use-receipt"))
	checkpoint := repositoryCheckpoint(t, plan, receipt)
	if err := operation.MarkRebootPending(plan, checkpoint); err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}

	restored := mustRepositoryLoad(t, repository, operation.ID())
	actualCheckpoint, exists := restored.Snapshot().RebootCheckpoint()
	if !exists || !actualCheckpoint.ReceiptDigest().Equal(receipt) || actualCheckpoint.Attempt() != 1 {
		t.Fatal("reboot checkpoint did not round-trip")
	}
	if err := restored.VerifyResume(plan, receipt); err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(context.Background(), restored.Snapshot()); err != nil {
		t.Fatal(err)
	}
	verified := mustRepositoryLoad(t, repository, operation.ID())
	if verified.State() != install.StateResumeVerified {
		t.Fatalf("state = %s", verified.State())
	}
}

func TestPF001InstallOperationRepositoryRejectsMalformedAndUnknownPayloads(t *testing.T) {
	t.Parallel()
	id := repositoryOperationID(t, "malformed-payload")
	tests := []struct {
		name    string
		payload string
	}{
		{name: "malformed", payload: "{"},
		{name: "unknown version", payload: `{"schema_version":99,"completed_steps":[]}`},
		{name: "unknown field", payload: `{"schema_version":1,"unexpected":true,"completed_steps":[]}`},
		{name: "trailing object", payload: `{"schema_version":1,"completed_steps":[]} {}`},
		{name: "duplicate key", payload: `{"schema_version":1,"schema_version":1,"completed_steps":[]}`},
		{name: "missing completed collection", payload: `{"schema_version":1}`},
		{name: "missing aggregate version", payload: fmt.Sprintf(`{"schema_version":%d,"completed_steps":[]}`, operationSnapshotSchemaVersion)},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			journal := &repositoryJournalStub{exists: true, latest: repositoryJournalSnapshot(id, []byte(test.payload), 1)}
			repository := mustOperationRepository(t, journal)
			_, err := repository.Load(context.Background(), id)
			assertRepositoryErrorIs(t, err, installapp.ErrOperationIntegrity)
			if strings.Contains(err.Error(), test.payload) {
				t.Fatal("untrusted payload escaped through the integrity error")
			}
		})
	}
}

func TestPF001InstallOperationRepositoryRejectsTamperedEvidenceFingerprint(t *testing.T) {
	t.Parallel()
	journal := &repositoryJournalStub{}
	repository := mustOperationRepository(t, journal)
	operation, plan := repositoryTestOperation(t, "tampered-fingerprint")
	if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if err := operation.CompleteStep(repositoryEvidence(t, install.PhaseVerifyHost, 1, plan, true, 0)); err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}

	var dto operationSnapshotDTO
	if err := json.Unmarshal(journal.latest.Payload, &dto); err != nil {
		t.Fatal(err)
	}
	dto.CompletedSteps[0].Fingerprint = install.DigestBytes([]byte("tampered")).String()
	journal.latest.Payload, _ = json.Marshal(dto)

	_, err := repository.Load(context.Background(), operation.ID())
	assertRepositoryErrorIs(t, err, installapp.ErrOperationIntegrity)
}

func TestPF001InstallOperationRepositoryRejectsInvalidDomainDTOFields(t *testing.T) {
	t.Parallel()
	operation, plan := repositoryTestOperation(t, "invalid-dto-fields")
	if err := operation.CompleteStep(repositoryEvidence(t, install.PhaseVerifyHost, 1, plan, true, 0)); err != nil {
		t.Fatal(err)
	}
	payload, _, err := encodeOperationSnapshot(operation.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var valid operationSnapshotDTO
	if err := json.Unmarshal(payload, &valid); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*operationSnapshotDTO)
	}{
		{name: "unknown state", mutate: func(dto *operationSnapshotDTO) { dto.State = "FutureState" }},
		{name: "unknown phase", mutate: func(dto *operationSnapshotDTO) { dto.CurrentPhase = "FuturePhase" }},
		{name: "bad plan digest", mutate: func(dto *operationSnapshotDTO) { dto.PlanDigest = "bad" }},
		{name: "missing facts", mutate: func(dto *operationSnapshotDTO) { dto.CompletedSteps[0].Facts = nil }},
		{name: "unknown ownership", mutate: func(dto *operationSnapshotDTO) { dto.CompletedSteps[0].RuntimeOwnership = "future" }},
		{name: "bad artifact digest", mutate: func(dto *operationSnapshotDTO) {
			bad := "bad"
			dto.CompletedSteps[0].VerifiedArtifactDigest = &bad
		}},
		{name: "bad evidence plan", mutate: func(dto *operationSnapshotDTO) { dto.CompletedSteps[0].PlanDigest = "bad" }},
		{name: "bad input digest", mutate: func(dto *operationSnapshotDTO) { dto.CompletedSteps[0].InputDigest = "bad" }},
		{name: "bad output digest", mutate: func(dto *operationSnapshotDTO) { dto.CompletedSteps[0].OutputDigest = "bad" }},
		{name: "bad compensation", mutate: func(dto *operationSnapshotDTO) { dto.CompletedSteps[0].CompensationBoundary = "rm -rf" }},
		{name: "bad next action", mutate: func(dto *operationSnapshotDTO) { dto.CompletedSteps[0].NextSafeAction = "run docker" }},
		{name: "bad fact", mutate: func(dto *operationSnapshotDTO) { dto.CompletedSteps[0].Facts[0].Name = "api_key" }},
		{name: "bad fingerprint", mutate: func(dto *operationSnapshotDTO) { dto.CompletedSteps[0].Fingerprint = "bad" }},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dto := cloneRepositoryDTO(t, valid)
			test.mutate(&dto)
			encoded, marshalError := json.Marshal(dto)
			if marshalError != nil {
				t.Fatal(marshalError)
			}
			if _, decodeError := decodeOperationSnapshot(encoded); decodeError == nil {
				t.Fatal("invalid DTO was accepted")
			}
		})
	}
}

func TestPF001InstallOperationRepositoryRejectsInvalidRebootDTOFields(t *testing.T) {
	t.Parallel()
	operation, plan := repositoryTestOperation(t, "invalid-reboot-dto")
	if err := operation.CompleteStep(repositoryEvidence(t, install.PhaseVerifyHost, 1, plan, false, 0)); err != nil {
		t.Fatal(err)
	}
	checkpoint := repositoryCheckpoint(t, plan, install.DigestBytes([]byte("receipt")))
	if err := operation.MarkRebootPending(plan, checkpoint); err != nil {
		t.Fatal(err)
	}
	payload, _, err := encodeOperationSnapshot(operation.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var valid operationSnapshotDTO
	if err := json.Unmarshal(payload, &valid); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*rebootCheckpointDTO)
	}{
		{name: "plan", mutate: func(dto *rebootCheckpointDTO) { dto.PlanDigest = "bad" }},
		{name: "phase", mutate: func(dto *rebootCheckpointDTO) { dto.Phase = "FuturePhase" }},
		{name: "receipt", mutate: func(dto *rebootCheckpointDTO) { dto.ReceiptDigest = "bad" }},
		{name: "action", mutate: func(dto *rebootCheckpointDTO) { dto.NextSafeAction = "restart docker" }},
		{name: "attempt", mutate: func(dto *rebootCheckpointDTO) { dto.Attempt = 0 }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dto := cloneRepositoryDTO(t, valid)
			test.mutate(dto.RebootCheckpoint)
			encoded, marshalError := json.Marshal(dto)
			if marshalError != nil {
				t.Fatal(marshalError)
			}
			if _, decodeError := decodeOperationSnapshot(encoded); decodeError == nil {
				t.Fatal("invalid reboot DTO was accepted")
			}
		})
	}
}

func TestPF001InstallOperationRepositoryMapsJournalErrorsWithoutLosingCause(t *testing.T) {
	t.Parallel()
	id := repositoryOperationID(t, "journal-errors")
	tests := []struct {
		name          string
		loadError     error
		want          error
		wantIntegrity bool
	}{
		{name: "not found", loadError: journalport.ErrNotFound, want: installapp.ErrOperationNotFound},
		{name: "corrupt", loadError: journalport.NewError(journalport.ErrorCorrupt, "load", errors.New("bad HMAC")), want: journalport.ErrCorrupt, wantIntegrity: true},
		{name: "unsafe permissions", loadError: journalport.ErrUnsafePermission, want: journalport.ErrUnsafePermission, wantIntegrity: true},
		{name: "I/O", loadError: journalport.ErrIO, want: journalport.ErrIO},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			repository := mustOperationRepository(t, &repositoryJournalStub{loadError: test.loadError})
			_, err := repository.Load(context.Background(), id)
			assertRepositoryErrorIs(t, err, test.want)
			if test.wantIntegrity {
				assertRepositoryErrorIs(t, err, installapp.ErrOperationIntegrity)
			}
		})
	}
}

func TestPF001InstallOperationRepositoryPreservesAppendConflictAndMapsCorruption(t *testing.T) {
	t.Parallel()
	operation, _ := repositoryTestOperation(t, "append-errors")
	tests := []struct {
		name          string
		appendError   error
		want          error
		wantIntegrity bool
	}{
		{name: "conflict", appendError: journalport.ErrConflict, want: journalport.ErrConflict},
		{name: "vanished journal", appendError: journalport.ErrNotFound, want: journalport.ErrNotFound, wantIntegrity: true},
		{name: "corrupt", appendError: journalport.ErrCorrupt, want: journalport.ErrCorrupt, wantIntegrity: true},
		{name: "invalid generated snapshot", appendError: journalport.ErrInvalidSnapshot, want: journalport.ErrInvalidSnapshot, wantIntegrity: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			journal := &repositoryJournalStub{appendError: test.appendError}
			repository := mustOperationRepository(t, journal)
			err := repository.Save(context.Background(), operation.Snapshot())
			assertRepositoryErrorIs(t, err, test.want)
			if errors.Is(test.want, journalport.ErrConflict) {
				assertRepositoryErrorIs(t, err, installapp.ErrOperationConflict)
			}
			if test.wantIntegrity {
				assertRepositoryErrorIs(t, err, installapp.ErrOperationIntegrity)
			}
		})
	}
}

func TestPF001InstallOperationRepositoryEnforcesEnvelopeIdentityAndPlan(t *testing.T) {
	t.Parallel()
	journal := &repositoryJournalStub{}
	repository := mustOperationRepository(t, journal)
	operation, _ := repositoryTestOperation(t, "identity-plan")
	if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}

	foreignID := repositoryOperationID(t, "foreign-id")
	_, err := repository.Load(context.Background(), foreignID)
	assertRepositoryErrorIs(t, err, installapp.ErrOperationIntegrity)

	journal.latest.OperationID = foreignID.String()
	err = repository.Save(context.Background(), operation.Snapshot())
	assertRepositoryConflict(t, err)
	journal.latest.OperationID = operation.ID().String()

	foreignPlan, _ := install.BindPlan([]byte("foreign-plan"))
	foreignOperation, newError := install.NewOperation(operation.ID(), foreignPlan)
	if newError != nil {
		t.Fatal(newError)
	}
	err = repository.Save(context.Background(), foreignOperation.Snapshot())
	assertRepositoryErrorIs(t, err, installapp.ErrOperationIntegrity)
}

func TestPF001InstallOperationRepositoryRejectsAuthenticatedCrossBoundPayload(t *testing.T) {
	t.Parallel()
	journal := &repositoryJournalStub{}
	repository := mustOperationRepository(t, journal)
	operation, _ := repositoryTestOperation(t, "envelope-owner")
	if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}
	foreign, _ := repositoryTestOperation(t, "payload-owner")
	foreignPayload, _, err := encodeOperationSnapshot(foreign.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	journal.latest.Payload = foreignPayload
	_, loadError := repository.Load(context.Background(), operation.ID())
	assertRepositoryErrorIs(t, loadError, installapp.ErrOperationIntegrity)

	err = repository.Save(context.Background(), operation.Snapshot())
	assertRepositoryErrorIs(t, err, installapp.ErrOperationIntegrity)
}

func TestPF001InstallOperationRepositoryRejectsInvalidDependenciesAndClock(t *testing.T) {
	t.Parallel()
	var typedNilProvider *repositoryJournalProviderStub
	var typedNilClock *repositoryClockStub
	fence := &repositoryFenceStub{}
	if _, err := NewInstallOperationRepository(nil, repositoryClockStub{now: repositoryFixedTime}, fence); err == nil {
		t.Fatal("nil journal provider was accepted")
	}
	if _, err := NewInstallOperationRepository(typedNilProvider, repositoryClockStub{now: repositoryFixedTime}, fence); err == nil {
		t.Fatal("typed nil journal provider was accepted")
	}
	provider := &repositoryJournalProviderStub{journal: &repositoryJournalStub{}}
	if _, err := NewInstallOperationRepository(provider, nil, fence); err == nil {
		t.Fatal("nil clock was accepted")
	}
	if _, err := NewInstallOperationRepository(provider, typedNilClock, fence); err == nil {
		t.Fatal("typed nil clock was accepted")
	}

	operation, _ := repositoryTestOperation(t, "zero-clock")
	if _, err := NewInstallOperationRepository(provider, repositoryClockStub{now: repositoryFixedTime}, nil); err == nil {
		t.Fatal("nil state fence was accepted")
	}
	repository, err := NewInstallOperationRepository(provider, repositoryClockStub{}, fence)
	if err != nil {
		t.Fatal(err)
	}
	err = repository.Save(context.Background(), operation.Snapshot())
	assertRepositoryErrorIs(t, err, journalport.ErrInvalidSnapshot)
	assertRepositoryErrorIs(t, err, installapp.ErrOperationIntegrity)
}

func TestPF001InstallOperationRepositoryRejectsProviderErrorsAndNilJournals(t *testing.T) {
	t.Parallel()
	operation, _ := repositoryTestOperation(t, "provider-failures")
	var typedNilJournal *repositoryJournalStub
	providerFailure := errors.New("provider selection failed")
	tests := []struct {
		name      string
		provider  *repositoryJournalProviderStub
		load      bool
		want      error
		integrity bool
		conflict  bool
	}{
		{name: "nil journal", provider: &repositoryJournalProviderStub{}, integrity: true},
		{name: "typed nil journal", provider: &repositoryJournalProviderStub{journal: typedNilJournal}, integrity: true},
		{name: "plain provider failure", provider: &repositoryJournalProviderStub{provideError: providerFailure}, want: providerFailure},
		{name: "load missing", provider: &repositoryJournalProviderStub{provideError: journalport.ErrNotFound}, load: true, want: installapp.ErrOperationNotFound},
		{name: "load collision", provider: &repositoryJournalProviderStub{provideError: journalport.ErrConflict}, load: true, want: journalport.ErrConflict, conflict: true},
		{name: "load corruption", provider: &repositoryJournalProviderStub{provideError: journalport.ErrCorrupt}, load: true, want: journalport.ErrCorrupt, integrity: true},
		{name: "save missing", provider: &repositoryJournalProviderStub{provideError: journalport.ErrNotFound}, want: journalport.ErrNotFound, integrity: true},
		{name: "save conflict", provider: &repositoryJournalProviderStub{provideError: journalport.ErrConflict}, want: journalport.ErrConflict, conflict: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			repository := mustOperationRepositoryWithProvider(t, test.provider)
			var err error
			if test.load {
				_, err = repository.Load(context.Background(), operation.ID())
			} else {
				err = repository.Save(context.Background(), operation.Snapshot())
			}
			if err == nil {
				t.Fatal("provider failure was accepted")
			}
			if test.want != nil {
				assertRepositoryErrorIs(t, err, test.want)
			}
			if test.integrity {
				assertRepositoryErrorIs(t, err, installapp.ErrOperationIntegrity)
			}
			if test.conflict {
				assertRepositoryErrorIs(t, err, installapp.ErrOperationConflict)
			}
		})
	}
}

func TestPF001InstallOperationRepositoryRejectsRevisionExhaustion(t *testing.T) {
	t.Parallel()
	operation, plan := repositoryTestOperation(t, "revision-exhaustion")
	payload, _, err := encodeOperationSnapshot(operation.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	journal := &repositoryJournalStub{
		exists: true,
		latest: repositoryJournalSnapshot(operation.ID(), payload, math.MaxUint64),
	}
	repository := mustOperationRepository(t, journal)
	if err := operation.FailRecoverable(plan); err != nil {
		t.Fatal(err)
	}
	err = repository.Save(context.Background(), operation.Snapshot())
	assertRepositoryConflict(t, err)
}

func TestPF001InstallOperationRepositoryHelperGuardsFailClosed(t *testing.T) {
	t.Parallel()
	if err := operationIntegrity(nil); !errors.Is(err, installapp.ErrOperationIntegrity) {
		t.Fatalf("nil integrity cause was not mapped: %v", err)
	}
	if nilInterface(42) || nilInterface(struct{}{}) || !nilInterface((func())(nil)) {
		t.Fatal("nil interface guard misclassified a dependency")
	}
	if err := rejectDuplicateJSONKeys([]byte(`[]`)); err != nil {
		t.Fatalf("empty array was rejected: %v", err)
	}
}

const repositoryTestKey = "0123456789abcdef0123456789abcdef"

var repositoryFixedTime = time.Date(2026, time.July, 13, 14, 30, 0, 123, time.FixedZone("GST", 4*60*60))

type repositoryClockStub struct {
	now time.Time
}

func (c repositoryClockStub) Now() time.Time { return c.now }

type repositoryAppendCall struct {
	expected uint64
	snapshot journalport.Snapshot
}

type repositoryJournalProviderStub struct {
	journal       journalport.Journal
	provideError  error
	selectJournal func(install.OperationID) (journalport.Journal, error)
	requests      []string
}

func (p *repositoryJournalProviderStub) JournalFor(
	ctx context.Context,
	operationID install.OperationID,
) (journalport.Journal, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.requests = append(p.requests, operationID.String())
	if p.provideError != nil {
		return nil, p.provideError
	}
	if p.selectJournal != nil {
		return p.selectJournal(operationID)
	}
	return p.journal, nil
}

type repositoryJournalStub struct {
	exists       bool
	latest       journalport.Snapshot
	loadError    error
	appendError  error
	confirmError error
	appends      []repositoryAppendCall
	confirms     int
}

func (j *repositoryJournalStub) LoadLatest(ctx context.Context) (journalport.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return journalport.Snapshot{}, err
	}
	if j.loadError != nil {
		return journalport.Snapshot{}, j.loadError
	}
	if !j.exists {
		return journalport.Snapshot{}, journalport.ErrNotFound
	}
	result := j.latest
	result.Payload = append(json.RawMessage(nil), j.latest.Payload...)
	return result, nil
}

func (j *repositoryJournalStub) Append(
	ctx context.Context,
	expected uint64,
	snapshot journalport.Snapshot,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if j.appendError != nil {
		return j.appendError
	}
	if j.exists && j.latest.Revision != expected {
		return journalport.ErrConflict
	}
	if !j.exists && expected != 0 {
		return journalport.ErrConflict
	}
	copyOfSnapshot := snapshot
	copyOfSnapshot.Payload = append(json.RawMessage(nil), snapshot.Payload...)
	j.appends = append(j.appends, repositoryAppendCall{expected: expected, snapshot: copyOfSnapshot})
	j.latest = copyOfSnapshot
	j.exists = true
	return nil
}

func (j *repositoryJournalStub) ConfirmDurable(
	ctx context.Context,
	operationID string,
	revision uint64,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	j.confirms++
	if j.confirmError != nil {
		return j.confirmError
	}
	if !j.exists || j.latest.OperationID != operationID || j.latest.Revision != revision {
		return journalport.ErrConflict
	}
	return nil
}

func mustOperationRepository(
	t testing.TB,
	journal journalport.Journal,
) *InstallOperationRepository {
	t.Helper()
	return mustOperationRepositoryWithProvider(t, &repositoryJournalProviderStub{journal: journal})
}

func mustOperationRepositoryWithProvider(
	t testing.TB,
	provider OperationJournalProvider,
) *InstallOperationRepository {
	t.Helper()
	repository, err := NewInstallOperationRepository(
		provider, repositoryClockStub{now: repositoryFixedTime}, &repositoryFenceStub{},
	)
	if err != nil {
		t.Fatal(err)
	}
	return repository
}

type repositoryFenceStub struct{ mu sync.Mutex }

func (f *repositoryFenceStub) WithExclusive(
	_ context.Context,
	_ install.OperationID,
	action func() error,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return action()
}

func repositoryTestOperation(t testing.TB, value string) (*install.Operation, install.PlanDigest) {
	t.Helper()
	id := repositoryOperationID(t, value)
	plan, err := install.BindPlan([]byte("canonical-plan:" + value))
	if err != nil {
		t.Fatal(err)
	}
	operation, err := install.NewOperation(id, plan)
	if err != nil {
		t.Fatal(err)
	}
	return operation, plan
}

func repositoryOperationID(t testing.TB, value string) install.OperationID {
	t.Helper()
	id, err := install.NewOperationID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func repositoryEvidence(
	t testing.TB,
	phase install.Phase,
	attempt uint32,
	plan install.PlanDigest,
	withArtifact bool,
	index int,
) install.StepEvidence {
	t.Helper()
	fact, err := install.NewNonSecretFact("probe_status", fmt.Sprintf("verified-%d", index))
	if err != nil {
		t.Fatal(err)
	}
	boundary, err := install.NewCompensationBoundary("remove_agentmemory_owned_partial")
	if err != nil {
		t.Fatal(err)
	}
	action, err := install.NewSafeAction("setup.continue")
	if err != nil {
		t.Fatal(err)
	}
	artifact := install.Digest{}
	if withArtifact || install.PhaseRequiresVerifiedArtifact(phase) {
		artifact = install.DigestBytes([]byte("artifact:" + phase.String()))
	}
	runtimeOwnership := install.RuntimeOwnershipUndetermined
	if phase != install.PhaseVerifyHost {
		runtimeOwnership = install.RuntimeOwnershipReusedExternal
	}
	evidence, err := install.NewStepEvidence(install.StepEvidenceInput{
		Phase:                  phase,
		Attempt:                attempt,
		PlanDigest:             plan,
		InputDigest:            install.DigestBytes([]byte(fmt.Sprintf("input:%s:%d", phase, index))),
		OutputDigest:           install.DigestBytes([]byte(fmt.Sprintf("output:%s:%d", phase, index))),
		VerifiedArtifactDigest: artifact,
		Facts:                  []install.NonSecretFact{fact},
		RuntimeOwnership:       runtimeOwnership,
		CompensationBoundary:   boundary,
		NextSafeAction:         action,
	})
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func repositoryCheckpoint(
	t testing.TB,
	plan install.PlanDigest,
	receipt install.Digest,
) install.RebootCheckpoint {
	t.Helper()
	action, err := install.NewSafeAction("setup.resume_after_restart")
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := install.NewRebootCheckpoint(
		plan,
		install.PhaseEnsureContainerRuntime,
		1,
		receipt,
		action,
	)
	if err != nil {
		t.Fatal(err)
	}
	return checkpoint
}

func mustRepositoryLoad(
	t testing.TB,
	repository *InstallOperationRepository,
	id install.OperationID,
) *install.Operation {
	t.Helper()
	operation, err := repository.Load(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return operation
}

func assertRepositoryOperationEqual(t testing.TB, actual, expected *install.Operation) {
	t.Helper()
	actualSnapshot := actual.Snapshot()
	expectedSnapshot := expected.Snapshot()
	if actualSnapshot.OperationID() != expectedSnapshot.OperationID() ||
		!actualSnapshot.PlanDigest().Equal(expectedSnapshot.PlanDigest()) ||
		actualSnapshot.AggregateVersion() != expectedSnapshot.AggregateVersion() ||
		actualSnapshot.State() != expectedSnapshot.State() ||
		actualSnapshot.CurrentPhase() != expectedSnapshot.CurrentPhase() ||
		actualSnapshot.Attempt() != expectedSnapshot.Attempt() {
		t.Fatalf("operation mismatch: actual=%+v expected=%+v", actualSnapshot, expectedSnapshot)
	}
	actualEvidence := actualSnapshot.CompletedEvidence()
	expectedEvidence := expectedSnapshot.CompletedEvidence()
	if len(actualEvidence) != len(expectedEvidence) {
		t.Fatalf("evidence length = %d, want %d", len(actualEvidence), len(expectedEvidence))
	}
	for index := range actualEvidence {
		if !actualEvidence[index].Equal(expectedEvidence[index]) {
			t.Fatalf("evidence %d differs", index)
		}
	}
}

func repositoryJournalSnapshot(
	id install.OperationID,
	payload []byte,
	revision uint64,
) journalport.Snapshot {
	return journalport.Snapshot{
		OperationID: id.String(),
		Revision:    revision,
		CapturedAt:  repositoryFixedTime,
		Payload:     append(json.RawMessage(nil), payload...),
	}
}

func cloneRepositoryDTO(t testing.TB, source operationSnapshotDTO) operationSnapshotDTO {
	t.Helper()
	encoded, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var result operationSnapshotDTO
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func assertRepositoryErrorIs(t testing.TB, actual, expected error) {
	t.Helper()
	if !errors.Is(actual, expected) {
		t.Fatalf("error = %T %v, want errors.Is(%v)", actual, actual, expected)
	}
}

func assertRepositoryConflict(t testing.TB, actual error) {
	t.Helper()
	assertRepositoryErrorIs(t, actual, installapp.ErrOperationConflict)
	assertRepositoryErrorIs(t, actual, journalport.ErrConflict)
}
