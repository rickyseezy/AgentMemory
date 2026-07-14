package filesystem

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001InstallOperationRepositoryJSONScannerFailsClosedAtNestedBoundaries(t *testing.T) {
	t.Parallel()
	for name, payload := range map[string]string{
		"empty":                  "",
		"closing object":         "}",
		"truncated object":       `{"value":`,
		"truncated object close": `{"value":1`,
		"truncated array":        `[1`,
		"nested truncated array": `[{"value":`,
		"trailing scalar":        `"first" "second"`,
		"invalid trailing token": `"first" ?`,
	} {
		name, payload := name, payload
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := rejectDuplicateJSONKeys([]byte(payload)); err == nil {
				t.Fatalf("malformed JSON %q was accepted", payload)
			}
		})
	}
}

func TestPF001InstallOperationRepositoryRejectsAdditionalDomainInvariantFailures(t *testing.T) {
	t.Parallel()
	operation, plan := repositoryTestOperation(t, "additional-domain-invariants")
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

	for name, mutate := range map[string]func(*operationSnapshotDTO){
		"invalid operation":  func(dto *operationSnapshotDTO) { dto.OperationID = "../escape" },
		"evidence phase":     func(dto *operationSnapshotDTO) { dto.CompletedSteps[0].Phase = "FuturePhase" },
		"evidence invariant": func(dto *operationSnapshotDTO) { dto.CompletedSteps[0].Attempt = 0 },
		"aggregate invariant": func(dto *operationSnapshotDTO) {
			dto.State = install.StateReady.String()
			dto.CurrentPhase = install.PhaseVerifyHost.String()
			dto.CompletedSteps = []stepEvidenceDTO{}
		},
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dto := cloneRepositoryDTO(t, valid)
			mutate(&dto)
			encoded, marshalError := json.Marshal(dto)
			if marshalError != nil {
				t.Fatal(marshalError)
			}
			if _, decodeError := decodeOperationSnapshot(encoded); decodeError == nil {
				t.Fatal("invalid aggregate DTO was accepted")
			}
		})
	}

	for _, ownership := range []string{"provisioned_by_agentmemory", "not_applicable"} {
		if _, err := decodeRuntimeOwnership(ownership); err != nil {
			t.Fatalf("supported ownership %q rejected: %v", ownership, err)
		}
	}
}

func TestPF001InstallOperationRepositoryRejectsZeroIdentityAndJournalLoadFailure(t *testing.T) {
	t.Parallel()
	journal := &repositoryJournalStub{}
	repository := mustOperationRepository(t, journal)
	if _, err := repository.Load(context.Background(), install.OperationID{}); !errors.Is(err, installapp.ErrOperationIntegrity) {
		t.Fatalf("zero operation load error = %v", err)
	}
	if err := repository.Save(context.Background(), install.OperationSnapshot{}); !errors.Is(err, installapp.ErrOperationIntegrity) {
		t.Fatalf("zero snapshot save error = %v", err)
	}

	operation, _ := repositoryTestOperation(t, "journal-load-failure")
	payload, _, err := encodeOperationSnapshot(operation.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("journal storage unavailable")
	journal = &repositoryJournalStub{
		exists:    true,
		latest:    repositoryJournalSnapshot(operation.ID(), bytes.Clone(payload), 1),
		loadError: journalport.NewError(journalport.ErrorIO, "load", sentinel),
	}
	repository = mustOperationRepository(t, journal)
	if err := repository.Save(context.Background(), operation.Snapshot()); !errors.Is(err, sentinel) {
		t.Fatalf("journal load failure = %v", err)
	}
}
