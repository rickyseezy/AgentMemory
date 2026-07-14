//go:build linux || (darwin && cgo)

package filesystem

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001InstallOperationRepositoryRecoversAmbiguousPostRenameDurability(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "bootstrap", "ambiguous-install-operation.json")
	failedAfterRename := false
	journal, err := newInstallJournal(path, []byte(repositoryTestKey), func(checkpoint writeCheckpoint) error {
		if checkpoint == checkpointRenamed && !failedAfterRename {
			failedAfterRename = true
			return errors.New("injected failure after rename")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	repository := mustOperationRepository(t, journal)
	operation, _ := repositoryTestOperation(t, "post-rename-confirmation")

	if err := repository.Save(context.Background(), operation.Snapshot()); err == nil {
		t.Fatal("first save unexpectedly acknowledged ambiguous post-rename durability")
	}
	if !failedAfterRename {
		t.Fatal("post-rename failure checkpoint did not execute")
	}
	if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatalf("retry did not confirm visible revision durability: %v", err)
	}
	latest := mustLoad(t, journal)
	if latest.Revision != 1 || latest.OperationID != operation.ID().String() {
		t.Fatalf("latest = revision %d operation %s", latest.Revision, latest.OperationID)
	}
}

func TestPF001InstallOperationRepositoryLoadConfirmsAmbiguousTerminalAndRebootStates(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		idSuffix string
		want     install.State
		prepare  func(testing.TB, *InstallOperationRepository, *install.Operation, install.PlanDigest)
	}{
		{
			name:     "ready",
			idSuffix: "ready",
			want:     install.StateReady,
			prepare: func(t testing.TB, repository *InstallOperationRepository, operation *install.Operation, plan install.PlanDigest) {
				t.Helper()
				for index, phase := range install.OrderedPhases() {
					if err := operation.CompleteStep(repositoryEvidence(t, phase, operation.Attempt(), plan, false, index)); err != nil {
						t.Fatal(err)
					}
					if phase != install.PhaseCommitActiveRelease {
						if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
							t.Fatal(err)
						}
					}
				}
			},
		},
		{
			name:     "reboot pending",
			idSuffix: "reboot-pending",
			want:     install.StateRebootPending,
			prepare: func(t testing.TB, repository *InstallOperationRepository, operation *install.Operation, plan install.PlanDigest) {
				t.Helper()
				if err := operation.CompleteStep(repositoryEvidence(t, install.PhaseVerifyHost, 1, plan, false, 0)); err != nil {
					t.Fatal(err)
				}
				if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
					t.Fatal(err)
				}
				checkpoint := repositoryCheckpoint(t, plan, install.DigestBytes([]byte("ambiguous-reboot-receipt")))
				if err := operation.MarkRebootPending(plan, checkpoint); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "bootstrap", "ambiguous-state.json")
			armed := false
			failedAfterRename := false
			journal, err := newInstallJournal(path, []byte(repositoryTestKey), func(checkpoint writeCheckpoint) error {
				if armed && checkpoint == checkpointRenamed && !failedAfterRename {
					failedAfterRename = true
					return errors.New("injected target-state failure after rename")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			repository := mustOperationRepository(t, journal)
			operation, plan := repositoryTestOperation(t, "ambiguous-state-"+test.idSuffix)
			if err := repository.Save(context.Background(), operation.Snapshot()); err != nil {
				t.Fatal(err)
			}
			test.prepare(t, repository, operation, plan)
			if operation.State() != test.want {
				t.Fatalf("prepared state = %s, want %s", operation.State(), test.want)
			}

			armed = true
			if err := repository.Save(context.Background(), operation.Snapshot()); err == nil {
				t.Fatal("target-state save unexpectedly acknowledged ambiguous durability")
			}
			if !failedAfterRename {
				t.Fatal("post-rename failure checkpoint did not execute")
			}
			restored, err := repository.Load(context.Background(), operation.ID())
			if err != nil {
				t.Fatalf("load did not confirm visible target revision: %v", err)
			}
			if restored.State() != test.want {
				t.Fatalf("restored state = %s, want %s", restored.State(), test.want)
			}
		})
	}
}

func TestPF001InstallOperationRepositoryUsesJournalRevisionAcrossRestart(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "bootstrap", "install-operation.json")
	journal := mustJournal(t, path, []byte(repositoryTestKey))
	firstRepository := mustOperationRepository(t, journal)
	operation, plan := repositoryTestOperation(t, "restart-revision")
	if err := firstRepository.Save(context.Background(), operation.Snapshot()); err != nil {
		t.Fatal(err)
	}

	secondJournal := mustJournal(t, path, []byte(repositoryTestKey))
	secondRepository := mustOperationRepository(t, secondJournal)
	restored := mustRepositoryLoad(t, secondRepository, operation.ID())
	if err := restored.CompleteStep(repositoryEvidence(t, install.PhaseVerifyHost, 1, plan, false, 0)); err != nil {
		t.Fatal(err)
	}
	if err := secondRepository.Save(context.Background(), restored.Snapshot()); err != nil {
		t.Fatal(err)
	}

	latest := mustLoad(t, secondJournal)
	if latest.Revision != 2 || latest.OperationID != operation.ID().String() {
		t.Fatalf("latest = revision %d operation %s", latest.Revision, latest.OperationID)
	}
	thirdRepository := mustOperationRepository(t, mustJournal(t, path, []byte(repositoryTestKey)))
	third := mustRepositoryLoad(t, thirdRepository, operation.ID())
	if third.CurrentPhase() != install.PhaseEnsureContainerRuntime {
		t.Fatalf("phase after restart = %s", third.CurrentPhase())
	}
}
