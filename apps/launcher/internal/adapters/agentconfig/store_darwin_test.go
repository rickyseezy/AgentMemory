//go:build darwin && cgo

package agentconfigadapter

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	port "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/agentconfig"
	domain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
)

const (
	darwinInstallationID = "018f0c74-7b5d-7cc1-8a2c-4f1ae7c16a01"
	darwinEntryID        = "018f0c74-7b5d-7cc1-9a2c-4f1ae7c16a02"
)

func TestPF001DarwinApplyBacksUpAtomicallyAndRestoreIsExact(t *testing.T) {
	t.Parallel()
	root, location, original := darwinFixture(t, true)
	store := mustDarwinStore(t, filepath.Join(root, "backups"))
	plan := darwinPlan(t, original, true)

	receipt, err := store.ApplyAtomic(context.Background(), location, plan)
	if err != nil {
		t.Fatalf("ApplyAtomic() error = %v", err)
	}
	if !receipt.Valid() || !receipt.BackupDigest().Equal(plan.BeforeDigest()) {
		t.Fatalf("ApplyAtomic() receipt is incomplete")
	}
	backup, err := os.ReadFile(receipt.BackupLocation())
	if err != nil || string(backup) != string(original) {
		t.Fatalf("backup error=%v content=%q", err, backup)
	}
	assertOwnerOnlyRegular(t, receipt.BackupLocation())
	configured, err := os.ReadFile(location.String())
	if err != nil || !domain.DigestBytes(configured).Equal(plan.AfterDigest()) || domain.VerifyManagedEntry(configured, plan.Target()) != nil {
		t.Fatalf("configured error=%v digest/entry mismatch", err)
	}
	assertOwnerOnlyRegular(t, location.String())

	restored, err := store.RestoreBackup(context.Background(), location, receipt)
	if err != nil {
		t.Fatalf("RestoreBackup() error = %v", err)
	}
	final, _ := os.ReadFile(location.String())
	if !restored.Exists() || !restored.Digest().Equal(plan.BeforeDigest()) || string(final) != string(original) {
		t.Fatalf("restore did not reproduce exact original bytes")
	}
	// Restore replay is idempotent and still proves backup integrity.
	if _, err := store.RestoreBackup(context.Background(), location, receipt); err != nil {
		t.Fatalf("RestoreBackup(replay) error = %v", err)
	}
}

func TestPF001DarwinAbsentConfigurationRestoresToAbsence(t *testing.T) {
	t.Parallel()
	root, location, _ := darwinFixture(t, false)
	store := mustDarwinStore(t, filepath.Join(root, "backups"))
	plan := darwinPlan(t, nil, false)
	receipt, err := store.ApplyAtomic(context.Background(), location, plan)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.OriginalExisted() || receipt.BackupLocation() != "" {
		t.Fatalf("absent input unexpectedly created a backup receipt")
	}
	if _, err := store.RestoreBackup(context.Background(), location, receipt); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(location.String()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("restored absent config stat error = %v", err)
	}
	if _, err := store.RestoreBackup(context.Background(), location, receipt); err != nil {
		t.Fatalf("absent restore replay error = %v", err)
	}
}

func TestPF001DarwinApplyRestoreApplyStartsANewDurableTransaction(t *testing.T) {
	t.Parallel()
	root, location, original := darwinFixture(t, true)
	store := mustDarwinStore(t, filepath.Join(root, "backups"))
	plan := darwinPlan(t, original, true)
	first, err := store.ApplyAtomic(context.Background(), location, plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RestoreBackup(context.Background(), location, first); err != nil {
		t.Fatal(err)
	}
	second, err := store.ApplyAtomic(context.Background(), location, plan)
	if err != nil {
		t.Fatalf("second apply after restore=%v", err)
	}
	if !second.AfterDigest().Equal(plan.AfterDigest()) {
		t.Fatal("second apply receipt did not bind the new transaction")
	}
	assertExactFile(t, location.String(), plan.AfterContent())
}

func TestPF001DarwinFailureInjectionCoversRecoverableJournalBoundaries(t *testing.T) {
	t.Run("unsafe detect and process lock", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		plan := darwinPlan(t, original, true)
		//nolint:gosec // The test deliberately makes the configuration world-readable.
		if err := os.Chmod(location.String(), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := mustDarwinStore(t, filepath.Join(root, "backups")).Detect(context.Background(), location); !errors.Is(err, port.ErrUnsafePath) {
			t.Fatalf("unsafe detect=%v", err)
		}
		if err := os.Chmod(location.String(), 0o600); err != nil {
			t.Fatal(err)
		}
		var absentStore *DarwinStore
		if _, err := absentStore.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrInvalidArgument) {
			t.Fatalf("nil store apply=%v", err)
		}
	})

	t.Run("unsafe apply lock and current file", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		backups := filepath.Join(root, "backups")
		if err := os.Mkdir(backups, 0o700); err != nil {
			t.Fatal(err)
		}
		lock := filepath.Join(backups, lockFileName)
		if err := os.WriteFile(lock, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		//nolint:gosec // The test deliberately makes lock metadata unsafe.
		if err := os.Chmod(lock, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := mustDarwinStore(t, backups).ApplyAtomic(
			context.Background(), location, darwinPlan(t, original, true),
		); !errors.Is(err, port.ErrUnsafePath) {
			t.Fatalf("unsafe apply lock=%v", err)
		}

		root, location, original = darwinFixture(t, true)
		//nolint:gosec // The test deliberately makes the configuration world-readable.
		if err := os.Chmod(location.String(), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := mustDarwinStore(t, filepath.Join(root, "backups")).ApplyAtomic(
			context.Background(), location, darwinPlan(t, original, true),
		); !errors.Is(err, port.ErrUnsafePath) {
			t.Fatalf("unsafe current apply=%v", err)
		}
	})

	t.Run("replay commit and cleanup failures", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		backups := filepath.Join(root, "backups")
		store := mustDarwinStore(t, backups)
		plan := darwinPlan(t, original, true)
		store.fault = func(stage faultStage) error {
			if stage == faultAfterExchange {
				return errors.New("stop after exchange")
			}
			return nil
		}
		if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrDurabilityAmbiguous) {
			t.Fatalf("faulted exchange=%v", err)
		}
		metadata := newTransactionMetadata(location, plan)
		if err := os.WriteFile(filepath.Join(backups, metadata.anchorName()+".commit"), []byte("wrong"), 0o600); err != nil {
			t.Fatal(err)
		}
		store.fault = nil
		if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrDurabilityAmbiguous) {
			t.Fatalf("replay commit conflict=%v", err)
		}

		root, location, _ = darwinFixture(t, false)
		store = mustDarwinStore(t, filepath.Join(root, "backups"))
		plan = darwinPlan(t, nil, false)
		store.fault = func(stage faultStage) error {
			if stage == faultAfterReplace {
				return errors.New("stop after replacement")
			}
			return nil
		}
		if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrDurabilityAmbiguous) {
			t.Fatalf("faulted absent apply=%v", err)
		}
		metadata = newTransactionMetadata(location, plan)
		journal := filepath.Join(filepath.Dir(location.String()), metadata.newName())
		if err := os.WriteFile(journal, plan.AfterContent(), 0o600); err != nil {
			t.Fatal(err)
		}
		//nolint:gosec // The test deliberately makes journal metadata unsafe.
		if err := os.Chmod(journal, 0o644); err != nil {
			t.Fatal(err)
		}
		store.fault = nil
		if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrUnsafePath) {
			t.Fatalf("unsafe replay cleanup=%v", err)
		}
	})

	t.Run("reset and initial journals reject corruption", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		store := mustDarwinStore(t, filepath.Join(root, "backups"))
		plan := darwinPlan(t, original, true)
		receipt, err := store.ApplyAtomic(context.Background(), location, plan)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.RestoreBackup(context.Background(), location, receipt); err != nil {
			t.Fatal(err)
		}
		metadata := newTransactionMetadata(location, plan)
		if err := os.WriteFile(filepath.Join(filepath.Dir(location.String()), metadata.proofName()), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrIntegrity) {
			t.Fatalf("corrupt reset proof=%v", err)
		}

		for _, proofCollision := range []bool{false, true} {
			root, location, original = darwinFixture(t, true)
			backups := filepath.Join(root, "backups")
			if err := os.Mkdir(backups, 0o700); err != nil {
				t.Fatal(err)
			}
			plan = darwinPlan(t, original, true)
			metadata = newTransactionMetadata(location, plan)
			if proofCollision {
				if err := os.WriteFile(filepath.Join(filepath.Dir(location.String()), metadata.proofName()), []byte("invalid"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(
				filepath.Join(backups, backupName(location, plan.BeforeDigest())), []byte("wrong"), 0o600,
			); err != nil {
				t.Fatal(err)
			}
			if _, err := mustDarwinStore(t, backups).ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrIntegrity) {
				t.Fatalf("proofCollision=%t apply=%v", proofCollision, err)
			}
		}
	})

	t.Run("exchange create archive commit and cleanup failures", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		store := mustDarwinStore(t, filepath.Join(root, "backups"))
		plan := darwinPlan(t, original, true)
		metadata := newTransactionMetadata(location, plan)
		store.fault = func(stage faultStage) error {
			if stage == faultBeforeReplace {
				return os.Remove(filepath.Join(filepath.Dir(location.String()), metadata.newName()))
			}
			return nil
		}
		if _, err := store.ApplyAtomic(context.Background(), location, plan); err == nil {
			t.Fatal("missing exchange replacement succeeded")
		}

		root, location, original = darwinFixture(t, true)
		store = mustDarwinStore(t, filepath.Join(root, "backups"))
		plan = darwinPlan(t, original, true)
		metadata = newTransactionMetadata(location, plan)
		var stat unix.Stat_t
		if err := unix.Stat(location.String(), &stat); err != nil {
			t.Fatal(err)
		}
		archive := darwinArchiveName(metadata.newName(), darwinDeviceIdentity(stat.Dev), stat.Ino)
		if err := os.WriteFile(filepath.Join(filepath.Dir(location.String()), archive), []byte("occupied"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrDurabilityAmbiguous) {
			t.Fatalf("occupied displaced archive=%v", err)
		}

		for _, createTarget := range []bool{false, true} {
			root, location, _ = darwinFixture(t, false)
			store = mustDarwinStore(t, filepath.Join(root, "backups"))
			plan = darwinPlan(t, nil, false)
			metadata = newTransactionMetadata(location, plan)
			store.fault = func(stage faultStage) error {
				if stage != faultBeforeReplace {
					return nil
				}
				if createTarget {
					return os.WriteFile(location.String(), []byte("external"), 0o600)
				}
				return os.Remove(filepath.Join(filepath.Dir(location.String()), metadata.newName()))
			}
			if _, err := store.ApplyAtomic(context.Background(), location, plan); err == nil {
				t.Fatalf("createTarget=%t publication succeeded", createTarget)
			}
		}

		for _, cleanupFailure := range []bool{false, true} {
			root, location, original = darwinFixture(t, true)
			backups := filepath.Join(root, "backups")
			if err := os.Mkdir(backups, 0o700); err != nil {
				t.Fatal(err)
			}
			plan = darwinPlan(t, original, true)
			metadata = newTransactionMetadata(location, plan)
			if cleanupFailure {
				store = mustDarwinStore(t, backups)
				store.fault = func(stage faultStage) error {
					if stage == faultAfterReplace {
						return os.WriteFile(
							filepath.Join(filepath.Dir(location.String()), metadata.newName()), []byte("wrong"), 0o600,
						)
					}
					return nil
				}
				if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrIntegrity) {
					t.Fatalf("post-commit cleanup=%v", err)
				}
				continue
			}
			if err := os.WriteFile(filepath.Join(backups, metadata.anchorName()+".commit"), []byte("wrong"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := mustDarwinStore(t, backups).ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrDurabilityAmbiguous) {
				t.Fatalf("commit collision=%v", err)
			}
		}
	})

	t.Run("restore lock replay and exchange failures", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		backups := filepath.Join(root, "backups")
		store := mustDarwinStore(t, backups)
		plan := darwinPlan(t, original, true)
		receipt, err := store.ApplyAtomic(context.Background(), location, plan)
		if err != nil {
			t.Fatal(err)
		}
		var absentStore *DarwinStore
		if _, err := absentStore.RestoreBackup(context.Background(), location, receipt); !errors.Is(err, port.ErrInvalidArgument) {
			t.Fatalf("nil restore store=%v", err)
		}
		//nolint:gosec // The test deliberately makes lock metadata unsafe.
		if err := os.Chmod(filepath.Join(backups, lockFileName), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := store.RestoreBackup(context.Background(), location, receipt); !errors.Is(err, port.ErrUnsafePath) {
			t.Fatalf("unsafe restore lock=%v", err)
		}

		for _, originalExisted := range []bool{false, true} {
			root, location, original = darwinFixture(t, originalExisted)
			if !originalExisted {
				original = nil
			}
			store = mustDarwinStore(t, filepath.Join(root, "backups"))
			plan = darwinPlan(t, original, originalExisted)
			receipt, err = store.ApplyAtomic(context.Background(), location, plan)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.RestoreBackup(context.Background(), location, receipt); err != nil {
				t.Fatal(err)
			}
			metadata := metadataFromReceipt(location, receipt)
			journal := filepath.Join(filepath.Dir(location.String()), metadata.restoreName())
			if err := os.WriteFile(journal, plan.AfterContent(), 0o600); err != nil {
				t.Fatal(err)
			}
			//nolint:gosec // The test deliberately makes journal metadata unsafe.
			if err := os.Chmod(journal, 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := store.RestoreBackup(context.Background(), location, receipt); !errors.Is(err, port.ErrUnsafePath) {
				t.Fatalf("originalExisted=%t unsafe replay=%v", originalExisted, err)
			}
		}
	})

	t.Run("restore injected interruption boundaries", func(t *testing.T) {
		for _, stage := range []faultStage{
			faultBeforeRestoreReplace,
			faultAfterRestoreExchange,
		} {
			root, location, original := darwinFixture(t, true)
			store := mustDarwinStore(t, filepath.Join(root, "backups"))
			plan := darwinPlan(t, original, true)
			receipt, err := store.ApplyAtomic(context.Background(), location, plan)
			if err != nil {
				t.Fatal(err)
			}
			store.fault = func(observed faultStage) error {
				if observed == stage {
					return errors.New("interrupt restore")
				}
				return nil
			}
			if _, err := store.RestoreBackup(context.Background(), location, receipt); err == nil {
				t.Fatalf("stage=%d restore succeeded", stage)
			}
		}

		for _, scenario := range []string{"occupied", "missing", "archive"} {
			root, location, original := darwinFixture(t, true)
			store := mustDarwinStore(t, filepath.Join(root, "backups"))
			plan := darwinPlan(t, original, true)
			receipt, err := store.ApplyAtomic(context.Background(), location, plan)
			if err != nil {
				t.Fatal(err)
			}
			metadata := metadataFromReceipt(location, receipt)
			journal := filepath.Join(filepath.Dir(location.String()), metadata.restoreName())
			switch scenario {
			case "occupied":
				if err := os.WriteFile(journal, []byte("wrong"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				store.fault = func(stage faultStage) error {
					if stage == faultBeforeRestoreReplace {
						return os.Remove(journal)
					}
					return nil
				}
			case "archive":
				var stat unix.Stat_t
				if err := unix.Stat(location.String(), &stat); err != nil {
					t.Fatal(err)
				}
				archive := darwinArchiveName(metadata.restoreName(), darwinDeviceIdentity(stat.Dev), stat.Ino)
				if err := os.WriteFile(filepath.Join(filepath.Dir(location.String()), archive), []byte("occupied"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.RestoreBackup(context.Background(), location, receipt); err == nil {
				t.Fatalf("scenario=%s restore succeeded", scenario)
			}
		}

		for _, stage := range []faultStage{
			faultAfterRestoreQuarantine,
			faultAfterRestoreJournal,
		} {
			root, location, _ := darwinFixture(t, false)
			store := mustDarwinStore(t, filepath.Join(root, "backups"))
			plan := darwinPlan(t, nil, false)
			receipt, err := store.ApplyAtomic(context.Background(), location, plan)
			if err != nil {
				t.Fatal(err)
			}
			store.fault = func(observed faultStage) error {
				if observed == stage {
					return errors.New("interrupt absence restore")
				}
				return nil
			}
			if _, err := store.RestoreBackup(context.Background(), location, receipt); err == nil {
				t.Fatalf("stage=%d absence restore succeeded", stage)
			}
		}
	})
}

func TestPF001DarwinCompareAndSwapPreservesExternalEdits(t *testing.T) {
	t.Parallel()
	root, location, original := darwinFixture(t, true)
	store := mustDarwinStore(t, filepath.Join(root, "backups"))
	plan := darwinPlan(t, original, true)
	external := []byte(`{"external":"before apply"}`)
	if err := os.WriteFile(location.String(), external, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrConflict) {
		t.Fatalf("ApplyAtomic(stale) error = %v, want ErrConflict", err)
	}
	assertExactFile(t, location.String(), external)

	if err := os.WriteFile(location.String(), original, 0o600); err != nil {
		t.Fatal(err)
	}
	receipt, err := store.ApplyAtomic(context.Background(), location, plan)
	if err != nil {
		t.Fatal(err)
	}
	external = []byte(`{"external":"before restore"}`)
	if err := os.WriteFile(location.String(), external, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RestoreBackup(context.Background(), location, receipt); !errors.Is(err, port.ErrConflict) {
		t.Fatalf("RestoreBackup(stale) error = %v, want ErrConflict", err)
	}
	assertExactFile(t, location.String(), external)
}

func TestPF001DarwinRejectsSymlinksAndUnsafePermissions(t *testing.T) {
	t.Parallel()
	root := darwinTempDir(t)
	realDirectory := filepath.Join(root, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDirectory, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	linked, _ := port.NewConfigLocation(filepath.Join(root, "linked", "config.json"))
	store := mustDarwinStore(t, filepath.Join(root, "backups"))
	if _, err := store.Detect(context.Background(), linked); !errors.Is(err, port.ErrUnsafePath) {
		t.Fatalf("Detect(symlink) error = %v, want ErrUnsafePath", err)
	}

	unsafeDirectory := filepath.Join(root, "unsafe")
	if err := os.Mkdir(unsafeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // The test deliberately creates a group-writable directory.
	if err := os.Chmod(unsafeDirectory, 0o770); err != nil {
		t.Fatal(err)
	}
	unsafeLocation, _ := port.NewConfigLocation(filepath.Join(unsafeDirectory, "config.json"))
	if _, err := store.Detect(context.Background(), unsafeLocation); !errors.Is(err, port.ErrUnsafePath) {
		t.Fatalf("Detect(unsafe permissions) error = %v, want ErrUnsafePath", err)
	}
}

func TestPF001DarwinBackupTamperIsFailClosed(t *testing.T) {
	t.Parallel()
	root, location, original := darwinFixture(t, true)
	store := mustDarwinStore(t, filepath.Join(root, "backups"))
	receipt, err := store.ApplyAtomic(context.Background(), location, darwinPlan(t, original, true))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receipt.BackupLocation(), []byte(`{"tampered":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RestoreBackup(context.Background(), location, receipt); !errors.Is(err, port.ErrIntegrity) {
		t.Fatalf("RestoreBackup(tampered backup) error = %v, want ErrIntegrity", err)
	}
}

func TestPF001DarwinPostReplaceFailureIsReplayRecoverable(t *testing.T) {
	t.Parallel()
	root, location, original := darwinFixture(t, true)
	store := mustDarwinStore(t, filepath.Join(root, "backups"))
	store.fault = func(stage faultStage) error {
		if stage == faultAfterReplace {
			return errors.New("injected sync boundary failure")
		}
		return nil
	}
	plan := darwinPlan(t, original, true)
	if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrDurabilityAmbiguous) {
		t.Fatalf("ApplyAtomic(fault) error = %v, want ErrDurabilityAmbiguous", err)
	}
	store.fault = nil
	receipt, err := store.ApplyAtomic(context.Background(), location, plan)
	if err != nil || !receipt.AfterDigest().Equal(plan.AfterDigest()) {
		t.Fatalf("ApplyAtomic(replay) receipt error=%v", err)
	}
}

func TestPF001DarwinConcurrentApplyHasOneEffectiveMutation(t *testing.T) {
	t.Parallel()
	root, location, original := darwinFixture(t, true)
	store := mustDarwinStore(t, filepath.Join(root, "backups"))
	plan := darwinPlan(t, original, true)
	var wait sync.WaitGroup
	errorsSeen := make(chan error, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := store.ApplyAtomic(context.Background(), location, plan)
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("concurrent ApplyAtomic() error = %v", err)
		}
	}
	configured, _ := os.ReadFile(location.String())
	if !domain.DigestBytes(configured).Equal(plan.AfterDigest()) {
		t.Fatal("concurrent apply produced unexpected state")
	}
}

func TestPF001DarwinOperationsHonorCancelledContext(t *testing.T) {
	t.Parallel()
	root, location, _ := darwinFixture(t, false)
	store := mustDarwinStore(t, filepath.Join(root, "backups"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Detect(ctx, location); !errors.Is(err, context.Canceled) {
		t.Fatalf("Detect(cancelled) error = %v", err)
	}
}

func TestPF001DarwinDetectAndReadAreExactAndSideEffectFree(t *testing.T) {
	t.Parallel()
	root, location, original := darwinFixture(t, true)
	store := mustDarwinStore(t, filepath.Join(root, "backups"))
	detected, err := store.Detect(context.Background(), location)
	if err != nil || !detected.Exists() {
		t.Fatalf("Detect(existing) detected=%t error=%v", detected.Exists(), err)
	}
	snapshot, err := store.Read(context.Background(), location)
	if err != nil || string(snapshot.Content()) != string(original) || !snapshot.Digest().Equal(domain.DigestBytes(original)) {
		t.Fatalf("Read(existing) error=%v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "backups")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only operations created backup state: %v", err)
	}
	if err := os.Remove(location.String()); err != nil {
		t.Fatal(err)
	}
	detected, err = store.Detect(context.Background(), location)
	if err != nil || detected.Exists() {
		t.Fatalf("Detect(absent) detected=%t error=%v", detected.Exists(), err)
	}
	if _, err := store.Read(context.Background(), location); !errors.Is(err, port.ErrNotFound) {
		t.Fatalf("Read(absent) error=%v", err)
	}
	missing, _ := port.NewConfigLocation(filepath.Join(root, "missing", "config.json"))
	detected, err = store.Detect(context.Background(), missing)
	if err != nil || detected.Exists() {
		t.Fatalf("Detect(missing parent) detected=%t error=%v", detected.Exists(), err)
	}
	if _, err := store.Read(context.Background(), missing); !errors.Is(err, port.ErrNotFound) {
		t.Fatalf("Read(missing parent) error=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Read(ctx, location); !errors.Is(err, context.Canceled) {
		t.Fatalf("Read(cancelled) error=%v", err)
	}
}

func TestPF001DarwinRejectsInvalidStoreAndUnsafeFileMetadata(t *testing.T) {
	t.Parallel()
	for _, invalid := range []string{"", "relative/backups", "/", "/tmp/../tmp/backups", "/tmp/bad\npath"} {
		if _, err := NewDarwinStore(invalid); !errors.Is(err, port.ErrInvalidArgument) {
			t.Fatalf("NewDarwinStore(%q) error=%v", invalid, err)
		}
	}
	root, location, _ := darwinFixture(t, true)
	store := mustDarwinStore(t, filepath.Join(root, "backups"))
	//nolint:gosec // The test deliberately creates a world-readable configuration.
	if err := os.Chmod(location.String(), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Detect(context.Background(), location); !errors.Is(err, port.ErrUnsafePath) {
		t.Fatalf("Detect(world-readable) error=%v", err)
	}
	if _, err := store.Read(context.Background(), location); !errors.Is(err, port.ErrUnsafePath) {
		t.Fatalf("Read(world-readable) error=%v", err)
	}
	if err := os.Remove(location.String()); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "target"), location.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(context.Background(), location); !errors.Is(err, port.ErrUnsafePath) {
		t.Fatalf("Read(symlink) error=%v", err)
	}
}

func TestPF001DarwinRejectsHardlinksAndExtendedACLs(t *testing.T) {
	t.Parallel()
	t.Run("hard-linked configuration", func(t *testing.T) {
		root, location, _ := darwinFixture(t, true)
		if err := os.Link(location.String(), filepath.Join(root, "second-link.json")); err != nil {
			t.Fatal(err)
		}
		store := mustDarwinStore(t, filepath.Join(root, "backups"))
		if _, err := store.Read(context.Background(), location); !errors.Is(err, port.ErrUnsafePath) {
			t.Fatalf("Read(hardlink) error=%v", err)
		}
	})
	t.Run("configuration ACL", func(t *testing.T) {
		root, location, _ := darwinFixture(t, true)
		addDarwinAgentConfigACL(t, location.String())
		store := mustDarwinStore(t, filepath.Join(root, "backups"))
		if _, err := store.Read(context.Background(), location); !errors.Is(err, port.ErrUnsafePath) {
			t.Fatalf("Read(extended ACL) error=%v", err)
		}
	})
	t.Run("directory ACL", func(t *testing.T) {
		root, location, _ := darwinFixture(t, true)
		addDarwinAgentConfigACL(t, filepath.Dir(location.String()))
		store := mustDarwinStore(t, filepath.Join(root, "backups"))
		if _, err := store.Detect(context.Background(), location); !errors.Is(err, port.ErrUnsafePath) {
			t.Fatalf("Detect(directory ACL) error=%v", err)
		}
	})
}

func TestPF001DarwinUsesNativeFullSyncForFilesAndDirectories(t *testing.T) {
	t.Parallel()
	root := darwinTempDir(t)
	//nolint:gosec // Test fixture path is constrained to t.TempDir.
	file, err := os.Create(filepath.Join(root, "full-sync"))
	if err != nil {
		t.Fatal(err)
	}
	if err := darwinFullSync(file); err != nil {
		t.Fatalf("file F_FULLFSYNC: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // Test fixture path is constrained to t.TempDir.
	directory, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = directory.Close() }()
	if err := darwinFullSync(directory); err != nil {
		t.Fatalf("directory F_FULLFSYNC: %v", err)
	}
}

func TestPF001DarwinPreReplaceFailurePreservesOriginalAndRetries(t *testing.T) {
	t.Parallel()
	root, location, original := darwinFixture(t, true)
	store := mustDarwinStore(t, filepath.Join(root, "backups"))
	store.fault = func(stage faultStage) error {
		if stage == faultBeforeReplace {
			return errors.New("injected before replacement")
		}
		return nil
	}
	plan := darwinPlan(t, original, true)
	if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrIO) {
		t.Fatalf("ApplyAtomic(pre-replace fault) error=%v", err)
	}
	assertExactFile(t, location.String(), original)
	store.fault = nil
	if _, err := store.ApplyAtomic(context.Background(), location, plan); err != nil {
		t.Fatalf("ApplyAtomic(pre-replace replay) error=%v", err)
	}
}

func TestPF001DarwinPublicBoundariesRejectInvalidAndCorruptEvidence(t *testing.T) {
	t.Parallel()
	root, location, original := darwinFixture(t, true)
	store := mustDarwinStore(t, filepath.Join(root, "backups"))
	plan := darwinPlan(t, original, true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.ApplyAtomic(ctx, location, plan); !errors.Is(err, context.Canceled) {
		t.Fatalf("ApplyAtomic(cancelled) error=%v", err)
	}
	first, _ := domain.PlanMerge(nil, false, plan.Target(), domain.Digest{})
	noChange, _ := domain.PlanMerge(first.AfterContent(), true, plan.Target(), domain.Digest{})
	if _, err := store.ApplyAtomic(context.Background(), location, noChange); !errors.Is(err, port.ErrInvalidArgument) {
		t.Fatalf("ApplyAtomic(no change) error=%v", err)
	}
	if _, err := store.RestoreBackup(context.Background(), location, port.ApplyReceipt{}); !errors.Is(err, port.ErrInvalidArgument) {
		t.Fatalf("RestoreBackup(invalid receipt) error=%v", err)
	}
	receipt, err := store.ApplyAtomic(context.Background(), location, plan)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if _, err := store.RestoreBackup(ctx, location, receipt); !errors.Is(err, context.Canceled) {
		t.Fatalf("RestoreBackup(cancelled) error=%v", err)
	}
	wrongBinding, err := port.NewApplyReceipt(
		true, true, receipt.BeforeDigest(), receipt.AfterDigest(), receipt.ManagedEntryDigest(),
		filepath.Join(root, "backups", "wrong.json"), receipt.BeforeDigest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RestoreBackup(context.Background(), location, wrongBinding); !errors.Is(err, port.ErrIntegrity) {
		t.Fatalf("RestoreBackup(wrong binding) error=%v", err)
	}
}

func TestPF001DarwinCorruptTransactionAnchorIsRejected(t *testing.T) {
	t.Parallel()
	root, location, original := darwinFixture(t, true)
	backupDirectory := filepath.Join(root, "backups")
	store := mustDarwinStore(t, backupDirectory)
	plan := darwinPlan(t, original, true)
	receipt, err := store.ApplyAtomic(context.Background(), location, plan)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(backupDirectory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "apply-v1-") {
			if err := os.WriteFile(filepath.Join(backupDirectory, entry.Name()), []byte(`{"corrupt":true}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := store.RestoreBackup(context.Background(), location, receipt); !errors.Is(err, port.ErrIntegrity) {
		t.Fatalf("RestoreBackup(corrupt anchor) error=%v", err)
	}
}

func TestPF001DarwinLowLevelDurabilityPrimitivesFailClosed(t *testing.T) {
	t.Parallel()
	root := darwinTempDir(t)
	//nolint:gosec // Owner-only directory mode is required by the test fixture.
	//nolint:gosec // Owner-only directory mode is required by the test fixture.
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	directory, err := openDirectoryPath(root, false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = directory.Close() }()
	fd := int(directory.Fd())
	content := []byte("owner-only")
	if err := writeNamedExact(fd, "value", content, 32); err != nil {
		t.Fatal(err)
	}
	if err := writeNamedExact(fd, "value", content, 32); err != nil {
		t.Fatalf("writeNamedExact(replay) error=%v", err)
	}
	if err := writeNamedExact(fd, "value", []byte("different"), 32); !errors.Is(err, port.ErrIntegrity) {
		t.Fatalf("writeNamedExact(conflict) error=%v", err)
	}
	if err := writeNamedExact(fd, "too-large", make([]byte, 33), 32); !errors.Is(err, port.ErrInvalidArgument) {
		t.Fatalf("writeNamedExact(oversize) error=%v", err)
	}
	if err := ensureImmutableFile(fd, "immutable", content, 32); err != nil {
		t.Fatal(err)
	}
	if err := ensureImmutableFile(fd, "immutable", content, 32); err != nil {
		t.Fatalf("ensureImmutableFile(replay) error=%v", err)
	}
	if err := ensureImmutableFile(fd, "immutable", []byte("different"), 32); !errors.Is(err, port.ErrIntegrity) {
		t.Fatalf("ensureImmutableFile(conflict) error=%v", err)
	}
	if err := writeNamedExact(fd, "replacement.next", []byte("next"), 32); err != nil {
		t.Fatal(err)
	}
	if err := replaceNamedExact(fd, "replacement.next", "replacement", []byte("next"), nil, 32); err != nil {
		t.Fatal(err)
	}
	if err := replaceNamedExact(fd, "missing.next", "created-replacement", []byte("created"), nil, 32); err != nil {
		t.Fatalf("replaceNamedExact(create) error=%v", err)
	}
	if err := writeNamedExact(fd, "conflict.next", []byte("old"), 32); err != nil {
		t.Fatal(err)
	}
	if err := replaceNamedExact(fd, "conflict.next", "ignored", []byte("new"), nil, 32); !errors.Is(err, port.ErrIntegrity) {
		t.Fatalf("replaceNamedExact(conflict) error=%v", err)
	}
	if err := syncNamed(fd, "missing-sync-target"); !errors.Is(err, port.ErrNotFound) {
		t.Fatalf("syncNamed(missing) error=%v", err)
	}
	if err := fsyncFD(-1, "invalid descriptor"); !errors.Is(err, port.ErrIO) {
		t.Fatalf("fsyncFD(invalid) error=%v", err)
	}
	if !errors.Is(mapFilesystemError(unix.ELOOP, "test"), port.ErrUnsafePath) ||
		!errors.Is(mapFilesystemError(unix.ENOENT, "test"), port.ErrNotFound) ||
		!errors.Is(mapFilesystemError(unix.ENOSPC, "test"), port.ErrIO) {
		t.Fatal("filesystem error taxonomy is unstable")
	}
	lock, err := acquireLock(context.Background(), fd)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := acquireLock(ctx, fd); !errors.Is(err, context.Canceled) {
		t.Fatalf("acquireLock(cancelled waiter) error=%v", err)
	}
	releaseLock(lock)
	//nolint:gosec // The test deliberately makes the lock metadata unsafe.
	if err := os.Chmod(filepath.Join(root, lockFileName), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireLock(context.Background(), fd); !errors.Is(err, port.ErrUnsafePath) {
		t.Fatalf("acquireLock(unsafe metadata) error=%v", err)
	}
	metadata := transactionMetadata{
		LocationDigest:     strings.Repeat("a", 64),
		AfterDigest:        domain.DigestBytes([]byte("desired")).String(),
		BeforeDigest:       domain.DigestBytes([]byte("before")).String(),
		ManagedEntryDigest: domain.DigestBytes([]byte("entry")).String(),
	}
	missingAnchor := metadata
	missingAnchor.LocationDigest = strings.Repeat("b", 64)
	if err := markCommitted(fd, missingAnchor); !errors.Is(err, port.ErrIntegrity) {
		t.Fatalf("markCommitted(without prepared anchor) error=%v", err)
	}
	if err := writeNamedExact(fd, metadata.proofName(), []byte("wrong proof"), 32); err != nil {
		t.Fatal(err)
	}
	if err := prepareReplacement(fd, metadata, []byte("desired"), unix.Stat_t{}); !errors.Is(err, port.ErrIntegrity) {
		t.Fatalf("prepareReplacement(wrong proof) error=%v", err)
	}
}

func TestPF001DarwinJournalPrimitivesCoverSecurityFailureBoundaries(t *testing.T) {
	t.Parallel()
	root := darwinTempDir(t)
	//nolint:gosec // Owner-only directory mode is required by the test fixture.
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	directory, err := openDirectoryPath(root, false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = directory.Close() }()
	fd := int(directory.Fd())

	if darwinFilesystemLocal(0) || !darwinFilesystemLocal(unix.MNT_LOCAL) {
		t.Fatal("Darwin network filesystem policy is not fail-closed")
	}
	rootDirectory, err := openDirectoryPath("/", false, false)
	if err != nil {
		t.Fatal(err)
	}
	_ = rootDirectory.Close()
	if _, err := openDirectoryPath("/System/.agentmemory-must-not-create/child", true, true); err == nil ||
		(!errors.Is(err, port.ErrIO) && !errors.Is(err, port.ErrUnsafePath)) {
		t.Fatalf("read-only directory creation error=%v", err)
	}

	metadata := func(marker byte, after []byte) transactionMetadata {
		return transactionMetadata{
			LocationDigest:     strings.Repeat(string(marker), 64),
			BeforeDigest:       domain.DigestBytes([]byte("before")).String(),
			AfterDigest:        domain.DigestBytes(after).String(),
			ManagedEntryDigest: domain.DigestBytes([]byte("entry")).String(),
		}
	}

	unsafeAnchor := metadata('c', []byte("after"))
	if err := writeNamedExact(fd, unsafeAnchor.anchorName(), unsafeAnchor.bytes("prepared"), maximumMetadataLen); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // The test deliberately makes anchor metadata unsafe.
	if err := os.Chmod(filepath.Join(root, unsafeAnchor.anchorName()), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := transactionState(fd, unsafeAnchor); !errors.Is(err, port.ErrUnsafePath) {
		t.Fatalf("unsafe transaction anchor error=%v", err)
	}

	commitConflict := metadata('d', []byte("after"))
	if err := ensurePrepared(fd, commitConflict); err != nil {
		t.Fatal(err)
	}
	if err := writeNamedExact(fd, commitConflict.anchorName()+".commit", []byte("wrong"), maximumMetadataLen); err != nil {
		t.Fatal(err)
	}
	if err := markCommitted(fd, commitConflict); !errors.Is(err, port.ErrIntegrity) {
		t.Fatalf("conflicting commit journal error=%v", err)
	}

	preparedConflict := metadata('e', []byte("desired"))
	if err := writeNamedExact(fd, preparedConflict.newName(), []byte("wrong"), domain.MaxDocumentBytes); err != nil {
		t.Fatal(err)
	}
	if err := prepareReplacement(fd, preparedConflict, []byte("desired"), unix.Stat_t{}); !errors.Is(err, port.ErrIntegrity) {
		t.Fatalf("conflicting replacement error=%v", err)
	}

	digestConflict := metadata('f', []byte("different digest"))
	if err := prepareReplacement(fd, digestConflict, []byte("actual content"), unix.Stat_t{}); !errors.Is(err, port.ErrIntegrity) {
		t.Fatalf("replacement digest mismatch error=%v", err)
	}

	location, err := port.NewConfigLocation(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	plan := darwinPlan(t, []byte("{}"), true)
	cleanupMetadata := newTransactionMetadata(location, plan)
	if err := writeNamedExact(fd, cleanupMetadata.proofName(), []byte("proof"), maximumMetadataLen); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // The test deliberately makes proof metadata unsafe.
	if err := os.Chmod(filepath.Join(root, cleanupMetadata.proofName()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cleanupApplyArtifacts(fd, cleanupMetadata, plan); !errors.Is(err, port.ErrUnsafePath) {
		t.Fatalf("unsafe proof journal cleanup error=%v", err)
	}
	if err := os.Remove(filepath.Join(root, cleanupMetadata.proofName())); err != nil {
		t.Fatal(err)
	}
	if err := writeNamedExact(fd, cleanupMetadata.newName(), plan.AfterContent(), domain.MaxDocumentBytes); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // The test deliberately makes replacement metadata unsafe.
	if err := os.Chmod(filepath.Join(root, cleanupMetadata.newName()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cleanupApplyArtifacts(fd, cleanupMetadata, plan); !errors.Is(err, port.ErrUnsafePath) {
		t.Fatalf("unsafe replacement journal cleanup error=%v", err)
	}

	receipt, err := applyReceipt(root, location, plan)
	if err != nil {
		t.Fatal(err)
	}
	restoreMetadata := metadataFromReceipt(location, receipt)
	if err := cleanupRestoreArtifact(fd, restoreMetadata, receipt); err != nil {
		t.Fatalf("missing restore journal cleanup error=%v", err)
	}
	if err := writeNamedExact(fd, restoreMetadata.restoreName(), plan.AfterContent(), domain.MaxDocumentBytes); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // The test deliberately makes restore metadata unsafe.
	if err := os.Chmod(filepath.Join(root, restoreMetadata.restoreName()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cleanupRestoreArtifact(fd, restoreMetadata, receipt); !errors.Is(err, port.ErrUnsafePath) {
		t.Fatalf("unsafe restore journal cleanup error=%v", err)
	}

	if err := ensureImmutableFile(fd, "oversize", []byte("xx"), 1); !errors.Is(err, port.ErrInvalidArgument) {
		t.Fatalf("oversize immutable journal error=%v", err)
	}
	if err := writeNamedExact(fd, "swap.next", []byte("committed"), 32); err != nil {
		t.Fatal(err)
	}
	if err := writeNamedExact(fd, "swap.target", []byte("prepared"), 32); err != nil {
		t.Fatal(err)
	}
	if err := replaceNamedExact(fd, "swap.next", "swap.target", []byte("committed"), []byte("prepared"), 32); err != nil {
		t.Fatalf("identity-bound metadata exchange error=%v", err)
	}
	assertExactFile(t, filepath.Join(root, "swap.target"), []byte("committed"))
	assertExactFile(t, filepath.Join(root, "swap.next"), []byte("prepared"))

	if err := writeNamedExact(fd, "mismatch.next", []byte("new"), 32); err != nil {
		t.Fatal(err)
	}
	if err := writeNamedExact(fd, "mismatch.target", []byte("old"), 32); err != nil {
		t.Fatal(err)
	}
	if err := replaceNamedExact(fd, "mismatch.next", "mismatch.target", []byte("new"), []byte("expected"), 32); !errors.Is(err, port.ErrIntegrity) {
		t.Fatalf("metadata destination mismatch error=%v", err)
	}

	if err := writeNamedExact(fd, "unsafe.next", []byte("new"), 32); err != nil {
		t.Fatal(err)
	}
	if err := writeNamedExact(fd, "unsafe.target", []byte("old"), 32); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // The test deliberately makes destination metadata unsafe.
	if err := os.Chmod(filepath.Join(root, "unsafe.target"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := replaceNamedExact(fd, "unsafe.next", "unsafe.target", []byte("new"), []byte("old"), 32); !errors.Is(err, port.ErrUnsafePath) {
		t.Fatalf("unsafe metadata destination error=%v", err)
	}

	//nolint:gosec // Test fixture path is constrained to t.TempDir.
	closed, err := os.Create(filepath.Join(root, "closed"))
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writeAndSync(closed, []byte("x")); err == nil {
		t.Fatal("closed durability descriptor accepted a write")
	}
}

func TestPF001DarwinCrashEvidenceAndDefensiveBranchesFailClosed(t *testing.T) {
	t.Parallel()
	t.Run("corrupt prepared proof", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		store := mustDarwinStore(t, filepath.Join(root, "backups"))
		plan := darwinPlan(t, original, true)
		store.fault = func(stage faultStage) error {
			if stage == faultBeforeReplace {
				return errors.New("stop before replacement")
			}
			return nil
		}
		if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrIO) {
			t.Fatalf("faulted apply=%v", err)
		}
		metadata := newTransactionMetadata(location, plan)
		proof := filepath.Join(filepath.Dir(location.String()), metadata.proofName())
		if err := os.WriteFile(proof, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		store.fault = nil
		if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrIntegrity) {
			t.Fatalf("corrupt proof replay=%v", err)
		}
	})
	t.Run("corrupt prepared replacement", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		store := mustDarwinStore(t, filepath.Join(root, "backups"))
		plan := darwinPlan(t, original, true)
		store.fault = func(stage faultStage) error {
			if stage == faultBeforeReplace {
				return errors.New("stop before replacement")
			}
			return nil
		}
		_, _ = store.ApplyAtomic(context.Background(), location, plan)
		metadata := newTransactionMetadata(location, plan)
		replacement := filepath.Join(filepath.Dir(location.String()), metadata.newName())
		if err := os.WriteFile(replacement, []byte("wrong"), 0o600); err != nil {
			t.Fatal(err)
		}
		store.fault = nil
		if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrIntegrity) {
			t.Fatalf("corrupt replacement replay=%v", err)
		}
	})
	t.Run("wrong post-replace identity proof", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		store := mustDarwinStore(t, filepath.Join(root, "backups"))
		plan := darwinPlan(t, original, true)
		store.fault = func(stage faultStage) error {
			if stage == faultAfterReplace {
				return errors.New("stop after replacement")
			}
			return nil
		}
		_, _ = store.ApplyAtomic(context.Background(), location, plan)
		metadata := newTransactionMetadata(location, plan)
		proof := filepath.Join(filepath.Dir(location.String()), metadata.proofName())
		if err := os.WriteFile(proof, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		store.fault = nil
		if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrConflict) {
			t.Fatalf("wrong replay identity=%v", err)
		}
	})
	t.Run("corrupt replay backup", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		backupDirectory := filepath.Join(root, "backups")
		store := mustDarwinStore(t, backupDirectory)
		plan := darwinPlan(t, original, true)
		store.fault = func(stage faultStage) error {
			if stage == faultAfterReplace {
				return errors.New("stop after replacement")
			}
			return nil
		}
		_, _ = store.ApplyAtomic(context.Background(), location, plan)
		backup := filepath.Join(backupDirectory, backupName(location, plan.BeforeDigest()))
		if err := os.WriteFile(backup, []byte("wrong"), 0o600); err != nil {
			t.Fatal(err)
		}
		store.fault = nil
		if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrIntegrity) {
			t.Fatalf("corrupt replay backup=%v", err)
		}
	})
	t.Run("corrupt committed anchor on apply replay", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		backupDirectory := filepath.Join(root, "backups")
		store := mustDarwinStore(t, backupDirectory)
		plan := darwinPlan(t, original, true)
		if _, err := store.ApplyAtomic(context.Background(), location, plan); err != nil {
			t.Fatal(err)
		}
		metadata := newTransactionMetadata(location, plan)
		if err := os.WriteFile(filepath.Join(backupDirectory, metadata.anchorName()), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrIntegrity) {
			t.Fatalf("corrupt apply anchor=%v", err)
		}
	})

	if _, err := openDirectoryPath("", false, false); !errors.Is(err, port.ErrInvalidArgument) {
		t.Fatalf("empty directory path=%v", err)
	}
	missing := filepath.Join(darwinTempDir(t), "missing")
	if _, err := openDirectoryPath(missing, false, false); !errors.Is(err, port.ErrNotFound) {
		t.Fatalf("missing directory path=%v", err)
	}
	if _, _, err := openConfigParent(port.ConfigLocation{}, false); !errors.Is(err, port.ErrInvalidArgument) {
		t.Fatalf("zero config location=%v", err)
	}
	if _, _, err := readOwnedRegular(-1, "missing", 1); !errors.Is(err, port.ErrIO) {
		t.Fatalf("invalid read descriptor=%v", err)
	}
	if err := writeNamedExact(-1, "value", []byte("x"), 1); !errors.Is(err, port.ErrIO) {
		t.Fatalf("invalid write descriptor=%v", err)
	}
	if err := ensureImmutableFile(-1, "value", []byte("x"), 1); !errors.Is(err, port.ErrIO) {
		t.Fatalf("invalid immutable descriptor=%v", err)
	}
	if err := replaceNamedExact(-1, "temporary", "target", []byte("x"), nil, 1); !errors.Is(err, port.ErrIO) {
		t.Fatalf("invalid replace descriptor=%v", err)
	}
	if _, err := acquireLock(context.Background(), -1); !errors.Is(err, port.ErrIO) {
		t.Fatalf("invalid lock descriptor=%v", err)
	}
	if err := renameAt2(-1, "a", -1, "b", 99); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("invalid rename flag=%v", err)
	}
	if err := darwinFullSync(nil); err == nil {
		t.Fatal("nil full-sync descriptor was accepted")
	}
	if err := darwinACLFree(nil); err == nil {
		t.Fatal("nil ACL descriptor was accepted")
	}
	if err := (&DarwinStore{}).acquireProcessLock(context.Background()); !errors.Is(err, port.ErrInvalidArgument) {
		t.Fatalf("unconfigured process lock=%v", err)
	}
	store := mustDarwinStore(t, filepath.Join(darwinTempDir(t), "backups"))
	if err := store.acquireProcessLock(context.Background()); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.acquireProcessLock(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled process lock=%v", err)
	}
	store.releaseProcessLock()
}

func TestPF001DarwinApplyRejectsUnprovenReplayAndUnsafeBackupState(t *testing.T) {
	t.Parallel()
	t.Run("unproven desired bytes", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		store := mustDarwinStore(t, filepath.Join(root, "backups"))
		plan := darwinPlan(t, original, true)
		if err := os.WriteFile(location.String(), plan.AfterContent(), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrConflict) {
			t.Fatalf("ApplyAtomic(unproven replay) error=%v", err)
		}
	})
	t.Run("missing expected original", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		store := mustDarwinStore(t, filepath.Join(root, "backups"))
		plan := darwinPlan(t, original, true)
		if err := os.Remove(location.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrConflict) {
			t.Fatalf("ApplyAtomic(missing original) error=%v", err)
		}
	})
	t.Run("unsafe backup directory", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		backups := filepath.Join(root, "backups")
		if err := os.Mkdir(backups, 0o700); err != nil {
			t.Fatal(err)
		}
		//nolint:gosec // The test deliberately makes the backup directory non-private.
		if err := os.Chmod(backups, 0o755); err != nil {
			t.Fatal(err)
		}
		store := mustDarwinStore(t, backups)
		if _, err := store.ApplyAtomic(context.Background(), location, darwinPlan(t, original, true)); !errors.Is(err, port.ErrUnsafePath) {
			t.Fatalf("ApplyAtomic(unsafe backups) error=%v", err)
		}
	})
	t.Run("post-backup fault", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		store := mustDarwinStore(t, filepath.Join(root, "backups"))
		store.fault = func(stage faultStage) error {
			if stage == faultAfterBackup {
				return errors.New("injected")
			}
			return nil
		}
		if _, err := store.ApplyAtomic(context.Background(), location, darwinPlan(t, original, true)); !errors.Is(err, port.ErrIO) {
			t.Fatalf("ApplyAtomic(post-backup fault) error=%v", err)
		}
		assertExactFile(t, location.String(), original)
	})
}

func TestPF001DarwinAtomicRaceAndBoundaryFailuresPreserveState(t *testing.T) {
	t.Parallel()
	t.Run("external edit during existing exchange", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		store := mustDarwinStore(t, filepath.Join(root, "backups"))
		plan := darwinPlan(t, original, true)
		external := []byte(`{"external":"exchange"}`)
		store.fault = func(stage faultStage) error {
			if stage == faultBeforeReplace {
				if err := os.WriteFile(location.String(), external, 0o600); err != nil {
					return err
				}
			}
			return nil
		}
		if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrConflict) {
			t.Fatalf("exchange CAS race=%v", err)
		}
		assertExactFile(t, location.String(), external)
		metadata := newTransactionMetadata(location, plan)
		assertExactFile(t, filepath.Join(filepath.Dir(location.String()), metadata.newName()), plan.AfterContent())
	})
	t.Run("concurrent create during no-replace", func(t *testing.T) {
		root, location, _ := darwinFixture(t, false)
		store := mustDarwinStore(t, filepath.Join(root, "backups"))
		plan := darwinPlan(t, nil, false)
		external := []byte(`{"external":"create"}`)
		store.fault = func(stage faultStage) error {
			if stage == faultBeforeReplace {
				return os.WriteFile(location.String(), external, 0o600)
			}
			return nil
		}
		if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrConflict) {
			t.Fatalf("create CAS race=%v", err)
		}
		assertExactFile(t, location.String(), external)
	})
	t.Run("external edit after existing exchange remains active", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		store := mustDarwinStore(t, filepath.Join(root, "backups"))
		plan := darwinPlan(t, original, true)
		external := []byte(`{"external":"after exchange"}`)
		store.fault = func(stage faultStage) error {
			if stage == faultAfterExchange {
				return os.WriteFile(location.String(), external, 0o600)
			}
			return nil
		}
		if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrConflict) {
			t.Fatalf("post-exchange CAS race=%v", err)
		}
		assertExactFile(t, location.String(), external)
		metadata := newTransactionMetadata(location, plan)
		assertExactFile(t, filepath.Join(filepath.Dir(location.String()), metadata.newName()), original)
	})
	t.Run("commit anchor changes after replace", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		backupDirectory := filepath.Join(root, "backups")
		store := mustDarwinStore(t, backupDirectory)
		plan := darwinPlan(t, original, true)
		metadata := newTransactionMetadata(location, plan)
		store.fault = func(stage faultStage) error {
			if stage == faultAfterReplace {
				return os.WriteFile(filepath.Join(backupDirectory, metadata.anchorName()), []byte("{}\n"), 0o600)
			}
			return nil
		}
		if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrDurabilityAmbiguous) {
			t.Fatalf("changed commit anchor=%v", err)
		}
	})
	t.Run("unsafe current file", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		//nolint:gosec // Deliberately unsafe permission fixture.
		if err := os.Chmod(location.String(), 0o644); err != nil {
			t.Fatal(err)
		}
		store := mustDarwinStore(t, filepath.Join(root, "backups"))
		if _, err := store.ApplyAtomic(context.Background(), location, darwinPlan(t, original, true)); !errors.Is(err, port.ErrUnsafePath) {
			t.Fatalf("unsafe current apply=%v", err)
		}
	})
	t.Run("unsafe lock file", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		backups := filepath.Join(root, "backups")
		if err := os.Mkdir(backups, 0o700); err != nil {
			t.Fatal(err)
		}
		//nolint:gosec // Deliberately unsafe lock permission fixture.
		if err := os.WriteFile(filepath.Join(backups, lockFileName), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := mustDarwinStore(t, backups).ApplyAtomic(
			context.Background(), location, darwinPlan(t, original, true),
		); !errors.Is(err, port.ErrUnsafePath) {
			t.Fatalf("unsafe lock apply=%v", err)
		}
	})
	t.Run("missing expected parent", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		if err := os.Remove(location.String()); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(filepath.Dir(location.String())); err != nil {
			t.Fatal(err)
		}
		if _, err := mustDarwinStore(t, filepath.Join(root, "backups")).ApplyAtomic(
			context.Background(), location, darwinPlan(t, original, true),
		); !errors.Is(err, port.ErrNotFound) {
			t.Fatalf("missing apply parent=%v", err)
		}
	})
	t.Run("process lock deadline", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		store := mustDarwinStore(t, filepath.Join(root, "backups"))
		if err := store.acquireProcessLock(context.Background()); err != nil {
			t.Fatal(err)
		}
		defer store.releaseProcessLock()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		if _, err := store.ApplyAtomic(ctx, location, darwinPlan(t, original, true)); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("process lock deadline=%v", err)
		}
	})
	t.Run("restore process lock deadline", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		store := mustDarwinStore(t, filepath.Join(root, "backups"))
		receipt, err := store.ApplyAtomic(context.Background(), location, darwinPlan(t, original, true))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.acquireProcessLock(context.Background()); err != nil {
			t.Fatal(err)
		}
		defer store.releaseProcessLock()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		if _, err := store.RestoreBackup(ctx, location, receipt); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("restore process lock deadline=%v", err)
		}
	})
}

func TestPF001DarwinRestoreAtomicRacesRetainBothObjects(t *testing.T) {
	t.Parallel()
	t.Run("existing exchange journals raced edit", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		store := mustDarwinStore(t, filepath.Join(root, "backups"))
		plan := darwinPlan(t, original, true)
		receipt, err := store.ApplyAtomic(context.Background(), location, plan)
		if err != nil {
			t.Fatal(err)
		}
		external := []byte(`{"external":"restore exchange"}`)
		store.fault = func(stage faultStage) error {
			if stage == faultBeforeRestoreReplace {
				return os.WriteFile(location.String(), external, 0o600)
			}
			return nil
		}
		if _, err := store.RestoreBackup(context.Background(), location, receipt); !errors.Is(err, port.ErrConflict) {
			t.Fatalf("restore exchange race=%v", err)
		}
		assertExactFile(t, location.String(), external)
		metadata := metadataFromReceipt(location, receipt)
		assertExactFile(t, filepath.Join(filepath.Dir(location.String()), metadata.restoreName()), original)
	})

	t.Run("absence quarantine journals raced edit", func(t *testing.T) {
		root, location, _ := darwinFixture(t, false)
		store := mustDarwinStore(t, filepath.Join(root, "backups"))
		plan := darwinPlan(t, nil, false)
		receipt, err := store.ApplyAtomic(context.Background(), location, plan)
		if err != nil {
			t.Fatal(err)
		}
		metadata := metadataFromReceipt(location, receipt)
		journal := filepath.Join(filepath.Dir(location.String()), metadata.restoreName())
		external := []byte(`{"external":"quarantine"}`)
		store.fault = func(stage faultStage) error {
			if stage == faultAfterRestoreQuarantine {
				return os.WriteFile(journal, external, 0o600)
			}
			return nil
		}
		if _, err := store.RestoreBackup(context.Background(), location, receipt); !errors.Is(err, port.ErrConflict) {
			t.Fatalf("restore quarantine race=%v", err)
		}
		assertExactFile(t, location.String(), external)
		if _, err := os.Stat(journal); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("republished quarantine journal stat=%v", err)
		}
	})

	t.Run("late existing restore edit remains active", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		store := mustDarwinStore(t, filepath.Join(root, "backups"))
		plan := darwinPlan(t, original, true)
		receipt, err := store.ApplyAtomic(context.Background(), location, plan)
		if err != nil {
			t.Fatal(err)
		}
		external := []byte(`{"external":"after restore exchange"}`)
		store.fault = func(stage faultStage) error {
			if stage == faultAfterRestoreExchange {
				return os.WriteFile(location.String(), external, 0o600)
			}
			return nil
		}
		if _, err := store.RestoreBackup(context.Background(), location, receipt); !errors.Is(err, port.ErrConflict) {
			t.Fatalf("late restore race=%v", err)
		}
		assertExactFile(t, location.String(), external)
		metadata := metadataFromReceipt(location, receipt)
		assertExactFile(t, filepath.Join(filepath.Dir(location.String()), metadata.restoreName()), plan.AfterContent())
	})

	t.Run("concurrent create after quarantine remains at target", func(t *testing.T) {
		root, location, _ := darwinFixture(t, false)
		store := mustDarwinStore(t, filepath.Join(root, "backups"))
		plan := darwinPlan(t, nil, false)
		receipt, err := store.ApplyAtomic(context.Background(), location, plan)
		if err != nil {
			t.Fatal(err)
		}
		external := []byte(`{"external":"concurrent create"}`)
		store.fault = func(stage faultStage) error {
			if stage == faultAfterRestoreJournal {
				return os.WriteFile(location.String(), external, 0o600)
			}
			return nil
		}
		if _, err := store.RestoreBackup(context.Background(), location, receipt); !errors.Is(err, port.ErrConflict) {
			t.Fatalf("restore concurrent create=%v", err)
		}
		assertExactFile(t, location.String(), external)
		metadata := metadataFromReceipt(location, receipt)
		journal := filepath.Join(filepath.Dir(location.String()), metadata.restoreName())
		if _, err := os.Stat(journal); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("archived quarantine source stat=%v", err)
		}
		assertDarwinJournalContains(t, filepath.Dir(location.String()), plan.AfterContent())
	})

	t.Run("interrupted journal phases replay without deletion", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		store := mustDarwinStore(t, filepath.Join(root, "backups"))
		plan := darwinPlan(t, original, true)
		receipt, err := store.ApplyAtomic(context.Background(), location, plan)
		if err != nil {
			t.Fatal(err)
		}
		store.fault = func(stage faultStage) error {
			if stage == faultBeforeRestoreReplace {
				return errors.New("interrupt")
			}
			return nil
		}
		if _, err := store.RestoreBackup(context.Background(), location, receipt); !errors.Is(err, port.ErrIO) {
			t.Fatalf("interrupted existing restore=%v", err)
		}
		store.fault = nil
		if _, err := store.RestoreBackup(context.Background(), location, receipt); err != nil {
			t.Fatalf("existing restore replay=%v", err)
		}

		root, location, _ = darwinFixture(t, false)
		store = mustDarwinStore(t, filepath.Join(root, "backups"))
		plan = darwinPlan(t, nil, false)
		receipt, err = store.ApplyAtomic(context.Background(), location, plan)
		if err != nil {
			t.Fatal(err)
		}
		store.fault = func(stage faultStage) error {
			if stage == faultAfterRestoreQuarantine {
				return errors.New("interrupt")
			}
			return nil
		}
		if _, err := store.RestoreBackup(context.Background(), location, receipt); !errors.Is(err, port.ErrDurabilityAmbiguous) {
			t.Fatalf("interrupted absence restore=%v", err)
		}
		store.fault = nil
		if result, err := store.RestoreBackup(context.Background(), location, receipt); err != nil || result.Exists() {
			t.Fatalf("absence restore replay exists=%t error=%v", result.Exists(), err)
		}
	})
}

func TestPF001DarwinRestoreReplaysCrashArtifactsAndMissingParents(t *testing.T) {
	t.Parallel()
	t.Run("existing restore artifact", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		store := mustDarwinStore(t, filepath.Join(root, "backups"))
		plan := darwinPlan(t, original, true)
		receipt, err := store.ApplyAtomic(context.Background(), location, plan)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.RestoreBackup(context.Background(), location, receipt); err != nil {
			t.Fatal(err)
		}
		metadata := metadataFromReceipt(location, receipt)
		artifactPath := filepath.Join(filepath.Dir(location.String()), metadata.restoreName())
		if err := os.WriteFile(artifactPath, []byte("unrecognized restore bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.RestoreBackup(context.Background(), location, receipt); !errors.Is(err, port.ErrIntegrity) {
			t.Fatalf("RestoreBackup(unrecognized crash artifact) error=%v", err)
		}
		if err := os.Remove(artifactPath); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(artifactPath, plan.AfterContent(), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.RestoreBackup(context.Background(), location, receipt); err != nil {
			t.Fatalf("RestoreBackup(crash artifact) error=%v", err)
		}
		if _, err := os.Stat(artifactPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("archived restore artifact stat=%v", err)
		}
		assertDarwinJournalContains(t, filepath.Dir(location.String()), plan.AfterContent())
	})
	t.Run("absent parent replay", func(t *testing.T) {
		root, location, _ := darwinFixture(t, false)
		store := mustDarwinStore(t, filepath.Join(root, "backups"))
		plan := darwinPlan(t, nil, false)
		receipt, err := store.ApplyAtomic(context.Background(), location, plan)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.RestoreBackup(context.Background(), location, receipt); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(filepath.Dir(location.String())); err != nil {
			t.Fatal(err)
		}
		result, err := store.RestoreBackup(context.Background(), location, receipt)
		if err != nil || result.Exists() {
			t.Fatalf("RestoreBackup(missing absent parent) exists=%t error=%v", result.Exists(), err)
		}
	})
	t.Run("missing existing parent", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		store := mustDarwinStore(t, filepath.Join(root, "backups"))
		receipt, err := store.ApplyAtomic(context.Background(), location, darwinPlan(t, original, true))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(location.String()); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(filepath.Dir(location.String())); err != nil {
			t.Fatal(err)
		}
		if _, err := store.RestoreBackup(context.Background(), location, receipt); !errors.Is(err, port.ErrNotFound) {
			t.Fatalf("RestoreBackup(missing existing parent) error=%v", err)
		}
	})
	t.Run("missing existing file", func(t *testing.T) {
		root, location, original := darwinFixture(t, true)
		store := mustDarwinStore(t, filepath.Join(root, "backups"))
		receipt, err := store.ApplyAtomic(context.Background(), location, darwinPlan(t, original, true))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(location.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := store.RestoreBackup(context.Background(), location, receipt); !errors.Is(err, port.ErrNotFound) {
			t.Fatalf("RestoreBackup(missing existing file) error=%v", err)
		}
	})
	t.Run("occupied absence quarantine", func(t *testing.T) {
		root, location, _ := darwinFixture(t, false)
		store := mustDarwinStore(t, filepath.Join(root, "backups"))
		plan := darwinPlan(t, nil, false)
		receipt, err := store.ApplyAtomic(context.Background(), location, plan)
		if err != nil {
			t.Fatal(err)
		}
		metadata := metadataFromReceipt(location, receipt)
		if err := os.WriteFile(filepath.Join(filepath.Dir(location.String()), metadata.restoreName()), []byte("occupied"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.RestoreBackup(context.Background(), location, receipt); !errors.Is(err, port.ErrIntegrity) {
			t.Fatalf("RestoreBackup(occupied quarantine) error=%v", err)
		}
	})
	t.Run("absence crash after quarantine", func(t *testing.T) {
		root, location, _ := darwinFixture(t, false)
		store := mustDarwinStore(t, filepath.Join(root, "backups"))
		plan := darwinPlan(t, nil, false)
		receipt, err := store.ApplyAtomic(context.Background(), location, plan)
		if err != nil {
			t.Fatal(err)
		}
		metadata := metadataFromReceipt(location, receipt)
		artifactPath := filepath.Join(filepath.Dir(location.String()), metadata.restoreName())
		if err := os.Rename(location.String(), artifactPath); err != nil {
			t.Fatal(err)
		}
		result, err := store.RestoreBackup(context.Background(), location, receipt)
		if err != nil || result.Exists() {
			t.Fatalf("RestoreBackup(quarantined crash) exists=%t error=%v", result.Exists(), err)
		}
		if _, err := os.Stat(artifactPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("archived quarantine source stat=%v", err)
		}
		assertDarwinJournalContains(t, filepath.Dir(location.String()), plan.AfterContent())
	})
}

func TestPF001DarwinRestoreRequiresExistingBackupDirectory(t *testing.T) {
	t.Parallel()
	root, location, original := darwinFixture(t, true)
	plan := darwinPlan(t, original, true)
	store := mustDarwinStore(t, filepath.Join(root, "missing-backups"))
	receipt, err := port.NewApplyReceipt(
		true,
		true,
		plan.BeforeDigest(),
		plan.AfterDigest(),
		plan.ManagedEntryDigest(),
		filepath.Join(root, "missing-backups", backupName(location, plan.BeforeDigest())),
		plan.BeforeDigest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RestoreBackup(context.Background(), location, receipt); !errors.Is(err, port.ErrIntegrity) {
		t.Fatalf("RestoreBackup(missing backup directory) error=%v", err)
	}
}

func darwinFixture(t *testing.T, existing bool) (string, port.ConfigLocation, []byte) {
	t.Helper()
	root := darwinTempDir(t)
	configDirectory := filepath.Join(root, "agent")
	if err := os.Mkdir(configDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(configDirectory, "config.json")
	original := []byte("{\n  \"future\": {\"nested\": true},\n  \"mcpServers\": {\"other\": {\"command\": \"other\"}}\n}\n")
	if existing {
		if err := os.WriteFile(path, original, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	location, err := port.NewConfigLocation(path)
	if err != nil {
		t.Fatal(err)
	}
	return root, location, original
}

func darwinTempDir(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func addDarwinAgentConfigACL(t *testing.T, path string) {
	t.Helper()
	//nolint:gosec // G204: executable and ACL expression are fixed; path is an isolated test fixture; owner=security expiry=2027-07-14.
	command := exec.CommandContext(context.Background(), "/bin/chmod", "+a", "everyone deny delete", path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("add extended ACL: %v: %s", err, output)
	}
	t.Cleanup(func() {
		//nolint:gosec // G204: executable and removal flag are fixed for the isolated fixture; owner=security expiry=2027-07-14.
		_ = exec.CommandContext(context.Background(), "/bin/chmod", "-N", path).Run()
	})
}

func darwinPlan(t *testing.T, original []byte, existed bool) domain.MergePlan {
	t.Helper()
	target, err := domain.NewTarget(darwinInstallationID, darwinEntryID, "/opt/agentmemory/bin/agentmemory", domain.DigestBytes([]byte("signed launcher")))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := domain.PlanMerge(original, existed, target, domain.Digest{})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func mustDarwinStore(t *testing.T, backups string) *DarwinStore {
	t.Helper()
	store, err := NewDarwinStore(backups)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func assertOwnerOnlyRegular(t *testing.T, path string) {
	t.Helper()
	information, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("path stat error=%v", err)
	}
	if !information.Mode().IsRegular() || information.Mode().Perm()&0o077 != 0 {
		t.Fatalf("path mode/type mode=%v", information.Mode())
	}
}

func assertExactFile(t *testing.T, path string, expected []byte) {
	t.Helper()
	//nolint:gosec // Test-only caller-provided fixture paths stay under t.TempDir.
	actual, err := os.ReadFile(path)
	if err != nil || string(actual) != string(expected) {
		t.Fatalf("file error=%v actual=%q expected=%q", err, actual, expected)
	}
}

func assertDarwinJournalContains(t *testing.T, directory string, expected []byte) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".agentmemory-journal-v1-") {
			continue
		}
		//nolint:gosec // Directory entries are enumerated from the isolated test fixture.
		content, readErr := os.ReadFile(filepath.Join(directory, entry.Name()))
		if readErr == nil && string(content) == string(expected) {
			return
		}
	}
	t.Fatalf("no retained Darwin journal contained %q", expected)
}
