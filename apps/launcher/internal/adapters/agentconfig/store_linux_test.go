//go:build linux && (amd64 || arm64)

package agentconfigadapter

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	port "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/agentconfig"
	domain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
)

const (
	linuxInstallationID = "018f0c74-7b5d-7cc1-8a2c-4f1ae7c16a01"
	linuxEntryID        = "018f0c74-7b5d-7cc1-9a2c-4f1ae7c16a02"
)

func TestPF001LinuxApplyBacksUpAtomicallyAndRestoreIsExact(t *testing.T) {
	t.Parallel()
	root, location, original := linuxFixture(t, true)
	store := mustLinuxStore(t, filepath.Join(root, "backups"))
	plan := linuxPlan(t, original, true)

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

func TestPF001LinuxAbsentConfigurationRestoresToAbsence(t *testing.T) {
	t.Parallel()
	root, location, _ := linuxFixture(t, false)
	store := mustLinuxStore(t, filepath.Join(root, "backups"))
	plan := linuxPlan(t, nil, false)
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

func TestPF001LinuxCompareAndSwapPreservesExternalEdits(t *testing.T) {
	t.Parallel()
	root, location, original := linuxFixture(t, true)
	store := mustLinuxStore(t, filepath.Join(root, "backups"))
	plan := linuxPlan(t, original, true)
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

func TestPF001LinuxRejectsSymlinksAndUnsafePermissions(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	realDirectory := filepath.Join(root, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDirectory, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	linked, _ := port.NewConfigLocation(filepath.Join(root, "linked", "config.json"))
	store := mustLinuxStore(t, filepath.Join(root, "backups"))
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

func TestPF001LinuxBackupTamperIsFailClosed(t *testing.T) {
	t.Parallel()
	root, location, original := linuxFixture(t, true)
	store := mustLinuxStore(t, filepath.Join(root, "backups"))
	receipt, err := store.ApplyAtomic(context.Background(), location, linuxPlan(t, original, true))
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

func TestPF001LinuxPostReplaceFailureIsReplayRecoverable(t *testing.T) {
	t.Parallel()
	root, location, original := linuxFixture(t, true)
	store := mustLinuxStore(t, filepath.Join(root, "backups"))
	store.fault = func(stage faultStage) error {
		if stage == faultAfterReplace {
			return errors.New("injected sync boundary failure")
		}
		return nil
	}
	plan := linuxPlan(t, original, true)
	if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrDurabilityAmbiguous) {
		t.Fatalf("ApplyAtomic(fault) error = %v, want ErrDurabilityAmbiguous", err)
	}
	store.fault = nil
	receipt, err := store.ApplyAtomic(context.Background(), location, plan)
	if err != nil || !receipt.AfterDigest().Equal(plan.AfterDigest()) {
		t.Fatalf("ApplyAtomic(replay) receipt error=%v", err)
	}
}

func TestPF001LinuxConcurrentApplyHasOneEffectiveMutation(t *testing.T) {
	t.Parallel()
	root, location, original := linuxFixture(t, true)
	store := mustLinuxStore(t, filepath.Join(root, "backups"))
	plan := linuxPlan(t, original, true)
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

func TestPF001LinuxOperationsHonorCancelledContext(t *testing.T) {
	t.Parallel()
	root, location, _ := linuxFixture(t, false)
	store := mustLinuxStore(t, filepath.Join(root, "backups"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Detect(ctx, location); !errors.Is(err, context.Canceled) {
		t.Fatalf("Detect(cancelled) error = %v", err)
	}
}

func TestPF001LinuxDetectAndReadAreExactAndSideEffectFree(t *testing.T) {
	t.Parallel()
	root, location, original := linuxFixture(t, true)
	store := mustLinuxStore(t, filepath.Join(root, "backups"))
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

func TestPF001LinuxRejectsInvalidStoreAndUnsafeFileMetadata(t *testing.T) {
	t.Parallel()
	for _, invalid := range []string{"", "relative/backups", "/", "/tmp/../tmp/backups", "/tmp/bad\npath"} {
		if _, err := NewLinuxStore(invalid); !errors.Is(err, port.ErrInvalidArgument) {
			t.Fatalf("NewLinuxStore(%q) error=%v", invalid, err)
		}
	}
	root, location, _ := linuxFixture(t, true)
	store := mustLinuxStore(t, filepath.Join(root, "backups"))
	//nolint:gosec // The test deliberately creates a world-readable configuration.
	if err := os.Chmod(location.String(), 0o644); err != nil {
		t.Fatal(err)
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

func TestPF001LinuxPreReplaceFailurePreservesOriginalAndRetries(t *testing.T) {
	t.Parallel()
	root, location, original := linuxFixture(t, true)
	store := mustLinuxStore(t, filepath.Join(root, "backups"))
	store.fault = func(stage faultStage) error {
		if stage == faultBeforeReplace {
			return errors.New("injected before replacement")
		}
		return nil
	}
	plan := linuxPlan(t, original, true)
	if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrIO) {
		t.Fatalf("ApplyAtomic(pre-replace fault) error=%v", err)
	}
	assertExactFile(t, location.String(), original)
	store.fault = nil
	if _, err := store.ApplyAtomic(context.Background(), location, plan); err != nil {
		t.Fatalf("ApplyAtomic(pre-replace replay) error=%v", err)
	}
}

func TestPF001LinuxAtomicRacesPreserveTheActiveExternalState(t *testing.T) {
	t.Parallel()
	t.Run("edit before apply exchange is exchanged back", func(t *testing.T) {
		root, location, original := linuxFixture(t, true)
		store := mustLinuxStore(t, filepath.Join(root, "backups"))
		plan := linuxPlan(t, original, true)
		external := []byte(`{"external":"before apply exchange"}`)
		store.fault = func(stage faultStage) error {
			if stage == faultBeforeReplace {
				return os.WriteFile(location.String(), external, 0o600)
			}
			return nil
		}
		if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrConflict) {
			t.Fatalf("pre-exchange apply race=%v", err)
		}
		assertExactFile(t, location.String(), external)
		metadata := newTransactionMetadata(location, plan)
		assertExactFile(t, filepath.Join(filepath.Dir(location.String()), metadata.newName()), plan.AfterContent())
		store.fault = nil
		if err := os.WriteFile(location.String(), original, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ApplyAtomic(context.Background(), location, plan); err != nil {
			t.Fatalf("conflict retry remained stuck: %v", err)
		}
	})

	t.Run("edit after apply exchange remains active", func(t *testing.T) {
		root, location, original := linuxFixture(t, true)
		store := mustLinuxStore(t, filepath.Join(root, "backups"))
		plan := linuxPlan(t, original, true)
		external := []byte(`{"external":"after apply exchange"}`)
		store.fault = func(stage faultStage) error {
			if stage == faultAfterExchange {
				return os.WriteFile(location.String(), external, 0o600)
			}
			return nil
		}
		if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrConflict) {
			t.Fatalf("post-exchange apply race=%v", err)
		}
		assertExactFile(t, location.String(), external)
		metadata := newTransactionMetadata(location, plan)
		assertExactFile(t, filepath.Join(filepath.Dir(location.String()), metadata.newName()), original)
	})

	t.Run("replacement before apply exchange is exchanged back", func(t *testing.T) {
		root, location, original := linuxFixture(t, true)
		store := mustLinuxStore(t, filepath.Join(root, "backups"))
		plan := linuxPlan(t, original, true)
		external := []byte(`{"external":"replacement before apply"}`)
		retainedOriginal := location.String() + ".original"
		store.fault = func(stage faultStage) error {
			if stage != faultBeforeReplace {
				return nil
			}
			if err := os.Rename(location.String(), retainedOriginal); err != nil {
				return err
			}
			return os.WriteFile(location.String(), external, 0o600)
		}
		if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrConflict) {
			t.Fatalf("replacement apply race=%v", err)
		}
		assertExactFile(t, location.String(), external)
		assertExactFile(t, retainedOriginal, original)
		metadata := newTransactionMetadata(location, plan)
		assertExactFile(t, filepath.Join(filepath.Dir(location.String()), metadata.newName()), plan.AfterContent())
	})

	t.Run("edit before restore exchange is exchanged back", func(t *testing.T) {
		root, location, original := linuxFixture(t, true)
		store := mustLinuxStore(t, filepath.Join(root, "backups"))
		plan := linuxPlan(t, original, true)
		receipt, err := store.ApplyAtomic(context.Background(), location, plan)
		if err != nil {
			t.Fatal(err)
		}
		external := []byte(`{"external":"before restore exchange"}`)
		store.fault = func(stage faultStage) error {
			if stage == faultBeforeRestoreReplace {
				return os.WriteFile(location.String(), external, 0o600)
			}
			return nil
		}
		if _, err := store.RestoreBackup(context.Background(), location, receipt); !errors.Is(err, port.ErrConflict) {
			t.Fatalf("pre-exchange restore race=%v", err)
		}
		assertExactFile(t, location.String(), external)
		metadata := metadataFromReceipt(location, receipt)
		assertExactFile(t, filepath.Join(filepath.Dir(location.String()), metadata.restoreName()), original)
	})

	t.Run("edit after restore exchange remains active", func(t *testing.T) {
		root, location, original := linuxFixture(t, true)
		store := mustLinuxStore(t, filepath.Join(root, "backups"))
		plan := linuxPlan(t, original, true)
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
			t.Fatalf("post-exchange restore race=%v", err)
		}
		assertExactFile(t, location.String(), external)
		metadata := metadataFromReceipt(location, receipt)
		assertExactFile(t, filepath.Join(filepath.Dir(location.String()), metadata.restoreName()), plan.AfterContent())
	})

	t.Run("replacement before restore exchange is exchanged back", func(t *testing.T) {
		root, location, original := linuxFixture(t, true)
		store := mustLinuxStore(t, filepath.Join(root, "backups"))
		plan := linuxPlan(t, original, true)
		receipt, err := store.ApplyAtomic(context.Background(), location, plan)
		if err != nil {
			t.Fatal(err)
		}
		external := []byte(`{"external":"replacement before restore"}`)
		retainedAfter := location.String() + ".agentmemory-after"
		store.fault = func(stage faultStage) error {
			if stage != faultBeforeRestoreReplace {
				return nil
			}
			if err := os.Rename(location.String(), retainedAfter); err != nil {
				return err
			}
			return os.WriteFile(location.String(), external, 0o600)
		}
		if _, err := store.RestoreBackup(context.Background(), location, receipt); !errors.Is(err, port.ErrConflict) {
			t.Fatalf("replacement restore race=%v", err)
		}
		assertExactFile(t, location.String(), external)
		assertExactFile(t, retainedAfter, plan.AfterContent())
		metadata := metadataFromReceipt(location, receipt)
		assertExactFile(t, filepath.Join(filepath.Dir(location.String()), metadata.restoreName()), original)
	})

	t.Run("quarantined edit is republished when target stays absent", func(t *testing.T) {
		root, location, _ := linuxFixture(t, false)
		store := mustLinuxStore(t, filepath.Join(root, "backups"))
		plan := linuxPlan(t, nil, false)
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
			t.Fatalf("quarantine race=%v", err)
		}
		assertExactFile(t, location.String(), external)
		if _, err := os.Stat(journal); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("republished journal stat=%v", err)
		}
	})

	t.Run("concurrent target create keeps quarantine journal", func(t *testing.T) {
		root, location, _ := linuxFixture(t, false)
		store := mustLinuxStore(t, filepath.Join(root, "backups"))
		plan := linuxPlan(t, nil, false)
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
			t.Fatalf("concurrent create race=%v", err)
		}
		assertExactFile(t, location.String(), external)
		metadata := metadataFromReceipt(location, receipt)
		journal := filepath.Join(filepath.Dir(location.String()), metadata.restoreName())
		if _, err := os.Stat(journal); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("archived quarantine source stat=%v", err)
		}
		assertLinuxJournalContains(t, filepath.Dir(location.String()), plan.AfterContent())
	})
}

func TestPF001LinuxApplyRestoreApplyStartsANewDurableTransaction(t *testing.T) {
	t.Parallel()
	root, location, original := linuxFixture(t, true)
	store := mustLinuxStore(t, filepath.Join(root, "backups"))
	plan := linuxPlan(t, original, true)
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

func TestPF001LinuxRejectsHardlinkedFilesAndRemoteFilesystemTypes(t *testing.T) {
	t.Parallel()
	root, location, _ := linuxFixture(t, true)
	if err := os.Link(location.String(), filepath.Join(root, "second-link.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := mustLinuxStore(t, filepath.Join(root, "backups")).Read(context.Background(), location); !errors.Is(err, port.ErrUnsafePath) {
		t.Fatalf("hard-linked config error=%v", err)
	}
	if linuxFilesystemLocal(unix.NFS_SUPER_MAGIC) || linuxFilesystemLocal(unix.CIFS_SUPER_MAGIC) ||
		!linuxFilesystemLocal(unix.EXT4_SUPER_MAGIC) {
		t.Fatal("Linux local-filesystem allowlist accepted a remote filesystem")
	}
}

func TestPF001LinuxPublicBoundariesRejectInvalidAndCorruptEvidence(t *testing.T) {
	t.Parallel()
	root, location, original := linuxFixture(t, true)
	store := mustLinuxStore(t, filepath.Join(root, "backups"))
	plan := linuxPlan(t, original, true)
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

func TestPF001LinuxCorruptTransactionAnchorIsRejected(t *testing.T) {
	t.Parallel()
	root, location, original := linuxFixture(t, true)
	backupDirectory := filepath.Join(root, "backups")
	store := mustLinuxStore(t, backupDirectory)
	plan := linuxPlan(t, original, true)
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

func TestPF001LinuxLowLevelDurabilityPrimitivesFailClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
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
	if !errors.Is(mapFilesystemError(syscall.ELOOP, "test"), port.ErrUnsafePath) ||
		!errors.Is(mapFilesystemError(syscall.ENOENT, "test"), port.ErrNotFound) ||
		!errors.Is(mapFilesystemError(syscall.ENOSPC, "test"), port.ErrIO) {
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
	if err := prepareReplacement(fd, metadata, []byte("desired"), syscall.Stat_t{}); !errors.Is(err, port.ErrIntegrity) {
		t.Fatalf("prepareReplacement(wrong proof) error=%v", err)
	}
}

func TestPF001LinuxJournalAndIdentityPrimitivesFailClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
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

	if linuxACLFree(nil, false) == nil {
		t.Fatal("nil ACL descriptor was accepted")
	}
	if _, err := openDirectoryPath("/", false, false); err != nil {
		t.Fatal(err)
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
		t.Fatalf("unsafe anchor error=%v", err)
	}

	commitConflict := metadata('d', []byte("after"))
	if err := ensurePrepared(fd, commitConflict); err != nil {
		t.Fatal(err)
	}
	if err := writeNamedExact(fd, commitConflict.anchorName()+".commit", []byte("wrong"), maximumMetadataLen); err != nil {
		t.Fatal(err)
	}
	if err := markCommitted(fd, commitConflict); !errors.Is(err, port.ErrIntegrity) {
		t.Fatalf("commit conflict error=%v", err)
	}

	preparedConflict := metadata('e', []byte("desired"))
	if err := writeNamedExact(fd, preparedConflict.newName(), []byte("wrong"), domain.MaxDocumentBytes); err != nil {
		t.Fatal(err)
	}
	if err := prepareReplacement(fd, preparedConflict, []byte("desired"), syscall.Stat_t{}); !errors.Is(err, port.ErrIntegrity) {
		t.Fatalf("replacement conflict error=%v", err)
	}

	digestConflict := metadata('f', []byte("different"))
	if err := prepareReplacement(fd, digestConflict, []byte("actual"), syscall.Stat_t{}); !errors.Is(err, port.ErrIntegrity) {
		t.Fatalf("replacement digest mismatch error=%v", err)
	}

	location, err := port.NewConfigLocation(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	plan := linuxPlan(t, []byte("{}"), true)
	cleanupMetadata := newTransactionMetadata(location, plan)
	if err := writeNamedExact(fd, cleanupMetadata.proofName(), []byte("proof"), maximumMetadataLen); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // The test deliberately makes proof metadata unsafe.
	if err := os.Chmod(filepath.Join(root, cleanupMetadata.proofName()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cleanupApplyArtifacts(fd, cleanupMetadata, plan); !errors.Is(err, port.ErrUnsafePath) {
		t.Fatalf("unsafe proof cleanup error=%v", err)
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
		t.Fatalf("unsafe replacement cleanup error=%v", err)
	}

	receipt, err := applyReceipt(root, location, plan)
	if err != nil {
		t.Fatal(err)
	}
	restoreMetadata := metadataFromReceipt(location, receipt)
	if err := cleanupRestoreArtifact(fd, restoreMetadata, receipt); err != nil {
		t.Fatalf("missing restore journal error=%v", err)
	}
	if err := writeNamedExact(fd, restoreMetadata.restoreName(), plan.AfterContent(), domain.MaxDocumentBytes); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // The test deliberately makes restore metadata unsafe.
	if err := os.Chmod(filepath.Join(root, restoreMetadata.restoreName()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cleanupRestoreArtifact(fd, restoreMetadata, receipt); !errors.Is(err, port.ErrUnsafePath) {
		t.Fatalf("unsafe restore cleanup error=%v", err)
	}

	if err := ensureImmutableFile(fd, "oversize", []byte("xx"), 1); !errors.Is(err, port.ErrInvalidArgument) {
		t.Fatalf("oversize immutable error=%v", err)
	}
	if err := writeNamedExact(fd, "swap.next", []byte("committed"), 32); err != nil {
		t.Fatal(err)
	}
	if err := writeNamedExact(fd, "swap.target", []byte("prepared"), 32); err != nil {
		t.Fatal(err)
	}
	if err := replaceNamedExact(fd, "swap.next", "swap.target", []byte("committed"), []byte("prepared"), 32); err != nil {
		t.Fatalf("metadata exchange error=%v", err)
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
		t.Fatalf("metadata mismatch error=%v", err)
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

	if err := archiveAllowedLinux(fd, "missing", []domain.Digest{domain.DigestBytes([]byte("x"))}, 32); err != nil {
		t.Fatal(err)
	}
	if err := writeNamedExact(fd, "archive-mismatch", []byte("wrong"), 32); err != nil {
		t.Fatal(err)
	}
	if err := archiveAllowedLinux(fd, "archive-mismatch", []domain.Digest{domain.DigestBytes([]byte("expected"))}, 32); !errors.Is(err, port.ErrIntegrity) {
		t.Fatalf("archive allowlist mismatch error=%v", err)
	}
	if err := archiveNamedLinux(-1, "missing", 32); !errors.Is(err, port.ErrIO) {
		t.Fatalf("archive invalid descriptor error=%v", err)
	}
	if err := writeNamedExact(fd, "archive-source", []byte("source"), 32); err != nil {
		t.Fatal(err)
	}
	_, sourceStat, err := readOwnedRegular(fd, "archive-source", 32)
	if err != nil {
		t.Fatal(err)
	}
	archiveName := linuxArchiveName("archive-source", sourceStat.Dev, sourceStat.Ino)
	if err := writeNamedExact(fd, archiveName, []byte("occupied"), 32); err != nil {
		t.Fatal(err)
	}
	if err := archiveNamedLinux(fd, "archive-source", 32); !errors.Is(err, port.ErrIO) {
		t.Fatalf("occupied archive destination error=%v", err)
	}

	if err := syncLinuxConflictState(fd, "missing"); err != nil {
		t.Fatal(err)
	}
	if err := exchangeBackLinux(
		fd, "swap.target", "swap.next", domain.DigestBytes([]byte("wrong")), syscall.Stat_t{}, nil, syscall.Stat_t{},
	); !errors.Is(err, port.ErrConflict) {
		t.Fatalf("changed exchange-back target error=%v", err)
	}
	if err := publishBackLinux(fd, "swap.next", "swap.target", []byte("prepared"), sourceStat); err == nil {
		t.Fatal("occupied quarantine republish unexpectedly succeeded")
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
		t.Fatal("closed file accepted a durability write")
	}
	if err := (&LinuxStore{}).acquireProcessLock(context.Background()); !errors.Is(err, port.ErrInvalidArgument) {
		t.Fatalf("unconfigured process lock error=%v", err)
	}
}

func TestPF001LinuxCrashEvidenceAndDefensiveBranchesFailClosed(t *testing.T) {
	t.Parallel()
	t.Run("corrupt prepared proof", func(t *testing.T) {
		root, location, original := linuxFixture(t, true)
		store := mustLinuxStore(t, filepath.Join(root, "backups"))
		plan := linuxPlan(t, original, true)
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
		root, location, original := linuxFixture(t, true)
		store := mustLinuxStore(t, filepath.Join(root, "backups"))
		plan := linuxPlan(t, original, true)
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
		root, location, original := linuxFixture(t, true)
		store := mustLinuxStore(t, filepath.Join(root, "backups"))
		plan := linuxPlan(t, original, true)
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
		root, location, original := linuxFixture(t, true)
		backupDirectory := filepath.Join(root, "backups")
		store := mustLinuxStore(t, backupDirectory)
		plan := linuxPlan(t, original, true)
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
		root, location, original := linuxFixture(t, true)
		backupDirectory := filepath.Join(root, "backups")
		store := mustLinuxStore(t, backupDirectory)
		plan := linuxPlan(t, original, true)
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
	missing := filepath.Join(t.TempDir(), "missing")
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
	if err := renameAt2(-1, "a", -1, "b", 99); err == nil {
		t.Fatal("invalid rename arguments were accepted")
	}
	if err := (&LinuxStore{}).acquireProcessLock(context.Background()); !errors.Is(err, port.ErrInvalidArgument) {
		t.Fatalf("unconfigured process lock=%v", err)
	}
	store := mustLinuxStore(t, filepath.Join(t.TempDir(), "backups"))
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

func TestPF001LinuxCommittedResetArchivesEveryOperationalJournal(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	configPath := filepath.Join(root, "config")
	backupPath := filepath.Join(root, "backups")
	for _, path := range []string{configPath, backupPath} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	configDirectory, err := openDirectoryPath(configPath, false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = configDirectory.Close() }()
	backupDirectory, err := openDirectoryPath(backupPath, false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = backupDirectory.Close() }()
	location, err := port.NewConfigLocation(filepath.Join(configPath, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	original := []byte("{}")
	plan := linuxPlan(t, original, true)
	metadata := newTransactionMetadata(location, plan)
	proof, err := json.Marshal(replacementProof{
		SchemaVersion:  1,
		AfterDigest:    metadata.AfterDigest,
		OriginalExists: metadata.OriginalExisted,
	})
	if err != nil {
		t.Fatal(err)
	}
	configFD := int(configDirectory.Fd())
	backupFD := int(backupDirectory.Fd())
	for name, content := range map[string][]byte{
		metadata.proofName():   append(proof, '\n'),
		metadata.newName():     plan.BeforeContent(),
		metadata.restoreName(): plan.AfterContent(),
	} {
		if err := writeNamedExact(configFD, name, content, domain.MaxDocumentBytes); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range map[string][]byte{
		metadata.anchorName():             metadata.bytes("committed"),
		metadata.anchorName() + ".commit": metadata.bytes("prepared"),
	} {
		if err := writeNamedExact(backupFD, name, content, maximumMetadataLen); err != nil {
			t.Fatal(err)
		}
	}
	if err := resetCommittedLinuxTransaction(configFD, backupFD, metadata, plan); err != nil {
		t.Fatalf("reset committed transaction=%v", err)
	}
	for _, name := range []string{metadata.proofName(), metadata.newName(), metadata.restoreName()} {
		if _, _, err := readOwnedRegular(configFD, name, domain.MaxDocumentBytes); !errors.Is(err, port.ErrNotFound) {
			t.Fatalf("operational journal %q remains: %v", name, err)
		}
	}
	for _, name := range []string{metadata.anchorName(), metadata.anchorName() + ".commit"} {
		if _, _, err := readOwnedRegular(backupFD, name, maximumMetadataLen); !errors.Is(err, port.ErrNotFound) {
			t.Fatalf("operational anchor %q remains: %v", name, err)
		}
	}
}

func TestPF001LinuxFailureInjectionCoversEveryRecoverableJournalBoundary(t *testing.T) {
	t.Run("unsafe detect", func(t *testing.T) {
		root, location, _ := linuxFixture(t, true)
		//nolint:gosec // The test deliberately makes the configuration world-readable.
		if err := os.Chmod(location.String(), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := mustLinuxStore(t, filepath.Join(root, "backups")).Detect(context.Background(), location); !errors.Is(err, port.ErrUnsafePath) {
			t.Fatalf("unsafe detect=%v", err)
		}
	})

	t.Run("apply process lock and path failures", func(t *testing.T) {
		root, location, original := linuxFixture(t, true)
		plan := linuxPlan(t, original, true)
		var absentStore *LinuxStore
		if _, err := absentStore.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrInvalidArgument) {
			t.Fatalf("nil store apply=%v", err)
		}
		rootLocation, err := port.NewConfigLocation("/config.json")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := mustLinuxStore(t, filepath.Join(root, "backups")).ApplyAtomic(context.Background(), rootLocation, plan); !errors.Is(err, port.ErrInvalidArgument) {
			t.Fatalf("root config apply=%v", err)
		}
	})

	t.Run("unsafe apply lock", func(t *testing.T) {
		root, location, original := linuxFixture(t, true)
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
		if _, err := mustLinuxStore(t, backups).ApplyAtomic(
			context.Background(), location, linuxPlan(t, original, true),
		); !errors.Is(err, port.ErrUnsafePath) {
			t.Fatalf("unsafe apply lock=%v", err)
		}
	})

	t.Run("unsafe current apply", func(t *testing.T) {
		root, location, original := linuxFixture(t, true)
		//nolint:gosec // The test deliberately makes the configuration world-readable.
		if err := os.Chmod(location.String(), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := mustLinuxStore(t, filepath.Join(root, "backups")).ApplyAtomic(
			context.Background(), location, linuxPlan(t, original, true),
		); !errors.Is(err, port.ErrUnsafePath) {
			t.Fatalf("unsafe current apply=%v", err)
		}
	})

	t.Run("replay commit journal conflict", func(t *testing.T) {
		root, location, original := linuxFixture(t, true)
		backups := filepath.Join(root, "backups")
		store := mustLinuxStore(t, backups)
		plan := linuxPlan(t, original, true)
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
	})

	t.Run("replay cleanup rejects unsafe operational journal", func(t *testing.T) {
		root, location, _ := linuxFixture(t, false)
		store := mustLinuxStore(t, filepath.Join(root, "backups"))
		plan := linuxPlan(t, nil, false)
		store.fault = func(stage faultStage) error {
			if stage == faultAfterReplace {
				return errors.New("stop after replacement")
			}
			return nil
		}
		if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrDurabilityAmbiguous) {
			t.Fatalf("faulted absent apply=%v", err)
		}
		metadata := newTransactionMetadata(location, plan)
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

	t.Run("reset rejects corrupt proof", func(t *testing.T) {
		root, location, original := linuxFixture(t, true)
		store := mustLinuxStore(t, filepath.Join(root, "backups"))
		plan := linuxPlan(t, original, true)
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
	})

	t.Run("normal apply rejects backup and proof collisions", func(t *testing.T) {
		for _, proofCollision := range []bool{false, true} {
			root, location, original := linuxFixture(t, true)
			backups := filepath.Join(root, "backups")
			if err := os.Mkdir(backups, 0o700); err != nil {
				t.Fatal(err)
			}
			plan := linuxPlan(t, original, true)
			metadata := newTransactionMetadata(location, plan)
			if proofCollision {
				if err := os.WriteFile(filepath.Join(filepath.Dir(location.String()), metadata.proofName()), []byte("invalid"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(
				filepath.Join(backups, backupName(location, plan.BeforeDigest())), []byte("wrong"), 0o600,
			); err != nil {
				t.Fatal(err)
			}
			if _, err := mustLinuxStore(t, backups).ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrIntegrity) {
				t.Fatalf("proofCollision=%t apply=%v", proofCollision, err)
			}
		}
	})

	t.Run("apply exchange and create publication failures", func(t *testing.T) {
		t.Run("missing exchange replacement", func(t *testing.T) {
			root, location, original := linuxFixture(t, true)
			store := mustLinuxStore(t, filepath.Join(root, "backups"))
			plan := linuxPlan(t, original, true)
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
		})
		t.Run("occupied displaced archive", func(t *testing.T) {
			root, location, original := linuxFixture(t, true)
			store := mustLinuxStore(t, filepath.Join(root, "backups"))
			plan := linuxPlan(t, original, true)
			metadata := newTransactionMetadata(location, plan)
			information, err := os.Lstat(location.String())
			if err != nil {
				t.Fatal(err)
			}
			stat := information.Sys().(*syscall.Stat_t)
			archive := linuxArchiveName(metadata.newName(), stat.Dev, stat.Ino)
			if err := os.WriteFile(filepath.Join(filepath.Dir(location.String()), archive), []byte("occupied"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrDurabilityAmbiguous) {
				t.Fatalf("occupied displaced archive=%v", err)
			}
		})
		for _, createTarget := range []bool{false, true} {
			root, location, _ := linuxFixture(t, false)
			store := mustLinuxStore(t, filepath.Join(root, "backups"))
			plan := linuxPlan(t, nil, false)
			metadata := newTransactionMetadata(location, plan)
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
	})

	t.Run("commit and post-commit cleanup failures", func(t *testing.T) {
		for _, cleanupFailure := range []bool{false, true} {
			root, location, original := linuxFixture(t, true)
			backups := filepath.Join(root, "backups")
			if err := os.Mkdir(backups, 0o700); err != nil {
				t.Fatal(err)
			}
			plan := linuxPlan(t, original, true)
			metadata := newTransactionMetadata(location, plan)
			if cleanupFailure {
				store := mustLinuxStore(t, backups)
				store.fault = func(stage faultStage) error {
					if stage == faultAfterReplace {
						journal := filepath.Join(filepath.Dir(location.String()), metadata.newName())
						if err := os.WriteFile(journal, []byte("wrong"), 0o600); err != nil {
							return err
						}
						return nil
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
			if _, err := mustLinuxStore(t, backups).ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrDurabilityAmbiguous) {
				t.Fatalf("commit journal collision=%v", err)
			}
		}
	})

	t.Run("restore process lock and lock metadata failures", func(t *testing.T) {
		root, location, original := linuxFixture(t, true)
		backups := filepath.Join(root, "backups")
		store := mustLinuxStore(t, backups)
		receipt, err := store.ApplyAtomic(context.Background(), location, linuxPlan(t, original, true))
		if err != nil {
			t.Fatal(err)
		}
		var absentStore *LinuxStore
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
	})

	t.Run("restore replay rejects unsafe journal", func(t *testing.T) {
		for _, originalExisted := range []bool{false, true} {
			root, location, original := linuxFixture(t, originalExisted)
			store := mustLinuxStore(t, filepath.Join(root, "backups"))
			if !originalExisted {
				original = nil
			}
			plan := linuxPlan(t, original, originalExisted)
			receipt, err := store.ApplyAtomic(context.Background(), location, plan)
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

	t.Run("restore existing exchange failures", func(t *testing.T) {
		for _, scenario := range []string{"occupied", "before-fault", "missing", "after-fault", "archive"} {
			root, location, original := linuxFixture(t, true)
			store := mustLinuxStore(t, filepath.Join(root, "backups"))
			plan := linuxPlan(t, original, true)
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
			case "before-fault":
				store.fault = func(stage faultStage) error {
					if stage == faultBeforeRestoreReplace {
						return errors.New("stop before restore")
					}
					return nil
				}
			case "missing":
				store.fault = func(stage faultStage) error {
					if stage == faultBeforeRestoreReplace {
						return os.Remove(journal)
					}
					return nil
				}
			case "after-fault":
				store.fault = func(stage faultStage) error {
					if stage == faultAfterRestoreExchange {
						return errors.New("stop after restore exchange")
					}
					return nil
				}
			case "archive":
				information, statErr := os.Lstat(location.String())
				if statErr != nil {
					t.Fatal(statErr)
				}
				stat := information.Sys().(*syscall.Stat_t)
				archive := linuxArchiveName(metadata.restoreName(), stat.Dev, stat.Ino)
				if err := os.WriteFile(filepath.Join(filepath.Dir(location.String()), archive), []byte("occupied"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.RestoreBackup(context.Background(), location, receipt); err == nil {
				t.Fatalf("scenario=%s restore succeeded", scenario)
			}
		}
	})

	t.Run("restore absence fault and archive boundaries", func(t *testing.T) {
		for _, scenario := range []string{"quarantine-fault", "publish-occupied", "journal-fault", "archive-occupied", "unsafe-target"} {
			root, location, _ := linuxFixture(t, false)
			store := mustLinuxStore(t, filepath.Join(root, "backups"))
			plan := linuxPlan(t, nil, false)
			receipt, err := store.ApplyAtomic(context.Background(), location, plan)
			if err != nil {
				t.Fatal(err)
			}
			metadata := metadataFromReceipt(location, receipt)
			journal := filepath.Join(filepath.Dir(location.String()), metadata.restoreName())
			if scenario == "archive-occupied" {
				information, statErr := os.Lstat(location.String())
				if statErr != nil {
					t.Fatal(statErr)
				}
				stat := information.Sys().(*syscall.Stat_t)
				archive := linuxArchiveName(metadata.restoreName(), stat.Dev, stat.Ino)
				if err := os.WriteFile(filepath.Join(filepath.Dir(location.String()), archive), []byte("occupied"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			store.fault = func(stage faultStage) error {
				switch scenario {
				case "quarantine-fault":
					if stage == faultAfterRestoreQuarantine {
						return errors.New("stop after quarantine")
					}
				case "publish-occupied":
					if stage == faultAfterRestoreQuarantine {
						if err := os.WriteFile(journal, []byte("changed"), 0o600); err != nil {
							return err
						}
						return os.WriteFile(location.String(), []byte("external"), 0o600)
					}
				case "journal-fault":
					if stage == faultAfterRestoreJournal {
						return errors.New("stop before quarantine archive")
					}
				case "unsafe-target":
					if stage == faultAfterRestoreJournal {
						return os.Symlink("external", location.String())
					}
				}
				return nil
			}
			if _, err := store.RestoreBackup(context.Background(), location, receipt); err == nil {
				t.Fatalf("scenario=%s restore succeeded", scenario)
			}
		}
	})
}

func TestPF001LinuxPrimitiveFailureTaxonomyCoversUnsafeInputs(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
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

	if _, err := openDirectoryPath("/proc/agentmemory-must-not-create/child", true, true); err == nil {
		t.Fatal("read-only pseudo-filesystem directory creation succeeded")
	}
	//nolint:gosec // Test fixture path is constrained to t.TempDir.
	closed, err := os.Create(filepath.Join(root, "closed-acl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := linuxACLFree(closed, false); err == nil {
		t.Fatal("closed ACL descriptor was accepted")
	}
	if err := writeNamedExact(fd, "unsafe-archive", []byte("value"), 32); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // The test deliberately makes archive metadata unsafe.
	if err := os.Chmod(filepath.Join(root, "unsafe-archive"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := archiveAllowedLinux(fd, "unsafe-archive", []domain.Digest{domain.DigestBytes([]byte("value"))}, 32); !errors.Is(err, port.ErrUnsafePath) {
		t.Fatalf("unsafe archive=%v", err)
	}
	if err := replaceNamedExact(fd, "oversize.next", "oversize.target", []byte("xx"), nil, 1); !errors.Is(err, port.ErrInvalidArgument) {
		t.Fatalf("oversize replacement=%v", err)
	}
	if err := writeNamedExact(fd, "publish.next", []byte("value"), 32); err != nil {
		t.Fatal(err)
	}
	if err := replaceNamedExact(fd, "publish.next", "missing/target", []byte("value"), nil, 32); err == nil {
		t.Fatal("publication into missing child succeeded")
	}
	if err := writeNamedExact(fd, "exchange.target", []byte("target"), 32); err != nil {
		t.Fatal(err)
	}
	content, stat, err := readOwnedRegular(fd, "exchange.target", 32)
	if err != nil {
		t.Fatal(err)
	}
	if err := exchangeBackLinux(
		fd,
		"exchange.target",
		"missing-displaced",
		domain.DigestBytes(content),
		stat,
		content,
		stat,
	); err == nil {
		t.Fatal("exchange-back with missing displaced journal succeeded")
	}
	//nolint:gosec // The test deliberately makes conflict metadata unsafe.
	if err := os.Chmod(filepath.Join(root, "exchange.target"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := syncLinuxConflictState(fd, "exchange.target"); !errors.Is(err, port.ErrUnsafePath) {
		t.Fatalf("unsafe conflict journal sync=%v", err)
	}
}

func TestPF001LinuxApplyRejectsUnprovenReplayAndUnsafeBackupState(t *testing.T) {
	t.Parallel()
	t.Run("unproven desired bytes", func(t *testing.T) {
		root, location, original := linuxFixture(t, true)
		store := mustLinuxStore(t, filepath.Join(root, "backups"))
		plan := linuxPlan(t, original, true)
		if err := os.WriteFile(location.String(), plan.AfterContent(), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrConflict) {
			t.Fatalf("ApplyAtomic(unproven replay) error=%v", err)
		}
	})
	t.Run("missing expected original", func(t *testing.T) {
		root, location, original := linuxFixture(t, true)
		store := mustLinuxStore(t, filepath.Join(root, "backups"))
		plan := linuxPlan(t, original, true)
		if err := os.Remove(location.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrConflict) {
			t.Fatalf("ApplyAtomic(missing original) error=%v", err)
		}
	})
	t.Run("unsafe backup directory", func(t *testing.T) {
		root, location, original := linuxFixture(t, true)
		backups := filepath.Join(root, "backups")
		if err := os.Mkdir(backups, 0o700); err != nil {
			t.Fatal(err)
		}
		//nolint:gosec // The test deliberately makes the backup directory non-private.
		if err := os.Chmod(backups, 0o755); err != nil {
			t.Fatal(err)
		}
		store := mustLinuxStore(t, backups)
		if _, err := store.ApplyAtomic(context.Background(), location, linuxPlan(t, original, true)); !errors.Is(err, port.ErrUnsafePath) {
			t.Fatalf("ApplyAtomic(unsafe backups) error=%v", err)
		}
	})
	t.Run("post-backup fault", func(t *testing.T) {
		root, location, original := linuxFixture(t, true)
		store := mustLinuxStore(t, filepath.Join(root, "backups"))
		store.fault = func(stage faultStage) error {
			if stage == faultAfterBackup {
				return errors.New("injected")
			}
			return nil
		}
		if _, err := store.ApplyAtomic(context.Background(), location, linuxPlan(t, original, true)); !errors.Is(err, port.ErrIO) {
			t.Fatalf("ApplyAtomic(post-backup fault) error=%v", err)
		}
		assertExactFile(t, location.String(), original)
	})
}

func TestPF001LinuxRestoreReplaysCrashArtifactsAndMissingParents(t *testing.T) {
	t.Parallel()
	t.Run("existing restore artifact", func(t *testing.T) {
		root, location, original := linuxFixture(t, true)
		store := mustLinuxStore(t, filepath.Join(root, "backups"))
		plan := linuxPlan(t, original, true)
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
			t.Fatalf("restore artifact remains: %v", err)
		}
	})
	t.Run("absent parent replay", func(t *testing.T) {
		root, location, _ := linuxFixture(t, false)
		store := mustLinuxStore(t, filepath.Join(root, "backups"))
		plan := linuxPlan(t, nil, false)
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
		root, location, original := linuxFixture(t, true)
		store := mustLinuxStore(t, filepath.Join(root, "backups"))
		receipt, err := store.ApplyAtomic(context.Background(), location, linuxPlan(t, original, true))
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
		root, location, original := linuxFixture(t, true)
		store := mustLinuxStore(t, filepath.Join(root, "backups"))
		receipt, err := store.ApplyAtomic(context.Background(), location, linuxPlan(t, original, true))
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
		root, location, _ := linuxFixture(t, false)
		store := mustLinuxStore(t, filepath.Join(root, "backups"))
		plan := linuxPlan(t, nil, false)
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
		root, location, _ := linuxFixture(t, false)
		store := mustLinuxStore(t, filepath.Join(root, "backups"))
		plan := linuxPlan(t, nil, false)
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
			t.Fatalf("quarantined crash artifact remains: %v", err)
		}
	})
}

func TestPF001LinuxRestoreRequiresExistingBackupDirectory(t *testing.T) {
	t.Parallel()
	root, location, original := linuxFixture(t, true)
	plan := linuxPlan(t, original, true)
	store := mustLinuxStore(t, filepath.Join(root, "missing-backups"))
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

func linuxFixture(t *testing.T, existing bool) (string, port.ConfigLocation, []byte) {
	t.Helper()
	root := t.TempDir()
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

func linuxPlan(t *testing.T, original []byte, existed bool) domain.MergePlan {
	t.Helper()
	target, err := domain.NewTarget(linuxInstallationID, linuxEntryID, "/opt/agentmemory/bin/agentmemory", domain.DigestBytes([]byte("signed launcher")))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := domain.PlanMerge(original, existed, target, domain.Digest{})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func mustLinuxStore(t *testing.T, backups string) *LinuxStore {
	t.Helper()
	store, err := NewLinuxStore(backups)
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

func assertLinuxJournalContains(t *testing.T, directory string, expected []byte) {
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
	t.Fatalf("no retained Linux journal contained %q", expected)
}
