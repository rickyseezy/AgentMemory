//go:build windows

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

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	port "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/agentconfig"
	domain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
)

const (
	windowsInstallationID = "018f0c74-7b5d-7cc1-8a2c-4f1ae7c16a01"
	windowsEntryID        = "018f0c74-7b5d-7cc1-9a2c-4f1ae7c16a02"
)

func TestPF001WindowsAgentConfigApplyBackupAndExactRestore(t *testing.T) {
	root, location, original := windowsAgentConfigFixture(t, true)
	store := mustWindowsStore(t, filepath.Join(root, "backups"))
	plan := windowsAgentConfigPlan(t, original, true)
	receipt, err := store.ApplyAtomic(context.Background(), location, plan)
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.Valid() || !receipt.OriginalExisted() || !receipt.BackupDigest().Equal(plan.BeforeDigest()) {
		t.Fatal("Windows apply receipt did not bind the backup")
	}
	configured, err := store.Read(context.Background(), location)
	if err != nil || !configured.Digest().Equal(plan.AfterDigest()) {
		t.Fatalf("configured snapshot error=%v", err)
	}
	restored, err := store.RestoreBackup(context.Background(), location, receipt)
	if err != nil || !restored.Exists() || !restored.Digest().Equal(plan.BeforeDigest()) {
		t.Fatalf("restore receipt=%v error=%v", restored.Valid(), err)
	}
	actual, _ := os.ReadFile(location.String())
	if string(actual) != string(original) {
		t.Fatal("Windows restore changed original bytes")
	}
	if _, err := store.RestoreBackup(context.Background(), location, receipt); err != nil {
		t.Fatalf("restore replay: %v", err)
	}
}

func TestPF001WindowsAgentConfigApplyRestoreApplyStartsNewTransaction(t *testing.T) {
	root, location, original := windowsAgentConfigFixture(t, true)
	store := mustWindowsStore(t, filepath.Join(root, "backups"))
	plan := windowsAgentConfigPlan(t, original, true)
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
	configured, err := os.ReadFile(location.String())
	if err != nil || !domain.DigestBytes(configured).Equal(plan.AfterDigest()) {
		t.Fatalf("second apply content error=%v", err)
	}
}

func TestPF001WindowsAgentConfigAbsentRestoreAndCAS(t *testing.T) {
	t.Run("absence", func(t *testing.T) {
		root, location, _ := windowsAgentConfigFixture(t, false)
		store := mustWindowsStore(t, filepath.Join(root, "backups"))
		plan := windowsAgentConfigPlan(t, nil, false)
		receipt, err := store.ApplyAtomic(context.Background(), location, plan)
		if err != nil {
			t.Fatal(err)
		}
		restored, err := store.RestoreBackup(context.Background(), location, receipt)
		if err != nil || restored.Exists() {
			t.Fatalf("absence restore exists=%t error=%v", restored.Exists(), err)
		}
		if _, err := os.Stat(location.String()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("absence restore stat=%v", err)
		}
	})
	t.Run("external edits", func(t *testing.T) {
		root, location, original := windowsAgentConfigFixture(t, true)
		store := mustWindowsStore(t, filepath.Join(root, "backups"))
		plan := windowsAgentConfigPlan(t, original, true)
		external := []byte(`{"external":"before"}`)
		if err := overwriteWindowsFixture(location.String(), external); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrConflict) {
			t.Fatalf("stale apply error=%v", err)
		}
		if err := overwriteWindowsFixture(location.String(), original); err != nil {
			t.Fatal(err)
		}
		receipt, err := store.ApplyAtomic(context.Background(), location, plan)
		if err != nil {
			t.Fatal(err)
		}
		external = []byte(`{"external":"after"}`)
		if err := overwriteWindowsFixture(location.String(), external); err != nil {
			t.Fatal(err)
		}
		if _, err := store.RestoreBackup(context.Background(), location, receipt); !errors.Is(err, port.ErrConflict) {
			t.Fatalf("stale restore error=%v", err)
		}
		actual, _ := os.ReadFile(location.String())
		if string(actual) != string(external) {
			t.Fatal("external Windows edit was overwritten")
		}
	})
}

func TestPF001WindowsAgentConfigRejectsReparseHardlinkADSAndForeignDACL(t *testing.T) {
	t.Run("directory junction", func(t *testing.T) {
		root, location, _ := windowsAgentConfigFixture(t, true)
		linked := filepath.Join(root, "linked-agent")
		//nolint:gosec // G204: fixed cmd/mklink operation with TempDir-scoped arguments; owner=security expiry=2027-07-14.
		command := exec.CommandContext(context.Background(), "cmd.exe", "/d", "/c", "mklink", "/J", linked, filepath.Dir(location.String()))
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("create test junction: %v: %s", err, output)
		}
		linkedLocation, _ := port.NewConfigLocation(filepath.Join(linked, filepath.Base(location.String())))
		if _, err := mustWindowsStore(t, filepath.Join(root, "backups")).Detect(context.Background(), linkedLocation); !errors.Is(err, port.ErrUnsafePath) {
			t.Fatalf("junction detection error=%v", err)
		}
	})
	t.Run("hardlink", func(t *testing.T) {
		root, location, _ := windowsAgentConfigFixture(t, true)
		if err := os.Link(location.String(), filepath.Join(root, "second-link.json")); err != nil {
			t.Fatal(err)
		}
		if _, err := mustWindowsStore(t, filepath.Join(root, "backups")).Read(context.Background(), location); err == nil {
			t.Fatal("multiply-linked Windows configuration was accepted")
		}
	})
	t.Run("alternate data stream", func(t *testing.T) {
		root, location, _ := windowsAgentConfigFixture(t, true)
		stream, err := os.OpenFile(location.String()+":attack", os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_ = stream.Close()
		if _, err := mustWindowsStore(t, filepath.Join(root, "backups")).Read(context.Background(), location); err == nil {
			t.Fatal("Windows configuration with ADS was accepted")
		}
	})
	t.Run("default DACL", func(t *testing.T) {
		root, location, _ := windowsAgentConfigFixture(t, false)
		if err := os.WriteFile(location.String(), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := mustWindowsStore(t, filepath.Join(root, "backups")).Read(context.Background(), location); err == nil {
			t.Fatal("default-DACL Windows configuration was accepted")
		}
	})
}

func TestPF001WindowsAgentConfigReplaysCrashAndSerializes(t *testing.T) {
	root, location, original := windowsAgentConfigFixture(t, true)
	store := mustWindowsStore(t, filepath.Join(root, "backups"))
	plan := windowsAgentConfigPlan(t, original, true)
	store.fault = func(stage faultStage) error {
		if stage == faultAfterReplace {
			return errors.New("injected")
		}
		return nil
	}
	if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrDurabilityAmbiguous) {
		t.Fatalf("post-replace fault=%v", err)
	}
	store.fault = nil
	if _, err := store.ApplyAtomic(context.Background(), location, plan); err != nil {
		t.Fatalf("apply replay=%v", err)
	}

	root, location, original = windowsAgentConfigFixture(t, true)
	store = mustWindowsStore(t, filepath.Join(root, "backups"))
	plan = windowsAgentConfigPlan(t, original, true)
	var group sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := store.ApplyAtomic(context.Background(), location, plan)
			results <- err
		}()
	}
	group.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent Windows apply=%v", err)
		}
	}
}

func TestPF001WindowsAgentConfigRetainsExternalWritersAcrossAtomicRaces(t *testing.T) {
	t.Run("apply exchange retains raced edit as journal evidence", func(t *testing.T) {
		root, location, original := windowsAgentConfigFixture(t, true)
		store := mustWindowsStore(t, filepath.Join(root, "backups"))
		plan := windowsAgentConfigPlan(t, original, true)
		external := []byte(`{"external":"apply exchange"}`)
		store.fault = func(stage faultStage) error {
			if stage == faultBeforeReplace {
				return overwriteWindowsFixture(location.String(), external)
			}
			return nil
		}
		if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrConflict) {
			t.Fatalf("apply race error=%v", err)
		}
		assertWindowsExactFile(t, location.String(), external)
		metadata := newWindowsTransactionMetadata(location, plan)
		assertWindowsExactFile(t, filepath.Join(filepath.Dir(location.String()), metadata.newName()), plan.AfterContent())
	})

	t.Run("restore exchange retains raced edit as journal evidence", func(t *testing.T) {
		root, location, original := windowsAgentConfigFixture(t, true)
		store := mustWindowsStore(t, filepath.Join(root, "backups"))
		plan := windowsAgentConfigPlan(t, original, true)
		receipt, err := store.ApplyAtomic(context.Background(), location, plan)
		if err != nil {
			t.Fatal(err)
		}
		external := []byte(`{"external":"restore exchange"}`)
		store.fault = func(stage faultStage) error {
			if stage == faultBeforeRestoreReplace {
				return overwriteWindowsFixture(location.String(), external)
			}
			return nil
		}
		if _, err := store.RestoreBackup(context.Background(), location, receipt); !errors.Is(err, port.ErrConflict) {
			t.Fatalf("restore race error=%v", err)
		}
		assertWindowsExactFile(t, location.String(), external)
		metadata := windowsMetadataFromReceipt(location, receipt)
		assertWindowsExactFile(t, filepath.Join(filepath.Dir(location.String()), metadata.restoreName()), original)
	})

	t.Run("absence restore retains raced edit in quarantine", func(t *testing.T) {
		root, location, _ := windowsAgentConfigFixture(t, false)
		store := mustWindowsStore(t, filepath.Join(root, "backups"))
		plan := windowsAgentConfigPlan(t, nil, false)
		receipt, err := store.ApplyAtomic(context.Background(), location, plan)
		if err != nil {
			t.Fatal(err)
		}
		external := []byte(`{"external":"quarantine"}`)
		store.fault = func(stage faultStage) error {
			if stage == faultAfterRestoreQuarantine {
				metadata := windowsMetadataFromReceipt(location, receipt)
				return overwriteWindowsFixture(filepath.Join(filepath.Dir(location.String()), metadata.restoreName()), external)
			}
			return nil
		}
		if _, err := store.RestoreBackup(context.Background(), location, receipt); !errors.Is(err, port.ErrConflict) {
			t.Fatalf("absence race error=%v", err)
		}
		assertWindowsExactFile(t, location.String(), external)
		metadata := windowsMetadataFromReceipt(location, receipt)
		if _, err := os.Stat(filepath.Join(filepath.Dir(location.String()), metadata.restoreName())); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("republished quarantine journal stat=%v", err)
		}
	})

	t.Run("late apply edit remains active", func(t *testing.T) {
		root, location, original := windowsAgentConfigFixture(t, true)
		store := mustWindowsStore(t, filepath.Join(root, "backups"))
		plan := windowsAgentConfigPlan(t, original, true)
		external := []byte(`{"external":"late apply"}`)
		store.fault = func(stage faultStage) error {
			if stage == faultAfterExchange {
				return overwriteWindowsFixture(location.String(), external)
			}
			return nil
		}
		if _, err := store.ApplyAtomic(context.Background(), location, plan); !errors.Is(err, port.ErrConflict) {
			t.Fatalf("late apply race error=%v", err)
		}
		assertWindowsExactFile(t, location.String(), external)
		metadata := newWindowsTransactionMetadata(location, plan)
		assertWindowsExactFile(t, filepath.Join(filepath.Dir(location.String()), metadata.oldName()), original)
	})

	t.Run("late restore edit remains active", func(t *testing.T) {
		root, location, original := windowsAgentConfigFixture(t, true)
		store := mustWindowsStore(t, filepath.Join(root, "backups"))
		plan := windowsAgentConfigPlan(t, original, true)
		receipt, err := store.ApplyAtomic(context.Background(), location, plan)
		if err != nil {
			t.Fatal(err)
		}
		external := []byte(`{"external":"late restore"}`)
		store.fault = func(stage faultStage) error {
			if stage == faultAfterRestoreExchange {
				return overwriteWindowsFixture(location.String(), external)
			}
			return nil
		}
		if _, err := store.RestoreBackup(context.Background(), location, receipt); !errors.Is(err, port.ErrConflict) {
			t.Fatalf("late restore race error=%v", err)
		}
		assertWindowsExactFile(t, location.String(), external)
		metadata := windowsMetadataFromReceipt(location, receipt)
		assertWindowsExactFile(t, filepath.Join(filepath.Dir(location.String()), metadata.restoreDisplacedName()), plan.AfterContent())
	})

	t.Run("concurrent create after quarantine remains at target", func(t *testing.T) {
		root, location, _ := windowsAgentConfigFixture(t, false)
		store := mustWindowsStore(t, filepath.Join(root, "backups"))
		plan := windowsAgentConfigPlan(t, nil, false)
		receipt, err := store.ApplyAtomic(context.Background(), location, plan)
		if err != nil {
			t.Fatal(err)
		}
		external := []byte(`{"external":"concurrent create"}`)
		store.fault = func(stage faultStage) error {
			if stage == faultAfterRestoreJournal {
				return writeWindowsPrivateFixture(location.String(), external)
			}
			return nil
		}
		if _, err := store.RestoreBackup(context.Background(), location, receipt); !errors.Is(err, port.ErrConflict) {
			t.Fatalf("concurrent create error=%v", err)
		}
		assertWindowsExactFile(t, location.String(), external)
		assertWindowsJournalContains(t, filepath.Dir(location.String()), plan.AfterContent())
	})
}

func TestPF001WindowsAgentConfigRejectsInvalidEvidenceAndCancellation(t *testing.T) {
	for _, invalid := range []string{"", `relative\\backups`, `C:\\`, `\\\\server\\share\\backups`, `C:\\bad:ads`} {
		if _, err := NewWindowsStore(invalid); !errors.Is(err, port.ErrInvalidArgument) {
			t.Fatalf("NewWindowsStore(%q)=%v", invalid, err)
		}
	}
	root, location, original := windowsAgentConfigFixture(t, true)
	store := mustWindowsStore(t, filepath.Join(root, "backups"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Detect(ctx, location); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled detect=%v", err)
	}
	if _, err := store.ApplyAtomic(ctx, location, windowsAgentConfigPlan(t, original, true)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled apply=%v", err)
	}
	if _, err := store.RestoreBackup(context.Background(), location, port.ApplyReceipt{}); !errors.Is(err, port.ErrInvalidArgument) {
		t.Fatalf("invalid restore receipt=%v", err)
	}
}

func windowsAgentConfigFixture(t *testing.T, existing bool) (string, port.ConfigLocation, []byte) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "private")
	if err := windowssecurity.CreatePrivateDirectory(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	configDirectory := filepath.Join(root, "agent")
	if err := windowssecurity.CreatePrivateDirectory(context.Background(), configDirectory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(configDirectory, "config.json")
	original := []byte("{\n  \"future\": true,\n  \"mcpServers\": {\"other\": {\"command\": \"other\"}}\n}\n")
	if existing {
		file, err := windowssecurity.CreatePrivateFile(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(original); err != nil {
			t.Fatal(err)
		}
		if err := windowssecurity.Flush(file); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	location, err := port.NewConfigLocation(path)
	if err != nil {
		t.Fatal(err)
	}
	return root, location, original
}

func windowsAgentConfigPlan(t *testing.T, original []byte, existed bool) domain.MergePlan {
	t.Helper()
	target, err := domain.NewTarget(
		windowsInstallationID,
		windowsEntryID,
		`C:\\AgentMemory\\agentmemory.exe`,
		domain.DigestBytes([]byte("signed launcher")),
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := domain.PlanMerge(original, existed, target, domain.Digest{})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func mustWindowsStore(t *testing.T, backups string) *WindowsStore {
	t.Helper()
	store, err := NewWindowsStore(backups)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func overwriteWindowsFixture(path string, content []byte) error {
	//nolint:gosec // Test fixture path is constrained to t.TempDir.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	if err := windowssecurity.Flush(file); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func writeWindowsPrivateFixture(path string, content []byte) error {
	file, err := windowssecurity.CreatePrivateFile(context.Background(), path)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	if err := windowssecurity.Flush(file); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func assertWindowsExactFile(t *testing.T, path string, expected []byte) {
	t.Helper()
	//nolint:gosec // Test fixture path is constrained to t.TempDir.
	actual, err := os.ReadFile(path)
	if err != nil || string(actual) != string(expected) {
		t.Fatalf("file error=%v actual=%q expected=%q", err, actual, expected)
	}
}

func assertWindowsJournalContains(t *testing.T, directory string, expected []byte) {
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
	t.Fatalf("no retained Windows journal contained %q", expected)
}

func TestPF001WindowsAgentConfigErrorTextDoesNotExposePaths(t *testing.T) {
	privatePath := `C:\Users\private-user\secret\config.json`
	location, _ := port.NewConfigLocation(privatePath)
	store := mustWindowsStore(t, `C:\AgentMemory\backups`)
	_, err := store.Read(context.Background(), location)
	if err != nil && strings.Contains(err.Error(), "private-user") {
		t.Fatalf("Windows adapter leaked a private path: %v", err)
	}
}
