//go:build darwin && cgo

package filesystem

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
)

func TestPF001DarwinJournalRejectsNontrivialExtendedACLs(t *testing.T) {
	t.Parallel()
	t.Run("operation directory", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "private")
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		addDarwinTestACL(t, directory)
		journal := mustJournal(t, filepath.Join(directory, "install.journal"), testJournalKey)
		if err := journal.Append(context.Background(), 0, testSnapshot(1)); !errors.Is(err, journalport.ErrUnsafePermission) {
			t.Fatalf("directory ACL error = %v", err)
		}
	})

	t.Run("journal file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "private", "install.journal")
		journal := mustJournal(t, path, testJournalKey)
		if err := journal.Append(context.Background(), 0, testSnapshot(1)); err != nil {
			t.Fatal(err)
		}
		addDarwinTestACL(t, path)
		if _, err := journal.LoadLatest(context.Background()); !errors.Is(err, journalport.ErrUnsafePermission) {
			t.Fatalf("journal ACL error = %v", err)
		}
	})

	t.Run("abandoned temporary", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "private")
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		stale := filepath.Join(directory, ".install.journal.attacker.tmp")
		if err := os.WriteFile(stale, []byte("attacker"), 0o600); err != nil {
			t.Fatal(err)
		}
		addDarwinTestACL(t, stale)
		journal := mustJournal(t, filepath.Join(directory, "install.journal"), testJournalKey)
		if err := journal.Append(context.Background(), 0, testSnapshot(1)); !errors.Is(err, journalport.ErrUnsafePermission) {
			t.Fatalf("temporary ACL error = %v", err)
		}
	})
}

func TestPF001DarwinJournalRejectsParentPathSubstitutionDuringAtomicReplace(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	directory := filepath.Join(root, "private")
	moved := filepath.Join(root, "moved")
	path := filepath.Join(directory, "install.journal")
	var attackerTemporary string
	journal, err := newInstallJournal(path, testJournalKey, func(checkpoint writeCheckpoint) error {
		if checkpoint != checkpointTempClosed {
			return nil
		}
		entries, readError := os.ReadDir(directory)
		if readError != nil {
			return readError
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".install.journal.") && strings.HasSuffix(entry.Name(), ".tmp") {
				attackerTemporary = entry.Name()
				break
			}
		}
		if attackerTemporary == "" {
			return errors.New("journal temporary was not found")
		}
		if renameError := os.Rename(directory, moved); renameError != nil {
			return renameError
		}
		if mkdirError := os.Mkdir(directory, 0o700); mkdirError != nil {
			return mkdirError
		}
		return os.WriteFile(filepath.Join(directory, attackerTemporary), []byte("attacker"), 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	err = journal.Append(context.Background(), 0, testSnapshot(1))
	if !errors.Is(err, journalport.ErrUnsafePermission) {
		t.Fatalf("path substitution error = %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("substituted destination was mutated: %v", err)
	}
	attackerPath := filepath.Join(directory, attackerTemporary)
	contents, err := os.ReadFile(attackerPath) //nolint:gosec // G304: fixed digest-free adversarial fixture path; owner=security expiry=2027-07-14.
	if err != nil || string(contents) != "attacker" {
		t.Fatalf("attacker replacement changed = %q, %v", contents, err)
	}
}

func TestPF001DarwinNativeACLAndFullSyncCapabilities(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "protected")
	if err := os.WriteFile(path, []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path) //nolint:gosec // G304: isolated native-capability fixture; owner=security expiry=2027-07-14.
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyPlatformDescriptor(context.Background(), file); err != nil {
		t.Fatalf("ACL-free file rejected: %v", err)
	}
	if err := platformDurableSync(file); err != nil {
		t.Fatalf("file F_FULLFSYNC failed: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	directoryFile, err := os.Open(directory) //nolint:gosec // G304: isolated native-capability fixture; owner=security expiry=2027-07-14.
	if err != nil {
		t.Fatal(err)
	}
	if err := platformDurableSync(directoryFile); err != nil {
		t.Fatalf("directory F_FULLFSYNC failed: %v", err)
	}
	if err := directoryFile.Close(); err != nil {
		t.Fatal(err)
	}
	addDarwinTestACL(t, path)
	file, err = os.Open(path) //nolint:gosec // G304: isolated native-capability fixture; owner=security expiry=2027-07-14.
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if err := verifyPlatformDescriptor(context.Background(), file); err == nil {
		t.Fatal("native ACL capability accepted a nontrivial ACL")
	}
}

func addDarwinTestACL(t *testing.T, path string) {
	t.Helper()
	//nolint:gosec // G204: executable and ACL expression are fixed; path is an isolated test fixture; owner=security expiry=2027-07-14.
	command := exec.CommandContext(context.Background(), "/bin/chmod", "+a", "everyone deny delete", path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("add extended ACL: %v: %s", err, output)
	}
	t.Cleanup(func() {
		//nolint:gosec // G204: executable/flag are fixed and remove ACL only from the isolated fixture; owner=security expiry=2027-07-14.
		_ = exec.CommandContext(context.Background(), "/bin/chmod", "-N", path).Run()
	})
}
