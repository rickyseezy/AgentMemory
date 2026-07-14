//go:build linux || (darwin && cgo)

package filesystem

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
)

func TestPF001InstallJournalDurabilityRejectsPostLoadFilesystemMutation(t *testing.T) {
	t.Parallel()

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()
		journal := mustJournal(t, filepath.Join(t.TempDir(), "private", "install.journal"), testJournalKey)
		if err := journal.syncCurrentFile(context.Background()); !errors.Is(err, journalport.ErrIO) {
			t.Fatalf("missing journal sync error = %v", err)
		}
	})

	t.Run("symbolic link", func(t *testing.T) {
		t.Parallel()
		directory := t.TempDir()
		target := filepath.Join(directory, "target")
		if err := os.WriteFile(target, []byte("state"), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "install.journal")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		journal := mustJournal(t, path, testJournalKey)
		if err := journal.syncCurrentFile(context.Background()); !errors.Is(err, journalport.ErrUnsafePermission) {
			t.Fatalf("symlink journal sync error = %v", err)
		}
	})

	t.Run("permission expansion", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "install.journal")
		if err := os.WriteFile(path, []byte("state"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec // G302: deliberate unsafe-permission fixture.
			t.Fatal(err)
		}
		journal := mustJournal(t, path, testJournalKey)
		if err := journal.syncCurrentFile(context.Background()); !errors.Is(err, journalport.ErrUnsafePermission) {
			t.Fatalf("expanded journal mode sync error = %v", err)
		}
	})
}

func TestPF001InstallJournalDescriptorProofRejectsUnavailableAndSubstitutedObjects(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := openVerifiedProtectedObject(context.Background(), missing, nil, "test_missing"); !errors.Is(err, journalport.ErrUnsafePermission) {
		t.Fatalf("missing protected object error = %v", err)
	}

	directory := t.TempDir()
	firstPath := filepath.Join(directory, "first")
	secondPath := filepath.Join(directory, "second")
	for _, path := range []string{firstPath, secondPath} {
		if err := os.WriteFile(path, []byte("state"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	firstInfo, err := os.Lstat(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	secondInfo, err := os.Lstat(secondPath)
	if err != nil {
		t.Fatal(err)
	}
	first, err := os.Open(firstPath) //nolint:gosec // G304: test-owned fixed temporary path.
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyOpenedProtectedObject(context.Background(), first, secondInfo, "test_substitution"); !errors.Is(err, journalport.ErrUnsafePermission) {
		_ = first.Close()
		t.Fatalf("substituted descriptor error = %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verifyOpenedProtectedObject(context.Background(), first, firstInfo, "test_closed"); !errors.Is(err, journalport.ErrIO) {
		t.Fatalf("closed descriptor error = %v", err)
	}

	if err := os.Chmod(firstPath, 0o644); err != nil { //nolint:gosec // G302: deliberate unsafe-permission fixture.
		t.Fatal(err)
	}
	unsafe, err := os.Open(firstPath) //nolint:gosec // G304: test-owned fixed temporary path.
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unsafe.Close() }()
	if err := verifyOpenedProtectedObject(context.Background(), unsafe, nil, "test_permissions"); !errors.Is(err, journalport.ErrUnsafePermission) {
		t.Fatalf("expanded descriptor mode error = %v", err)
	}
}

func TestPF001InstallJournalAtomicHelpersRejectUnavailableParents(t *testing.T) {
	t.Parallel()
	missingDirectory := filepath.Join(t.TempDir(), "missing")
	journal := mustJournal(t, filepath.Join(missingDirectory, "install.journal"), testJournalKey)
	if err := journal.writeAtomically(context.Background(), []byte("state")); !errors.Is(err, journalport.ErrIO) {
		t.Fatalf("missing atomic-write parent error = %v", err)
	}
	if err := journal.removeAbandonedTemporaryFiles(context.Background()); !errors.Is(err, journalport.ErrIO) {
		t.Fatalf("missing temporary-list parent error = %v", err)
	}

	fileParent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(fileParent, []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}
	journal = mustJournal(t, filepath.Join(fileParent, "install.journal"), testJournalKey)
	if err := journal.writeAtomically(context.Background(), []byte("state")); !errors.Is(err, journalport.ErrIO) {
		t.Fatalf("file atomic-write parent error = %v", err)
	}

	unsafeDirectory := filepath.Join(t.TempDir(), "unsafe")
	if err := os.Mkdir(unsafeDirectory, 0o755); err != nil { //nolint:gosec // G301: deliberate unsafe-permission fixture.
		t.Fatal(err)
	}
	journal = mustJournal(t, filepath.Join(unsafeDirectory, "install.journal"), testJournalKey)
	if err := journal.writeAtomically(context.Background(), []byte("state")); !errors.Is(err, journalport.ErrUnsafePermission) {
		t.Fatalf("unsafe atomic-write parent error = %v", err)
	}
	if err := syncDirectory(context.Background(), unsafeDirectory); !errors.Is(err, journalport.ErrUnsafePermission) {
		t.Fatalf("unsafe directory sync error = %v", err)
	}
}
