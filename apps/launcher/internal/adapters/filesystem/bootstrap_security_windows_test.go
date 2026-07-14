//go:build windows

package filesystem

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001WindowsRollbackAnchorRejectsReplayTamperAndWrongOwner(t *testing.T) {
	root := windowsTestConfigRoot(t)
	locator, _ := bootstrapadapter.NewOperationLocator(root)
	owner, _ := install.BindOwner("windows-machine", "windows-user")
	wrongOwner, _ := install.BindOwner("other-machine", "windows-user")
	owners := windowsOwnerBindingStub{owner: owner}
	keys, _ := bootstrapadapter.NewMemoryOperationKeySource(bytes.NewReader(bytes.Repeat([]byte{0x51}, 128)))
	store, err := NewWindowsFileRollbackAnchorStore(locator, keys, owners)
	if err != nil {
		t.Fatal(err)
	}
	operationID, _ := install.NewOperationID("windows-rollback-anchor")
	keyRef, _ := keys.Ensure(context.Background(), operationID, owner)
	first, _ := install.NewRollbackAnchor(operationID, owner, 1, install.DigestBytes([]byte("first")))
	second, _ := install.NewRollbackAnchor(operationID, owner, 2, install.DigestBytes([]byte("second")))
	if err := store.Advance(context.Background(), keyRef, 0, first); err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(context.Background(), keyRef, 1, second); err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(context.Background(), keyRef, 1, second); !errors.Is(err, bootstrapport.ErrConflict) {
		t.Fatalf("rollback replay error = %v", err)
	}
	if _, err := store.Load(context.Background(), keyRef, operationID, wrongOwner); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("wrong owner error = %v", err)
	}
	loaded, err := store.Load(context.Background(), keyRef, operationID, owner)
	if err != nil || loaded.Sequence() != 2 {
		t.Fatalf("loaded anchor = %#v, %v", loaded, err)
	}
	if err := store.ConfirmDurable(context.Background(), keyRef, second); err != nil {
		t.Fatal(err)
	}
	if err := store.ConfirmDurable(context.Background(), keyRef, first); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("stale confirmation error = %v", err)
	}
	anchorPath, _ := locator.RollbackAnchorPath(operationID)
	//nolint:gosec // G304: test path is derived from this test's TempDir through the fixed production locator.
	contents, err := os.ReadFile(anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	contents[len(contents)-1] ^= 0xff
	//nolint:gosec // G703: deliberate tampering targets this test's fixed TempDir anchor path.
	if err := os.WriteFile(anchorPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(context.Background(), keyRef, operationID, owner); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("tampered anchor error = %v", err)
	}
}

func TestPF001WindowsOperationJournalProviderRejectsOldAuthenticatedReplay(t *testing.T) {
	root := windowsTestConfigRoot(t)
	locator, _ := bootstrapadapter.NewOperationLocator(root)
	owner, _ := install.BindOwner("windows-machine", "windows-user")
	owners := windowsOwnerBindingStub{owner: owner}
	keys, _ := bootstrapadapter.NewMemoryOperationKeySource(bytes.NewReader(bytes.Repeat([]byte{0x83}, 64)))
	anchors, _ := NewWindowsFileRollbackAnchorStore(locator, keys, owners)
	provider, err := NewWindowsOperationJournalProvider(locator, keys, owners, anchors)
	if err != nil {
		t.Fatal(err)
	}
	operationID, _ := install.NewOperationID("windows-provider-replay")
	journal, err := provider.JournalFor(context.Background(), operationID)
	if err != nil {
		t.Fatal(err)
	}
	first := journalport.Snapshot{
		OperationID: operationID.String(),
		Revision:    1,
		CapturedAt:  time.Date(2026, time.July, 14, 2, 0, 0, 0, time.UTC),
		Payload:     json.RawMessage(`{"state":"first"}`),
	}
	if err := journal.Append(context.Background(), 0, first); err != nil {
		t.Fatal(err)
	}
	journalPath, _ := locator.JournalPath(operationID)
	//nolint:gosec // G304: test path is derived from this test's TempDir through the fixed production locator.
	oldValid, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Append(context.Background(), 1, journalport.Snapshot{
		OperationID: operationID.String(),
		Revision:    2,
		CapturedAt:  first.CapturedAt.Add(time.Second),
		Payload:     json.RawMessage(`{"state":"second"}`),
	}); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // G703: deliberate replay targets this test's fixed TempDir journal path.
	if err := os.WriteFile(journalPath, oldValid, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.LoadLatest(context.Background()); !errors.Is(err, journalport.ErrCorrupt) {
		t.Fatalf("old authenticated replay error = %v", err)
	}
}

func TestPF001WindowsNativeFilesystemRejectsInheritedDACLHardlinksAndADS(t *testing.T) {
	root := windowsTestConfigRoot(t)
	locator, _ := bootstrapadapter.NewOperationLocator(root)
	operationID, _ := install.NewOperationID("windows-filesystem-attacks")
	directory, _ := locator.OperationDirectory(operationID)
	if err := windowssecurity.EnsureOperationDirectory(context.Background(), root, directory); err != nil {
		t.Fatal(err)
	}

	inherited := filepath.Join(directory, "inherited.bin")
	if err := os.WriteFile(inherited, []byte("unsafe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if file, _, err := windowssecurity.OpenVerified(context.Background(), inherited, false, false, true); err == nil {
		_ = file.Close()
		t.Fatal("inherited Windows DACL was accepted")
	}

	protected := filepath.Join(directory, "protected.bin")
	file, err := windowssecurity.CreatePrivateFile(context.Background(), protected)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("protected")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	hardlink := filepath.Join(directory, "hardlink.bin")
	if err := os.Link(protected, hardlink); err != nil {
		t.Fatal(err)
	}
	if opened, _, err := windowssecurity.OpenVerified(context.Background(), protected, false, false, true); err == nil {
		_ = opened.Close()
		t.Fatal("multiply-linked Windows protected file was accepted")
	}
	if err := os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // G304: deliberate ADS attack is confined to this test's fixed TempDir protected path.
	stream, err := os.OpenFile(protected+":attack", os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if opened, _, err := windowssecurity.OpenVerified(context.Background(), protected, false, false, true); err == nil {
		_ = opened.Close()
		t.Fatal("Windows alternate data stream was accepted")
	}
}

func TestPF001WindowsOperationGuardBlocksDirectoryPathSubstitution(t *testing.T) {
	root := windowsTestConfigRoot(t)
	locator, _ := bootstrapadapter.NewOperationLocator(root)
	operationID, _ := install.NewOperationID("windows-directory-path-guard")
	directory, _ := locator.OperationDirectory(operationID)
	guard, err := windowssecurity.AcquireOperationDirectory(context.Background(), root, directory, true)
	if err != nil {
		t.Fatal(err)
	}
	substituted := directory + "-moved"
	if err := os.Rename(directory, substituted); err == nil {
		_ = guard.Close()
		t.Fatal("operation directory was renamed while its Windows path guard was held")
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}
	if err := windowssecurity.VerifyOperationDirectory(context.Background(), root, directory); err != nil {
		t.Fatal(err)
	}
}

func TestPF001WindowsJournalReconcilesAmbiguousPostRenameFailure(t *testing.T) {
	root := windowsTestConfigRoot(t)
	locator, _ := bootstrapadapter.NewOperationLocator(root)
	operationID, _ := install.NewOperationID("windows-journal-crash-reconciliation")
	directory, _ := locator.OperationDirectory(operationID)
	if err := windowssecurity.EnsureOperationDirectory(context.Background(), root, directory); err != nil {
		t.Fatal(err)
	}
	journalPath, _ := locator.JournalPath(operationID)
	sentinel := errors.New("simulated process interruption after rename")
	journal, err := newInstallJournal(journalPath, bytes.Repeat([]byte{0xa4}, 32), func(checkpoint writeCheckpoint) error {
		if checkpoint == checkpointRenamed {
			return sentinel
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := journalport.Snapshot{
		OperationID: operationID.String(),
		Revision:    1,
		CapturedAt:  time.Date(2026, time.July, 14, 3, 0, 0, 0, time.UTC),
		Payload:     json.RawMessage(`{"state":"renamed"}`),
	}
	if err := journal.Append(context.Background(), 0, snapshot); !errors.Is(err, sentinel) {
		t.Fatalf("ambiguous post-rename error = %v", err)
	}
	restarted, err := NewInstallJournal(journalPath, bytes.Repeat([]byte{0xa4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := restarted.LoadLatest(context.Background())
	if err != nil || loaded.Revision != 1 {
		t.Fatalf("restarted journal = %#v, %v", loaded, err)
	}
	if err := restarted.ConfirmDurable(context.Background(), operationID.String(), 1); err != nil {
		t.Fatal(err)
	}
}

func windowsTestConfigRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "config")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

type windowsOwnerBindingStub struct {
	owner install.OwnerBinding
	err   error
}

func (s windowsOwnerBindingStub) Current(context.Context) (install.OwnerBinding, error) {
	return s.owner, s.err
}
