//go:build darwin && !cgo

package filesystem

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
)

func TestPF001DarwinFilesystemSecurityCompositionFailsClosedWithoutCGO(t *testing.T) {
	t.Parallel()
	if err := verifyPlatformDescriptor(context.Background(), nil); !errors.Is(err, errDarwinFilesystemProofUnavailable) {
		t.Fatalf("no-cgo descriptor proof error=%v", err)
	}
	if err := platformDurableSync(nil); !errors.Is(err, errDarwinFilesystemProofUnavailable) {
		t.Fatalf("no-cgo durable sync error=%v", err)
	}
	directory := filepath.Join(t.TempDir(), "operation")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := NewInstallJournal(filepath.Join(directory, "journal.json"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	err = journal.Append(context.Background(), 0, journalport.Snapshot{
		OperationID: "darwin-no-cgo",
		Revision:    1,
		CapturedAt:  time.Date(2026, time.July, 14, 0, 0, 0, 0, time.UTC),
		Payload:     json.RawMessage(`{"state":"must-not-persist"}`),
	})
	if !errors.Is(err, journalport.ErrUnsafePermission) || !errors.Is(err, errDarwinFilesystemProofUnavailable) {
		t.Fatalf("journal without native macOS proof error = %v", err)
	}
	if _, statError := os.Lstat(filepath.Join(directory, "journal.json")); !errors.Is(statError, os.ErrNotExist) {
		t.Fatalf("fail-closed journal created state: %v", statError)
	}
}
