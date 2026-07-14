package bootstrap

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001OperationLocatorNeverUsesRawOperationIDAsAPath(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "config")
	locator, err := NewOperationLocator(root)
	if err != nil {
		t.Fatal(err)
	}
	segmentPattern := regexp.MustCompile(`^sha256-[0-9a-f]{64}$`)
	for _, rawID := range []string{"..", ".", "019f5c00-0000-7000-8000-000000000001"} {
		operationID, idError := install.NewOperationID(rawID)
		if idError != nil {
			t.Fatal(idError)
		}
		directory, locateError := locator.OperationDirectory(operationID)
		if locateError != nil {
			t.Fatal(locateError)
		}
		relative, relError := filepath.Rel(root, directory)
		if relError != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			t.Fatalf("operation path escaped root: %q (%v)", directory, relError)
		}
		if !segmentPattern.MatchString(filepath.Base(directory)) || strings.Contains(directory, rawID+string(filepath.Separator)) {
			t.Fatalf("operation ID influenced path structure: id=%q path=%q", rawID, directory)
		}
		journalPath, _ := locator.JournalPath(operationID)
		keyPath, _ := locator.KeyPath(operationID)
		anchorPath, _ := locator.RollbackAnchorPath(operationID)
		if filepath.Base(journalPath) != "install-operation.json" || filepath.Base(keyPath) != "bootstrap-hmac.key" || filepath.Base(anchorPath) != "rollback-anchor.bin" {
			t.Fatal("locator emitted a non-closed bootstrap filename")
		}
	}
}

func TestPF001OperationLocatorIsDeterministicAndRejectsUnsafeRoot(t *testing.T) {
	t.Parallel()
	if _, err := NewOperationLocator("relative/config"); err == nil {
		t.Fatal("relative bootstrap root was accepted")
	}
	locator, err := NewOperationLocator(filepath.Join(t.TempDir(), "config"))
	if err != nil {
		t.Fatal(err)
	}
	first, _ := install.NewOperationID("first")
	second, _ := install.NewOperationID("second")
	firstPath, _ := locator.OperationDirectory(first)
	repeatedPath, _ := locator.OperationDirectory(first)
	secondPath, _ := locator.OperationDirectory(second)
	if firstPath != repeatedPath || firstPath == secondPath {
		t.Fatal("operation locator is not deterministic and collision-separated")
	}
	if locator.Root() == "" {
		t.Fatal("normalized locator root is absent")
	}
	if _, err := locator.OperationDirectory(install.OperationID{}); err == nil {
		t.Fatal("zero operation identity was accepted")
	}
	var nilLocator *OperationLocator
	if _, err := nilLocator.OperationDirectory(first); err == nil {
		t.Fatal("nil operation locator was accepted")
	}
	if _, err := locator.JournalPath(install.OperationID{}); err == nil {
		t.Fatal("zero operation journal path was accepted")
	}
}
