//go:build windows

package dockercli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
)

func secureComposeTestRoot(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	placeholder, err := os.MkdirTemp(home, ".agentmemory-compose-test-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(placeholder); err != nil {
		t.Fatal(err)
	}
	if err := windowssecurity.CreatePrivateDirectory(context.Background(), placeholder); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(placeholder) })
	resolved, err := filepath.EvalSymlinks(placeholder)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func ensurePrivateTestDirectory(t *testing.T, path string) {
	t.Helper()
	if err := windowssecurity.CreatePrivateDirectory(context.Background(), path); err != nil && !errors.Is(err, os.ErrExist) {
		if file, _, verifyError := windowssecurity.OpenVerified(context.Background(), path, true, false, true); verifyError == nil {
			_ = file.Close()
			return
		}
		t.Fatal(err)
	}
}

func writePrivateTestFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	file, err := windowssecurity.CreatePrivateFile(context.Background(), path)
	if err != nil {
		file, _, err = windowssecurity.OpenVerified(context.Background(), path, false, true, true)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if err := file.Truncate(0); err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt(contents, 0); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
}
