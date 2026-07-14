//go:build windows

package process

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
)

func testCurrentExecutable(t *testing.T) string {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(canonical)
	if err != nil {
		t.Fatal(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(home, ".agentmemory-process-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	isolated := filepath.Join(directory, "test-program.exe")
	file, err := windowssecurity.CreatePrivateFile(context.Background(), isolated)
	if err != nil {
		t.Fatal(err)
	}
	written, writeError := file.Write(contents)
	if writeError != nil || written != len(contents) {
		_ = file.Close()
		t.Fatalf("copy executable bytes=%d err=%v", written, writeError)
	}
	if err := windowssecurity.Flush(file); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return isolated
}
