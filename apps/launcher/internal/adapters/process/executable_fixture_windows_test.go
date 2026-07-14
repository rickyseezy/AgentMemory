//go:build windows

package process

import (
	"os"
	"path/filepath"
	"testing"
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
	if err := os.WriteFile(isolated, contents, 0o700); err != nil {
		t.Fatal(err)
	}
	return isolated
}
