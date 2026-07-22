//go:build darwin || linux

package launcher

import (
	"os"
	"path/filepath"
	"testing"
)

func protectedSessionTestRoot(t testing.TB) (string, error) {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	root, err := os.MkdirTemp(home, ".agentmemory-session-test-")
	if err != nil {
		return "", err
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o700); err != nil { //nolint:gosec // G302: owner-only directory fixture, not a regular file.
		return "", err
	}
	return filepath.EvalSymlinks(root)
}

func writeProtectedSessionTestFile(path string, value []byte) error {
	if err := os.WriteFile(path, value, 0o400); err != nil {
		return err
	}
	return os.Chmod(path, 0o400)
}

func createProtectedSessionTestDirectory(parent, name string) (string, error) {
	path := filepath.Join(parent, name)
	if err := os.Mkdir(path, 0o700); err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(path)
}
