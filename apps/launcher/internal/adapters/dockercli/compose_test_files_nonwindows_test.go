//go:build !windows && (!darwin || cgo)

package dockercli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func secureComposeTestRoot(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(home, ".agentmemory-compose-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	//nolint:gosec // G302: the execution-authority fixture must be owner-only; owner=security expiry=2027-07-14.
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	removeInheritedTestACL(t, root, true)
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func ensurePrivateTestDirectory(t *testing.T, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	//nolint:gosec // G302: owner-only directory mode is required by the test security boundary; owner=security expiry=2027-07-14.
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	removeInheritedTestACL(t, path, true)
	if !privateComposePath(path, true) {
		t.Fatalf("private Compose test directory could not be established: %q", path)
	}
}

func writePrivateTestFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	removeInheritedTestACL(t, path, false)
	if !privateComposePath(path, false) {
		t.Fatalf("private Compose test file could not be established: %q", path)
	}
}
