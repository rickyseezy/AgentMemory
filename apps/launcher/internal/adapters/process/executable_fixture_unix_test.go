//go:build darwin || linux

package process

import (
	"os"
	"path/filepath"
	"testing"
)

// testCurrentExecutable copies the generated test program below a private,
// user-owned home directory. Go's build cache may live below a shared-writable
// temporary directory on native CI hosts, which the production executable
// ancestry policy must correctly reject.
func testCurrentExecutable(t *testing.T) string {
	t.Helper()
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err = filepath.EvalSymlinks(source)
	if err != nil {
		t.Fatal(err)
	}
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		t.Fatalf("secure fixture home unavailable: %v", err)
	}
	directory, err := os.MkdirTemp(home, ".agentmemory-process-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil { //nolint:gosec // G302: owner-only executable fixture directory.
		_ = os.RemoveAll(directory)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	contents, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "test-program")
	if err := os.WriteFile(target, contents, 0o700); err != nil { //nolint:gosec // G306: isolated executable test fixture.
		t.Fatal(err)
	}
	return target
}
