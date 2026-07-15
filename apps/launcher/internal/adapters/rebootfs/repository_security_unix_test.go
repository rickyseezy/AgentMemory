//go:build darwin || linux

package rebootfs

import (
	"os"
	"testing"
)

func makeProtectedFixtureUnsafe(t testing.TB, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o644); err != nil { // #nosec G302 -- deliberate unsafe fixture.
		t.Fatal(err)
	}
}

func restoreProtectedFixtureFile(t testing.TB, path string, _ []byte) {
	t.Helper()
	if err := os.Chmod(path, 0o600); err != nil { // #nosec G302 -- restores owner-only fixture mode.
		t.Fatal(err)
	}
}
