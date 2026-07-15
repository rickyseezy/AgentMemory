//go:build windows

package rebootfs

import (
	"os"
	"path/filepath"
	"testing"
)

func makeProtectedFixtureUnsafe(t testing.TB, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(t.TempDir(), "foreign-continuation")
	if err := os.WriteFile(foreign, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(foreign, path); err != nil {
		t.Fatal(err)
	}
}

func restoreProtectedFixtureFile(t testing.TB, path string, content []byte) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	writeProtectedFixtureFile(t, path, content)
}
