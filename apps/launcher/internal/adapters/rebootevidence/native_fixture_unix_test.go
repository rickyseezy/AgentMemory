//go:build darwin || linux

package rebootevidence

import (
	"os"
	"testing"
)

func writeNativeObjectFixture(t testing.TB, path string, content []byte, executable bool) {
	t.Helper()
	mode := os.FileMode(0o600)
	if executable {
		mode = 0o700
	}
	if err := os.WriteFile(path, content, mode); err != nil { // #nosec G306 -- mode is closed above.
		t.Fatal(err)
	}
}

func makeNativeObjectUnsafe(t testing.TB, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o722); err != nil { // #nosec G302 -- deliberate unsafe fixture.
		t.Fatal(err)
	}
}

func restoreNativeObjectFixture(t testing.TB, path string, _ []byte, executable bool) {
	t.Helper()
	mode := os.FileMode(0o600)
	if executable {
		mode = 0o700
	}
	if err := os.Chmod(path, mode); err != nil { // #nosec G302 -- restores owner-only fixture mode.
		t.Fatal(err)
	}
}
