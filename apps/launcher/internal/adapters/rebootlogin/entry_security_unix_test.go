//go:build darwin || linux

package rebootlogin

import (
	"os"
	"testing"
)

func makeLoginEntryUnsafe(t testing.TB, target string) {
	t.Helper()
	if err := os.Chmod(target, 0o644); err != nil { // #nosec G302 -- deliberate unsafe fixture.
		t.Fatal(err)
	}
}

func verifyLoginEntryPrivate(t testing.TB, target string) {
	t.Helper()
	info, err := os.Lstat(target)
	if err != nil || info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
		t.Fatalf("entry metadata = (%v, %v)", info, err)
	}
}
