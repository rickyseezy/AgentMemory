//go:build !windows

package dockercli

import (
	"errors"
	"os"
	"testing"
)

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
}
