//go:build darwin || linux

package artifactfs

import (
	"os"
	"testing"
)

func makeSecureTestDirectory(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func writeSecureTestFile(t *testing.T, path string, value []byte) {
	t.Helper()
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
}

func truncateSecureTestFile(t *testing.T, path string, size int64) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // Exact test-owned path.
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(size); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
