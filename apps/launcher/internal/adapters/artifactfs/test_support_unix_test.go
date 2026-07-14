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
