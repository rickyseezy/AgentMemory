//go:build darwin && !cgo

package agentconfigadapter

import (
	"os"
	"testing"
)

func TestPF001DarwinNoCGOACLValidationFailsClosed(t *testing.T) {
	t.Parallel()
	if err := darwinACLFree(nil); err == nil {
		t.Fatal("nil descriptor passed no-cgo ACL validation")
	}
	path := t.TempDir() + "/owner-only"
	if err := os.WriteFile(path, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path) // #nosec G304 -- test opens its private fixture.
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if err := darwinACLFree(file); err == nil {
		t.Fatal("descriptor passed without the required native ACL capability")
	}
}
