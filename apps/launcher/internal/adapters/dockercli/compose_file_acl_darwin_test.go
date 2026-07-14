//go:build darwin && cgo

package dockercli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPF001ComposeInputSecurityRejectsDarwinExtendedACL(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	//nolint:gosec // G302: owner-only directory mode is the security condition under test; owner=security expiry=2027-07-14.
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "compose.yaml")
	if err := os.WriteFile(path, []byte("services: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // G204: fixed chmod/ACL expression; path is an isolated test fixture; owner=security expiry=2027-07-14.
	command := exec.CommandContext(context.Background(), "/bin/chmod", "+a", "everyone deny delete", path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("add extended ACL: %v: %s", err, output)
	}
	t.Cleanup(func() {
		//nolint:gosec // G204: fixed chmod flag; path is the isolated fixture above; owner=security expiry=2027-07-14.
		_ = exec.CommandContext(context.Background(), "/bin/chmod", "-N", path).Run()
	})
	if privateComposePath(path, false) {
		t.Fatal("Compose input with a nontrivial Darwin ACL was accepted")
	}
}
