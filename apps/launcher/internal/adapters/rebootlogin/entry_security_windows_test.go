//go:build windows

package rebootlogin

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
)

func makeLoginEntryUnsafe(t testing.TB, target string) {
	t.Helper()
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(t.TempDir(), "foreign-login-entry")
	if err := os.WriteFile(foreign, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(foreign, target); err != nil {
		t.Fatal(err)
	}
}

func verifyLoginEntryPrivate(t testing.TB, target string) {
	t.Helper()
	file, _, err := windowssecurity.OpenVerified(context.Background(), target, false, false, true)
	if file != nil {
		_ = file.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
}
