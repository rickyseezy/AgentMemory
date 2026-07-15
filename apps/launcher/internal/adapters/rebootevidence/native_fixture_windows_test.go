//go:build windows

package rebootevidence

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
)

func writeNativeObjectFixture(t testing.TB, path string, content []byte, _ bool) {
	t.Helper()
	file, err := windowssecurity.CreatePrivateFile(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write(content); err == nil {
		err = file.Sync()
	}
	if closeError := file.Close(); err == nil {
		err = closeError
	}
	if err != nil {
		t.Fatal(err)
	}
}

func makeNativeObjectUnsafe(t testing.TB, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(t.TempDir(), "foreign-native-object")
	if err := os.WriteFile(foreign, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(foreign, path); err != nil {
		t.Fatal(err)
	}
}

func restoreNativeObjectFixture(t testing.TB, path string, content []byte, executable bool) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	writeNativeObjectFixture(t, path, content, executable)
}
