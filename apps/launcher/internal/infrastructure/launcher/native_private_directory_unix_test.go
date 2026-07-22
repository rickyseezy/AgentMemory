//go:build darwin || linux

package launcher

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPF005NativePrivateDirectoryRejectsInvalidContextAndUncreatablePath(t *testing.T) {
	t.Parallel()
	root := t.TempDir()

	//lint:ignore SA1012 Deliberately proves the public nil-context boundary.
	if err := ensureNativePrivateDirectory(nil, filepath.Join(root, "nil-context")); err == nil { //nolint:staticcheck // Deliberate invalid boundary.
		t.Fatal("nil context was accepted")
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ensureNativePrivateDirectory(cancelled, filepath.Join(root, "cancelled")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context error = %v", err)
	}

	blockedParent := filepath.Join(root, "regular-file")
	if err := os.WriteFile(blockedParent, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureNativePrivateDirectory(context.Background(), filepath.Join(blockedParent, "child")); err == nil {
		t.Fatal("uncreatable private directory was accepted")
	}
}
