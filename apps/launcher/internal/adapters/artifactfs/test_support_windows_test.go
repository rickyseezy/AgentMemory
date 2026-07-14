//go:build windows

package artifactfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
)

func resolvedTempDir(t *testing.T) string {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "agentmemory-private")
	if err := windowssecurity.CreatePrivateDirectory(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	return root
}

func makeSecureTestDirectory(t *testing.T, path string) {
	t.Helper()
	ctx := context.Background()
	ancestor := path
	for {
		if _, _, err := windowssecurity.OpenVerified(ctx, ancestor, true, false, true); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) && filepath.Dir(ancestor) == ancestor {
			t.Fatal(err)
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			t.Fatalf("no protected ancestor for %s", path)
		}
		ancestor = parent
	}
	if ancestor == path {
		return
	}
	if _, _, err := windowssecurity.EnsurePrivateDirectoryTree(ctx, ancestor, path); err != nil {
		t.Fatal(err)
	}
}
