//go:build windows

package artifactfs

import (
	"context"
	"path/filepath"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
)

func ensurePrivateMaterializationDirectory(ctx context.Context, privateBoundary, target string) error {
	if ctx == nil || privateBoundary == "" || target == "" ||
		filepath.Clean(privateBoundary) != privateBoundary || filepath.Clean(target) != target {
		return artifactapp.ErrStoreIntegrity
	}
	if _, _, err := windowssecurity.EnsurePrivateDirectoryTree(ctx, privateBoundary, target); err != nil {
		return artifactapp.ErrStoreIntegrity
	}
	return nil
}
