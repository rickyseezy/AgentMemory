//go:build windows

package launcher

import (
	"context"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
)

func ensureNativePrivateDirectory(ctx context.Context, path string) error {
	if ctx == nil {
		return errors.New("native private directory context is absent")
	}
	_, _, err := windowssecurity.EnsurePrivateDirectoryTree(ctx, path, path)
	return err
}
