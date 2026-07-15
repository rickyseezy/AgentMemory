//go:build windows

package rebootlogin

import (
	"context"
	"errors"
	"os"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
)

func platformEnsureLoginDirectory(root string) error {
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		if err := windowssecurity.CreatePrivateDirectory(context.Background(), root); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	directory, _, err := windowssecurity.OpenVerified(context.Background(), root, true, true, true)
	if directory != nil {
		_ = directory.Close()
	}
	return err
}

func platformOpenLoginEntry(ctx context.Context, path string) (*os.File, error) {
	file, _, err := windowssecurity.OpenVerified(ctx, path, false, true, true)
	return file, err
}

func platformCreateLoginEntry(ctx context.Context, path string) (*os.File, error) {
	return windowssecurity.CreatePrivateFile(ctx, path)
}

func platformSyncLoginDirectory(string) error { return nil }
