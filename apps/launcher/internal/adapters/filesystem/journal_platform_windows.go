//go:build windows

package filesystem

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
)

func platformOpenProtectedObject(ctx context.Context, path string, expected os.FileInfo) (*os.File, error) {
	wantDirectory := expected != nil && expected.IsDir()
	file, _, err := windowssecurity.OpenVerified(ctx, path, wantDirectory, true, true)
	return file, err
}

func platformUnsafePermissions(os.FileInfo) bool { return false }

// Windows ownership and the complete protected DACL are proved from the
// opened handle by verifyPlatformDescriptor, not from os.FileInfo metadata.
func platformVerifyCurrentOwner(os.FileInfo) error { return nil }

func verifyPlatformDescriptor(ctx context.Context, file *os.File) error {
	if file == nil {
		return errors.New("windows filesystem descriptor is absent")
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	_, err = windowssecurity.VerifyOpened(ctx, file, info.IsDir(), true)
	return err
}

func platformDurableSync(file *os.File) error { return windowssecurity.Flush(file) }

func platformEnsurePrivateDirectory(ctx context.Context, directory string) error {
	if _, err := os.Lstat(directory); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return windowssecurity.CreatePrivateDirectory(ctx, directory)
}

func createProtectedRootTemporary(ctx context.Context, root *os.Root, prefix string) (*os.File, string, error) {
	for range 32 {
		var random [12]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", err
		}
		name := prefix + hex.EncodeToString(random[:]) + ".tmp"
		file, err := windowssecurity.CreatePrivateFile(ctx, filepath.Join(root.Name(), name))
		if err == nil {
			return file, name, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, "", err
		}
	}
	return nil, "", errors.New("temporary windows journal name collision limit reached")
}

func platformAtomicRename(ctx context.Context, root *os.Root, temporaryName, targetName string) error {
	temporaryPath := filepath.Join(root.Name(), temporaryName)
	targetPath := filepath.Join(root.Name(), targetName)
	_, err := os.Lstat(targetPath)
	targetExists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return windowssecurity.AtomicReplace(ctx, temporaryPath, targetPath, targetExists)
}
