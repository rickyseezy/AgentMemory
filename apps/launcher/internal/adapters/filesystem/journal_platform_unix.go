//go:build linux || darwin

package filesystem

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func platformOpenProtectedObject(_ context.Context, path string, _ os.FileInfo) (*os.File, error) {
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), filepath.Base(path))
	if file == nil {
		_ = syscall.Close(descriptor)
		return nil, errors.New("filesystem descriptor is invalid")
	}
	return file, nil
}

func platformUnsafePermissions(info os.FileInfo) bool { return info.Mode().Perm()&0o077 != 0 }

func platformVerifyCurrentOwner(info os.FileInfo) error {
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("filesystem ownership metadata is unavailable")
	}
	if int64(status.Uid) != int64(os.Geteuid()) {
		return errors.New("filesystem object is not owned by the invoking user")
	}
	return nil
}

func platformEnsurePrivateDirectory(_ context.Context, directory string) error {
	//nolint:gosec // G703: caller passes the normalized journal parent path; the directory is owner/ACL verified immediately after creation.
	return os.MkdirAll(directory, 0o700)
}

func createProtectedRootTemporary(_ context.Context, root *os.Root, prefix string) (*os.File, string, error) {
	for range 32 {
		var random [12]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", err
		}
		name := prefix + hex.EncodeToString(random[:]) + ".tmp"
		file, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return file, name, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, "", err
		}
	}
	return nil, "", errors.New("temporary journal name collision limit reached")
}

func platformAtomicRename(_ context.Context, root *os.Root, temporaryName, targetName string) error {
	return root.Rename(temporaryName, targetName)
}
