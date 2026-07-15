//go:build linux || darwin

package rebootfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func platformEnsurePrivateRoot(root string) error {
	if info, err := os.Lstat(root); err == nil {
		return verifyUnixObject(info, true)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	return verifyUnixObject(info, true)
}

func platformOpenProtectedFile(_ context.Context, path string) (*os.File, error) {
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), filepath.Base(path))
	if file == nil {
		_ = syscall.Close(descriptor)
		return nil, errors.New("continuation descriptor is invalid")
	}
	info, err := file.Stat()
	if err != nil || verifyUnixObject(info, false) != nil {
		_ = file.Close()
		return nil, errors.New("continuation file ownership is invalid")
	}
	return file, nil
}

func platformCreateProtectedFile(_ context.Context, path string) (*os.File, error) {
	descriptor, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), filepath.Base(path))
	if file == nil {
		_ = syscall.Close(descriptor)
		return nil, errors.New("continuation descriptor is invalid")
	}
	return file, nil
}

func platformSyncDirectory(root string) error {
	directory, err := os.Open(root) // #nosec G304 -- root is an absolute, clean, composition-selected private state directory.
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}

func verifyUnixObject(info os.FileInfo, directory bool) error {
	if info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory || (!directory && !info.Mode().IsRegular()) ||
		info.Mode().Perm()&0o077 != 0 {
		return errors.New("continuation object shape or permissions are unsafe")
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(status.Uid) != os.Geteuid() {
		return errors.New("continuation object owner is invalid")
	}
	return nil
}
