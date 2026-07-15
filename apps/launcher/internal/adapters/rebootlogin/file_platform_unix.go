//go:build linux || darwin

package rebootlogin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/rebootapp"
)

func platformEnsureLoginDirectory(root string) error {
	if info, err := os.Lstat(root); err == nil {
		return verifyLoginUnixObject(info, true)
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
	return verifyLoginUnixObject(info, true)
}

func platformOpenLoginEntry(_ context.Context, path string) (*os.File, error) {
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), filepath.Base(path))
	if file == nil {
		_ = syscall.Close(descriptor)
		return nil, errors.New("login entry descriptor is invalid")
	}
	info, err := file.Stat()
	if err != nil || verifyLoginUnixObject(info, false) != nil {
		_ = file.Close()
		return nil, rebootapp.ErrIntegrity
	}
	return file, nil
}

func platformCreateLoginEntry(_ context.Context, path string) (*os.File, error) {
	descriptor, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(descriptor), filepath.Base(path)), nil
}

func platformSyncLoginDirectory(root string) error {
	directory, err := os.Open(root) // #nosec G304 -- root is a validated native login-registration directory.
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}

func verifyLoginUnixObject(info os.FileInfo, directory bool) error {
	if info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory || (!directory && !info.Mode().IsRegular()) ||
		(directory && info.Mode().Perm()&0o022 != 0) || (!directory && info.Mode().Perm()&0o077 != 0) {
		return errors.New("login entry shape or permissions are unsafe")
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(status.Uid) != os.Geteuid() {
		return errors.New("login entry owner is invalid")
	}
	return nil
}
