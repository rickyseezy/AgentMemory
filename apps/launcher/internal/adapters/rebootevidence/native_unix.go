//go:build linux || darwin

package rebootevidence

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func platformOpenNativeObject(_ context.Context, path string, executable bool) (*os.File, error) {
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), filepath.Base(path))
	if file == nil {
		_ = syscall.Close(descriptor)
		return nil, errors.New("native continuation descriptor is invalid")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New("native continuation object is not a regular file")
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(status.Uid) != os.Geteuid() {
		_ = file.Close()
		return nil, errors.New("native continuation object owner is invalid")
	}
	if (executable && (info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o100 == 0)) ||
		(!executable && info.Mode().Perm()&0o077 != 0) {
		_ = file.Close()
		return nil, errors.New("native continuation object permissions are unsafe")
	}
	return file, nil
}
