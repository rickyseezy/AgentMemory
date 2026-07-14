//go:build darwin || linux

package dockercli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func createPrivateExecutionDirectory(_ context.Context, path string) error {
	return os.Mkdir(path, 0o700)
}

func createPrivateExecutionChild(
	_ context.Context,
	directory *os.File,
	name string,
	_ string,
) (*os.File, bool, error) {
	if directory == nil || filepath.Base(name) != name || name == "." || name == ".." {
		return nil, false, os.ErrInvalid
	}
	descriptor, err := unix.Openat(
		int(directory.Fd()),
		name,
		unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_CREAT|unix.O_EXCL,
		0o600,
	)
	created := err == nil
	if err != nil {
		descriptor, err = unix.Openat(
			int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0,
		)
	}
	if err != nil {
		return nil, false, err
	}
	file := os.NewFile(uintptr(descriptor), name)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, false, os.ErrInvalid
	}
	info, err := file.Stat()
	if err != nil || !privateUnixExecutionFile(info) || !composeACLFreeOpened(file) {
		_ = file.Close()
		return nil, false, os.ErrPermission
	}
	return file, created, nil
}

func openPrivateExecutionFile(_ context.Context, path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil || !privateUnixComposeFile(before, int64(os.Geteuid())) || !composeACLFree(path) {
		return nil, os.ErrPermission
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), filepath.Base(path))
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, os.ErrInvalid
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !privateUnixComposeFile(after, int64(os.Geteuid())) {
		_ = file.Close()
		return nil, os.ErrPermission
	}
	return file, nil
}

func openPrivateExecutionDirectory(_ context.Context, path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil || !privateComposeDirectory(before) || !composeACLFree(path) {
		return nil, os.ErrPermission
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(descriptor), filepath.Base(path))
	if directory == nil {
		_ = unix.Close(descriptor)
		return nil, os.ErrInvalid
	}
	after, err := directory.Stat()
	if err != nil || !os.SameFile(before, after) || !privateComposeDirectory(after) {
		_ = directory.Close()
		return nil, os.ErrPermission
	}
	return directory, nil
}

func sealExecutionFile(file *os.File) error {
	if file == nil {
		return os.ErrInvalid
	}
	// Every protected projection remains owner-only on the host. Runtime
	// qualification must prove that the selected local Compose implementation
	// projects the source as the fixed service UID/GID before stack activation.
	return file.Chmod(0o400)
}

func sealExecutionDirectory(directory *os.File) error {
	if directory == nil {
		return os.ErrInvalid
	}
	return directory.Chmod(0o500)
}

func syncExecutionDirectory(directory *os.File) error {
	if directory == nil {
		return os.ErrInvalid
	}
	return directory.Sync()
}

func sealedExecutionMaterialization(directory, secret, environment os.FileInfo) bool {
	return privateComposeDirectory(directory) && directory.Mode().Perm() == 0o500 &&
		privateUnixExecutionFile(secret) && secret.Mode().Perm() == 0o400 &&
		privateUnixExecutionFile(environment) && environment.Mode().Perm() == 0o400
}

func privateUnixExecutionFile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	mode := info.Mode().Perm()
	if mode != 0o600 && mode != 0o400 && mode != 0o444 {
		return false
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	return ok && int64(status.Uid) == int64(os.Geteuid()) && status.Nlink == 1
}

func privateExecutionMaterializationPath(path string, wantDirectory bool) bool {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	if wantDirectory {
		return privateComposeDirectory(info) && info.Mode().Perm() == 0o500 && composeACLFree(path)
	}
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !privateComposeDirectory(parentInfo) ||
		(parentInfo.Mode().Perm() != 0o700 && parentInfo.Mode().Perm() != 0o500) ||
		!composeACLFree(parent) {
		return false
	}
	return privateUnixExecutionFile(info) && info.Mode().Perm() == 0o400 && composeACLFree(path)
}

type unixExecutionAncestor struct {
	path     string
	file     *os.File
	identity os.FileInfo
}

type unixExecutionAncestorAuthority struct {
	entries []unixExecutionAncestor
}

func openExecutionAncestorAuthority(ctx context.Context, projectDirectory string) (executionAncestorAuthority, error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(projectDirectory) ||
		filepath.Clean(projectDirectory) != projectDirectory {
		return nil, os.ErrPermission
	}
	authority := &unixExecutionAncestorAuthority{}
	failed := true
	defer func() {
		if failed {
			_ = authority.close()
		}
	}()
	rootDescriptor, err := unix.Open(
		string(filepath.Separator), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0,
	)
	if err != nil {
		return nil, err
	}
	root := os.NewFile(uintptr(rootDescriptor), string(filepath.Separator))
	if root == nil {
		_ = unix.Close(rootDescriptor)
		return nil, os.ErrInvalid
	}
	if err := authority.append(ctx, string(filepath.Separator), root); err != nil {
		_ = root.Close()
		return nil, err
	}
	current := root
	currentPath := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(projectDirectory, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			return nil, os.ErrInvalid
		}
		descriptor, openError := unix.Openat(
			int(current.Fd()), component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0,
		)
		if openError != nil {
			return nil, openError
		}
		opened := os.NewFile(uintptr(descriptor), component)
		if opened == nil {
			_ = unix.Close(descriptor)
			return nil, os.ErrInvalid
		}
		currentPath = filepath.Join(currentPath, component)
		if err := authority.append(ctx, currentPath, opened); err != nil {
			_ = opened.Close()
			return nil, err
		}
		current = opened
	}
	failed = false
	return authority, nil
}

func (a *unixExecutionAncestorAuthority) append(ctx context.Context, path string, file *os.File) error {
	if ctx == nil || ctx.Err() != nil || file == nil {
		return os.ErrPermission
	}
	identity, err := file.Stat()
	if err != nil || !secureExecutionAncestor(file, identity) {
		return os.ErrPermission
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(identity, pathInfo) {
		return os.ErrPermission
	}
	a.entries = append(a.entries, unixExecutionAncestor{path: path, file: file, identity: identity})
	return nil
}

func secureExecutionAncestor(file *os.File, info os.FileInfo) bool {
	if file == nil || info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o022 != 0 {
		return false
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || status.Uid != 0 && int64(status.Uid) != int64(os.Geteuid()) {
		return false
	}
	if int64(status.Uid) == int64(os.Geteuid()) {
		return true
	}
	err := unix.Faccessat(int(file.Fd()), ".", unix.W_OK, unix.AT_EACCESS)
	return errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EROFS)
}

func (a *unixExecutionAncestorAuthority) verify(ctx context.Context) error {
	if a == nil || ctx == nil || ctx.Err() != nil || len(a.entries) == 0 {
		return os.ErrPermission
	}
	for _, entry := range a.entries {
		current, err := entry.file.Stat()
		if err != nil || !os.SameFile(entry.identity, current) || !secureExecutionAncestor(entry.file, current) {
			return os.ErrPermission
		}
		pathInfo, err := os.Lstat(entry.path)
		if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(current, pathInfo) {
			return os.ErrPermission
		}
	}
	return nil
}

func (a *unixExecutionAncestorAuthority) close() error {
	if a == nil {
		return nil
	}
	var result error
	for index := len(a.entries) - 1; index >= 0; index-- {
		if a.entries[index].file != nil {
			result = errors.Join(result, a.entries[index].file.Close())
			a.entries[index].file = nil
		}
	}
	return result
}
