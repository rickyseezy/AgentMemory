//go:build darwin || linux

package corehttp

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type credentialIdentity struct {
	device uint64
	inode  uint64
	mode   uint32
	owner  uint32
	links  uint64
	size   int64
}

func readNativeCredential(ctx context.Context, path string) ([]byte, error) {
	if ctx == nil || !validUnixCredentialPath(path) {
		return nil, errCredentialIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, identity, err := openCredentialFile(ctx, path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	value := make([]byte, protectedCredentialBytes)
	if _, err := io.ReadFull(file, value); err != nil {
		clear(value)
		return nil, errCredentialUnavailable
	}
	var extra [1]byte
	if count, readError := file.Read(extra[:]); count != 0 || !errors.Is(readError, io.EOF) {
		clear(value)
		return nil, errCredentialIntegrity
	}
	after, err := credentialFileIdentity(file)
	if err != nil || after != identity {
		clear(value)
		return nil, errCredentialIntegrity
	}
	reopened, observed, err := openCredentialFile(ctx, path)
	if reopened != nil {
		_ = reopened.Close()
	}
	if err != nil || observed != identity {
		clear(value)
		return nil, errCredentialIntegrity
	}
	if err := ctx.Err(); err != nil {
		clear(value)
		return nil, err
	}
	return value, nil
}

func openCredentialFile(ctx context.Context, path string) (*os.File, credentialIdentity, error) {
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	if len(components) < 2 {
		return nil, credentialIdentity{}, errCredentialIntegrity
	}
	rootFD, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, credentialIdentity{}, errCredentialUnavailable
	}
	current := os.NewFile(uintptr(rootFD), string(filepath.Separator))
	if current == nil {
		_ = unix.Close(rootFD)
		return nil, credentialIdentity{}, errCredentialUnavailable
	}
	fail := func(cause error) (*os.File, credentialIdentity, error) {
		_ = current.Close()
		return nil, credentialIdentity{}, cause
	}
	uid := uint32(os.Geteuid()) //nolint:gosec // Certified Unix UIDs are unsigned 32-bit values.
	for index, component := range components[:len(components)-1] {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		fd, openError := unix.Openat(
			int(current.Fd()), component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		if openError != nil {
			return fail(classifyCredentialError(openError))
		}
		next := os.NewFile(uintptr(fd), component)
		if next == nil {
			_ = unix.Close(fd)
			return fail(errCredentialUnavailable)
		}
		finalParent := index == len(components)-2
		if directoryError := verifyCredentialDirectory(next, uid, finalParent); directoryError != nil {
			_ = next.Close()
			return fail(directoryError)
		}
		_ = current.Close()
		current = next
	}
	leaf := components[len(components)-1]
	fd, err := unix.Openat(int(current.Fd()), leaf, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail(classifyCredentialError(err))
	}
	file := os.NewFile(uintptr(fd), leaf)
	if file == nil {
		_ = unix.Close(fd)
		return fail(errCredentialUnavailable)
	}
	_ = current.Close()
	identity, err := credentialFileIdentity(file)
	if err != nil {
		_ = file.Close()
		return nil, credentialIdentity{}, err
	}
	if identity.owner != uid || identity.mode&uint32(unix.S_IFMT) != uint32(unix.S_IFREG) ||
		identity.mode&0o7777 != 0o400 || identity.links != 1 || identity.size != protectedCredentialBytes ||
		verifyCredentialACL(int(file.Fd()), false) != nil {
		_ = file.Close()
		return nil, credentialIdentity{}, errCredentialIntegrity
	}
	return file, identity, nil
}

func verifyCredentialDirectory(file *os.File, uid uint32, final bool) error {
	var status unix.Stat_t
	if unix.Fstat(int(file.Fd()), &status) != nil || uint32(status.Mode)&uint32(unix.S_IFMT) != uint32(unix.S_IFDIR) {
		return errCredentialIntegrity
	}
	permissions := uint32(status.Mode) & 0o7777
	if permissions&0o022 != 0 {
		return errCredentialIntegrity
	}
	if status.Uid != 0 && status.Uid != uid {
		return errCredentialIntegrity
	}
	if final && (status.Uid != uid || permissions != 0o700 || verifyCredentialACL(int(file.Fd()), true) != nil) {
		return errCredentialIntegrity
	}
	return nil
}

func credentialFileIdentity(file *os.File) (credentialIdentity, error) {
	var status unix.Stat_t
	if file == nil || unix.Fstat(int(file.Fd()), &status) != nil {
		return credentialIdentity{}, errCredentialUnavailable
	}
	device, ok := credentialDeviceIdentity(&status)
	if !ok {
		return credentialIdentity{}, errCredentialIntegrity
	}
	return credentialIdentity{
		device: device,
		inode:  status.Ino, mode: uint32(status.Mode),
		owner: status.Uid, links: uint64(status.Nlink), size: status.Size,
	}, nil
}

func validUnixCredentialPath(path string) bool {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, '\x00') {
		return false
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}

func classifyCredentialError(err error) error {
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		return errCredentialIntegrity
	}
	return errCredentialUnavailable
}
