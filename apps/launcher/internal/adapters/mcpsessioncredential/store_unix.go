//go:build darwin || linux

package mcpsessioncredential

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func writeCredentialFile(ctx context.Context, root, leaf string, secret []byte) (string, error) {
	directory, err := openCredentialRoot(root)
	if err != nil {
		return "", err
	}
	defer func() { _ = directory.Close() }()
	digest := sha256.Sum256(secret)
	temporary := "." + leaf + "." + hex.EncodeToString(digest[:8]) + ".tmp"
	fd, err := unix.Openat(
		int(directory.Fd()), temporary,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0o600,
	)
	if err != nil {
		return "", errors.New("PF-005 credential temporary file cannot be created")
	}
	file := os.NewFile(uintptr(fd), temporary)
	if file == nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(int(directory.Fd()), temporary, 0)
		return "", errors.New("PF-005 credential file is unavailable")
	}
	removeTemporary := true
	defer func() {
		_ = file.Close()
		if removeTemporary {
			_ = unix.Unlinkat(int(directory.Fd()), temporary, 0)
		}
	}()
	if written, writeError := file.Write(secret); writeError != nil || written != len(secret) {
		return "", errors.New("PF-005 credential write failed")
	}
	// The owner-only 0700 parent protects the host path. Read-only 0444 is required
	// because Linux bind mounts preserve host ownership while the container runs as
	// the fixed non-root UID 10001; the file is mounted directly and no parent is exposed.
	if err := file.Sync(); err != nil || unix.Fchmod(fd, 0o444) != nil || file.Sync() != nil {
		return "", errors.New("PF-005 credential durability failed")
	}
	if err := verifyUnixCredential(file, int64(len(secret))); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := unix.Linkat(int(directory.Fd()), temporary, int(directory.Fd()), leaf, 0); err != nil {
		return "", errors.New("PF-005 credential publication failed")
	}
	if err := unix.Unlinkat(int(directory.Fd()), temporary, 0); err != nil {
		_ = unix.Unlinkat(int(directory.Fd()), leaf, 0)
		return "", errors.New("PF-005 credential publication cleanup failed")
	}
	removeTemporary = false
	if err := unix.Fsync(int(directory.Fd())); err != nil {
		_ = unix.Unlinkat(int(directory.Fd()), leaf, 0)
		_ = unix.Fsync(int(directory.Fd()))
		return "", errors.New("PF-005 credential directory sync failed")
	}
	path := filepath.Join(root, leaf)
	verified, err := unix.Openat(int(directory.Fd()), leaf, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", errors.New("PF-005 credential publication cannot be verified")
	}
	verifiedFile := os.NewFile(uintptr(verified), leaf)
	if verifiedFile == nil {
		_ = unix.Close(verified)
		return "", errors.New("PF-005 credential publication is unavailable")
	}
	defer func() { _ = verifiedFile.Close() }()
	if err := verifyUnixCredential(verifiedFile, int64(len(secret))); err != nil {
		return "", err
	}
	return path, nil
}

func deleteCredentialFile(ctx context.Context, root, leaf, expectedDigest string) error {
	directory, err := openCredentialRoot(root)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	fd, err := unix.Openat(int(directory.Fd()), leaf, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return errCredentialMissing
	}
	if err != nil {
		return errors.New("PF-005 credential cannot be opened for deletion")
	}
	file := os.NewFile(uintptr(fd), leaf)
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("PF-005 credential deletion handle is unavailable")
	}
	defer func() { _ = file.Close() }()
	if err := verifyUnixCredential(file, credentialBytes); err != nil {
		return err
	}
	value, err := io.ReadAll(io.LimitReader(file, credentialBytes+1))
	if err != nil || len(value) != credentialBytes {
		clear(value)
		return errors.New("PF-005 credential cannot be verified for deletion")
	}
	digest := sha256.Sum256(value)
	clear(value)
	if hex.EncodeToString(digest[:]) != expectedDigest || ctx.Err() != nil {
		return errCredentialAuthority
	}
	if err := unix.Unlinkat(int(directory.Fd()), leaf, 0); err != nil {
		return errors.New("PF-005 credential deletion failed")
	}
	if err := unix.Fsync(int(directory.Fd())); err != nil {
		return errors.New("PF-005 credential deletion is not durable")
	}
	return nil
}

func openCredentialRoot(root string) (*os.File, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errCredentialAuthority
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("PF-005 credential root is unavailable")
	}
	for _, component := range splitUnixPath(root) {
		next, openError := unix.Openat(
			fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0,
		)
		if openError != nil {
			_ = unix.Close(fd)
			return nil, errors.New("PF-005 credential root is unavailable")
		}
		_ = unix.Close(fd)
		fd = next
	}
	var status unix.Stat_t
	if unix.Fstat(fd, &status) != nil || uint32(status.Mode)&uint32(unix.S_IFMT) != uint32(unix.S_IFDIR) ||
		uint32(status.Mode)&0o7777 != 0o700 || status.Uid != uint32(os.Geteuid()) { //nolint:gosec // Native EUID is nonnegative.
		_ = unix.Close(fd)
		return nil, errCredentialAuthority
	}
	directory := os.NewFile(uintptr(fd), root)
	if directory == nil {
		_ = unix.Close(fd)
		return nil, errors.New("PF-005 credential root handle is unavailable")
	}
	return directory, nil
}

func splitUnixPath(path string) []string {
	return strings.Split(strings.TrimPrefix(path, "/"), "/")
}

func verifyUnixCredential(file *os.File, size int64) error {
	var status unix.Stat_t
	if file == nil || unix.Fstat(int(file.Fd()), &status) != nil ||
		uint32(status.Mode)&uint32(unix.S_IFMT) != uint32(unix.S_IFREG) ||
		uint32(status.Mode)&0o7777 != 0o444 || status.Uid != uint32(os.Geteuid()) || //nolint:gosec // Native EUID is nonnegative.
		uint64(status.Nlink) != 1 || status.Size != size {
		return errCredentialAuthority
	}
	return nil
}
