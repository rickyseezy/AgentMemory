//go:build darwin || linux

package installplanfs

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type unixStore struct {
	directory *os.File
	uid       uint32
}

func openPlatformStore(ctx context.Context, root string) (platformStore, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	uid := uint32(os.Geteuid()) //nolint:gosec // UIDs are native unsigned 32-bit values on certified Unix targets.
	directory, err := openOrCreatePrivateDirectory(root, uid)
	if err != nil {
		return nil, err
	}
	return &unixStore{directory: directory, uid: uid}, nil
}

func openOrCreatePrivateDirectory(path string, uid uint32) (*os.File, error) {
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	rootFD, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(rootFD), string(filepath.Separator))
	if current == nil {
		_ = unix.Close(rootFD)
		return nil, errors.New("private repository root descriptor is invalid")
	}
	for index, component := range components {
		if component == "" || component == "." || component == ".." {
			_ = current.Close()
			return nil, errors.New("private repository path component is invalid")
		}
		fd, openError := unix.Openat(int(current.Fd()), component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(openError, unix.ENOENT) {
			if makeError := unix.Mkdirat(int(current.Fd()), component, 0o700); makeError != nil && !errors.Is(makeError, unix.EEXIST) {
				_ = current.Close()
				return nil, makeError
			}
			fd, openError = unix.Openat(int(current.Fd()), component,
				unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if openError != nil {
			_ = current.Close()
			return nil, openError
		}
		next := os.NewFile(uintptr(fd), component)
		if next == nil {
			_ = unix.Close(fd)
			_ = current.Close()
			return nil, errors.New("private repository directory descriptor is invalid")
		}
		var stat unix.Stat_t
		if statError := unix.Fstat(fd, &stat); statError != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			_ = next.Close()
			_ = current.Close()
			return nil, errors.New("private repository path is not a directory")
		}
		leaf := index == len(components)-1
		if leaf {
			if stat.Uid != uid || stat.Mode&0o077 != 0 {
				_ = next.Close()
				_ = current.Close()
				return nil, errors.New("private repository directory is not owner-only")
			}
		} else if stat.Mode&0o022 != 0 && (stat.Uid != 0 || stat.Mode&unix.S_ISVTX == 0) {
			_ = next.Close()
			_ = current.Close()
			return nil, errors.New("private repository ancestor is writable by another principal")
		}
		_ = current.Close()
		current = next
	}
	return current, nil
}

func (s *unixStore) load(ctx context.Context, name string) ([]byte, error) {
	if s == nil || s.directory == nil || filepath.Base(name) != name {
		return nil, errors.New("plan repository descriptor is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(s.directory.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, errPlanNotFound
	}
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("plan file descriptor is invalid")
	}
	defer func() { _ = file.Close() }()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Uid != s.uid || before.Mode&0o177 != 0 || before.Nlink != 1 ||
		before.Size <= 0 || before.Size > maximumPersistedPlanBytes {
		return nil, errors.New("plan file ownership or shape is invalid")
	}
	limited := io.LimitReader(file, maximumPersistedPlanBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil || len(raw) == 0 || len(raw) > maximumPersistedPlanBytes {
		return nil, errors.New("plan file read is invalid")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !sameUnixFile(before, after) || int64(len(raw)) != after.Size {
		return nil, errors.New("plan file changed during read")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return raw, nil
}

func (s *unixStore) save(ctx context.Context, name string, raw []byte) error {
	if s == nil || s.directory == nil || filepath.Base(name) != name || len(raw) == 0 || len(raw) > maximumPersistedPlanBytes {
		return errors.New("plan publication input is invalid")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	temporary, err := randomTemporaryName()
	if err != nil {
		return err
	}
	fd, err := unix.Openat(int(s.directory.Fd()), temporary,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), temporary)
	if file == nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(int(s.directory.Fd()), temporary, 0)
		return errors.New("temporary plan descriptor is invalid")
	}
	removeTemporary := true
	defer func() {
		_ = file.Close()
		if removeTemporary {
			_ = unix.Unlinkat(int(s.directory.Fd()), temporary, 0)
		}
	}()
	if err := writeAll(file, raw); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := unix.Fchmod(fd, 0o400); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	published, err := publishExclusive(int(s.directory.Fd()), temporary, name)
	if err != nil {
		return err
	}
	if !published {
		existing, loadError := s.load(ctx, name)
		if loadError != nil || !bytes.Equal(existing, raw) {
			return errImmutableConflict
		}
		return nil
	}
	removeTemporary = false
	if err := unix.Fsync(int(s.directory.Fd())); err != nil {
		return err
	}
	return nil
}

func (s *unixStore) close() error {
	if s == nil || s.directory == nil {
		return nil
	}
	err := s.directory.Close()
	s.directory = nil
	return err
}

func randomTemporaryName() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return ".plan-" + hex.EncodeToString(value[:]) + ".tmp", nil
}

func writeAll(file *os.File, raw []byte) error {
	for len(raw) > 0 {
		written, err := file.Write(raw)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		raw = raw[written:]
	}
	return nil
}

func sameUnixFile(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Uid == right.Uid &&
		left.Mode == right.Mode && left.Nlink == right.Nlink && left.Size == right.Size
}
