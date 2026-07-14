//go:build darwin || linux

package artifactfs

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"golang.org/x/sys/unix"
)

type secureFile struct {
	file      *os.File
	directory *os.File
	leaf      string
}

func (f *secureFile) close() {
	if f == nil {
		return
	}
	if f.file != nil {
		_ = f.file.Close()
	}
	if f.directory != nil {
		_ = f.directory.Close()
	}
}

func openSecureDirectory(path string) (*os.File, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, artifactapp.ErrStoreIntegrity
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(fd), "/")
	if current == nil {
		_ = unix.Close(fd)
		return nil, artifactapp.ErrStoreIntegrity
	}
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(components) == 1 && components[0] == "" {
		_ = current.Close()
		return nil, artifactapp.ErrStoreIntegrity
	}
	for index, component := range components {
		if !safeLeaf(component) {
			_ = current.Close()
			return nil, artifactapp.ErrStoreIntegrity
		}
		nextFD, openError := unix.Openat(
			int(current.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0,
		)
		if openError != nil {
			_ = current.Close()
			return nil, openError
		}
		var stat unix.Stat_t
		if unix.Fstat(nextFD, &stat) != nil || !safeControlledDirectoryStat(&stat, index == len(components)-1) {
			_ = unix.Close(nextFD)
			_ = current.Close()
			return nil, artifactapp.ErrStoreIntegrity
		}
		_ = current.Close()
		current = os.NewFile(uintptr(nextFD), component)
		if current == nil {
			_ = unix.Close(nextFD)
			return nil, artifactapp.ErrStoreIntegrity
		}
	}
	directory := current
	if directory == nil {
		return nil, artifactapp.ErrStoreIntegrity
	}
	info, statError := directory.Stat()
	if statError != nil || !safeDirectoryInfo(info) {
		_ = directory.Close()
		return nil, artifactapp.ErrStoreIntegrity
	}
	return directory, nil
}

func safeControlledDirectoryStat(stat *unix.Stat_t, final bool) bool {
	if stat == nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return false
	}
	owner := stat.Uid
	effective, valid := effectiveUserID()
	if !valid || owner != 0 && owner != effective {
		return false
	}
	if final {
		return owner == effective && stat.Mode&0o077 == 0
	}
	if stat.Mode&0o022 != 0 {
		return owner == 0 && stat.Mode&unix.S_ISVTX != 0
	}
	return true
}

func captureDirectoryIdentity(path string) (string, error) {
	directory, err := openSecureDirectory(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = directory.Close() }()
	var stat unix.Stat_t
	if unix.Fstat(int(directory.Fd()), &stat) != nil {
		return "", artifactapp.ErrStoreIntegrity
	}
	return fmt.Sprintf("%d:%d", stat.Dev, stat.Ino), nil
}

const storeIdentityLeaf = ".agentmemory-store-identity"

func openStoreIdentity(root *os.File) (*secureFile, [32]byte, error) {
	var identity [32]byte
	opened, _, err := openSecureLeafAt(root, storeIdentityLeaf, false)
	if err == nil {
		return readStoreIdentity(opened)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, identity, err
	}
	if _, err := rand.Read(identity[:]); err != nil {
		return nil, [32]byte{}, artifactapp.ErrStoreOperation
	}
	tempLeaf := fmt.Sprintf("%s.tmp-%x", storeIdentityLeaf, identity[:16])
	temporary, created, err := openSecureLeafAt(root, tempLeaf, true)
	if err != nil || !created {
		if temporary != nil {
			temporary.close()
		}
		return nil, [32]byte{}, artifactapp.ErrStoreOperation
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = removeOpenSecureFile(temporary)
		}
		temporary.close()
	}()
	written, writeError := temporary.file.WriteAt(identity[:], 0)
	if writeError != nil || written != len(identity) || durableSync(temporary.file) != nil ||
		temporary.verifyExactSize(uint64(len(identity))) != nil {
		return nil, [32]byte{}, artifactapp.ErrStoreOperation
	}
	if err := renameNoReplace(temporary.directory, tempLeaf, root, storeIdentityLeaf); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return nil, [32]byte{}, artifactapp.ErrStoreOperation
		}
		if removeError := removeOpenSecureFile(temporary); removeError != nil {
			return nil, [32]byte{}, artifactapp.ErrStoreOperation
		}
		removeTemporary = false
		winner, _, openError := openSecureLeafAt(root, storeIdentityLeaf, false)
		if openError != nil {
			return nil, [32]byte{}, artifactapp.ErrStoreIntegrity
		}
		return readStoreIdentity(winner)
	}
	// The final name becomes visible only after all bytes and file metadata are
	// durable. A crash before this rename leaves at most an ignorable temp; a
	// crash after it leaves an absent-or-complete final marker.
	removeTemporary = false
	if durableSync(root) != nil {
		return nil, [32]byte{}, artifactapp.ErrStoreOperation
	}
	published, _, openError := openSecureLeafAt(root, storeIdentityLeaf, false)
	if openError != nil {
		return nil, [32]byte{}, artifactapp.ErrStoreIntegrity
	}
	return readStoreIdentity(published)
}

func readStoreIdentity(opened *secureFile) (*secureFile, [32]byte, error) {
	var identity [32]byte
	if opened.verifyExactSize(uint64(len(identity))) != nil {
		opened.close()
		return nil, [32]byte{}, artifactapp.ErrStoreIntegrity
	}
	read, readError := opened.file.ReadAt(identity[:], 0)
	if readError != nil || read != len(identity) || !validStoreIdentity(opened, identity) {
		opened.close()
		return nil, [32]byte{}, artifactapp.ErrStoreIntegrity
	}
	return opened, identity, nil
}

func validStoreIdentity(opened *secureFile, expected [32]byte) bool {
	if opened == nil || expected == [32]byte{} || opened.verifyExactSize(uint64(len(expected))) != nil {
		return false
	}
	var observed [32]byte
	read, err := opened.file.ReadAt(observed[:], 0)
	return err == nil && read == len(observed) && observed == expected
}

func boundFilesystemIdentity(filesystemID string, root *os.File, identity [32]byte) (string, error) {
	if filesystemID == "" || identity == [32]byte{} || !safeDirectoryDescriptor(root) {
		return "", artifactapp.ErrStoreIntegrity
	}
	var stat unix.Stat_t
	if unix.Fstat(int(root.Fd()), &stat) != nil {
		return "", artifactapp.ErrStoreIntegrity
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf(
		"agentmemory-artifact-root-v2\x00%d\x00%x", stat.Ino, identity,
	)))
	return fmt.Sprintf("fs-%x", digest), nil
}

func directoryIdentityMatches(path, expected string) bool {
	if expected == "" {
		return false
	}
	identity, err := captureDirectoryIdentity(path)
	return err == nil && identity == expected
}

func openSecureLeaf(directoryPath, leaf string, create bool) (*secureFile, bool, error) {
	if !safeLeaf(leaf) {
		return nil, false, artifactapp.ErrStoreIntegrity
	}
	directory, err := openSecureDirectory(directoryPath)
	if err != nil {
		return nil, false, err
	}
	result, created, openError := openSecureLeafAt(directory, leaf, create)
	_ = directory.Close()
	return result, created, openError
}

// duplicateSecureDirectory gives each operation an independent descriptor
// while preserving the already verified directory object even if its path is
// renamed or replaced concurrently.
func duplicateSecureDirectory(directory *os.File) (*os.File, error) {
	if !safeDirectoryDescriptor(directory) {
		return nil, artifactapp.ErrStoreIntegrity
	}
	fd, err := unix.FcntlInt(directory.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	duplicate := os.NewFile(uintptr(fd), directory.Name())
	if duplicate == nil {
		_ = unix.Close(fd)
		return nil, artifactapp.ErrStoreIntegrity
	}
	if !safeDirectoryDescriptor(duplicate) {
		_ = duplicate.Close()
		return nil, artifactapp.ErrStoreIntegrity
	}
	return duplicate, nil
}

func safeDirectoryDescriptor(directory *os.File) bool {
	if directory == nil {
		return false
	}
	var stat unix.Stat_t
	return unix.Fstat(int(directory.Fd()), &stat) == nil && safeControlledDirectoryStat(&stat, true)
}

func openSecureLeafAt(directory *os.File, leaf string, create bool) (*secureFile, bool, error) {
	if !safeLeaf(leaf) {
		return nil, false, artifactapp.ErrStoreIntegrity
	}
	ownedDirectory, err := duplicateSecureDirectory(directory)
	if err != nil {
		return nil, false, err
	}
	flags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_CLOEXEC
	created := false
	fd, err := unix.Openat(int(ownedDirectory.Fd()), leaf, flags, 0)
	if errors.Is(err, unix.ENOENT) && create {
		fd, err = unix.Openat(int(ownedDirectory.Fd()), leaf, flags|unix.O_CREAT|unix.O_EXCL, 0o600)
		created = err == nil
	}
	if err != nil {
		_ = ownedDirectory.Close()
		return nil, false, err
	}
	file := os.NewFile(uintptr(fd), leaf)
	if file == nil {
		_ = unix.Close(fd)
		_ = ownedDirectory.Close()
		return nil, false, artifactapp.ErrStoreIntegrity
	}
	result := &secureFile{file: file, directory: ownedDirectory, leaf: leaf}
	if err := result.verifyPathIdentity(); err != nil {
		result.close()
		return nil, false, err
	}
	return result, created, nil
}

func openSecureReadLeafAt(directory *os.File, leaf string) (*secureFile, error) {
	if !safeLeaf(leaf) {
		return nil, artifactapp.ErrStoreIntegrity
	}
	ownedDirectory, err := duplicateSecureDirectory(directory)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(ownedDirectory.Fd()), leaf, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = ownedDirectory.Close()
		return nil, err
	}
	file := os.NewFile(uintptr(fd), leaf)
	if file == nil {
		_ = unix.Close(fd)
		_ = ownedDirectory.Close()
		return nil, artifactapp.ErrStoreIntegrity
	}
	result := &secureFile{file: file, directory: ownedDirectory, leaf: leaf}
	if err := result.verifyPathIdentity(); err != nil {
		result.close()
		return nil, err
	}
	return result, nil
}

func openSecureChildDirectoryAt(parent *os.File, leaf string, create bool) (*os.File, error) {
	if !safeLeaf(leaf) || !safeDirectoryDescriptor(parent) {
		return nil, artifactapp.ErrStoreIntegrity
	}
	if create {
		if err := unix.Mkdirat(int(parent.Fd()), leaf, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
			return nil, err
		}
	}
	fd, err := unix.Openat(int(parent.Fd()), leaf, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	child := os.NewFile(uintptr(fd), leaf)
	if child == nil {
		_ = unix.Close(fd)
		return nil, artifactapp.ErrStoreIntegrity
	}
	if !secureChildDirectoryIdentity(parent, leaf, child) {
		_ = child.Close()
		return nil, artifactapp.ErrStoreIntegrity
	}
	return child, nil
}

func secureChildDirectoryIdentity(parent *os.File, leaf string, child *os.File) bool {
	if !safeLeaf(leaf) || !safeDirectoryDescriptor(parent) || !safeDirectoryDescriptor(child) {
		return false
	}
	var descriptor, path unix.Stat_t
	return unix.Fstat(int(child.Fd()), &descriptor) == nil &&
		unix.Fstatat(int(parent.Fd()), leaf, &path, unix.AT_SYMLINK_NOFOLLOW) == nil &&
		path.Mode&unix.S_IFMT == unix.S_IFDIR && descriptor.Dev == path.Dev && descriptor.Ino == path.Ino
}

func (f *secureFile) verifyPathIdentity() error {
	if f == nil || f.file == nil || f.directory == nil || !safeLeaf(f.leaf) {
		return artifactapp.ErrStoreIntegrity
	}
	var descriptor, path unix.Stat_t
	if unix.Fstat(int(f.file.Fd()), &descriptor) != nil ||
		unix.Fstatat(int(f.directory.Fd()), f.leaf, &path, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		!safeUnixFileStat(&descriptor) || !safeUnixFileStat(&path) || descriptor.Dev != path.Dev || descriptor.Ino != path.Ino {
		return artifactapp.ErrStoreIntegrity
	}
	return nil
}

func (f *secureFile) verifyExactSize(size uint64) error {
	if err := f.verifyPathIdentity(); err != nil {
		return err
	}
	info, err := f.file.Stat()
	if err != nil || !safeFileInfo(info, size) {
		return artifactapp.ErrStoreIntegrity
	}
	return nil
}

func (f *secureFile) syncDirectory() error {
	if f == nil || f.directory == nil {
		return artifactapp.ErrStoreOperation
	}
	return durableSync(f.directory)
}

func removeSecureLeaf(directoryPath, leaf string, expectedSize uint64) error {
	opened, _, err := openSecureLeaf(directoryPath, leaf, false)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return artifactapp.ErrStoreIntegrity
	}
	defer opened.close()
	if err := opened.verifyExactSize(expectedSize); err != nil {
		return err
	}
	if err := unix.Unlinkat(int(opened.directory.Fd()), leaf, 0); err != nil {
		return artifactapp.ErrStoreOperation
	}
	if err := opened.syncDirectory(); err != nil {
		return artifactapp.ErrStoreOperation
	}
	return nil
}

func removeSecureLeafAt(directory *os.File, leaf string, expectedSize uint64) error {
	opened, _, err := openSecureLeafAt(directory, leaf, false)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return artifactapp.ErrStoreIntegrity
	}
	defer opened.close()
	if err := opened.verifyExactSize(expectedSize); err != nil {
		return err
	}
	if err := unix.Unlinkat(int(opened.directory.Fd()), leaf, 0); err != nil {
		return artifactapp.ErrStoreOperation
	}
	if err := opened.syncDirectory(); err != nil {
		return artifactapp.ErrStoreOperation
	}
	return nil
}

func removeSecureLeafAtMost(directoryPath, leaf string, maximumSize uint64) error {
	opened, _, err := openSecureLeaf(directoryPath, leaf, false)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return artifactapp.ErrStoreIntegrity
	}
	defer opened.close()
	info, statError := opened.file.Stat()
	observed, valid := nonNegativeInt64(infoSize(info, statError))
	if statError != nil || !valid || observed > maximumSize || opened.verifyExactSize(observed) != nil {
		return artifactapp.ErrStoreIntegrity
	}
	if err := unix.Unlinkat(int(opened.directory.Fd()), leaf, 0); err != nil {
		return artifactapp.ErrStoreOperation
	}
	if err := opened.syncDirectory(); err != nil {
		return artifactapp.ErrStoreOperation
	}
	return nil
}

func removeSecureLeafAtMostAt(directory *os.File, leaf string, maximumSize uint64) error {
	opened, _, err := openSecureLeafAt(directory, leaf, false)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return artifactapp.ErrStoreIntegrity
	}
	defer opened.close()
	info, statError := opened.file.Stat()
	observed, valid := nonNegativeInt64(infoSize(info, statError))
	if statError != nil || !valid || observed > maximumSize || opened.verifyExactSize(observed) != nil {
		return artifactapp.ErrStoreIntegrity
	}
	if err := unix.Unlinkat(int(opened.directory.Fd()), leaf, 0); err != nil {
		return artifactapp.ErrStoreOperation
	}
	if err := opened.syncDirectory(); err != nil {
		return artifactapp.ErrStoreOperation
	}
	return nil
}

func safeLeaf(value string) bool {
	return value != "" && value != "." && value != ".." && filepath.Base(value) == value &&
		!strings.ContainsAny(value, "/\\\x00")
}

func safeUnixFileStat(stat *unix.Stat_t) bool {
	effective, valid := effectiveUserID()
	return stat != nil && stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Mode&0o077 == 0 &&
		valid && stat.Uid == effective && stat.Nlink == 1
}

func safeDirectoryInfo(info os.FileInfo) bool {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	effective, valid := effectiveUserID()
	return ok && valid && stat.Uid == effective
}

func effectiveUserID() (uint32, bool) {
	value := os.Geteuid()
	if value < 0 || uint64(value) > math.MaxUint32 {
		return 0, false
	}
	return uint32(value), true // #nosec G115 -- value is explicitly bounded to uint32 above.
}
