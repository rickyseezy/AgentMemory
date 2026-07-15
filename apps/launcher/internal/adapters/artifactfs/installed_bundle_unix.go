//go:build darwin || linux

package artifactfs

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"golang.org/x/sys/unix"
)

func openBundleDirectory(path string, policy bundleAccessPolicy) (*os.File, error) {
	if policy == bundleAccessOwnerPrivate {
		return openSecureDirectory(path)
	}
	if policy != bundleAccessInstalledReadOnly || path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, artifactapp.ErrFetchIntegrity
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(fd), "/")
	if current == nil {
		_ = unix.Close(fd)
		return nil, artifactapp.ErrFetchIntegrity
	}
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(components) == 1 && components[0] == "" {
		_ = current.Close()
		return nil, artifactapp.ErrFetchIntegrity
	}
	for index, component := range components {
		if !safeLeaf(component) {
			_ = current.Close()
			return nil, artifactapp.ErrFetchIntegrity
		}
		nextFD, openError := unix.Openat(
			int(current.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0,
		)
		if openError != nil {
			_ = current.Close()
			return nil, openError
		}
		var stat unix.Stat_t
		final := index == len(components)-1
		if unix.Fstat(nextFD, &stat) != nil ||
			final && !safeInstalledBundleDirectoryStat(&stat) ||
			!final && !safeControlledDirectoryStat(&stat, false) {
			_ = unix.Close(nextFD)
			_ = current.Close()
			return nil, artifactapp.ErrFetchIntegrity
		}
		_ = current.Close()
		current = os.NewFile(uintptr(nextFD), component)
		if current == nil {
			_ = unix.Close(nextFD)
			return nil, artifactapp.ErrFetchIntegrity
		}
	}
	if !safeBundleDirectoryDescriptor(current, policy) {
		_ = current.Close()
		return nil, artifactapp.ErrFetchIntegrity
	}
	return current, nil
}

func safeInstalledBundleDirectoryStat(stat *unix.Stat_t) bool {
	if stat == nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		stat.Mode&(unix.S_ISUID|unix.S_ISGID|unix.S_ISVTX) != 0 {
		return false
	}
	effective, valid := effectiveUserID()
	if !valid {
		return false
	}
	if stat.Uid == effective && effective != 0 {
		return stat.Mode&0o077 == 0
	}
	permissions := stat.Mode & 0o777
	return stat.Uid == 0 && (permissions == 0o755 || permissions == 0o555)
}

func safeBundleDirectoryDescriptor(directory *os.File, policy bundleAccessPolicy) bool {
	if policy == bundleAccessOwnerPrivate {
		return safeDirectoryDescriptor(directory)
	}
	if directory == nil || policy != bundleAccessInstalledReadOnly {
		return false
	}
	var stat unix.Stat_t
	return unix.Fstat(int(directory.Fd()), &stat) == nil && safeInstalledBundleDirectoryStat(&stat)
}

func duplicateBundleDirectory(directory *os.File, policy bundleAccessPolicy) (*os.File, error) {
	if policy == bundleAccessOwnerPrivate {
		return duplicateSecureDirectory(directory)
	}
	if !safeBundleDirectoryDescriptor(directory, policy) {
		return nil, artifactapp.ErrFetchIntegrity
	}
	fd, err := unix.FcntlInt(directory.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	duplicate := os.NewFile(uintptr(fd), directory.Name())
	if duplicate == nil {
		_ = unix.Close(fd)
		return nil, artifactapp.ErrFetchIntegrity
	}
	if !safeBundleDirectoryDescriptor(duplicate, policy) {
		_ = duplicate.Close()
		return nil, artifactapp.ErrFetchIntegrity
	}
	return duplicate, nil
}

func openBundleChildDirectoryAt(parent *os.File, leaf string, policy bundleAccessPolicy) (*os.File, error) {
	if policy == bundleAccessOwnerPrivate {
		return openSecureChildDirectoryAt(parent, leaf, false)
	}
	if !safeLeaf(leaf) || !safeBundleDirectoryDescriptor(parent, policy) {
		return nil, artifactapp.ErrFetchIntegrity
	}
	fd, err := unix.Openat(int(parent.Fd()), leaf, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	child := os.NewFile(uintptr(fd), leaf)
	if child == nil {
		_ = unix.Close(fd)
		return nil, artifactapp.ErrFetchIntegrity
	}
	var descriptor, path unix.Stat_t
	if !safeBundleDirectoryDescriptor(child, policy) || unix.Fstat(int(child.Fd()), &descriptor) != nil ||
		unix.Fstatat(int(parent.Fd()), leaf, &path, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		!safeInstalledBundleDirectoryStat(&path) || descriptor.Dev != path.Dev || descriptor.Ino != path.Ino {
		_ = child.Close()
		return nil, artifactapp.ErrFetchIntegrity
	}
	return child, nil
}

func openBundleReadLeafAt(directory *os.File, leaf string, policy bundleAccessPolicy) (*secureFile, error) {
	if policy == bundleAccessOwnerPrivate {
		return openSecureReadLeafAt(directory, leaf)
	}
	if !safeLeaf(leaf) || !safeBundleDirectoryDescriptor(directory, policy) {
		return nil, artifactapp.ErrFetchIntegrity
	}
	ownedDirectory, err := duplicateBundleDirectory(directory, policy)
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
		return nil, artifactapp.ErrFetchIntegrity
	}
	result := &secureFile{
		file: file, directory: ownedDirectory, leaf: leaf,
		bundlePolicy: bundleAccessInstalledReadOnly,
	}
	if err := result.verifyPathIdentity(); err != nil {
		result.close()
		return nil, err
	}
	return result, nil
}
