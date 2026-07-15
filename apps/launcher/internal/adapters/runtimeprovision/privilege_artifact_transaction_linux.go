//go:build linux

package runtimeprovision

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"golang.org/x/sys/unix"
)

type nativePrivilegeArtifactCopier struct{}

func newNativePrivilegeArtifactCopier() privilegeArtifactCopier {
	return nativePrivilegeArtifactCopier{}
}

func (nativePrivilegeArtifactCopier) CopyPrivilegeArtifacts(
	ctx context.Context,
	root string,
	uid uint32,
	gid uint32,
	artifacts []PrivilegeTransactionArtifact,
) error {
	if ctx == nil || os.Geteuid() != 0 || uid == 0 || gid == 0 || len(artifacts) == 0 ||
		len(artifacts) > 4096 || filepath.Dir(root) != linuxPrivilegeTransactionRoot ||
		!canonicalLowerSHA256ForTransaction(filepath.Base(root)) ||
		!slices.IsSortedFunc(artifacts, func(left, right PrivilegeTransactionArtifact) int {
			return comparePrivilegeArtifactID(left.artifactID, right.artifactID)
		}) {
		return ErrProvisionIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, directory := range []struct {
		path string
		mode os.FileMode
	}{
		{path: "/var/lib/agentmemory", mode: 0o755},
		{path: "/var/lib/agentmemory/runtime-helper", mode: 0o755},
		{path: linuxPrivilegeTransactionRoot, mode: 0o700},
		{path: root, mode: 0o700},
	} {
		if err := ensureRootPrivilegeDirectory(directory.path, directory.mode); err != nil {
			return ErrProvisionIntegrity
		}
	}
	for _, artifact := range artifacts {
		if err := copyPrivilegeArtifact(ctx, root, uid, gid, artifact); err != nil {
			if contextError := ctx.Err(); contextError != nil {
				return contextError
			}
			return ErrProvisionIntegrity
		}
	}
	return syncPrivilegeDirectory(root)
}

func comparePrivilegeArtifactID(left string, right string) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

func canonicalLowerSHA256ForTransaction(value string) bool {
	hash, err := runtimeinstall.ParseHash(value)
	return err == nil && !hash.IsZero()
}

func ensureRootPrivilegeDirectory(path string, mode os.FileMode) error {
	if err := os.Mkdir(path, mode); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode {
		return ErrProvisionIntegrity
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 {
		return ErrProvisionIntegrity
	}
	return nil
}

func copyPrivilegeArtifact(
	ctx context.Context,
	root string,
	uid uint32,
	gid uint32,
	artifact PrivilegeTransactionArtifact,
) error {
	if artifact.artifactID == "" || artifact.sha256.IsZero() || artifact.size == 0 ||
		filepath.Dir(artifact.targetPath) != root {
		return ErrProvisionIntegrity
	}
	if existingPrivilegeArtifactMatches(artifact.targetPath, 0, 0, artifact.sha256, artifact.size) {
		return nil
	}
	sourceDescriptor, err := unix.Open(artifact.sourcePath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	source := os.NewFile(uintptr(sourceDescriptor), "privilege-artifact-source")
	if source == nil {
		_ = unix.Close(sourceDescriptor)
		return ErrProvisionIntegrity
	}
	defer func() { _ = source.Close() }()
	if !privilegeArtifactDescriptorMatches(sourceDescriptor, uid, gid, artifact.size) {
		return ErrProvisionIntegrity
	}
	temporary := filepath.Join(root, "."+filepath.Base(artifact.targetPath)+".partial")
	targetDescriptor, err := unix.Open(
		temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600,
	)
	if err != nil {
		return err
	}
	target := os.NewFile(uintptr(targetDescriptor), "privilege-artifact-target")
	if target == nil {
		_ = unix.Close(targetDescriptor)
		_ = os.Remove(temporary)
		return ErrProvisionIntegrity
	}
	committed := false
	defer func() {
		_ = target.Close()
		if !committed {
			_ = os.Remove(temporary)
		}
	}()
	digest := sha256.New()
	written, err := io.CopyN(io.MultiWriter(target, digest), source, int64(artifact.size)) // #nosec G115 -- size is bounded to the exact JSON-safe catalog field.
	if err != nil || uint64(written) != artifact.size {
		return ErrProvisionIntegrity
	}
	var extra [1]byte
	if count, readError := source.Read(extra[:]); count != 0 || !errors.Is(readError, io.EOF) {
		return ErrProvisionIntegrity
	}
	var actual runtimeinstall.Hash
	copy(actual[:], digest.Sum(nil))
	if actual != artifact.sha256 || ctx.Err() != nil || target.Sync() != nil || target.Chmod(0o600) != nil ||
		target.Close() != nil {
		return ErrProvisionIntegrity
	}
	if err := unix.Renameat2(
		unix.AT_FDCWD, temporary, unix.AT_FDCWD, artifact.targetPath, unix.RENAME_NOREPLACE,
	); err != nil {
		if errors.Is(err, unix.EEXIST) &&
			existingPrivilegeArtifactMatches(artifact.targetPath, 0, 0, artifact.sha256, artifact.size) {
			return nil
		}
		return err
	}
	committed = true
	return syncPrivilegeDirectory(root)
}

func privilegeArtifactDescriptorMatches(descriptor int, uid uint32, gid uint32, size uint64) bool {
	var stat unix.Stat_t
	return unix.Fstat(descriptor, &stat) == nil && stat.Mode&unix.S_IFMT == unix.S_IFREG &&
		stat.Uid == uid && stat.Gid == gid && stat.Mode&0o077 == 0 && stat.Nlink == 1 &&
		stat.Size >= 0 && uint64(stat.Size) == size
}

func existingPrivilegeArtifactMatches(
	path string,
	uid uint32,
	gid uint32,
	digest runtimeinstall.Hash,
	size uint64,
) bool {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	file := os.NewFile(uintptr(descriptor), "privilege-existing-artifact")
	if file == nil {
		_ = unix.Close(descriptor)
		return false
	}
	defer func() { _ = file.Close() }()
	if !privilegeArtifactDescriptorMatches(descriptor, uid, gid, size) {
		return false
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, int64(size)+1)) // #nosec G115 -- size is a JSON-safe signed field.
	if err != nil || uint64(written) != size {
		return false
	}
	var actual runtimeinstall.Hash
	copy(actual[:], hasher.Sum(nil))
	return actual == digest
}

func syncPrivilegeDirectory(path string) error {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(descriptor) }()
	return unix.Fsync(descriptor)
}

var _ privilegeArtifactCopier = nativePrivilegeArtifactCopier{}
