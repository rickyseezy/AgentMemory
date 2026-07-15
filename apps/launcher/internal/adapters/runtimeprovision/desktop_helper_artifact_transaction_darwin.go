//go:build darwin

package runtimeprovision

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"golang.org/x/sys/unix"
)

type nativeDesktopMutationArtifactCopier struct{}

func newNativeDesktopMutationArtifactCopier() desktopMutationArtifactCopier {
	return nativeDesktopMutationArtifactCopier{}
}

func (nativeDesktopMutationArtifactCopier) CopyDesktopMutationArtifact(
	ctx context.Context,
	request runtimeport.DesktopMutationRequest,
	artifact DesktopMutationTransactionArtifact,
) error {
	uid, ok := darwinDesktopMutationPrincipalUID(request.Authority().PrincipalID())
	expected, targetError := desktopMutationArtifactTarget(runtimeinstall.PlatformDarwin, request.Digest())
	if ctx == nil || os.Geteuid() != 0 || !ok || request.Authority().Platform() != runtimeinstall.PlatformDarwin ||
		artifact.targetPath != expected || targetError != nil || artifact.sourcePath != request.Authority().ArtifactPath() ||
		artifact.sha256 != request.ArtifactDigest() || artifact.size != request.Authority().ArtifactBytes() {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	requestRoot := filepath.Dir(artifact.targetPath)
	for _, directory := range []struct {
		path string
		mode os.FileMode
	}{
		{path: "/Library/Application Support/AgentMemory", mode: 0o755},
		{path: "/Library/Application Support/AgentMemory/runtime-helper", mode: 0o755},
		{path: darwinDesktopMutationTransactionRoot, mode: 0o700},
		{path: requestRoot, mode: 0o700},
	} {
		if err := ensureDarwinDesktopMutationDirectory(directory.path, directory.mode); err != nil {
			return runtimeport.ErrDesktopMutationIntegrity
		}
	}
	if darwinDesktopMutationArtifactMatches(artifact.targetPath, 0, artifact.sha256, artifact.size, 0o600) {
		return nil
	}
	sourceDescriptor, err := unix.Open(artifact.sourcePath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	source := os.NewFile(uintptr(sourceDescriptor), "desktop-mutation-source")
	if source == nil {
		_ = unix.Close(sourceDescriptor)
		return runtimeport.ErrDesktopMutationIntegrity
	}
	defer func() { _ = source.Close() }()
	if !darwinDesktopMutationDescriptorMatches(sourceDescriptor, uid, artifact.size, 0o600) {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	temporary := filepath.Join(requestRoot, ".installer."+artifact.sha256.String()+".partial")
	if err := removeDarwinDesktopMutationTemporary(temporary); err != nil {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	targetDescriptor, err := unix.Open(
		temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600,
	)
	if err != nil {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	target := os.NewFile(uintptr(targetDescriptor), "desktop-mutation-target")
	if target == nil {
		_ = unix.Close(targetDescriptor)
		_ = os.Remove(temporary)
		return runtimeport.ErrDesktopMutationIntegrity
	}
	committed := false
	defer func() {
		_ = target.Close()
		if !committed {
			_ = os.Remove(temporary)
		}
	}()
	hasher := sha256.New()
	written, err := io.CopyN(io.MultiWriter(target, hasher), source, int64(artifact.size)) // #nosec G115 -- catalog size is bounded to JSON-safe integer.
	var extra [1]byte
	extraCount, extraError := source.Read(extra[:])
	var actual runtimeinstall.Hash
	copy(actual[:], hasher.Sum(nil))
	if err != nil || uint64(written) != artifact.size || extraCount != 0 || !errors.Is(extraError, io.EOF) ||
		actual != artifact.sha256 || ctx.Err() != nil || target.Sync() != nil || target.Chmod(0o600) != nil ||
		target.Close() != nil {
		return desktopMutationHelperContextOrIntegrity(ctx)
	}
	if err := unix.RenameatxNp(
		unix.AT_FDCWD, temporary, unix.AT_FDCWD, artifact.targetPath, unix.RENAME_EXCL,
	); err != nil {
		if errors.Is(err, unix.EEXIST) &&
			darwinDesktopMutationArtifactMatches(artifact.targetPath, 0, artifact.sha256, artifact.size, 0o600) {
			return nil
		}
		return runtimeport.ErrDesktopMutationIntegrity
	}
	committed = true
	if err := syncPrivilegeProtectedDirectory(requestRoot); err != nil ||
		!darwinDesktopMutationArtifactMatches(artifact.targetPath, 0, artifact.sha256, artifact.size, 0o600) {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	return nil
}

func darwinDesktopMutationPrincipalUID(principal string) (uint32, bool) {
	value := strings.TrimPrefix(principal, "uid:")
	parsed, err := strconv.ParseUint(value, 10, 32)
	return uint32(parsed), err == nil && value != principal && parsed > 0
}

func ensureDarwinDesktopMutationDirectory(path string, mode os.FileMode) error {
	if err := os.Mkdir(path, mode); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	status, ok := infoSyscallStat(info)
	if err != nil || !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode ||
		status.Uid != 0 || status.Gid != 0 {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	return nil
}

func infoSyscallStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	return status, ok
}

func darwinDesktopMutationDescriptorMatches(descriptor int, uid uint32, size uint64, mode uint32) bool {
	var status unix.Stat_t
	return unix.Fstat(descriptor, &status) == nil && status.Mode&unix.S_IFMT == unix.S_IFREG &&
		status.Uid == uid && status.Nlink == 1 && uint32(status.Mode)&0o7777 == mode &&
		status.Size >= 0 && uint64(status.Size) == size
}

func darwinDesktopMutationArtifactMatches(
	path string,
	uid uint32,
	digest runtimeinstall.Hash,
	size uint64,
	mode uint32,
) bool {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	file := os.NewFile(uintptr(descriptor), "desktop-mutation-existing")
	if file == nil {
		_ = unix.Close(descriptor)
		return false
	}
	defer func() { _ = file.Close() }()
	if !darwinDesktopMutationDescriptorMatches(descriptor, uid, size, mode) {
		return false
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, int64(size)+1)) // #nosec G115 -- catalog size is JSON-safe.
	var actual runtimeinstall.Hash
	copy(actual[:], hasher.Sum(nil))
	return err == nil && uint64(written) == size && actual == digest
}

func removeDarwinDesktopMutationTemporary(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	status, ok := infoSyscallStat(info)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 || status.Uid != 0 || status.Gid != 0 || status.Nlink != 1 {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	return os.Remove(path)
}

var _ desktopMutationArtifactCopier = nativeDesktopMutationArtifactCopier{}
