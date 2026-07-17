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

type nativeDesktopMutationArtifactCopier struct {
	operations darwinDesktopMutationArtifactOperations
}

type darwinDesktopMutationArtifactOperations struct {
	effectiveUID      func() int
	ensureDirectory   func(string, os.FileMode) error
	artifactMatches   func(string, uint32, runtimeinstall.Hash, uint64) bool
	open              func(string, int, uint32) (int, error)
	newFile           func(uintptr, string) *os.File
	closeDescriptor   func(int) error
	descriptorMatches func(int, uint32, uint64, uint32) bool
	removeTemporary   func(string) error
	remove            func(string) error
	renameNoReplace   func(string, string) error
	syncDirectory     func(string) error
}

func newNativeDesktopMutationArtifactCopier() desktopMutationArtifactCopier {
	return nativeDesktopMutationArtifactCopier{operations: newDarwinDesktopMutationArtifactOperations()}
}

func newDarwinDesktopMutationArtifactOperations() darwinDesktopMutationArtifactOperations {
	return darwinDesktopMutationArtifactOperations{
		effectiveUID: os.Geteuid, ensureDirectory: ensureDarwinDesktopMutationDirectory,
		artifactMatches: darwinDesktopMutationArtifactMatches, open: unix.Open, newFile: os.NewFile,
		closeDescriptor: unix.Close, descriptorMatches: darwinDesktopMutationDescriptorMatches,
		removeTemporary: removeDarwinDesktopMutationTemporary, remove: os.Remove,
		renameNoReplace: func(source, target string) error {
			return unix.RenameatxNp(unix.AT_FDCWD, source, unix.AT_FDCWD, target, unix.RENAME_EXCL)
		},
		syncDirectory: syncPrivilegeProtectedDirectory,
	}
}

func (o darwinDesktopMutationArtifactOperations) valid() bool {
	return o.effectiveUID != nil && o.ensureDirectory != nil && o.artifactMatches != nil && o.open != nil &&
		o.newFile != nil && o.closeDescriptor != nil && o.descriptorMatches != nil && o.removeTemporary != nil &&
		o.remove != nil && o.renameNoReplace != nil && o.syncDirectory != nil
}

func (c nativeDesktopMutationArtifactCopier) CopyDesktopMutationArtifact(
	ctx context.Context,
	request runtimeport.DesktopMutationRequest,
	artifact DesktopMutationTransactionArtifact,
) error {
	if !c.operations.valid() {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	uid, validationError := validateDarwinDesktopMutationArtifactCopy(
		ctx, c.operations.effectiveUID(), request, artifact,
	)
	if validationError != nil {
		return validationError
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
		if err := c.operations.ensureDirectory(directory.path, directory.mode); err != nil {
			return runtimeport.ErrDesktopMutationIntegrity
		}
	}
	if c.operations.artifactMatches(artifact.targetPath, 0, artifact.sha256, artifact.size) {
		return nil
	}
	sourceDescriptor, err := c.operations.open(
		artifact.sourcePath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0,
	)
	if err != nil {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	source := c.operations.newFile(uintptr(sourceDescriptor), "desktop-mutation-source")
	if source == nil {
		_ = c.operations.closeDescriptor(sourceDescriptor)
		return runtimeport.ErrDesktopMutationIntegrity
	}
	defer func() { _ = source.Close() }()
	if !c.operations.descriptorMatches(sourceDescriptor, uid, artifact.size, 0o600) {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	temporary := filepath.Join(requestRoot, ".installer."+artifact.sha256.String()+".partial")
	if err := c.operations.removeTemporary(temporary); err != nil {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	targetDescriptor, err := c.operations.open(
		temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600,
	)
	if err != nil {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	target := c.operations.newFile(uintptr(targetDescriptor), "desktop-mutation-target")
	if target == nil {
		_ = c.operations.closeDescriptor(targetDescriptor)
		_ = c.operations.remove(temporary)
		return runtimeport.ErrDesktopMutationIntegrity
	}
	committed := false
	defer func() {
		_ = target.Close()
		if !committed {
			_ = c.operations.remove(temporary)
		}
	}()
	hasher := sha256.New()
	written, err := io.CopyN(io.MultiWriter(target, hasher), source, int64(artifact.size)) // #nosec G115 -- catalog size is bounded to JSON-safe integer.
	var extra [1]byte
	extraCount, extraError := source.Read(extra[:])
	var actual runtimeinstall.Hash
	copy(actual[:], hasher.Sum(nil))
	if err != nil || written < 0 || uint64(written) != artifact.size || extraCount != 0 || !errors.Is(extraError, io.EOF) ||
		actual != artifact.sha256 || ctx.Err() != nil || target.Sync() != nil || target.Chmod(0o600) != nil ||
		target.Close() != nil {
		return desktopMutationHelperContextOrIntegrity(ctx)
	}
	if err := c.operations.renameNoReplace(temporary, artifact.targetPath); err != nil {
		if errors.Is(err, unix.EEXIST) &&
			c.operations.artifactMatches(artifact.targetPath, 0, artifact.sha256, artifact.size) {
			return nil
		}
		return runtimeport.ErrDesktopMutationIntegrity
	}
	committed = true
	if err := c.operations.syncDirectory(requestRoot); err != nil ||
		!c.operations.artifactMatches(artifact.targetPath, 0, artifact.sha256, artifact.size) {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	return nil
}

func validateDarwinDesktopMutationArtifactCopy(
	ctx context.Context,
	effectiveUID int,
	request runtimeport.DesktopMutationRequest,
	artifact DesktopMutationTransactionArtifact,
) (uint32, error) {
	uid, principalValid := darwinDesktopMutationPrincipalUID(request.Authority().PrincipalID())
	expected, targetError := desktopMutationArtifactTarget(runtimeinstall.PlatformDarwin, request.Digest())
	if ctx == nil || effectiveUID != 0 || !principalValid ||
		request.Authority().Platform() != runtimeinstall.PlatformDarwin || targetError != nil ||
		artifact.targetPath != expected || artifact.sourcePath != request.Authority().ArtifactPath() ||
		artifact.sha256 != request.ArtifactDigest() || artifact.size != request.Authority().ArtifactBytes() {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	return uid, nil
}

func darwinDesktopMutationPrincipalUID(principal string) (uint32, bool) {
	value := strings.TrimPrefix(principal, "uid:")
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil || value == principal || parsed == 0 {
		return 0, false
	}
	return uint32(parsed), true
}

func ensureDarwinDesktopMutationDirectory(path string, mode os.FileMode) error {
	if err := os.Mkdir(path, mode); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	status, ok := infoSyscallStat(info)
	if err != nil || !darwinDesktopMutationDirectorySafe(info, status, ok, mode) {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	return nil
}

func darwinDesktopMutationDirectorySafe(
	info os.FileInfo,
	status *syscall.Stat_t,
	statusValid bool,
	mode os.FileMode,
) bool {
	return info != nil && statusValid && status != nil && info.IsDir() &&
		info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == mode && status.Uid == 0 && status.Gid == 0
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
	if !darwinDesktopMutationDescriptorMatches(descriptor, uid, size, 0o600) {
		return false
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, int64(size)+1)) // #nosec G115 -- catalog size is JSON-safe.
	var actual runtimeinstall.Hash
	copy(actual[:], hasher.Sum(nil))
	return err == nil && written >= 0 && uint64(written) == size && actual == digest
}

func removeDarwinDesktopMutationTemporary(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	status, ok := infoSyscallStat(info)
	if err != nil || !darwinDesktopMutationTemporarySafe(info, status, ok) {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	return os.Remove(path)
}

func darwinDesktopMutationTemporarySafe(
	info os.FileInfo,
	status *syscall.Stat_t,
	statusValid bool,
) bool {
	return info != nil && statusValid && status != nil && info.Mode().IsRegular() &&
		info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == 0o600 && status.Uid == 0 &&
		status.Gid == 0 && status.Nlink == 1
}

var _ desktopMutationArtifactCopier = nativeDesktopMutationArtifactCopier{}
