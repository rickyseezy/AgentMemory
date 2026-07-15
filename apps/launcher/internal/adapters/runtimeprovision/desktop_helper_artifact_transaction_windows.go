//go:build windows

package runtimeprovision

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"golang.org/x/sys/windows"
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
	expected, targetError := desktopMutationArtifactTarget(runtimeinstall.PlatformWindows, request.Digest())
	ownerSID := strings.TrimPrefix(request.Authority().PrincipalID(), "sid:")
	if ctx == nil || targetError != nil || ownerSID == request.Authority().PrincipalID() || ownerSID == "" ||
		request.Authority().Platform() != runtimeinstall.PlatformWindows ||
		!strings.EqualFold(artifact.targetPath, expected) ||
		!strings.EqualFold(artifact.sourcePath, request.Authority().ArtifactPath()) ||
		artifact.sha256 != request.ArtifactDigest() || artifact.size != request.Authority().ArtifactBytes() {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	requestRoot := filepath.Dir(artifact.targetPath)
	if _, _, err := windowssecurity.EnsurePrivateDirectoryTree(
		ctx, `C:\ProgramData\AgentMemory\runtime-helper`, requestRoot,
	); err != nil {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	if windowsDesktopMutationArtifactMatches(ctx, artifact.targetPath, artifact.sha256, artifact.size) {
		return nil
	}
	source, _, err := windowssecurity.OpenVerifiedForOwnerSIDLockedRead(ctx, artifact.sourcePath, ownerSID)
	if err != nil {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	defer func() { _ = source.Close() }()
	info, err := source.Stat()
	if err != nil || info.Size() < 0 || uint64(info.Size()) != artifact.size {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	temporary := filepath.Join(requestRoot, ".installer."+artifact.sha256.String()+".partial")
	if err := removeWindowsDesktopMutationTemporary(ctx, temporary); err != nil {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	target, err := windowssecurity.CreatePrivateFile(ctx, temporary)
	if err != nil {
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
	written, err := io.CopyN(io.MultiWriter(target, hasher), source, int64(artifact.size)) // #nosec G115 -- signed size is JSON-safe.
	var extra [1]byte
	extraCount, extraError := source.Read(extra[:])
	var actual runtimeinstall.Hash
	copy(actual[:], hasher.Sum(nil))
	if err != nil || uint64(written) != artifact.size || extraCount != 0 || !errors.Is(extraError, io.EOF) ||
		actual != artifact.sha256 || ctx.Err() != nil || target.Sync() != nil || target.Close() != nil {
		return desktopMutationHelperContextOrIntegrity(ctx)
	}
	from, fromError := windows.UTF16PtrFromString(temporary)
	to, toError := windows.UTF16PtrFromString(artifact.targetPath)
	if fromError != nil || toError != nil || windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH) != nil {
		if windowsDesktopMutationArtifactMatches(ctx, artifact.targetPath, artifact.sha256, artifact.size) {
			return nil
		}
		return runtimeport.ErrDesktopMutationIntegrity
	}
	committed = true
	if !windowsDesktopMutationArtifactMatches(ctx, artifact.targetPath, artifact.sha256, artifact.size) {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	return nil
}

func windowsDesktopMutationArtifactMatches(
	ctx context.Context,
	path string,
	digest runtimeinstall.Hash,
	size uint64,
) bool {
	file, _, err := windowssecurity.OpenVerifiedLockedRead(ctx, path, false)
	if err != nil {
		return false
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || info.Size() < 0 || uint64(info.Size()) != size {
		return false
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, int64(size)+1)) // #nosec G115 -- signed size is JSON-safe.
	var actual runtimeinstall.Hash
	copy(actual[:], hasher.Sum(nil))
	return err == nil && uint64(written) == size && actual == digest
}

func removeWindowsDesktopMutationTemporary(ctx context.Context, path string) error {
	file, _, err := windowssecurity.OpenVerified(ctx, path, false, true, true)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	info, statError := file.Stat()
	closeError := file.Close()
	if statError != nil || closeError != nil || info.Size() < 0 {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	return os.Remove(path)
}

var _ desktopMutationArtifactCopier = nativeDesktopMutationArtifactCopier{}
