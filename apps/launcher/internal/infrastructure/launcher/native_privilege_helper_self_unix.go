//go:build darwin || linux

package launcher

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"golang.org/x/sys/unix"
)

type nativePrivilegeHelperFileVerifier struct {
	path string
	uid  uint32
	gid  uint32
}

// NewNativePrivilegeHelperSelfVerifier constructs the exact root-owned helper
// executable verifier used by the Linux command composition.
func NewNativePrivilegeHelperSelfVerifier() (nativePrivilegeHelperSelfVerifier, error) {
	return newNativePrivilegeHelperFileVerifier(nativeLinuxRuntimeHelperPath, 0, 0)
}

func newNativePrivilegeHelperFileVerifier(
	path string,
	uid uint32,
	gid uint32,
) (*nativePrivilegeHelperFileVerifier, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		strings.ContainsAny(path, "\x00\r\n") {
		return nil, errors.New("canonical privilege helper path is required")
	}
	return &nativePrivilegeHelperFileVerifier{path: path, uid: uid, gid: gid}, nil
}

func (v *nativePrivilegeHelperFileVerifier) VerifyPrivilegeHelperSelf(
	ctx context.Context,
	resource releaseinventory.Resource,
	authority runtimeport.LinuxAuthority,
) (runtimeinstall.Hash, error) {
	if v == nil || ctx == nil || v.path == "" || !authority.Valid() ||
		resource.Kind() != releaseinventory.ResourceKindHelper ||
		resource.Purpose() != releaseinventory.ResourcePurposeNativeHelper ||
		resource.MediaType() != releaseinventory.MediaTypeNativeExecutable ||
		resource.Platform().OS() != runtimeinstall.PlatformLinux.String() ||
		resource.Platform().Architecture() != authority.Architecture().String() ||
		resource.Digest().IsZero() || resource.Size() == 0 || resource.Size() > math.MaxInt64 ||
		resource.NativePublisherIdentity() == "" || resource.NativePublisherPolicyID() == "" {
		return runtimeinstall.Hash{}, runtimeport.ErrPrivilegeIntegrity
	}
	if err := ctx.Err(); err != nil {
		return runtimeinstall.Hash{}, err
	}
	fileDescriptor, err := unix.Open(v.path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return runtimeinstall.Hash{}, runtimeport.ErrPrivilegeIntegrity
	}
	file := os.NewFile(uintptr(fileDescriptor), v.path)
	if file == nil {
		_ = unix.Close(fileDescriptor)
		return runtimeinstall.Hash{}, runtimeport.ErrPrivilegeIntegrity
	}
	defer func() { _ = file.Close() }()
	var metadata unix.Stat_t
	if err := unix.Fstat(fileDescriptor, &metadata); err != nil ||
		metadata.Mode&unix.S_IFMT != unix.S_IFREG || metadata.Uid != v.uid || metadata.Gid != v.gid ||
		metadata.Nlink != 1 || metadata.Mode&0o022 != 0 || metadata.Mode&0o100 == 0 ||
		metadata.Mode&0o7000 != 0 || metadata.Size < 0 || uint64(metadata.Size) != resource.Size() {
		return runtimeinstall.Hash{}, runtimeport.ErrPrivilegeIntegrity
	}
	hasher := sha256.New()
	written, err := io.CopyN(hasher, file, metadata.Size)
	if err != nil || written != metadata.Size {
		return runtimeinstall.Hash{}, runtimeport.ErrPrivilegeIntegrity
	}
	trailing := []byte{0}
	count, readError := file.Read(trailing)
	if count != 0 || readError != io.EOF {
		return runtimeinstall.Hash{}, runtimeport.ErrPrivilegeIntegrity
	}
	if err := ctx.Err(); err != nil {
		return runtimeinstall.Hash{}, err
	}
	var digest runtimeinstall.Hash
	copy(digest[:], hasher.Sum(nil))
	if releaseinventory.Digest(digest) != resource.Digest() {
		return runtimeinstall.Hash{}, runtimeport.ErrPrivilegeIntegrity
	}
	return digest, nil
}

var _ nativePrivilegeHelperSelfVerifier = (*nativePrivilegeHelperFileVerifier)(nil)
