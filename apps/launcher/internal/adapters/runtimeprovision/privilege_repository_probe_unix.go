//go:build darwin || linux

package runtimeprovision

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"golang.org/x/sys/unix"
)

// PrivilegeRepositoryStateProbe independently proves the exact protected
// repository configuration and signing key state.
type PrivilegeRepositoryStateProbe interface {
	PrivilegeRepositoryStateMatches(context.Context, runtimeport.LinuxAuthority) (bool, error)
}

// NativePrivilegeRepositoryStateProbe reads only internally derived system
// paths with descriptor, owner, mode, link-count, and content verification.
type NativePrivilegeRepositoryStateProbe struct {
	root string
	uid  uint32
	gid  uint32
}

// NewNativePrivilegeRepositoryStateProbe constructs the production root-owned
// Linux repository observer.
func NewNativePrivilegeRepositoryStateProbe() (*NativePrivilegeRepositoryStateProbe, error) {
	if runtime.GOOS != "linux" {
		return nil, ErrUnsupportedHost
	}
	return newNativePrivilegeRepositoryStateProbe("", 0, 0)
}

func newNativePrivilegeRepositoryStateProbe(
	root string,
	uid uint32,
	gid uint32,
) (*NativePrivilegeRepositoryStateProbe, error) {
	if root != "" && (!filepath.IsAbs(root) || filepath.Clean(root) != root) {
		return nil, errors.New("repository observation root must be canonical")
	}
	return &NativePrivilegeRepositoryStateProbe{root: root, uid: uid, gid: gid}, nil
}

// PrivilegeRepositoryStateMatches returns false for an absent exact file and
// fails closed for an unsafe or substituted existing object.
func (p *NativePrivilegeRepositoryStateProbe) PrivilegeRepositoryStateMatches(
	ctx context.Context,
	authority runtimeport.LinuxAuthority,
) (bool, error) {
	if p == nil || ctx == nil || !authority.Valid() {
		return false, runtimeport.ErrPrivilegeIntegrity
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	configurationPath, keyPath, configuration, err := renderPrivilegeRepository(authority)
	if err != nil || runtimeinstall.Sum(configuration) != authority.Repository().ConfigurationDigest() {
		return false, runtimeport.ErrPrivilegeIntegrity
	}
	configurationBytes, present, err := p.readPrivilegeRepositoryFile(configurationPath)
	if err != nil || !present {
		return false, err
	}
	if string(configurationBytes) != string(configuration) {
		return false, nil
	}
	keyBytes, present, err := p.readPrivilegeRepositoryFile(keyPath)
	if err != nil || !present {
		return false, err
	}
	return len(keyBytes) != 0 && runtimeinstall.Sum(keyBytes) == authority.Repository().SigningKeyDigest(), nil
}

func (p *NativePrivilegeRepositoryStateProbe) readPrivilegeRepositoryFile(
	systemPath string,
) ([]byte, bool, error) {
	if p == nil || !canonicalPrivilegeSystemPath(systemPath) {
		return nil, false, runtimeport.ErrPrivilegeIntegrity
	}
	path := systemPath
	if p.root != "" {
		path = filepath.Join(p.root, systemPath)
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0o022 != 0 {
		return nil, false, runtimeport.ErrPrivilegeIntegrity
	}
	parentMetadata, valid := parent.Sys().(*syscall.Stat_t)
	if !valid || parentMetadata.Uid != p.uid || parentMetadata.Gid != p.gid {
		return nil, false, runtimeport.ErrPrivilegeIntegrity
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, runtimeport.ErrPrivilegeIntegrity
	}
	file := os.NewFile(uintptr(descriptor), "privilege-repository-state")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, false, runtimeport.ErrPrivilegeIntegrity
	}
	defer func() { _ = file.Close() }()
	var metadata unix.Stat_t
	if unix.Fstat(descriptor, &metadata) != nil || metadata.Mode&unix.S_IFMT != unix.S_IFREG ||
		metadata.Uid != p.uid || metadata.Gid != p.gid || metadata.Nlink != 1 ||
		uint32(metadata.Mode)&0o7777 != privilegeRepositoryFileMode || metadata.Size <= 0 ||
		metadata.Size > maximumPrivilegeConfigurationBytes {
		return nil, false, runtimeport.ErrPrivilegeIntegrity
	}
	hasher := sha256.New()
	raw, err := io.ReadAll(io.TeeReader(io.LimitReader(file, maximumPrivilegeConfigurationBytes+1), hasher))
	if err != nil || int64(len(raw)) != metadata.Size || len(raw) > maximumPrivilegeConfigurationBytes {
		return nil, false, runtimeport.ErrPrivilegeIntegrity
	}
	return raw, true, nil
}

var _ PrivilegeRepositoryStateProbe = (*NativePrivilegeRepositoryStateProbe)(nil)
