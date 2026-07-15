//go:build darwin || linux

package runtimeprovision

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"golang.org/x/sys/unix"
)

const maximumPrivilegeConfigurationBytes = 1 << 20

type nativePrivilegeProtectedFileWriter struct {
	destinations []string
	transactions string
	uid          uint32
	gid          uint32
}

// NewNativePrivilegeProtectedFileWriter constructs the production root-owned
// repository publisher. It is unavailable outside Linux.
func NewNativePrivilegeProtectedFileWriter() (PrivilegeProtectedFileWriter, error) {
	if runtime.GOOS != "linux" {
		return nil, ErrUnsupportedHost
	}
	return newNativePrivilegeProtectedFileWriter([]string{
		"/etc/apt/keyrings", "/etc/apt/sources.list.d", "/etc/pki/rpm-gpg", "/etc/yum.repos.d",
	}, linuxPrivilegeTransactionRoot, 0, 0)
}

func newNativePrivilegeProtectedFileWriter(
	destinations []string,
	transactions string,
	uid uint32,
	gid uint32,
) (*nativePrivilegeProtectedFileWriter, error) {
	if len(destinations) == 0 || transactions == "" || !filepath.IsAbs(transactions) ||
		filepath.Clean(transactions) != transactions || strings.ContainsAny(transactions, "\x00\r\n") {
		return nil, errors.New("protected privilege destination and transaction roots are required")
	}
	result := append([]string(nil), destinations...)
	slices.Sort(result)
	for index, destination := range result {
		if destination == "" || !filepath.IsAbs(destination) || filepath.Clean(destination) != destination ||
			strings.ContainsAny(destination, "\x00\r\n") || index > 0 && result[index-1] == destination {
			return nil, errors.New("protected privilege destination root is invalid")
		}
	}
	return &nativePrivilegeProtectedFileWriter{
		destinations: result, transactions: transactions, uid: uid, gid: gid,
	}, nil
}

func (w *nativePrivilegeProtectedFileWriter) EnsurePrivilegeFile(
	ctx context.Context,
	path string,
	contents []byte,
	mode uint32,
) (bool, error) {
	if w == nil || ctx == nil || len(contents) == 0 || len(contents) > maximumPrivilegeConfigurationBytes ||
		mode != privilegeRepositoryFileMode || !w.authorizesDestination(path) {
		return false, runtimeport.ErrPrivilegeIntegrity
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return w.ensurePrivilegeReader(ctx, path, bytes.NewReader(contents), uint64(len(contents)), runtimeinstall.Sum(contents), mode)
}

func (w *nativePrivilegeProtectedFileWriter) EnsurePrivilegeArtifactFile(
	ctx context.Context,
	path string,
	artifact PrivilegeTransactionArtifact,
	mode uint32,
) (bool, error) {
	if w == nil || ctx == nil || mode != privilegeRepositoryFileMode || !w.authorizesDestination(path) ||
		artifact.artifactID == "" || artifact.packageSet || artifact.sha256.IsZero() || artifact.size == 0 ||
		artifact.size > math.MaxInt64 ||
		filepath.Dir(filepath.Dir(artifact.targetPath)) != w.transactions ||
		!canonicalPrivilegeTransactionDigest(filepath.Base(filepath.Dir(artifact.targetPath))) {
		return false, runtimeport.ErrPrivilegeIntegrity
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	descriptor, err := unix.Open(artifact.targetPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return false, runtimeport.ErrPrivilegeIntegrity
	}
	source := os.NewFile(uintptr(descriptor), "privilege-protected-artifact")
	if source == nil {
		_ = unix.Close(descriptor)
		return false, runtimeport.ErrPrivilegeIntegrity
	}
	defer func() { _ = source.Close() }()
	if !privilegeProtectedDescriptorMatches(descriptor, w.uid, w.gid, artifact.size, 0o600) {
		return false, runtimeport.ErrPrivilegeIntegrity
	}
	return w.ensurePrivilegeReader(ctx, path, source, artifact.size, artifact.sha256, mode)
}

func (w *nativePrivilegeProtectedFileWriter) ensurePrivilegeReader(
	ctx context.Context,
	path string,
	source io.Reader,
	size uint64,
	digest runtimeinstall.Hash,
	mode uint32,
) (bool, error) {
	if matches, present, err := w.existingPrivilegeDestination(path, size, digest, mode); err != nil {
		return false, runtimeport.ErrPrivilegeIntegrity
	} else if present && matches {
		return false, nil
	}
	if err := ensurePrivilegeProtectedDirectory(filepath.Dir(path), w.uid, w.gid); err != nil {
		return false, runtimeport.ErrPrivilegeIntegrity
	}
	temporary := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+"."+digest.String()+".partial")
	if err := removePrivilegeProtectedTemporary(temporary, w.uid, w.gid); err != nil {
		return false, runtimeport.ErrPrivilegeIntegrity
	}
	descriptor, err := unix.Open(temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return false, runtimeport.ErrPrivilegeIntegrity
	}
	target := os.NewFile(uintptr(descriptor), "privilege-protected-target")
	if target == nil {
		_ = unix.Close(descriptor)
		_ = os.Remove(temporary)
		return false, runtimeport.ErrPrivilegeIntegrity
	}
	committed := false
	defer func() {
		_ = target.Close()
		if !committed {
			_ = os.Remove(temporary)
		}
	}()
	hasher := sha256.New()
	written, err := io.CopyN(io.MultiWriter(target, hasher), source, int64(size)) // #nosec G115 -- signed artifact sizes are JSON-safe.
	if err != nil || written != int64(size) {                                     // #nosec G115 -- size is proven at most MaxInt64 by both public entry points.
		return false, runtimeport.ErrPrivilegeIntegrity
	}
	var actual runtimeinstall.Hash
	copy(actual[:], hasher.Sum(nil))
	if actual != digest || ctx.Err() != nil || target.Sync() != nil || target.Chmod(os.FileMode(mode)) != nil ||
		target.Close() != nil || os.Rename(temporary, path) != nil || syncPrivilegeProtectedDirectory(filepath.Dir(path)) != nil {
		return false, privilegeOperationContextOrIntegrity(ctx)
	}
	committed = true
	matches, present, err := w.existingPrivilegeDestination(path, size, digest, mode)
	if err != nil || !present || !matches {
		return false, runtimeport.ErrPrivilegeIntegrity
	}
	return true, nil
}

func (w *nativePrivilegeProtectedFileWriter) authorizesDestination(path string) bool {
	if w == nil || !canonicalPrivilegeSystemPath(path) {
		return false
	}
	parent := filepath.Dir(path)
	return slices.Contains(w.destinations, parent) && filepath.Base(path) != "." && filepath.Base(path) != ".."
}

func (w *nativePrivilegeProtectedFileWriter) existingPrivilegeDestination(
	path string,
	size uint64,
	digest runtimeinstall.Hash,
	mode uint32,
) (bool, bool, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return false, false, nil
	}
	if err != nil {
		return false, true, err
	}
	file := os.NewFile(uintptr(descriptor), "privilege-protected-existing")
	if file == nil {
		_ = unix.Close(descriptor)
		return false, true, runtimeport.ErrPrivilegeIntegrity
	}
	defer func() { _ = file.Close() }()
	if !privilegeProtectedDescriptorMatches(descriptor, w.uid, w.gid, size, mode) {
		return false, true, runtimeport.ErrPrivilegeIntegrity
	}
	hasher := sha256.New()
	written, err := io.CopyN(hasher, file, int64(size)) // #nosec G115 -- signed sizes are JSON-safe.
	if err != nil || written != int64(size) {           // #nosec G115 -- size is proven at most MaxInt64 by both public entry points.
		return false, true, runtimeport.ErrPrivilegeIntegrity
	}
	var actual runtimeinstall.Hash
	copy(actual[:], hasher.Sum(nil))
	return actual == digest, true, nil
}

func privilegeProtectedDescriptorMatches(
	descriptor int,
	uid uint32,
	gid uint32,
	size uint64,
	mode uint32,
) bool {
	var metadata unix.Stat_t
	return unix.Fstat(descriptor, &metadata) == nil && metadata.Mode&unix.S_IFMT == unix.S_IFREG &&
		metadata.Uid == uid && metadata.Gid == gid && metadata.Nlink == 1 && metadata.Size >= 0 &&
		uint64(metadata.Size) == size && uint32(metadata.Mode)&0o7777 == mode
}

func canonicalPrivilegeTransactionDigest(value string) bool {
	digest, err := runtimeinstall.ParseHash(value)
	return err == nil && !digest.IsZero()
}

func syncPrivilegeProtectedDirectory(path string) error {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(descriptor) }()
	err = unix.Fsync(descriptor)
	if runtime.GOOS == "darwin" && errors.Is(err, unix.EINVAL) {
		return nil
	}
	return err
}

func ensurePrivilegeProtectedDirectory(path string, uid uint32, gid uint32) error {
	if err := os.Mkdir(path, 0o755); err != nil && !errors.Is(err, os.ErrExist) { // #nosec G301 -- root-owned system repository directories must remain traversable.
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o755 {
		return runtimeport.ErrPrivilegeIntegrity
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != uid || metadata.Gid != gid {
		return runtimeport.ErrPrivilegeIntegrity
	}
	return nil
}

func removePrivilegeProtectedTemporary(path string, uid uint32, gid uint32) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return runtimeport.ErrPrivilegeIntegrity
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != uid || metadata.Gid != gid || metadata.Nlink != 1 || info.Mode().Perm() != 0o600 {
		return runtimeport.ErrPrivilegeIntegrity
	}
	return os.Remove(path)
}

var _ PrivilegeProtectedFileWriter = (*nativePrivilegeProtectedFileWriter)(nil)
