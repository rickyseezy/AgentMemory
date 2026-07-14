//go:build darwin || linux

package process

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"golang.org/x/sys/unix"
)

const maximumExecutableBytes = int64(512 * 1024 * 1024)

type executableAncestor struct {
	path     string
	file     *os.File
	identity os.FileInfo
}

type executableLease struct {
	file         *os.File
	path         string
	identity     os.FileInfo
	identityText string
	owner        string
	digest       [sha256.Size]byte
	ancestors    []executableAncestor
}

func acquireExecutableLease(
	ctx context.Context,
	authority argvprocess.ExecutableAuthority,
	allowMutableTestPath bool,
) (*executableLease, error) {
	if ctx == nil || ctx.Err() != nil || !authority.Valid() || authority.Platform() != runtime.GOOS ||
		authority.Architecture() != runtime.GOARCH {
		return nil, argvprocess.ErrInvalidInvocation
	}
	expectedUID, err := parseUnixOwner(authority.OwnerIdentity())
	if err != nil {
		return nil, err
	}
	lease := &executableLease{path: authority.CanonicalPath(), owner: authority.OwnerIdentity()}
	failed := true
	defer func() {
		if failed {
			lease.close()
		}
	}()
	rootDescriptor, err := unix.Open(
		string(filepath.Separator), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0,
	)
	if err != nil {
		return nil, err
	}
	root := os.NewFile(uintptr(rootDescriptor), string(filepath.Separator))
	if root == nil {
		_ = unix.Close(rootDescriptor)
		return nil, os.ErrInvalid
	}
	if err := lease.appendAncestor(string(filepath.Separator), root, expectedUID); err != nil {
		_ = root.Close()
		return nil, err
	}
	current := root
	currentPath := string(filepath.Separator)
	components := strings.Split(strings.TrimPrefix(authority.CanonicalPath(), string(filepath.Separator)), string(filepath.Separator))
	if len(components) < 2 {
		return nil, argvprocess.ErrInvalidInvocation
	}
	for _, component := range components[:len(components)-1] {
		if component == "" || component == "." || component == ".." {
			return nil, argvprocess.ErrInvalidInvocation
		}
		descriptor, openError := unix.Openat(
			int(current.Fd()), component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0,
		)
		if openError != nil {
			return nil, openError
		}
		opened := os.NewFile(uintptr(descriptor), component)
		if opened == nil {
			_ = unix.Close(descriptor)
			return nil, os.ErrInvalid
		}
		currentPath = filepath.Join(currentPath, component)
		if err := lease.appendAncestor(currentPath, opened, expectedUID); err != nil {
			_ = opened.Close()
			return nil, err
		}
		current = opened
	}
	name := components[len(components)-1]
	if name == "" || name == "." || name == ".." {
		return nil, argvprocess.ErrInvalidInvocation
	}
	descriptor, err := unix.Openat(int(current.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	lease.file = os.NewFile(uintptr(descriptor), name)
	if lease.file == nil {
		_ = unix.Close(descriptor)
		return nil, os.ErrInvalid
	}
	lease.identity, err = lease.file.Stat()
	if err != nil || !secureUnixExecutable(lease.file, lease.identity, expectedUID) ||
		!platformExecutablePathSupported(authority, lease.ancestors, lease.identity, expectedUID, allowMutableTestPath) {
		return nil, argvprocess.ErrInvalidInvocation
	}
	pathInfo, err := os.Lstat(authority.CanonicalPath())
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(lease.identity, pathInfo) {
		return nil, argvprocess.ErrInvalidInvocation
	}
	lease.identityText, err = platformExecutableIdentity(lease.identity)
	if err != nil {
		return nil, err
	}
	lease.digest, err = digestExecutable(lease.file)
	if err != nil || lease.digest != authority.SHA256() {
		return nil, argvprocess.ErrInvalidInvocation
	}
	if err := lease.verify(ctx, authority); err != nil {
		return nil, err
	}
	failed = false
	return lease, nil
}

func parseUnixOwner(value string) (uint32, error) {
	if !strings.HasPrefix(value, "uid:") {
		return 0, argvprocess.ErrInvalidInvocation
	}
	parsed, err := strconv.ParseUint(strings.TrimPrefix(value, "uid:"), 10, 32)
	if err != nil || "uid:"+strconv.FormatUint(parsed, 10) != value {
		return 0, argvprocess.ErrInvalidInvocation
	}
	return uint32(parsed), nil
}

func (l *executableLease) appendAncestor(path string, file *os.File, expectedUID uint32) error {
	identity, err := file.Stat()
	if err != nil || !secureExecutableAncestor(file, identity, expectedUID) {
		return argvprocess.ErrInvalidInvocation
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(identity, pathInfo) {
		return argvprocess.ErrInvalidInvocation
	}
	l.ancestors = append(l.ancestors, executableAncestor{path: path, file: file, identity: identity})
	return nil
}

func secureExecutableAncestor(file *os.File, info os.FileInfo, expectedUID uint32) bool {
	if file == nil || info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o022 != 0 {
		return false
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || status.Uid != 0 && status.Uid != expectedUID {
		return false
	}
	if status.Uid == expectedUID {
		return true
	}
	err := unix.Faccessat(int(file.Fd()), ".", unix.W_OK, unix.AT_EACCESS)
	return errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EROFS)
}

func secureUnixExecutable(file *os.File, info os.FileInfo, expectedUID uint32) bool {
	if file == nil || info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 ||
		info.Size() <= 0 || info.Size() > maximumExecutableBytes || !executableACLFree(file) {
		return false
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	return ok && status.Uid == expectedUID && status.Nlink == 1
}

func digestExecutable(file *os.File) ([sha256.Size]byte, error) {
	if file == nil {
		return [sha256.Size]byte{}, os.ErrInvalid
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return [sha256.Size]byte{}, err
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, maximumExecutableBytes+1))
	if err != nil || written <= 0 || written > maximumExecutableBytes {
		return [sha256.Size]byte{}, argvprocess.ErrInvalidInvocation
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return [sha256.Size]byte{}, err
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

func (l *executableLease) verify(ctx context.Context, authority argvprocess.ExecutableAuthority) error {
	if l == nil || l.file == nil || ctx == nil || ctx.Err() != nil || l.path != authority.CanonicalPath() ||
		l.owner != authority.OwnerIdentity() || l.digest != authority.SHA256() {
		return argvprocess.ErrInvalidInvocation
	}
	expectedUID, err := parseUnixOwner(authority.OwnerIdentity())
	if err != nil {
		return err
	}
	for _, ancestor := range l.ancestors {
		current, statError := ancestor.file.Stat()
		pathInfo, pathError := os.Lstat(ancestor.path)
		if statError != nil || pathError != nil || !os.SameFile(ancestor.identity, current) ||
			!os.SameFile(current, pathInfo) || !secureExecutableAncestor(ancestor.file, current, expectedUID) {
			return argvprocess.ErrInvalidInvocation
		}
	}
	current, err := l.file.Stat()
	if err != nil || !os.SameFile(l.identity, current) || !secureUnixExecutable(l.file, current, expectedUID) {
		return argvprocess.ErrInvalidInvocation
	}
	identity, err := platformExecutableIdentity(current)
	if err != nil || identity != l.identityText {
		return argvprocess.ErrInvalidInvocation
	}
	pathInfo, err := os.Lstat(l.path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(current, pathInfo) {
		return argvprocess.ErrInvalidInvocation
	}
	digest, err := digestExecutable(l.file)
	if err != nil || digest != l.digest {
		return argvprocess.ErrInvalidInvocation
	}
	return nil
}

func (l *executableLease) evidence(authority argvprocess.ExecutableAuthority) ExecutableEvidence {
	return ExecutableEvidence{
		CanonicalID: authority.CanonicalID(), FileIdentity: l.identityText, Digest: l.digest, OwnerIdentity: l.owner,
		ReleaseManifestDigest: authority.ReleaseManifestDigest(),
		RuntimePlanDigest:     authority.RuntimePlanDigest(), Role: authority.Role(),
	}
}

func (l *executableLease) command(ctx context.Context, arguments []string) (*exec.Cmd, error) {
	return platformExecutableCommand(ctx, l, arguments)
}

func (l *executableLease) trustedWorkingDirectory() string { return string(filepath.Separator) }

func (l *executableLease) close() {
	if l == nil {
		return
	}
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
	for index := len(l.ancestors) - 1; index >= 0; index-- {
		if l.ancestors[index].file != nil {
			_ = l.ancestors[index].file.Close()
			l.ancestors[index].file = nil
		}
	}
}

func executableIdentityText(device, inode uint64, changedSeconds, changedNanos int64, size int64) string {
	return fmt.Sprintf("unix:%d:%d:%d:%d:%d", device, inode, changedSeconds, changedNanos, size)
}
