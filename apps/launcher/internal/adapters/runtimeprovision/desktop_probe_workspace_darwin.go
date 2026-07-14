//go:build darwin

package runtimeprovision

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"golang.org/x/sys/unix"
)

func prepareNativeDesktopProbeWorkspace(
	ctx context.Context,
	authority runtimeport.DesktopAuthority,
) (probeWorkspace, error) {
	if ctx == nil {
		return probeWorkspace{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return probeWorkspace{}, err
	}
	if !authority.Valid() || authority.Platform() != runtimeinstall.PlatformDarwin || os.Geteuid() <= 0 ||
		authority.PrincipalID() != "uid:"+strconv.Itoa(os.Geteuid()) {
		return probeWorkspace{}, ErrProvisionIntegrity
	}
	base := filepath.Join(authority.HomeDirectory(), "Library", "Caches", "AgentMemory")
	if err := ensureDarwinDesktopProbeBase(base); err != nil {
		return probeWorkspace{}, err
	}
	directory := filepath.Join(base, "runtime-probe-"+authority.PlanDigest().String()[:20])
	inputPath := filepath.Join(directory, "input.bin")
	content := []byte("agentmemory-runtime-probe-v1\n" + authority.CapabilityPolicyDigest().String() + "\n")
	digest := runtimeinstall.Sum(content)
	if err := removeDarwinDesktopProbeWorkspace(directory, inputPath, digest); err != nil {
		return probeWorkspace{}, err
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		return probeWorkspace{}, err
	}
	if err := validateDarwinDesktopProbeDirectory(directory); err != nil {
		_ = os.Remove(directory)
		return probeWorkspace{}, err
	}
	descriptor, err := unix.Open(inputPath, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		_ = os.Remove(directory)
		return probeWorkspace{}, err
	}
	file := os.NewFile(uintptr(descriptor), "desktop-runtime-probe-input")
	if file == nil {
		_ = unix.Close(descriptor)
		_ = os.Remove(directory)
		return probeWorkspace{}, ErrProbeFailed
	}
	writeError := writeAndSyncDesktopProbe(file, content)
	closeError := file.Close()
	if writeError != nil || closeError != nil {
		_ = os.Remove(inputPath)
		_ = os.Remove(directory)
		return probeWorkspace{}, ErrProbeFailed
	}
	return probeWorkspace{
		directory: directory, inputPath: inputPath, digest: digest,
		cleanup: func() error { return removeDarwinDesktopProbeWorkspace(directory, inputPath, digest) },
	}, nil
}

func ensureDarwinDesktopProbeBase(base string) error {
	parent := filepath.Dir(base)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return ErrProvisionIntegrity
	}
	if err := os.Mkdir(base, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return validateDarwinDesktopProbeDirectory(base)
}

func validateDarwinDesktopProbeDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return ErrRuntimeConflict
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	uid := os.Geteuid()
	if !ok || uid <= 0 || status.Uid != uint32(uid) { // #nosec G115 -- positive Darwin UID.
		return ErrRuntimeConflict
	}
	return nil
}

func removeDarwinDesktopProbeWorkspace(
	directory string,
	inputPath string,
	expected runtimeinstall.Hash,
) error {
	_, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || validateDarwinDesktopProbeDirectory(directory) != nil {
		return ErrRuntimeConflict
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) > 1 || len(entries) == 1 && entries[0].Name() != "input.bin" {
		return ErrRuntimeConflict
	}
	if len(entries) == 1 {
		descriptor, openError := unix.Open(inputPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openError != nil {
			return ErrRuntimeConflict
		}
		file := os.NewFile(uintptr(descriptor), "desktop-runtime-probe-cleanup")
		if file == nil {
			_ = unix.Close(descriptor)
			return ErrProbeFailed
		}
		opened, statError := file.Stat()
		content, readError := io.ReadAll(io.LimitReader(file, 4097))
		closeError := file.Close()
		uid := os.Geteuid()
		if statError != nil || opened == nil || uid <= 0 {
			return ErrRuntimeConflict
		}
		status, ok := opened.Sys().(*syscall.Stat_t)
		if !ok || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0o600 ||
			status.Uid != uint32(uid) || status.Nlink != 1 || readError != nil || closeError != nil || // #nosec G115 -- positive UID.
			runtimeinstall.Sum(content) != expected {
			return ErrRuntimeConflict
		}
		if err := os.Remove(inputPath); err != nil {
			return err
		}
	}
	return os.Remove(directory)
}
