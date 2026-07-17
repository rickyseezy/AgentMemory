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
	if err := validateDarwinDesktopProbeAuthority(authority, os.Geteuid()); err != nil {
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

func validateDarwinDesktopProbeAuthority(authority runtimeport.DesktopAuthority, effectiveUID int) error {
	if !authority.Valid() || authority.Platform() != runtimeinstall.PlatformDarwin ||
		authority.PrincipalID() != "uid:"+strconv.Itoa(effectiveUID) {
		return ErrProvisionIntegrity
	}
	return nil
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
	status, statusValid := infoSyscallStat(info)
	if err != nil || !darwinDesktopProbeDirectorySafe(info, status, statusValid, os.Geteuid()) {
		return ErrRuntimeConflict
	}
	return nil
}

func darwinDesktopProbeDirectorySafe(
	info os.FileInfo,
	status *syscall.Stat_t,
	statusValid bool,
	effectiveUID int,
) bool {
	return info != nil && statusValid && status != nil && effectiveUID > 0 && info.IsDir() &&
		info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == 0o700 &&
		status.Uid == uint32(effectiveUID) // #nosec G115 -- positive Darwin UID.
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
	if err != nil || !darwinDesktopProbeEntriesSafe(entries) {
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
		status, statusValid := infoSyscallStat(opened)
		if statError != nil || !darwinDesktopProbeInputSafe(
			opened, status, statusValid, uid, content, expected, readError, closeError,
		) {
			return ErrRuntimeConflict
		}
		if err := os.Remove(inputPath); err != nil {
			return err
		}
	}
	return os.Remove(directory)
}

func darwinDesktopProbeEntriesSafe(entries []os.DirEntry) bool {
	return len(entries) == 0 || len(entries) == 1 && entries[0].Name() == "input.bin"
}

func darwinDesktopProbeInputSafe(
	info os.FileInfo,
	status *syscall.Stat_t,
	statusValid bool,
	effectiveUID int,
	content []byte,
	expected runtimeinstall.Hash,
	readError error,
	closeError error,
) bool {
	return info != nil && statusValid && status != nil && effectiveUID > 0 && info.Mode().IsRegular() &&
		info.Mode().Perm() == 0o600 && status.Uid == uint32(effectiveUID) && status.Nlink == 1 && // #nosec G115 -- positive Darwin UID.
		readError == nil && closeError == nil && runtimeinstall.Sum(content) == expected
}
