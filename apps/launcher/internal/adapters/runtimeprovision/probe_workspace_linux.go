//go:build linux

package runtimeprovision

import (
	"context"
	"errors"
	"io"
	"os"
	"syscall"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"golang.org/x/sys/unix"
)

func prepareNativeProbeWorkspace(
	ctx context.Context,
	authority runtimeport.LinuxAuthority,
) (probeWorkspace, error) {
	if ctx == nil {
		return probeWorkspace{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return probeWorkspace{}, err
	}
	if !authority.Valid() || validateOwnerDirectory(authority.RuntimeDirectory(), authority.InvokingUID(), true) != nil {
		return probeWorkspace{}, ErrProvisionIntegrity
	}
	directory := authority.RuntimeDirectory() + "/agentmemory-runtime-probe-" + authority.PlanDigest().String()[:20]
	inputPath := directory + "/input.bin"
	content := []byte("agentmemory-runtime-probe-v1\n" + authority.CapabilityPolicyDigest().String() + "\n")
	contentDigest := runtimeinstall.Sum(content)
	if err := removeExistingProbeWorkspace(directory, inputPath, authority.InvokingUID(), contentDigest); err != nil {
		return probeWorkspace{}, err
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		return probeWorkspace{}, err
	}
	if err := validateOwnerDirectory(directory, authority.InvokingUID(), true); err != nil {
		_ = os.Remove(directory)
		return probeWorkspace{}, ErrProbeFailed
	}
	descriptor, err := unix.Open(inputPath, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		_ = os.Remove(directory)
		return probeWorkspace{}, err
	}
	file := os.NewFile(uintptr(descriptor), "runtime-probe-input")
	if file == nil {
		_ = unix.Close(descriptor)
		_ = os.Remove(directory)
		return probeWorkspace{}, ErrProbeFailed
	}
	writeError := writeAndSync(file, content)
	closeError := file.Close()
	if writeError != nil || closeError != nil {
		_ = os.Remove(inputPath)
		_ = os.Remove(directory)
		return probeWorkspace{}, ErrProbeFailed
	}
	workspace := probeWorkspace{
		directory: directory, inputPath: inputPath, digest: contentDigest,
	}
	workspace.cleanup = func() error {
		return removeExistingProbeWorkspace(directory, inputPath, authority.InvokingUID(), contentDigest)
	}
	return workspace, nil
}

func writeAndSync(file *os.File, content []byte) error {
	if file == nil {
		return ErrProbeFailed
	}
	written, err := file.Write(content)
	if err != nil || written != len(content) {
		return ErrProbeFailed
	}
	if err := file.Sync(); err != nil {
		return err
	}
	return nil
}

func removeExistingProbeWorkspace(
	directory string,
	inputPath string,
	uid uint32,
	expectedDigest runtimeinstall.Hash,
) error {
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return ErrRuntimeConflict
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid {
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
		file := os.NewFile(uintptr(descriptor), "runtime-probe-cleanup")
		if file == nil {
			_ = unix.Close(descriptor)
			return ErrProbeFailed
		}
		var fileStat unix.Stat_t
		valid := unix.Fstat(descriptor, &fileStat) == nil && fileStat.Mode&unix.S_IFMT == unix.S_IFREG &&
			fileStat.Uid == uid && fileStat.Mode&0o777 == 0o600 && fileStat.Nlink == 1
		content, readError := io.ReadAll(io.LimitReader(file, 4097))
		closeError := file.Close()
		if !valid || readError != nil || closeError != nil || runtimeinstall.Sum(content) != expectedDigest {
			return ErrRuntimeConflict
		}
		if err := os.Remove(inputPath); err != nil {
			return err
		}
	}
	if err := os.Remove(directory); err != nil {
		return err
	}
	return nil
}
