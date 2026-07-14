//go:build windows

package runtimeprovision

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
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
	if !authority.Valid() || authority.Platform() != runtimeinstall.PlatformWindows {
		return probeWorkspace{}, ErrProvisionIntegrity
	}
	boundary := filepath.Join(authority.HomeDirectory(), "AppData", "Local", "AgentMemory")
	directory := filepath.Join(boundary, "runtime-probe-"+authority.PlanDigest().String()[:20])
	inputPath := filepath.Join(directory, "input.bin")
	content := []byte("agentmemory-runtime-probe-v1\n" + authority.CapabilityPolicyDigest().String() + "\n")
	digest := runtimeinstall.Sum(content)
	if err := removeWindowsDesktopProbeWorkspace(ctx, directory, inputPath, digest); err != nil {
		return probeWorkspace{}, err
	}
	if _, _, err := windowssecurity.EnsurePrivateDirectoryTree(ctx, boundary, directory); err != nil {
		return probeWorkspace{}, err
	}
	file, err := os.OpenFile(inputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- authority-bound private path.
	if err != nil {
		_ = os.Remove(directory)
		return probeWorkspace{}, err
	}
	writeError := writeAndSyncDesktopProbe(file, content)
	closeError := file.Close()
	if writeError != nil || closeError != nil {
		_ = os.Remove(inputPath)
		_ = os.Remove(directory)
		return probeWorkspace{}, ErrProbeFailed
	}
	opened, _, err := windowssecurity.OpenVerified(ctx, inputPath, false, false, false)
	if err != nil {
		_ = os.Remove(inputPath)
		_ = os.Remove(directory)
		return probeWorkspace{}, ErrProbeFailed
	}
	_ = opened.Close()
	cleanupContext := context.WithoutCancel(ctx)
	return probeWorkspace{
		directory: directory, inputPath: inputPath, digest: digest,
		cleanup: func() error {
			return removeWindowsDesktopProbeWorkspace(cleanupContext, directory, inputPath, digest)
		},
	}, nil
}

func removeWindowsDesktopProbeWorkspace(
	ctx context.Context,
	directory string,
	inputPath string,
	expected runtimeinstall.Hash,
) error {
	_, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return ErrRuntimeConflict
	}
	directoryHandle, _, err := windowssecurity.OpenVerified(ctx, directory, true, false, true)
	if err != nil {
		return ErrRuntimeConflict
	}
	defer func() {
		if directoryHandle != nil {
			_ = directoryHandle.Close()
		}
	}()
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) > 1 || len(entries) == 1 && !strings.EqualFold(entries[0].Name(), "input.bin") {
		return ErrRuntimeConflict
	}
	if len(entries) == 1 {
		file, _, openError := windowssecurity.OpenVerified(ctx, inputPath, false, false, false)
		if openError != nil {
			return ErrRuntimeConflict
		}
		content, readError := io.ReadAll(io.LimitReader(file, 4097))
		closeError := file.Close()
		if readError != nil || closeError != nil || runtimeinstall.Sum(content) != expected {
			return ErrRuntimeConflict
		}
		if err := os.Remove(inputPath); err != nil {
			return err
		}
	}
	if err := directoryHandle.Close(); err != nil {
		return err
	}
	directoryHandle = nil
	return os.Remove(directory)
}
