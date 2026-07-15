//go:build darwin || windows

package launcher

import (
	"context"
	"runtime"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/dockercli"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func (f *nativePlatformRuntimeFactory) buildPlatformProductExecutors(
	ctx context.Context,
	verified nativeVerifiedRuntimeExecution,
) (dockercli.Executors, error) {
	wanted := runtimeinstall.PlatformDarwin
	if runtime.GOOS == "windows" {
		wanted = runtimeinstall.PlatformWindows
	}
	if verified.runtime.Platform() != wanted {
		return dockercli.Executors{}, errNativeInstallerIntegrity
	}
	authoritySet, err := buildNativeDesktopAuthority(ctx, verified, f.release)
	if err != nil || !authoritySet.authority.ValidFor(verified.authority.Plan()) {
		return dockercli.Executors{}, errNativeInstallerIntegrity
	}
	runners, err := newNativeDesktopRunnerPair(
		authoritySet.authority,
		verified.request.SignedRelease.Manifest().Digest(),
	)
	if err != nil {
		return dockercli.Executors{}, errNativeInstallerIntegrity
	}
	executors, err := dockercli.NewExecutors(runners.docker, runners.compose)
	if err != nil {
		return dockercli.Executors{}, errNativeInstallerIntegrity
	}
	return executors, nil
}
