package launcher

import (
	"context"
	"runtime"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/dockercli"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

// buildProductExecutors reconstructs the Docker/Compose process capabilities
// from the signed catalog on every product-phase call. It deliberately does
// not retain an ambient CLI path or a planning-time runner.
func (f *nativePlatformRuntimeFactory) buildProductExecutors(
	ctx context.Context,
	verified nativeVerifiedRuntimeExecution,
) (dockercli.Executors, error) {
	if f == nil || ctx == nil || f.release == nil || verified.authority.BindingDigest().IsZero() ||
		verified.inventory.ReleaseID() == "" || verified.inventory.ManifestDigest().IsZero() ||
		!verified.inventory.ManifestDigest().Equal(verified.request.SignedRelease.Manifest().Digest()) {
		return dockercli.Executors{}, errNativeInstallerIntegrity
	}
	if err := ctx.Err(); err != nil {
		return dockercli.Executors{}, err
	}
	switch runtime.GOOS {
	case "linux":
		if verified.runtime.Platform() != runtimeinstall.PlatformLinux {
			return dockercli.Executors{}, errNativeInstallerIntegrity
		}
		return f.buildLinuxProductExecutors(ctx, verified)
	case "darwin":
		if verified.runtime.Platform() != runtimeinstall.PlatformDarwin {
			return dockercli.Executors{}, errNativeInstallerIntegrity
		}
	case "windows":
		if verified.runtime.Platform() != runtimeinstall.PlatformWindows {
			return dockercli.Executors{}, errNativeInstallerIntegrity
		}
	default:
		return dockercli.Executors{}, errNativeInstallerUnavailable
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
