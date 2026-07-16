//go:build linux

package launcher

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/dockercli"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func (f *nativePlatformRuntimeFactory) buildPlatformProductExecutors(
	ctx context.Context,
	verified nativeVerifiedRuntimeExecution,
) (dockercli.Executors, error) {
	if verified.runtime.Platform() != runtimeinstall.PlatformLinux {
		return dockercli.Executors{}, errNativeInstallerIntegrity
	}
	return f.buildLinuxProductExecutors(ctx, verified)
}

func (f *nativePlatformRuntimeFactory) buildLinuxProductExecutors(
	ctx context.Context,
	verified nativeVerifiedRuntimeExecution,
) (dockercli.Executors, error) {
	if f == nil || nilAny(f.linuxBindings) {
		return dockercli.Executors{}, errNativeInstallerIntegrity
	}
	authorityResolver, err := runtimeprovision.NewCatalogLinuxAuthorityResolver(
		verified.catalog,
		f.linuxBindings,
	)
	if err != nil {
		return dockercli.Executors{}, errNativeInstallerIntegrity
	}
	authority, err := authorityResolver.ResolveLinuxAuthority(
		ctx,
		verified.authority.Plan().CanonicalBytes(),
	)
	if err != nil || !authority.ValidFor(verified.authority.Plan()) {
		return dockercli.Executors{}, errNativeInstallerIntegrity
	}
	runners, err := newNativeLinuxRunnerSet(
		authority,
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
