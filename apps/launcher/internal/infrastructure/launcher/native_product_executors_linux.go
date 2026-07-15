//go:build linux

package launcher

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/dockercli"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeprovision"
)

func (f *nativePlatformRuntimeFactory) buildLinuxProductExecutors(
	ctx context.Context,
	verified nativeVerifiedRuntimeExecution,
) (dockercli.Executors, error) {
	authorityResolver, err := runtimeprovision.NewCatalogLinuxAuthorityResolver(
		verified.catalog,
		runtimeprovision.NewNativeLinuxHostBindingProvider(),
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
