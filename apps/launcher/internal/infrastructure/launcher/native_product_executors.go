package launcher

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/dockercli"
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
	return f.buildPlatformProductExecutors(ctx, verified)
}
