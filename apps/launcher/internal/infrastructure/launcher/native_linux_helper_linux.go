//go:build linux

package launcher

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeprovision"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
)

func buildNativeLinuxPrivilegeCodec(
	ctx context.Context,
	release *nativeReleaseAuthority,
	verified nativeVerifiedRuntimeExecution,
	authority runtimeport.LinuxAuthority,
	artifactStager runtimeprovision.PrivilegeArtifactStager,
) (*runtimeprovision.CanonicalPrivilegeTransportCodec, nativeLinuxHelperAuthority, error) {
	if release == nil || release.verifier() == nil {
		return nil, nativeLinuxHelperAuthority{}, errNativeInstallerIntegrity
	}
	resolver, err := newNativeLinuxHelperAuthorityResolver(
		&nativeVerifiedReleaseResource{application: release.verifier()}, verified.request.SignedRelease,
		verified.request.SignedRelease.Manifest().Digest(), verified.request.SignedRelease.Manifest().Resources(),
	)
	if err != nil {
		return nil, nativeLinuxHelperAuthority{}, errNativeInstallerIntegrity
	}
	return buildNativeLinuxPrivilegeCodecWithEncoders(
		ctx, verified, authority, resolver, artifactStager,
		releaseinventory.EncodeSignedManifestV1, runtimecatalog.EncodeSignedManifestV1,
	)
}
