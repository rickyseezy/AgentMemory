package launcher

import (
	"crypto/sha256"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

// buildNativeDesktopMutationEncoder transports the same independently signed
// release, catalog, and canonical plan that produced DesktopAuthority. The
// helper treats the envelope as untrusted and repeats the verification join.
func buildNativeDesktopMutationEncoder(
	verified nativeVerifiedRuntimeExecution,
) (*runtimeprovision.CanonicalDesktopMutationTransportCodec, error) {
	platform := verified.runtime.Platform()
	architecture := verified.runtime.Architecture()
	resource := verified.request.RuntimeCatalogResource
	if (platform != runtimeinstall.PlatformDarwin && platform != runtimeinstall.PlatformWindows) ||
		architecture == runtimeinstall.ArchitectureUnknown || verified.authority.BindingDigest().IsZero() ||
		verified.request.RuntimeCatalogID == "" || resource.ID() != verified.request.RuntimeCatalogID ||
		resource.Kind() != releaseinventory.ResourceKindRuntimeCatalog ||
		resource.Purpose() != releaseinventory.ResourcePurposeRuntimeCatalog ||
		resource.MediaType() != releaseinventory.MediaTypeRuntimeCatalog || resource.Platform().IsAny() ||
		resource.Platform().OS() != platform.String() ||
		resource.Platform().Architecture() != architecture.String() || resource.Digest().IsZero() || resource.Size() == 0 {
		return nil, errNativeInstallerIntegrity
	}
	helperID, err := nativeDesktopMutationHelperResourceID(
		verified.request.SignedRelease.Manifest().Digest(),
		verified.request.SignedRelease.Manifest().Resources(), platform, architecture,
	)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	releaseRaw, releaseError := releaseinventory.EncodeSignedManifestV1(verified.request.SignedRelease)
	catalogRaw, catalogError := runtimecatalog.EncodeSignedManifestV1(verified.signedCatalog)
	catalogDigest := sha256.Sum256(catalogRaw)
	if releaseError != nil || catalogError != nil || uint64(len(catalogRaw)) != resource.Size() ||
		releaseinventory.Digest(catalogDigest) != resource.Digest() {
		return nil, errNativeInstallerIntegrity
	}
	codec, err := runtimeprovision.NewCanonicalDesktopMutationTransportCodec(
		runtimeprovision.DesktopMutationEnvelopeInput{
			SignedRelease: releaseRaw, SignedRuntimeCatalog: catalogRaw,
			CanonicalPlan:            verified.authority.Plan().CanonicalBytes(),
			RuntimeCatalogResourceID: resource.ID(), HelperResourceID: helperID,
		},
	)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	return codec, nil
}

func nativeDesktopMutationHelperResourceID(
	manifestDigest releaseinventory.Digest,
	resources []releaseinventory.Resource,
	platform runtimeinstall.Platform,
	architecture runtimeinstall.Architecture,
) (string, error) {
	if manifestDigest.IsZero() || (platform != runtimeinstall.PlatformDarwin && platform != runtimeinstall.PlatformWindows) ||
		architecture == runtimeinstall.ArchitectureUnknown {
		return "", errNativeInstallerIntegrity
	}
	selected := ""
	for _, resource := range resources {
		if resource.Kind() != releaseinventory.ResourceKindHelper || resource.Platform().OS() != platform.String() ||
			resource.Platform().Architecture() != architecture.String() {
			continue
		}
		if selected != "" || resource.Purpose() != releaseinventory.ResourcePurposeNativeHelper ||
			resource.MediaType() != releaseinventory.MediaTypeNativeExecutable || resource.Platform().IsAny() ||
			resource.Digest().IsZero() || resource.Size() == 0 || resource.NativePublisherIdentity() == "" ||
			resource.NativePublisherPolicyID() == "" {
			return "", errNativeInstallerIntegrity
		}
		selected = resource.ID()
	}
	if selected == "" {
		return "", errNativeInstallerIntegrity
	}
	return selected, nil
}
