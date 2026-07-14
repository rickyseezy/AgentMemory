package launcher

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installphase"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/brainbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productinstall"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productstack"
)

// nativeInstallPhaseCapabilities contains the production capabilities whose
// authority is established outside the protected persistence composition.
// Release, host-policy, and artifact-acquisition authority are deliberately
// absent: the builder derives those only from the verified retained release.
type nativeInstallPhaseCapabilities struct {
	RuntimeEvidence    installplanapp.RuntimeEvidenceResolver
	ReadinessReceipts  installplanapp.ReadinessReceiptRepository
	RuntimeEnsurer     installphase.RuntimeEnsurer
	Capacity           installphase.ArtifactCapacityApplication
	Directories        productinstall.DirectoryEnsurer
	Secrets            productinstall.SecretEnsurer
	ManagedResources   installphase.ManagedResourceEnsurer
	ProductStack       productstack.Ensurer
	BrainBootstrap     brainbootstrap.Bootstrapper
	AgentConfiguration installphase.AgentConfigurationMerger
	Readiness          installphase.ReadinessVerifier
	ActiveRelease      installphase.ActiveReleaseCommitter
}

// newNativeInstallApplicationsBuilder joins the purpose-separated protected
// repositories to one already verified release. It is the only production
// path that may supply VerifyHost, VerifyRelease, or artifact acquisition to
// the fourteen-phase graph.
func newNativeInstallApplicationsBuilder(
	composition *nativeComposition,
	capabilities nativeInstallPhaseCapabilities,
) (nativeInstallApplicationsBuilder, error) {
	if composition == nil || composition.plans == nil || composition.operations == nil ||
		composition.artifacts == nil || composition.artifactStore == nil ||
		composition.resourceState == nil || composition.installLock == nil {
		return nil, errNativeInstallerIntegrity
	}
	required := []any{
		capabilities.RuntimeEvidence, capabilities.ReadinessReceipts, capabilities.RuntimeEnsurer,
		capabilities.Capacity, capabilities.Directories, capabilities.Secrets,
		capabilities.ManagedResources, capabilities.ProductStack, capabilities.BrainBootstrap,
		capabilities.AgentConfiguration, capabilities.Readiness, capabilities.ActiveRelease,
	}
	for _, capability := range required {
		if nilAny(capability) {
			return nil, errNativeInstallerIntegrity
		}
	}
	return func(
		ctx context.Context,
		release *nativeReleaseAuthority,
	) (nativeInstallApplicationFactory, error) {
		if ctx == nil || release == nil || release.hostVerification() == nil ||
			release.releaseVerification() == nil {
			return nil, errNativeInstallerIntegrity
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		artifacts, err := newNativeArtifactApplication(
			composition.artifacts, composition.artifactStore, release,
		)
		if err != nil {
			return nil, errNativeInstallerIntegrity
		}
		return newNativeInstallApplicationFactory(nativeInstallGraphDependencies{
			Plans: composition.plans, RuntimePlans: composition.plans,
			RuntimeEvidence: capabilities.RuntimeEvidence,
			Operations:      composition.operations, Cancellation: composition.operations,
			ReadinessReceipts: capabilities.ReadinessReceipts,
			ResourceInventory: composition.resourceState, InstallationLock: composition.installLock,
			HostVerifier: release.hostVerification(), RuntimeEnsurer: capabilities.RuntimeEnsurer,
			ReleaseVerifier: release.releaseVerification(), Artifacts: artifacts,
			Capacity: capabilities.Capacity, Directories: capabilities.Directories,
			Secrets: capabilities.Secrets, ManagedResources: capabilities.ManagedResources,
			ProductStack: capabilities.ProductStack, BrainBootstrap: capabilities.BrainBootstrap,
			AgentConfiguration: capabilities.AgentConfiguration, Readiness: capabilities.Readiness,
			ActiveRelease: capabilities.ActiveRelease,
		})
	}, nil
}
