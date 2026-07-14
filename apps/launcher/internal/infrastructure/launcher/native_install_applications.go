package launcher

import (
	"context"
	"sync"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/corehttp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/installplanfs"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/productfs"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/setuphost"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/activereleaseapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installphase"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productstack"
)

// nativeInstallPhaseCapabilities contains the production capabilities whose
// authority is established outside the protected persistence composition.
// Release, host-policy, and artifact-acquisition authority are deliberately
// absent: the builder derives those only from the verified retained release.
type nativeInstallPhaseCapabilities struct {
	RuntimeEvidence    installplanapp.RuntimeEvidenceResolver
	RuntimeEnsurer     installphase.RuntimeEnsurer
	Capacity           installphase.ArtifactCapacityApplication
	ManagedResources   installphase.ManagedResourceEnsurer
	ProductStack       productstack.Ensurer
	AgentConfiguration installphase.AgentConfigurationMerger
}

// newNativeInstallApplicationsBuilder joins the purpose-separated protected
// repositories to one already verified release. It is the only production
// path that may supply VerifyHost, VerifyRelease, or artifact acquisition to
// the fourteen-phase graph.
func newNativeInstallApplicationsBuilder(
	composition *nativeComposition,
	capabilities nativeInstallPhaseCapabilities,
) (nativeInstallApplicationsBuilder, error) {
	return newNativeInstallApplicationsBuilderWithDecoder(composition, capabilities, decodeRuntimePlan)
}

func newNativeInstallApplicationsBuilderWithDecoder(
	composition *nativeComposition,
	capabilities nativeInstallPhaseCapabilities,
	decode runtimePlanDecoder,
) (nativeInstallApplicationsBuilder, error) {
	if composition == nil || composition.plans == nil || composition.operations == nil ||
		composition.artifacts == nil || composition.artifactStore == nil ||
		composition.resourceState == nil || composition.installLock == nil ||
		composition.activations == nil || composition.hostPointers == nil ||
		composition.readinessRoot == "" || decode == nil {
		return nil, errNativeInstallerIntegrity
	}
	required := []any{
		capabilities.RuntimeEvidence, capabilities.RuntimeEnsurer,
		capabilities.Capacity, capabilities.ManagedResources, capabilities.ProductStack,
		capabilities.AgentConfiguration,
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
		productFiles := productfs.NewEnsurer()
		brain, err := corehttp.New(corehttp.NewNativeCredentialSource())
		if err != nil {
			return nil, errNativeInstallerIntegrity
		}
		artifacts, err := newNativeArtifactApplication(
			composition.artifacts, composition.artifactStore, release,
		)
		if err != nil {
			return nil, errNativeInstallerIntegrity
		}
		credentials := corehttp.NewNativeCredentialSource()
		return func(
			operationContext context.Context,
			authority nativeInstallAuthority,
		) (nativeInstallApplication, error) {
			projection, decodeError := decode(authority.CanonicalPlan)
			if operationContext == nil || decodeError != nil || projection.operationID != authority.OperationID ||
				!projection.digest.Equal(authority.PlanDigest) {
				return nil, errNativeInstallerIntegrity
			}
			receipts, receiptError := installplanfs.NewReadinessRepository(
				operationContext, composition.readinessRoot, projection.credentialPath, credentials,
			)
			if receiptError != nil {
				return nil, errNativeInstallerIntegrity
			}
			failed := true
			defer func() {
				if failed {
					_ = receipts.Close()
				}
			}()
			readiness, readinessError := corehttp.NewReadinessClient(credentials, receipts)
			if readinessError != nil {
				return nil, errNativeInstallerIntegrity
			}
			corePointers, pointerError := corehttp.NewActiveReleaseClient(
				credentials, projection.coreEndpoint, projection.credentialPath,
			)
			if pointerError != nil {
				return nil, errNativeInstallerIntegrity
			}
			active, activeError := activereleaseapp.New(activereleaseapp.Dependencies{
				Clock: setuphost.Clock{}, ReadinessReceipts: receipts,
				Activations: composition.activations, HostPointers: composition.hostPointers,
				CorePointers: corePointers,
			})
			if activeError != nil {
				return nil, errNativeInstallerIntegrity
			}
			graph, graphError := newNativeInstallApplicationFactory(nativeInstallGraphDependencies{
				Plans: composition.plans, RuntimePlans: composition.plans,
				RuntimeEvidence: capabilities.RuntimeEvidence,
				Operations:      composition.operations, Cancellation: composition.operations,
				ReadinessReceipts: receipts, ResourceInventory: composition.resourceState,
				InstallationLock: composition.installLock,
				HostVerifier:     release.hostVerification(), RuntimeEnsurer: capabilities.RuntimeEnsurer,
				ReleaseVerifier: release.releaseVerification(), Artifacts: artifacts,
				Capacity: capabilities.Capacity, Directories: productFiles,
				Secrets: productFiles, ManagedResources: capabilities.ManagedResources,
				ProductStack: capabilities.ProductStack, BrainBootstrap: brain,
				AgentConfiguration: capabilities.AgentConfiguration, Readiness: readiness,
				ActiveRelease: active,
			})
			if graphError != nil {
				return nil, errNativeInstallerIntegrity
			}
			application, applicationError := graph(operationContext, authority)
			if applicationError != nil {
				return nil, applicationError
			}
			failed = false
			return &managedNativeInstallApplication{application: application, receipts: receipts}, nil
		}, nil
	}, nil
}

type managedNativeInstallApplication struct {
	application nativeInstallApplication
	receipts    *installplanfs.ReadinessRepository
	closeOnce   sync.Once
	closeError  error
}

func (a *managedNativeInstallApplication) Install(
	ctx context.Context,
	command installapp.InstallCommand,
) (installapp.InstallResult, error) {
	if a == nil || nilAny(a.application) {
		return installapp.InstallResult{}, errNativeInstallerIntegrity
	}
	return a.application.Install(ctx, command)
}

func (a *managedNativeInstallApplication) Close(context.Context) error {
	if a == nil {
		return nil
	}
	a.closeOnce.Do(func() {
		if a.receipts != nil {
			a.closeError = a.receipts.Close()
		}
	})
	return a.closeError
}
