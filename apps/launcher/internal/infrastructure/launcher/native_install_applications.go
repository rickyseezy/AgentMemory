package launcher

import (
	"context"
	"sync"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/corehttp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/installplanfs"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/productfs"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/setuphost"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/activereleaseapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installphase"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
)

type nativeAgentConfigurationBuilder func(
	*nativeReleaseAuthority,
	[]byte,
	string,
) (installphase.AgentConfigurationMerger, error)

// newNativeInstallApplicationsBuilder joins the purpose-separated protected
// repositories to one already verified release. It is the only production
// path that may supply VerifyHost, VerifyRelease, or artifact acquisition to
// the fourteen-phase graph.
func newNativeInstallApplicationsBuilder(
	composition *nativeComposition,
) (nativeInstallApplicationsBuilder, error) {
	return newNativeInstallApplicationsBuilderWithDecoder(
		composition,
		decodeRuntimePlan,
		func(
			release *nativeReleaseAuthority,
			canonical []byte,
			backupDirectory string,
		) (installphase.AgentConfigurationMerger, error) {
			return newNativeAgentConfigurationMerger(release, canonical, backupDirectory)
		},
	)
}

func newNativeInstallApplicationsBuilderWithDecoder(
	composition *nativeComposition,
	decode runtimePlanDecoder,
	agents nativeAgentConfigurationBuilder,
) (nativeInstallApplicationsBuilder, error) {
	if composition == nil || composition.plans == nil || composition.operations == nil ||
		composition.artifacts == nil || composition.artifactStore == nil ||
		composition.capacityState == nil || composition.expandedTargets == nil ||
		composition.resourceState == nil || composition.installLock == nil ||
		composition.rebootCoordinator == nil ||
		composition.runtimeOwnership == nil ||
		composition.runtimeCatalogAnchor == nil ||
		composition.activations == nil || composition.hostPointers == nil ||
		composition.readinessRoot == "" || composition.agentConfigurationBackups == "" ||
		decode == nil || agents == nil {
		return nil, errNativeInstallerIntegrity
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
		runtimePlatform, err := newNativePlatformRuntimeFactory(composition, release, artifacts)
		if err != nil {
			return nil, errNativeInstallerIntegrity
		}
		observer, err := runtimeprovision.NewNativeCatalogObserver(
			release.runtimeCatalogPublisherVerifier(),
			nativeRuntimeHostReattestor{verifier: release.hostVerification()},
		)
		if err != nil {
			return nil, errNativeInstallerIntegrity
		}
		catalogPolicy, err := newNativeRuntimeCatalogPolicy(
			setuphost.Clock{}, release.runtimeCatalogSignatureVerifier(),
			release.runtimeCatalogPublisherVerifier(), composition.runtimeCatalogAnchor,
		)
		if err != nil {
			return nil, errNativeInstallerIntegrity
		}
		runtimeEvidence, err := newNativeRuntimeEvidenceResolver(
			release.runtimeCatalogLoader(), catalogPolicy, observer,
		)
		if err != nil {
			return nil, errNativeInstallerIntegrity
		}
		runtimeExecution, err := newNativeRuntimeExecutionVerifier(
			release.runtimeCatalogLoader(), catalogPolicy,
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
			agentConfiguration, agentError := agents(
				release,
				authority.CanonicalPlan,
				composition.agentConfigurationBackups,
			)
			if agentError != nil || nilAny(agentConfiguration) {
				return nil, errNativeInstallerIntegrity
			}
			runtimeBuilder := func(
				_ context.Context,
				plans *installplanapp.Application,
				buildAuthority nativeInstallAuthority,
			) (installphase.RuntimeEnsurer, error) {
				return newNativeRuntimeEnsurer(
					buildAuthority.PlanDigest, buildAuthority.OperationID, plans,
					runtimeExecution, runtimePlatform,
				)
			}
			productBuilder := func(
				_ context.Context,
				plans *installplanapp.Application,
				buildAuthority nativeInstallAuthority,
			) (nativeProductCapabilities, error) {
				productAuthority, productError := newNativeProductAuthorityResolver(
					buildAuthority.PlanDigest, buildAuthority.OperationID, plans, composition.operations,
					runtimeExecution, runtimePlatform,
				)
				if productError != nil {
					return nativeProductCapabilities{}, productError
				}
				products, productError := newNativeProductApplications(productAuthority, composition)
				if productError != nil {
					return nativeProductCapabilities{}, productError
				}
				return nativeProductCapabilities{
					Capacity: products, ManagedResources: products, ProductStack: products,
				}, nil
			}
			graph, graphError := newNativeInstallApplicationFactory(nativeInstallGraphDependencies{
				Plans: composition.plans, RuntimePlans: composition.plans,
				RuntimeEvidence: runtimeEvidence,
				Operations:      composition.operations, Cancellation: composition.operations,
				ReadinessReceipts: receipts, ResourceInventory: composition.resourceState,
				InstallationLock:  composition.installLock,
				RebootCoordinator: composition.rebootCoordinator,
				HostVerifier:      release.hostVerification(), RuntimeEnsurer: runtimeBuilder,
				ProductApplications: productBuilder,
				ReleaseVerifier:     release.releaseVerification(), Artifacts: artifacts,
				Directories: productFiles, Secrets: productFiles, BrainBootstrap: brain,
				AgentConfiguration: agentConfiguration, Readiness: readiness,
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
