package launcher

import (
	"context"
	"reflect"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installphase"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/brainbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productinstall"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productstack"
)

// nativeInstallGraphDependencies is the complete command-independent PF-001
// production graph. The only operation-scoped dependency is created after an
// authenticated supervisor command reaches Build.
type nativeInstallGraphDependencies struct {
	Plans             installplanapp.Repository
	RuntimePlans      installplanapp.RuntimePlanRepository
	RuntimeEvidence   installplanapp.RuntimeEvidenceResolver
	Operations        installapp.OperationRepository
	Cancellation      installapp.CancellationIntentPort
	ReadinessReceipts installplanapp.ReadinessReceiptRepository
	ResourceInventory installplanapp.ResourceInventoryRepository
	InstallationLock  installapp.InstallationLockPort
	RebootCoordinator installapp.RebootCoordinator

	HostVerifier        installphase.HostVerifier
	RuntimeEnsurer      nativeRuntimeEnsurerBuilder
	ProductApplications nativeProductApplicationsBuilder
	ReleaseVerifier     installphase.ReleaseVerifier
	Artifacts           installphase.ArtifactApplication
	Directories         productinstall.DirectoryEnsurer
	Secrets             productinstall.SecretEnsurer
	BrainBootstrap      brainbootstrap.Bootstrapper
	AgentConfiguration  installphase.AgentConfigurationMerger
	Readiness           installphase.ReadinessVerifier
	ActiveRelease       installphase.ActiveReleaseCommitter
}

type nativeRuntimeEnsurerBuilder func(
	context.Context,
	*installplanapp.Application,
	nativeInstallAuthority,
) (installphase.RuntimeEnsurer, error)

type nativeProductCapabilities struct {
	Capacity         installphase.ArtifactCapacityApplication
	ManagedResources installphase.ManagedResourceEnsurer
	ProductStack     productstack.Ensurer
}

type nativeProductApplicationsBuilder func(
	context.Context,
	*installplanapp.Application,
	nativeInstallAuthority,
) (nativeProductCapabilities, error)

// newNativeInstallApplicationFactory assembles every one of the fourteen
// narrow phase capabilities. It rejects a partial graph before a worker can be
// registered, so an asynchronous installer cannot stall on a missing adapter.
func newNativeInstallApplicationFactory(
	dependencies nativeInstallGraphDependencies,
) (nativeInstallApplicationFactory, error) {
	required := []any{
		dependencies.Plans, dependencies.RuntimePlans, dependencies.RuntimeEvidence,
		dependencies.Operations, dependencies.Cancellation, dependencies.ReadinessReceipts,
		dependencies.ResourceInventory, dependencies.InstallationLock,
		dependencies.RebootCoordinator,
		dependencies.HostVerifier, dependencies.RuntimeEnsurer, dependencies.ProductApplications,
		dependencies.ReleaseVerifier, dependencies.Artifacts, dependencies.Directories,
		dependencies.Secrets,
		dependencies.BrainBootstrap, dependencies.AgentConfiguration, dependencies.Readiness,
		dependencies.ActiveRelease,
	}
	for _, dependency := range required {
		if nilAny(dependency) {
			return nil, errNativeInstallerIntegrity
		}
	}
	if !sameNativeCapability(dependencies.Operations, dependencies.Cancellation) {
		return nil, errNativeInstallerIntegrity
	}
	return func(ctx context.Context, authority nativeInstallAuthority) (nativeInstallApplication, error) {
		if ctx == nil || authority.OperationID.IsZero() || authority.PlanDigest.IsZero() ||
			len(authority.CanonicalPlan) == 0 {
			return nil, errNativeInstallerIntegrity
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		plans, err := installplanapp.New(installplanapp.Dependencies{
			Plans: dependencies.Plans, RuntimePlans: dependencies.RuntimePlans,
			RuntimeEvidence: dependencies.RuntimeEvidence, Operations: dependencies.Operations,
			ReadinessReceipts: dependencies.ReadinessReceipts, Resources: dependencies.ResourceInventory,
			OperationID: authority.OperationID,
		})
		if err != nil {
			return nil, errNativeInstallerIntegrity
		}
		host, err := installphase.NewHostVerificationPhase(plans, dependencies.HostVerifier)
		if err != nil {
			return nil, errNativeInstallerIntegrity
		}
		runtimeEnsurer, err := dependencies.RuntimeEnsurer(ctx, plans, authority)
		if err != nil || nilAny(runtimeEnsurer) {
			return nil, errNativeInstallerIntegrity
		}
		runtimePhase, err := installphase.NewContainerRuntimePhase(plans, runtimeEnsurer)
		if err != nil {
			return nil, errNativeInstallerIntegrity
		}
		products, err := dependencies.ProductApplications(ctx, plans, authority)
		if err != nil || nilAny(products.Capacity) || nilAny(products.ManagedResources) ||
			nilAny(products.ProductStack) {
			return nil, errNativeInstallerIntegrity
		}
		release, err := installphase.NewReleaseVerificationPhase(plans, dependencies.ReleaseVerifier)
		if err != nil {
			return nil, errNativeInstallerIntegrity
		}
		space, err := installphase.NewSpaceReservationPhase(plans, dependencies.Artifacts, products.Capacity)
		if err != nil {
			return nil, errNativeInstallerIntegrity
		}
		directories, err := installphase.NewDirectoryPhase(plans, dependencies.Directories)
		if err != nil {
			return nil, errNativeInstallerIntegrity
		}
		secrets, err := installphase.NewSecretPhase(plans, dependencies.Secrets)
		if err != nil {
			return nil, errNativeInstallerIntegrity
		}
		compose, err := installphase.NewComposeBundlePhase(plans, dependencies.Artifacts, products.Capacity)
		if err != nil {
			return nil, errNativeInstallerIntegrity
		}
		resources, err := installphase.NewNetworkVolumePhase(plans, products.ManagedResources, products.Capacity)
		if err != nil {
			return nil, errNativeInstallerIntegrity
		}
		migrations, err := installphase.NewMigrationPhase(plans, products.ProductStack)
		if err != nil {
			return nil, errNativeInstallerIntegrity
		}
		core, err := installphase.NewCoreGraphPhase(plans, products.ProductStack)
		if err != nil {
			return nil, errNativeInstallerIntegrity
		}
		brain, err := installphase.NewBrainBootstrapPhase(plans, dependencies.BrainBootstrap)
		if err != nil {
			return nil, errNativeInstallerIntegrity
		}
		agent, err := installphase.NewAgentConfigurationPhase(plans, dependencies.AgentConfiguration)
		if err != nil {
			return nil, errNativeInstallerIntegrity
		}
		readiness, err := installphase.NewReadinessPhase(plans, dependencies.Readiness)
		if err != nil {
			return nil, errNativeInstallerIntegrity
		}
		active, err := installphase.NewActiveReleasePhase(plans, dependencies.ActiveRelease, products.Capacity)
		if err != nil {
			return nil, errNativeInstallerIntegrity
		}
		application, err := installapp.NewInstallApplication(installapp.Dependencies{
			Operations: dependencies.Operations, CancellationIntents: dependencies.Cancellation,
			InstallationLock: dependencies.InstallationLock, RebootCoordinator: dependencies.RebootCoordinator,
			HostVerification: host,
			ContainerRuntime: runtimePhase, ReleaseVerification: release, SpaceReservation: space,
			Directories: directories, Keys: secrets, ComposeBundle: compose,
			NetworkAndVolumes: resources, Migrations: migrations, CoreAndGraph: core,
			BrainBootstrap: brain, AgentConfiguration: agent, Readiness: readiness,
			ActiveRelease: active,
		})
		if err != nil {
			return nil, errNativeInstallerIntegrity
		}
		return application, nil
	}, nil
}

func sameNativeCapability(left, right any) bool {
	leftValue, rightValue := reflect.ValueOf(left), reflect.ValueOf(right)
	return leftValue.IsValid() && rightValue.IsValid() && leftValue.Type() == rightValue.Type() &&
		leftValue.Kind() == reflect.Pointer && leftValue.Pointer() == rightValue.Pointer()
}
