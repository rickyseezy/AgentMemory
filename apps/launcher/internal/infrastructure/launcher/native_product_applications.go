package launcher

import (
	"context"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/artifactfs"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/dockercli"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installphase"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productstack"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/productstackapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/resourceapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

type nativeProductRuntime struct {
	executors dockercli.Executors
	verified  nativeVerifiedRuntimeExecution
	endpoint  containerengine.Endpoint
}

type nativeProductRuntimeResolver interface {
	ResolveProductRuntime(context.Context) (nativeProductRuntime, error)
}

type nativeProductAuthorityResolver struct {
	planDigest install.PlanDigest
	operation  install.OperationID
	plans      *installplanapp.Application
	operations cancellationRepository
	verifier   *nativeRuntimeExecutionVerifier
	platform   *nativePlatformRuntimeFactory
}

func newNativeProductAuthorityResolver(
	planDigest install.PlanDigest,
	operation install.OperationID,
	plans *installplanapp.Application,
	operations cancellationRepository,
	verifier *nativeRuntimeExecutionVerifier,
	platform *nativePlatformRuntimeFactory,
) (*nativeProductAuthorityResolver, error) {
	if planDigest.IsZero() || operation.IsZero() || nilAny(plans) || nilAny(operations) ||
		nilAny(verifier) || nilAny(platform) {
		return nil, errNativeInstallerIntegrity
	}
	return &nativeProductAuthorityResolver{
		planDigest: planDigest, operation: operation, plans: plans,
		operations: operations, verifier: verifier, platform: platform,
	}, nil
}

func (r *nativeProductAuthorityResolver) ResolveProductRuntime(
	ctx context.Context,
) (nativeProductRuntime, error) {
	if r == nil || ctx == nil || r.planDigest.IsZero() || r.operation.IsZero() ||
		nilAny(r.plans) || nilAny(r.operations) || nilAny(r.verifier) || nilAny(r.platform) {
		return nativeProductRuntime{}, errNativeInstallerIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nativeProductRuntime{}, err
	}
	operation, err := r.operations.Load(ctx, r.operation)
	if err != nil || !runtimePhaseCompleted(operation, r.planDigest, r.operation) {
		return nativeProductRuntime{}, errNativeInstallerIntegrity
	}
	execution, err := r.plans.ResolveRuntimeExecutionAuthority(ctx, r.planDigest, r.operation)
	if err != nil {
		return nativeProductRuntime{}, errNativeInstallerIntegrity
	}
	verified, err := r.verifier.VerifyRuntimeExecution(ctx, execution)
	if err != nil || verified.authority.OperationID() != r.operation ||
		!verified.authority.ParentPlanDigest().Equal(r.planDigest) {
		return nativeProductRuntime{}, errNativeInstallerIntegrity
	}
	endpoint, err := containerengine.NewEndpoint(verified.request.RuntimeEndpoint)
	if err != nil {
		return nativeProductRuntime{}, errNativeInstallerIntegrity
	}
	executors, err := r.platform.buildProductExecutors(ctx, verified)
	if err != nil {
		return nativeProductRuntime{}, err
	}
	return nativeProductRuntime{executors: executors, verified: verified, endpoint: endpoint}, nil
}

func runtimePhaseCompleted(
	operation *install.Operation,
	planDigest install.PlanDigest,
	operationID install.OperationID,
) bool {
	if operation == nil || operation.ID() != operationID ||
		!operation.PlanDigest().Equal(planDigest) || operation.CurrentPhase() <= install.PhaseEnsureContainerRuntime {
		return false
	}
	for _, evidence := range operation.CompletedEvidence() {
		if evidence.Phase() == install.PhaseEnsureContainerRuntime &&
			evidence.PlanDigest().Equal(planDigest) && evidence.Attempt() > 0 &&
			evidence.RuntimeOwnership().Resolved() && !evidence.OutputDigest().IsZero() {
			return true
		}
	}
	return false
}

// nativeProductApplications resolves fresh release-bound executors before
// every product effect, including cleanup. No Docker capability survives a
// process restart or a runtime-catalog re-verification boundary.
type nativeProductApplications struct {
	runtime             nativeProductRuntimeResolver
	capacityState       artifactapp.CapacityRepository
	artifactStore       *artifactfs.Store
	expandedTargets     artifactapp.ExpandedTargetRepository
	resourceState       resourceapp.Repository
	capacityApplication nativeCapacityApplicationBuilder
	resourceApplication nativeResourceApplicationBuilder
	stackApplication    nativeStackApplicationBuilder
}

type nativeCapacityApplicationBuilder func(
	context.Context,
) (installphase.ArtifactCapacityApplication, nativeProductRuntime, error)

type nativeResourceApplicationBuilder func(
	context.Context,
) (installphase.ManagedResourceEnsurer, nativeProductRuntime, error)

type nativeStackApplicationBuilder func(
	context.Context,
) (productstack.Ensurer, nativeProductRuntime, error)

func newNativeProductApplications(
	runtime nativeProductRuntimeResolver,
	composition *nativeComposition,
) (*nativeProductApplications, error) {
	if nilAny(runtime) || composition == nil || composition.capacityState == nil ||
		composition.artifactStore == nil || composition.expandedTargets == nil ||
		composition.resourceState == nil {
		return nil, errNativeInstallerIntegrity
	}
	applications := &nativeProductApplications{
		runtime: runtime, capacityState: composition.capacityState,
		artifactStore: composition.artifactStore, expandedTargets: composition.expandedTargets,
		resourceState: composition.resourceState,
	}
	applications.capacityApplication = applications.buildCapacityApplication
	applications.resourceApplication = applications.buildResourceApplication
	applications.stackApplication = applications.buildStackApplication
	return applications, nil
}

func (a *nativeProductApplications) buildCapacityApplication(
	ctx context.Context,
) (installphase.ArtifactCapacityApplication, nativeProductRuntime, error) {
	runtimeAuthority, err := a.resolve(ctx)
	if err != nil {
		return nil, nativeProductRuntime{}, err
	}
	probe, err := dockercli.NewCapacityPoolProbe(runtimeAuthority.executors)
	if err != nil {
		return nil, nativeProductRuntime{}, errNativeInstallerIntegrity
	}
	pools, err := artifactfs.NewPoolAttestor(a.artifactStore, probe)
	if err != nil {
		return nil, nativeProductRuntime{}, errNativeInstallerIntegrity
	}
	dockerPool, err := probe.AttestDockerPool(ctx, artifactapp.CapacityTarget{
		Kind: artifactapp.CapacityDockerEngine, Locator: runtimeAuthority.endpoint.String(),
	})
	if err != nil {
		return nil, nativeProductRuntime{}, errNativeInstallerUnavailable
	}
	dockerLeases, err := dockercli.NewCapacityLeases(
		runtimeAuthority.executors,
		runtimeAuthority.endpoint,
		runtimeAuthority.verified.inventory,
		dockerPool,
	)
	if err != nil {
		return nil, nativeProductRuntime{}, errNativeInstallerIntegrity
	}
	hostRelease := artifactfs.NewHostReleaseCapacity()
	targetEngine, err := artifactfs.NewComposeBundleTargetEngine(a.artifactStore, hostRelease)
	if err != nil {
		return nil, nativeProductRuntime{}, errNativeInstallerIntegrity
	}
	expanded, err := dockercli.NewExpandedTargets(
		dockercli.SignedExpandedTargetAuthorityResolver{},
		a.expandedTargets,
		targetEngine,
	)
	if err != nil {
		return nil, nativeProductRuntime{}, errNativeInstallerIntegrity
	}
	lifecycle, err := dockercli.NewCapacityLifecycle(hostRelease, dockerLeases, expanded)
	if err != nil {
		return nil, nativeProductRuntime{}, errNativeInstallerIntegrity
	}
	application, err := artifactapp.NewCapacityApplication(artifactapp.CapacityDependencies{
		Repository: a.capacityState, Pools: pools, Leases: lifecycle, Materializer: lifecycle,
	})
	if err != nil {
		return nil, nativeProductRuntime{}, errNativeInstallerIntegrity
	}
	return application, runtimeAuthority, nil
}

func (a *nativeProductApplications) buildResourceApplication(
	ctx context.Context,
) (installphase.ManagedResourceEnsurer, nativeProductRuntime, error) {
	runtimeAuthority, err := a.resolve(ctx)
	if err != nil {
		return nil, nativeProductRuntime{}, err
	}
	engine, err := dockercli.NewManagedResources(runtimeAuthority.executors)
	if err != nil {
		return nil, nativeProductRuntime{}, errNativeInstallerIntegrity
	}
	application, err := resourceapp.New(resourceapp.Dependencies{
		Repository: a.resourceState,
		Engine:     engine,
	})
	if err != nil {
		return nil, nativeProductRuntime{}, errNativeInstallerIntegrity
	}
	return application, runtimeAuthority, nil
}

func (a *nativeProductApplications) buildStackApplication(
	ctx context.Context,
) (productstack.Ensurer, nativeProductRuntime, error) {
	runtimeAuthority, err := a.resolve(ctx)
	if err != nil {
		return nil, nativeProductRuntime{}, err
	}
	compose, err := dockercli.NewCompose(runtimeAuthority.executors)
	if err != nil {
		return nil, nativeProductRuntime{}, errNativeInstallerIntegrity
	}
	application, err := productstackapp.New(compose)
	if err != nil {
		return nil, nativeProductRuntime{}, errNativeInstallerIntegrity
	}
	return application, runtimeAuthority, nil
}

func (a *nativeProductApplications) resolve(ctx context.Context) (nativeProductRuntime, error) {
	if a == nil || ctx == nil || nilAny(a.runtime) {
		return nativeProductRuntime{}, errNativeInstallerIntegrity
	}
	return a.runtime.ResolveProductRuntime(ctx)
}

func capacityCommandMatchesRuntime(command artifactapp.CapacityCommand, runtimeAuthority nativeProductRuntime) bool {
	return command.OperationID == runtimeAuthority.verified.authority.OperationID().String() &&
		command.ParentPlanDigest.Equal(runtimeAuthority.verified.authority.ParentPlanDigest()) &&
		command.DockerEngine.Kind == artifactapp.CapacityDockerEngine &&
		command.DockerEngine.Locator == runtimeAuthority.endpoint.String() &&
		command.DockerDataVolume.Kind == artifactapp.CapacityDockerDataVolume &&
		command.DockerDataVolume.Locator == runtimeAuthority.endpoint.String()
}

func (a *nativeProductApplications) ReserveCapacity(
	ctx context.Context,
	command artifactapp.CapacityCommand,
) (artifactapp.CapacityResult, error) {
	if a == nil || a.capacityApplication == nil {
		return artifactapp.CapacityResult{}, errNativeInstallerIntegrity
	}
	application, runtimeAuthority, err := a.capacityApplication(ctx)
	if err != nil || !capacityCommandMatchesRuntime(command, runtimeAuthority) {
		return artifactapp.CapacityResult{}, errors.Join(err, errNativeInstallerIntegrity)
	}
	return application.ReserveCapacity(ctx, command)
}

func (a *nativeProductApplications) ConsumeArtifactExpansion(
	ctx context.Context,
	command artifactapp.CapacityCommand,
	artifactID string,
) (artifactapp.CapacityResult, error) {
	if a == nil || a.capacityApplication == nil {
		return artifactapp.CapacityResult{}, errNativeInstallerIntegrity
	}
	application, runtimeAuthority, err := a.capacityApplication(ctx)
	if err != nil || !capacityCommandMatchesRuntime(command, runtimeAuthority) {
		return artifactapp.CapacityResult{}, errors.Join(err, errNativeInstallerIntegrity)
	}
	return application.ConsumeArtifactExpansion(ctx, command, artifactID)
}

func (a *nativeProductApplications) PrepareSecretProjectionCapacity(
	ctx context.Context,
	command artifactapp.CapacityCommand,
	generationID string,
) (artifactapp.CapacityResult, error) {
	if a == nil || a.capacityApplication == nil {
		return artifactapp.CapacityResult{}, errNativeInstallerIntegrity
	}
	application, runtimeAuthority, err := a.capacityApplication(ctx)
	if err != nil || !capacityCommandMatchesRuntime(command, runtimeAuthority) {
		return artifactapp.CapacityResult{}, errors.Join(err, errNativeInstallerIntegrity)
	}
	return application.PrepareSecretProjectionCapacity(ctx, command, generationID)
}

func (a *nativeProductApplications) TransferActivationCapacity(
	ctx context.Context,
	command artifactapp.CapacityCommand,
	generationID string,
	installationID string,
) (artifactapp.CapacityResult, error) {
	if a == nil || a.capacityApplication == nil {
		return artifactapp.CapacityResult{}, errNativeInstallerIntegrity
	}
	application, runtimeAuthority, err := a.capacityApplication(ctx)
	if err != nil || !capacityCommandMatchesRuntime(command, runtimeAuthority) {
		return artifactapp.CapacityResult{}, errors.Join(err, errNativeInstallerIntegrity)
	}
	return application.TransferActivationCapacity(ctx, command, generationID, installationID)
}

func (a *nativeProductApplications) ReleaseOperationCapacity(
	ctx context.Context,
	command artifactapp.CapacityCommand,
) (artifactapp.CapacityResult, error) {
	if a == nil || a.capacityApplication == nil {
		return artifactapp.CapacityResult{}, errNativeInstallerIntegrity
	}
	application, runtimeAuthority, err := a.capacityApplication(ctx)
	if err != nil || !capacityCommandMatchesRuntime(command, runtimeAuthority) {
		return artifactapp.CapacityResult{}, errors.Join(err, errNativeInstallerIntegrity)
	}
	return application.ReleaseOperationCapacity(ctx, command)
}

func (a *nativeProductApplications) CompensateOperationCapacity(
	ctx context.Context,
	command artifactapp.CapacityCommand,
) (artifactapp.CapacityResult, error) {
	if a == nil || a.capacityApplication == nil {
		return artifactapp.CapacityResult{}, errNativeInstallerIntegrity
	}
	application, runtimeAuthority, err := a.capacityApplication(ctx)
	if err != nil || !capacityCommandMatchesRuntime(command, runtimeAuthority) {
		return artifactapp.CapacityResult{}, errors.Join(err, errNativeInstallerIntegrity)
	}
	return application.CompensateOperationCapacity(ctx, command)
}

func (a *nativeProductApplications) ReleaseActivatedCapacity(
	ctx context.Context,
	command artifactapp.CapacityCommand,
	generationID string,
	installationID string,
) (artifactapp.CapacityResult, error) {
	if a == nil || a.capacityApplication == nil {
		return artifactapp.CapacityResult{}, errNativeInstallerIntegrity
	}
	application, runtimeAuthority, err := a.capacityApplication(ctx)
	if err != nil || !capacityCommandMatchesRuntime(command, runtimeAuthority) {
		return artifactapp.CapacityResult{}, errors.Join(err, errNativeInstallerIntegrity)
	}
	return application.ReleaseActivatedCapacity(ctx, command, generationID, installationID)
}

func (a *nativeProductApplications) EnsureNetworkAndVolumes(
	ctx context.Context,
	command resourceapp.Command,
) (resourceapp.Result, error) {
	if a == nil || a.resourceApplication == nil {
		return resourceapp.Result{}, errNativeInstallerIntegrity
	}
	application, runtimeAuthority, err := a.resourceApplication(ctx)
	if err != nil || command.Endpoint.String() != runtimeAuthority.endpoint.String() ||
		command.CreationOperation != runtimeAuthority.verified.authority.OperationID().String() {
		return resourceapp.Result{}, errors.Join(err, errNativeInstallerIntegrity)
	}
	return application.EnsureNetworkAndVolumes(ctx, command)
}

func (a *nativeProductApplications) RunMigrations(
	ctx context.Context,
	authorization productstack.Authorization,
) (productstack.Receipt, error) {
	return a.runStack(ctx, authorization, true)
}

func (a *nativeProductApplications) StartCoreAndGraph(
	ctx context.Context,
	authorization productstack.Authorization,
) (productstack.Receipt, error) {
	return a.runStack(ctx, authorization, false)
}

func (a *nativeProductApplications) runStack(
	ctx context.Context,
	authorization productstack.Authorization,
	migrations bool,
) (productstack.Receipt, error) {
	if a == nil || a.stackApplication == nil {
		return productstack.Receipt{}, errNativeInstallerIntegrity
	}
	application, runtimeAuthority, err := a.stackApplication(ctx)
	if err != nil || authorization.OperationID() != runtimeAuthority.verified.authority.OperationID() ||
		!authorization.ParentPlanDigest().Equal(runtimeAuthority.verified.authority.ParentPlanDigest()) ||
		authorization.Source().Endpoint().String() != runtimeAuthority.endpoint.String() {
		return productstack.Receipt{}, errors.Join(err, errNativeInstallerIntegrity)
	}
	if migrations {
		return application.RunMigrations(ctx, authorization)
	}
	return application.StartCoreAndGraph(ctx, authorization)
}

var (
	_ installphase.ArtifactCapacityApplication = (*nativeProductApplications)(nil)
	_ installphase.ManagedResourceEnsurer      = (*nativeProductApplications)(nil)
	_ productstack.Ensurer                     = (*nativeProductApplications)(nil)
)
