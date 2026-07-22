package launcher

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/corehttp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/installplanfs"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/mcpsessioncheckpoint"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/mcpsessioncredential"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/mcpsessiondocker"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/mcpsessionhost"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/setuphost"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installphase"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpbootstrapapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpsessionapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeinstallapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/activerelease"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/installplan"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/mcpsession"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const (
	sessionServiceID       = "mcp-session"
	sessionCredentialRoot  = "mcp-session-credentials" //nolint:gosec // Local directory name, not credential material.
	pathIdentityKeyPurpose = "agentmemory.pf005.path-identity.v1"
	gitIdentityKeyPurpose  = "agentmemory.pf005.git-identity.v1"
)

type nativeProductSessionFactory struct {
	composition        *nativeComposition
	runtimeEvidence    installplanapp.RuntimeEvidenceResolver
	runtimeExecution   *nativeRuntimeExecutionVerifier
	runtimePlatform    *nativePlatformRuntimeFactory
	sessionAuthorities nativeSessionAuthorityResolver
	sessionPlan        nativeSessionPlanDecoder
	operationState     nativeSessionOperationState
}

type nativeSessionAuthorities struct {
	receipts      *installplanfs.ReadinessRepository
	runtimePlan   installphase.RuntimePlan
	ensurer       installphase.RuntimeEnsurer
	product       nativeProductRuntime
	pointer       activerelease.Pointer
	activeRelease mcpsessionapp.ActiveReleasePort
	lock          mcpsessionapp.InstallationLockPort
	image         string
}

type nativeSessionAuthorityResolver func(
	context.Context,
	runtimePlanProjection,
	installplan.Plan,
) (nativeSessionAuthorities, error)

type nativeSessionPlanDecoder func([]byte) (runtimePlanProjection, installplan.Plan, error)
type nativeSessionOperationState func(context.Context, install.OperationID) (install.State, error)

func newNativeProductSessionFactory(
	ctx context.Context,
	composition *nativeComposition,
	release *nativeReleaseAuthority,
) (*nativeProductSessionFactory, error) {
	if ctx == nil || composition == nil || release == nil || composition.factory == nil ||
		composition.plans == nil || composition.operations == nil || composition.resourceState == nil ||
		composition.installLock == nil || composition.hostPointers == nil || composition.resources == nil {
		return nil, errNativeInstallerIntegrity
	}
	artifacts, err := newNativeArtifactApplication(
		composition.artifacts, composition.artifactStore, release,
	)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	platform, err := newNativePlatformRuntimeFactory(composition, release, artifacts)
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
	policy, err := newNativeRuntimeCatalogPolicy(
		setuphost.Clock{}, release.runtimeCatalogSignatureVerifier(),
		release.runtimeCatalogPublisherVerifier(), composition.runtimeCatalogAnchor,
	)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	evidence, err := newNativeRuntimeEvidenceResolver(
		release.runtimeCatalogLoader(), policy, observer,
	)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	execution, err := newNativeRuntimeExecutionVerifier(
		release.runtimeCatalogLoader(), policy,
	)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	factory := &nativeProductSessionFactory{
		composition: composition, runtimeEvidence: evidence,
		runtimeExecution: execution, runtimePlatform: platform,
		sessionPlan: decodeNativeSessionPlan,
		operationState: func(loadContext context.Context, operationID install.OperationID) (install.State, error) {
			operation, loadError := composition.operations.Load(loadContext, operationID)
			if loadError != nil {
				return install.StateUnknown, loadError
			}
			return operation.State(), nil
		},
	}
	factory.sessionAuthorities = factory.resolveSessionAuthorities
	return factory, nil
}

func (f *nativeProductSessionFactory) BuildReadySession(
	ctx context.Context,
	host agentconfig.AgentHost,
	resolved mcpbootstrapapp.ResolvedBootstrap,
) (MCPRunner, bool, error) {
	if f == nil || ctx == nil || !host.Valid() || !resolved.Valid() || f.composition == nil ||
		nilAny(f.runtimeEvidence) || f.runtimeExecution == nil || f.runtimePlatform == nil ||
		f.sessionAuthorities == nil || f.sessionPlan == nil || f.operationState == nil {
		return nil, false, errNativeInstallerIntegrity
	}
	projection, plan, err := f.sessionPlan(resolved.CanonicalPlan())
	if err != nil || projection.host != host || projection.installationID != resolved.InstallationID() ||
		projection.operationID != resolved.OperationID() || !projection.digest.Equal(resolved.PlanDigest()) {
		return nil, false, errNativeInstallerIntegrity
	}
	state, err := f.operationState(ctx, projection.operationID)
	if err != nil {
		return nil, false, errNativeInstallerIntegrity
	}
	if state != install.StateReady {
		return nil, false, nil
	}
	return f.build(ctx, host, projection, plan)
}

func decodeNativeSessionPlan(canonical []byte) (runtimePlanProjection, installplan.Plan, error) {
	projection, err := decodeRuntimePlan(canonical)
	if err != nil {
		return runtimePlanProjection{}, installplan.Plan{}, err
	}
	plan, err := installplan.DecodeV1(canonical)
	if err != nil {
		return runtimePlanProjection{}, installplan.Plan{}, err
	}
	return projection, plan, nil
}

func (f *nativeProductSessionFactory) build(
	ctx context.Context,
	host agentconfig.AgentHost,
	projection runtimePlanProjection,
	plan installplan.Plan,
) (MCPRunner, bool, error) {
	authorities, err := f.sessionAuthorities(ctx, projection, plan)
	if err != nil {
		return nil, false, errNativeInstallerIntegrity
	}
	if authorities.receipts == nil || nilAny(authorities.ensurer) ||
		authorities.pointer.IsZero() || nilAny(authorities.activeRelease) || nilAny(authorities.lock) ||
		!mcpsession.ValidImageReference(authorities.image) {
		_ = authorities.receipts.Close()
		return nil, false, errNativeInstallerIntegrity
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = authorities.receipts.Close()
		}
	}()
	credentials := corehttp.NewNativeCredentialSource()
	dockerRunner, composeRunner, err := authorities.product.executors.SessionRunners()
	if err != nil {
		return nil, false, errNativeInstallerIntegrity
	}
	dockerProcess, err := mcpsessiondocker.NewProcess(dockerRunner)
	if err != nil {
		return nil, false, errNativeInstallerIntegrity
	}
	composeProcess, err := mcpsessiondocker.NewComposeProcess(composeRunner)
	if err != nil {
		return nil, false, errNativeInstallerIntegrity
	}
	projectName := "agentmemory_" + strings.ReplaceAll(projection.installationID, "-", "")
	network := projectName + "_internal"
	runtimeAuthority, err := mcpsessiondocker.NewRuntimeAuthority(
		authorities.pointer, projectName, projection.composeProjectDirectory,
		projection.composeConfigurationPath, projection.emptyEnvironmentPath, authorities.image, network,
	)
	if err != nil {
		return nil, false, errNativeInstallerIntegrity
	}
	status, err := corehttp.NewStatusClient(credentials, projection.coreEndpoint, projection.credentialPath)
	if err != nil {
		return nil, false, errNativeInstallerIntegrity
	}
	activator := &nativeSessionRuntimeActivator{
		ensurer: authorities.ensurer,
		command: runtimeinstallapp.Command{
			OperationID: projection.operationID.String(), CanonicalPlan: authorities.runtimePlan.CanonicalPlan(),
		},
		endpoint: projection.runtimeEndpoint,
	}
	runtimeController, err := mcpsessiondocker.NewRuntimeController(
		dockerProcess, composeProcess, status, activator, runtimeAuthority,
	)
	if err != nil {
		return nil, false, errNativeInstallerIntegrity
	}
	rootKey, err := credentials.ReadCredential(ctx, projection.installationRootKeyPath)
	if err != nil || len(rootKey) != sha256.Size {
		clear(rootKey)
		return nil, false, errNativeInstallerIntegrity
	}
	pathKey := deriveSessionKey(rootKey, pathIdentityKeyPurpose)
	gitKey := deriveSessionKey(rootKey, gitIdentityKeyPurpose)
	clear(rootKey)
	defer clear(pathKey)
	defer clear(gitKey)
	paths, err := mcpsessionhost.NewPathIdentityResolver(pathKey)
	if err != nil {
		return nil, false, errNativeInstallerIntegrity
	}
	git, err := mcpsessionhost.NewFilesystemGitIdentityResolver(gitKey)
	if err != nil {
		return nil, false, errNativeInstallerIntegrity
	}
	credentialRoot := filepath.Join(projection.runtimeDirectory, sessionCredentialRoot)
	if err := ensureNativePrivateDirectory(ctx, credentialRoot); err != nil {
		return nil, false, errNativeInstallerIntegrity
	}
	credentialFiles, err := mcpsessioncredential.NewFileStore(credentialRoot)
	if err != nil {
		return nil, false, errNativeInstallerIntegrity
	}
	credentialRegistrar, err := corehttp.NewSessionCredentialRegistrar(
		credentials, projection.coreEndpoint, projection.credentialPath,
	)
	if err != nil {
		return nil, false, errNativeInstallerIntegrity
	}
	clock := setuphost.Clock{}
	sessionCredentials, err := mcpsessioncredential.New(
		credentialRegistrar, credentialFiles, clock,
	)
	if err != nil {
		return nil, false, errNativeInstallerIntegrity
	}
	sessions, err := corehttp.NewSessionLifecycleRepository(
		credentials, projection.coreEndpoint, projection.credentialPath,
	)
	if err != nil {
		return nil, false, errNativeInstallerIntegrity
	}
	checkpointSink, err := corehttp.NewWorkspaceCheckpointClient(
		credentials, projection.coreEndpoint, projection.credentialPath,
	)
	if err != nil {
		return nil, false, errNativeInstallerIntegrity
	}
	checkpoints, err := mcpsessioncheckpoint.NewScanner(checkpointSink)
	if err != nil {
		return nil, false, errNativeInstallerIntegrity
	}
	ids, err := bootstrap.NewUUIDv7Generator(clock)
	if err != nil {
		return nil, false, errNativeInstallerIntegrity
	}
	child, err := mcpsessiondocker.NewContainer(dockerProcess)
	if err != nil {
		return nil, false, errNativeInstallerIntegrity
	}
	application, err := mcpsessionapp.New(mcpsessionapp.Dependencies{
		Authority: mcpsessionapp.SessionAuthorityScope{
			BrainID: projection.brainID, ActorID: projection.actorID, GrantID: projection.grantID,
		},
		Lock: authorities.lock, ActiveRelease: authorities.activeRelease, Runtime: runtimeController,
		Paths: paths, Git: git, IDs: ids, Credentials: sessionCredentials,
		Sessions: sessions, Child: child, Checkpoints: checkpoints, Clock: clock,
	}, mcpsessionapp.ProductionPolicy())
	if err != nil {
		return nil, false, errNativeInstallerIntegrity
	}
	lifecycle := &nativeProductSessionLifecycle{
		receipts: authorities.receipts, resources: f.composition.resources,
	}
	runner, err := NewManagedSessionRunner(application, host, lifecycle)
	if err != nil {
		return nil, false, errNativeInstallerIntegrity
	}
	succeeded = true
	return runner, true, nil
}

func (f *nativeProductSessionFactory) resolveSessionAuthorities(
	ctx context.Context,
	projection runtimePlanProjection,
	plan installplan.Plan,
) (nativeSessionAuthorities, error) {
	credentials := corehttp.NewNativeCredentialSource()
	receipts, err := installplanfs.NewReadinessRepository(
		ctx, f.composition.readinessRoot, projection.credentialPath, credentials,
	)
	if err != nil {
		return nativeSessionAuthorities{}, errNativeInstallerIntegrity
	}
	failed := true
	defer func() {
		if failed {
			_ = receipts.Close()
		}
	}()
	plans, err := installplanapp.New(installplanapp.Dependencies{
		Plans: f.composition.plans, RuntimePlans: f.composition.plans,
		RuntimeEvidence: f.runtimeEvidence, Operations: f.composition.operations,
		ReadinessReceipts: receipts, Resources: f.composition.resourceState,
		OperationID: projection.operationID,
	})
	if err != nil {
		return nativeSessionAuthorities{}, errNativeInstallerIntegrity
	}
	runtimePlan, err := plans.ResolveRuntimePlan(ctx, projection.digest, projection.operationID)
	if err != nil {
		return nativeSessionAuthorities{}, errNativeInstallerIntegrity
	}
	ensurer, err := newNativeRuntimeEnsurer(
		projection.digest, projection.operationID, plans,
		f.runtimeExecution, f.runtimePlatform,
	)
	if err != nil {
		return nativeSessionAuthorities{}, errNativeInstallerIntegrity
	}
	productResolver, err := newNativeProductAuthorityResolver(
		projection.digest, projection.operationID, plans, f.composition.operations,
		f.runtimeExecution, f.runtimePlatform,
	)
	if err != nil {
		return nativeSessionAuthorities{}, errNativeInstallerIntegrity
	}
	product, err := productResolver.ResolveProductRuntime(ctx)
	if err != nil {
		return nativeSessionAuthorities{}, errNativeInstallerIntegrity
	}
	pointerSource, err := mcpsessionhost.NewActiveRelease(
		f.composition.hostPointers, projection.installationID,
	)
	if err != nil {
		return nativeSessionAuthorities{}, errNativeInstallerIntegrity
	}
	pointer, err := pointerSource.LoadActive(ctx)
	if err != nil {
		return nativeSessionAuthorities{}, errNativeInstallerIntegrity
	}
	image, err := sessionImage(plan.SignedRelease().Manifest())
	if err != nil {
		return nativeSessionAuthorities{}, errNativeInstallerIntegrity
	}
	lock, err := mcpsessionhost.NewInstallationLock(f.composition.installLock)
	if err != nil {
		return nativeSessionAuthorities{}, errNativeInstallerIntegrity
	}
	failed = false
	return nativeSessionAuthorities{
		receipts: receipts, runtimePlan: runtimePlan, ensurer: ensurer, product: product,
		pointer: pointer, activeRelease: pointerSource, lock: lock, image: image,
	}, nil
}

type nativeSessionRuntimeActivator struct {
	ensurer  installphase.RuntimeEnsurer
	command  runtimeinstallapp.Command
	endpoint string
}

func (a *nativeSessionRuntimeActivator) EnsureEndpoint(
	ctx context.Context,
	pointer activerelease.Pointer,
) error {
	if a == nil || ctx == nil || nilAny(a.ensurer) || pointer.IsZero() ||
		pointer.RuntimeEndpoint() != a.endpoint {
		return errNativeInstallerIntegrity
	}
	result, err := a.ensurer.Ensure(ctx, a.command)
	if err != nil || result.State != runtimeinstall.OperationStateReady ||
		result.Outcome != runtimeinstallapp.OutcomeCompleted || result.ErrorCode != runtimeinstallapp.ErrorCodeNone {
		return errNativeInstallerUnavailable
	}
	return nil
}

type nativeProductSessionLifecycle struct {
	receipts  *installplanfs.ReadinessRepository
	resources *nativeResources
}

func (l *nativeProductSessionLifecycle) Close(ctx context.Context) error {
	if l == nil || ctx == nil {
		return errNativeInstallerIntegrity
	}
	var result error
	if l.receipts != nil {
		result = l.receipts.Close()
		l.receipts = nil
	}
	if l.resources != nil {
		result = errors.Join(result, l.resources.Close(ctx))
		l.resources = nil
	}
	return result
}

func deriveSessionKey(root []byte, purpose string) []byte {
	keyed := hmac.New(sha256.New, root)
	_, _ = keyed.Write([]byte(purpose))
	return keyed.Sum(nil)
}

func sessionImage(manifest releaseinventory.Manifest) (string, error) {
	return sessionImageForArchitecture(manifest, runtime.GOARCH)
}

func sessionImageForArchitecture(
	manifest releaseinventory.Manifest,
	architecture string,
) (string, error) {
	var imageIDs []string
	for _, service := range manifest.DockerTopology().Services() {
		if service.ID() != sessionServiceID {
			continue
		}
		if imageIDs != nil || len(service.NetworkIDs()) != 1 || service.NetworkIDs()[0] != "internal" ||
			len(service.VolumeMounts()) != 0 || len(service.PublishedPorts()) != 0 ||
			service.UserID() != 10001 || service.GroupID() != 10001 || service.Privileged() ||
			!service.ReadOnlyRootFilesystem() || !service.NoNewPrivileges() ||
			len(service.Capabilities()) != 0 {
			return "", errNativeInstallerIntegrity
		}
		imageIDs = service.ImageResourceIDs()
	}
	if len(imageIDs) == 0 {
		return "", errNativeInstallerIntegrity
	}
	wanted := make(map[string]struct{}, len(imageIDs))
	for _, id := range imageIDs {
		wanted[id] = struct{}{}
	}
	image := ""
	for _, resource := range manifest.Resources() {
		if _, selected := wanted[resource.ID()]; !selected ||
			resource.Kind() != releaseinventory.ResourceKindOCIImage ||
			resource.Platform().OS() != "linux" || resource.Platform().Architecture() != architecture {
			continue
		}
		if image != "" || !mcpsession.ValidImageReference(resource.SourceRef()) {
			return "", errNativeInstallerIntegrity
		}
		image = resource.SourceRef()
	}
	if image == "" {
		return "", errNativeInstallerIntegrity
	}
	return image, nil
}

var (
	_ ProductSessionFactory                 = (*nativeProductSessionFactory)(nil)
	_ mcpsessiondocker.RuntimeActivatorPort = (*nativeSessionRuntimeActivator)(nil)
	_ RuntimeLifecycle                      = (*nativeProductSessionLifecycle)(nil)
)
