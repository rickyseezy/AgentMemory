package launcher

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/activereleasejournal"
	agentconfigadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/artifactjournal"
	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/corehttp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/filesystem"
	firststartadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/firststart"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/hostlock"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/installplanfs"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/installprogress"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/mcpbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/releaseanchor"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/resourcejournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/setuphost"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/setuphttp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/firststartapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpbootstrapapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/setupprogressapp"
	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/installplan"
)

// NativeRoots are purpose-separated owner-controlled launcher state roots.
// They are selected only by the platform composition root, never by an MCP
// request or installation plan.
type NativeRoots struct {
	OperationState     string
	BootstrapPointer   string
	SetupDecisions     string
	PreparationState   string
	RuntimeState       string
	ReleaseAnchorState string
	ArtifactState      string
	ResourceState      string
	ActiveReleaseState string
	InstallationLock   string
	CanonicalPlans     string
}

type nativeRootsResolver func() (NativeRoots, error)
type nativeJournalFactory func(*bootstrapadapter.OperationLocator) (filesystem.OperationJournalProvider, error)

// NativeFactory lazily constructs platform-protected repositories for one MCP
// process. Construction itself does not claim an installation exists.
type NativeFactory struct {
	roots    nativeRootsResolver
	journals nativeJournalFactory
	ready    mcpbootstrap.ReadySurfaceProvider
}

// NewNativeFactory constructs the production launcher factory. Missing or
// damaged protected material is reported only when BuildMCP resolves it.
func NewNativeFactory() MCPFactory {
	return &NativeFactory{
		roots: defaultNativeRoots, journals: newPlatformJournalProvider,
		ready: pendingReadySurface{},
	}
}

// BuildMCP creates a short-lived native composition and transfers ownership
// of its resources to the returned managed runner.
func (f *NativeFactory) BuildMCP(
	ctx context.Context,
	host agentconfigdomain.AgentHost,
) (MCPRunner, error) {
	if f == nil || ctx == nil || !host.Valid() || f.roots == nil || f.journals == nil || nilCapability(f.ready) {
		return nil, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	roots, err := f.roots()
	if err != nil || !roots.valid() {
		return nil, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	composition, err := composeNative(ctx, roots, f.journals, f.ready)
	if err != nil {
		return nil, mcpbootstrapapp.ErrBootstrapUnavailable
	}
	runner, err := composition.factory.BuildMCP(ctx, host)
	if err != nil {
		_ = composition.resources.Close(context.WithoutCancel(ctx))
		return nil, err
	}
	return runner, nil
}

func defaultNativeRoots() (NativeRoots, error) {
	configurationRoot, err := os.UserConfigDir()
	if err != nil || configurationRoot == "" || !filepath.IsAbs(configurationRoot) {
		return NativeRoots{}, errors.New("native configuration root is unavailable")
	}
	base := filepath.Join(filepath.Clean(configurationRoot), "AgentMemory", "launcher-v1")
	return NativeRoots{
		OperationState:     filepath.Join(base, "operation-state"),
		BootstrapPointer:   filepath.Join(base, "bootstrap-pointer"),
		SetupDecisions:     filepath.Join(base, "setup-decisions"),
		PreparationState:   filepath.Join(base, "preparation-state"),
		RuntimeState:       filepath.Join(base, "runtime-state"),
		ReleaseAnchorState: filepath.Join(base, "release-anchor-state"),
		ArtifactState:      filepath.Join(base, "artifact-state"),
		ResourceState:      filepath.Join(base, "resource-state"),
		ActiveReleaseState: filepath.Join(base, "active-release-state"),
		InstallationLock:   filepath.Join(base, "installation.lock"),
		CanonicalPlans:     filepath.Join(base, "canonical-plans"),
	}, nil
}

func (r NativeRoots) valid() bool {
	values := []string{
		r.OperationState, r.BootstrapPointer, r.SetupDecisions,
		r.PreparationState, r.RuntimeState, r.ReleaseAnchorState, r.CanonicalPlans,
		r.ArtifactState, r.ResourceState, r.ActiveReleaseState, r.InstallationLock,
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

type nativeComposition struct {
	factory       *Factory
	resources     *nativeResources
	preparations  firststartapp.PreparationRepository
	binder        firststartapp.PreparationBinder
	runtimeState  *filesystem.RuntimeOperationRepository
	releaseAnchor *releaseanchor.Repository
	artifacts     *artifactjournal.Repository
	resourceState *resourcejournal.Repository
	activations   *activereleasejournal.ActivationRepository
	hostPointers  *activereleasejournal.HostPointerRepository
	installLock   *hostlock.Port
}

func composeNative(
	ctx context.Context,
	roots NativeRoots,
	journalFactory nativeJournalFactory,
	ready mcpbootstrap.ReadySurfaceProvider,
) (nativeComposition, error) {
	if ctx == nil || !roots.valid() || journalFactory == nil || nilCapability(ready) {
		return nativeComposition{}, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	operationLocator, err := bootstrapadapter.NewOperationLocator(roots.OperationState)
	if err != nil {
		return nativeComposition{}, err
	}
	pointerLocator, err := bootstrapadapter.NewOperationLocator(roots.BootstrapPointer)
	if err != nil {
		return nativeComposition{}, err
	}
	decisionLocator, err := bootstrapadapter.NewOperationLocator(roots.SetupDecisions)
	if err != nil {
		return nativeComposition{}, err
	}
	preparationLocator, err := bootstrapadapter.NewOperationLocator(roots.PreparationState)
	if err != nil {
		return nativeComposition{}, err
	}
	runtimeLocator, err := bootstrapadapter.NewOperationLocator(roots.RuntimeState)
	if err != nil {
		return nativeComposition{}, err
	}
	releaseAnchorLocator, err := bootstrapadapter.NewOperationLocator(roots.ReleaseAnchorState)
	if err != nil {
		return nativeComposition{}, err
	}
	artifactLocator, err := bootstrapadapter.NewOperationLocator(roots.ArtifactState)
	if err != nil {
		return nativeComposition{}, err
	}
	resourceLocator, err := bootstrapadapter.NewOperationLocator(roots.ResourceState)
	if err != nil {
		return nativeComposition{}, err
	}
	activeReleaseLocator, err := bootstrapadapter.NewOperationLocator(roots.ActiveReleaseState)
	if err != nil {
		return nativeComposition{}, err
	}
	operationJournals, err := journalFactory(operationLocator)
	if err != nil || nilCapability(operationJournals) {
		return nativeComposition{}, mcpbootstrapapp.ErrBootstrapUnavailable
	}
	pointerJournals, err := journalFactory(pointerLocator)
	if err != nil || nilCapability(pointerJournals) {
		return nativeComposition{}, mcpbootstrapapp.ErrBootstrapUnavailable
	}
	decisionJournals, err := journalFactory(decisionLocator)
	if err != nil || nilCapability(decisionJournals) {
		return nativeComposition{}, mcpbootstrapapp.ErrBootstrapUnavailable
	}
	preparationJournals, err := journalFactory(preparationLocator)
	if err != nil || nilCapability(preparationJournals) {
		return nativeComposition{}, mcpbootstrapapp.ErrBootstrapUnavailable
	}
	runtimeJournals, err := journalFactory(runtimeLocator)
	if err != nil || nilCapability(runtimeJournals) {
		return nativeComposition{}, mcpbootstrapapp.ErrBootstrapUnavailable
	}
	releaseAnchorJournals, err := journalFactory(releaseAnchorLocator)
	if err != nil || nilCapability(releaseAnchorJournals) {
		return nativeComposition{}, mcpbootstrapapp.ErrBootstrapUnavailable
	}
	artifactJournals, err := journalFactory(artifactLocator)
	if err != nil || nilCapability(artifactJournals) {
		return nativeComposition{}, mcpbootstrapapp.ErrBootstrapUnavailable
	}
	resourceJournals, err := journalFactory(resourceLocator)
	if err != nil || nilCapability(resourceJournals) {
		return nativeComposition{}, mcpbootstrapapp.ErrBootstrapUnavailable
	}
	activeReleaseJournals, err := journalFactory(activeReleaseLocator)
	if err != nil || nilCapability(activeReleaseJournals) {
		return nativeComposition{}, mcpbootstrapapp.ErrBootstrapUnavailable
	}
	fence, err := filesystem.NewNativeOperationStateFence(operationLocator)
	if err != nil {
		return nativeComposition{}, err
	}
	runtimeFence, err := filesystem.NewNativeOperationStateFence(runtimeLocator)
	if err != nil {
		return nativeComposition{}, err
	}
	clock := setuphost.Clock{}
	artifactRepository, err := artifactjournal.New(artifactJournals, clock)
	if err != nil {
		return nativeComposition{}, err
	}
	resourceRepository, err := resourcejournal.New(resourceJournals, clock)
	if err != nil {
		return nativeComposition{}, err
	}
	activationRepository, err := activereleasejournal.NewActivationRepository(activeReleaseJournals, clock)
	if err != nil {
		return nativeComposition{}, err
	}
	hostPointerRepository, err := activereleasejournal.NewHostPointerRepository(activeReleaseJournals, clock)
	if err != nil {
		return nativeComposition{}, err
	}
	installationLock, err := hostlock.New(roots.InstallationLock)
	if err != nil {
		return nativeComposition{}, err
	}
	releaseAnchorRepository, err := releaseanchor.NewRepositoryFromProvider(ctx, releaseAnchorJournals, clock)
	if err != nil {
		return nativeComposition{}, err
	}
	preparations, err := firststartadapter.NewPreparationRepository(preparationJournals, clock)
	if err != nil {
		return nativeComposition{}, err
	}
	owners, err := newPlatformOwnerBindingSource()
	if err != nil || nilAny(owners) {
		return nativeComposition{}, mcpbootstrapapp.ErrBootstrapUnavailable
	}
	projection, err := firststartadapter.NewNativeHostProjectionSource(
		agentconfigadapter.NewLocationResolver(), owners,
	)
	if err != nil {
		return nativeComposition{}, err
	}
	binder, err := firststartadapter.NewPlanBinder(projection)
	if err != nil {
		return nativeComposition{}, err
	}
	operations, err := filesystem.NewInstallOperationRepository(operationJournals, clock, fence)
	if err != nil {
		return nativeComposition{}, err
	}
	runtimeState, err := filesystem.NewRuntimeOperationRepository(runtimeJournals, clock, runtimeFence)
	if err != nil {
		return nativeComposition{}, err
	}
	plans, err := installplanfs.NewRepository(ctx, roots.CanonicalPlans)
	if err != nil {
		return nativeComposition{}, err
	}
	resources := &nativeResources{plans: plans}
	resolver, err := NewProtectedResolver(pointerJournals, plans, operations, clock)
	if err != nil {
		_ = resources.Close(context.WithoutCancel(ctx))
		return nativeComposition{}, err
	}
	runtime := &nativeRuntimeFactory{
		operations: operations, decisions: decisionJournals, clock: clock,
		ready: ready, resources: resources, decodePlan: decodeRuntimePlan,
		setup: newNativeSetupController, readyForPlan: newNativeReadySurface,
	}
	factory, err := NewFactory(resolver, runtime)
	if err != nil {
		_ = resources.Close(context.WithoutCancel(ctx))
		return nativeComposition{}, err
	}
	return nativeComposition{
		factory: factory, resources: resources, preparations: preparations, binder: binder,
		runtimeState: runtimeState, releaseAnchor: releaseAnchorRepository,
		artifacts: artifactRepository, resourceState: resourceRepository,
		activations: activationRepository, hostPointers: hostPointerRepository, installLock: installationLock,
	}, nil
}

type cancellationRepository interface {
	Load(context.Context, install.OperationID) (*install.Operation, error)
	Request(context.Context, installapp.CancellationRequest) (installapp.CancellationIntent, error)
}

// boundCancellation is both the MCP cancellation port and the idempotent
// decision effect. It writes intent through the same aggregate CAS authority
// used by the installer; it never marks terminal settlement itself.
type boundCancellation struct {
	binding    setupprogressapp.Binding
	repository cancellationRepository
	supervisor firststartapp.InstallationSupervisor
	canonical  []byte
}

func (c *boundCancellation) RequestCancellation(ctx context.Context) error {
	if c == nil || ctx == nil || !c.binding.Valid() || nilAny(c.repository) {
		return setupprogressapp.ErrAuthorityIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	operation, err := c.repository.Load(ctx, c.binding.OperationID())
	if err != nil || operation == nil || operation.ID() != c.binding.OperationID() ||
		!operation.PlanDigest().Equal(c.binding.PlanDigest()) {
		return errors.New("installation cancellation authority is unavailable")
	}
	if operation.State() == install.StateCancelled {
		return nil
	}
	if operation.State().Terminal() {
		return setupprogressapp.ErrAuthorityConflict
	}
	intent, err := c.repository.Request(ctx, installapp.CancellationRequest{
		OperationID: c.binding.OperationID(), PlanDigest: c.binding.PlanDigest(),
		ObservedAggregateVersion: operation.AggregateVersion(),
	})
	if err != nil || !intent.ValidFor(c.binding.OperationID(), c.binding.PlanDigest()) {
		return errors.New("installation cancellation intent is unavailable")
	}
	return nil
}

func (c *boundCancellation) ApplySetupDecision(
	ctx context.Context,
	command setupprogressapp.DecisionCommand,
) error {
	if c == nil || command.Binding().OperationID() != c.binding.OperationID() ||
		!command.Binding().PlanDigest().Equal(c.binding.PlanDigest()) {
		return setupprogressapp.ErrAuthorityIntegrity
	}
	switch command.Decision() {
	case setupprogressapp.DecisionCancel, setupprogressapp.DecisionDecline:
		return c.RequestCancellation(ctx)
	case setupprogressapp.DecisionAccept, setupprogressapp.DecisionRetry:
		if nilAny(c.supervisor) || len(c.canonical) == 0 {
			return setupprogressapp.ErrAuthorityConflict
		}
		if err := c.supervisor.EnsureRunning(ctx, installapp.InstallCommand{
			OperationID:   c.binding.OperationID().String(),
			CanonicalPlan: append([]byte(nil), c.canonical...),
		}); err != nil {
			return errors.New("installation resume authority is unavailable")
		}
		return nil
	default:
		return setupprogressapp.ErrAuthorityIntegrity
	}
}

type nativeRuntimeFactory struct {
	operations   cancellationRepository
	decisions    installprogress.DecisionJournalProvider
	clock        installprogress.Clock
	ready        mcpbootstrap.ReadySurfaceProvider
	readyForPlan readySurfaceFactory
	resources    *nativeResources
	decodePlan   runtimePlanDecoder
	setup        nativeSetupFactory
	supervisor   firststartapp.InstallationSupervisor
}

type runtimePlanProjection struct {
	digest         install.PlanDigest
	operationID    install.OperationID
	installationID string
	host           agentconfigdomain.AgentHost
	totalBytes     uint64
	coreEndpoint   string
	credentialPath string
}

type runtimePlanDecoder func([]byte) (runtimePlanProjection, error)
type readySurfaceFactory func(runtimePlanProjection) (mcpbootstrap.ReadySurfaceProvider, error)

func decodeRuntimePlan(canonical []byte) (runtimePlanProjection, error) {
	plan, err := installplan.DecodeV1(canonical)
	if err != nil {
		return runtimePlanProjection{}, err
	}
	product := plan.Product()
	credentialPath := ""
	for _, secret := range product.SecretFiles() {
		if secret.Purpose() == installplan.SecretAPICredential {
			if credentialPath != "" {
				return runtimePlanProjection{}, installplan.ErrIntegrity
			}
			credentialPath = secret.Path()
		}
	}
	if credentialPath == "" {
		return runtimePlanProjection{}, installplan.ErrIntegrity
	}
	return runtimePlanProjection{
		digest: plan.Digest(), operationID: plan.OperationID(),
		installationID: plan.InstallationID(), host: plan.AgentConfiguration().AgentHost(),
		totalBytes:   plan.AcquisitionPlan().Totals().DownloadBytes(),
		coreEndpoint: product.CoreEndpoint(), credentialPath: credentialPath,
	}, nil
}

func newNativeReadySurface(plan runtimePlanProjection) (mcpbootstrap.ReadySurfaceProvider, error) {
	status, err := corehttp.NewStatusClient(
		corehttp.NewNativeCredentialSource(), plan.coreEndpoint, plan.credentialPath,
	)
	if err != nil {
		return nil, errors.New("native core status authority is unavailable")
	}
	return newCoreReadySurface(plan.installationID, status)
}

type nativeSetupController interface {
	mcpbootstrapapp.SetupPort
	Close(context.Context) error
}

type nativeSetupFactory func(
	context.Context,
	*setupprogressapp.Application,
) (nativeSetupController, error)

func newNativeSetupController(
	ctx context.Context,
	progress *setupprogressapp.Application,
) (nativeSetupController, error) {
	browser, err := setuphost.NewBrowserOpener()
	if err != nil {
		return nil, errors.New("native setup browser is unavailable")
	}
	controller, err := setuphttp.NewController(ctx, setuphttp.Config{}, setuphttp.Dependencies{
		Application: progress, PrincipalVerifier: setuphost.NewPrincipalVerifier(),
		BrowserOpener: browser, Clock: setuphost.Clock{},
	})
	if err != nil {
		return nil, errors.New("native setup controller is unavailable")
	}
	return controller, nil
}

func (f *nativeRuntimeFactory) BuildBootstrapRuntime(
	ctx context.Context,
	host agentconfigdomain.AgentHost,
	resolved mcpbootstrapapp.ResolvedBootstrap,
) (BootstrapRuntime, error) {
	if f == nil || ctx == nil || !host.Valid() || !resolved.Valid() ||
		nilAny(f.operations) || nilAny(f.decisions) || nilAny(f.clock) ||
		(nilCapability(f.ready) && f.readyForPlan == nil) ||
		f.resources == nil || f.decodePlan == nil || f.setup == nil {
		return BootstrapRuntime{}, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	plan, err := f.decodePlan(resolved.CanonicalPlan())
	if err != nil || !plan.digest.Equal(resolved.PlanDigest()) ||
		plan.operationID != resolved.OperationID() ||
		plan.installationID != resolved.InstallationID() || plan.host != host ||
		plan.totalBytes > setupprogressapp.MaximumSafeInteger {
		return BootstrapRuntime{}, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	ready := f.ready
	if f.readyForPlan != nil {
		ready, err = f.readyForPlan(plan)
		if err != nil || nilCapability(ready) {
			return BootstrapRuntime{}, mcpbootstrapapp.ErrBootstrapUnavailable
		}
	}
	binding, err := setupprogressapp.NewBinding(resolved.OperationID(), resolved.PlanDigest())
	if err != nil {
		return BootstrapRuntime{}, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	cancellation := &boundCancellation{
		binding: binding, repository: f.operations,
		supervisor: f.supervisor, canonical: resolved.CanonicalPlan(),
	}
	authority, err := installprogress.NewAuthority(
		binding, plan.totalBytes,
		f.operations, f.decisions, cancellation, f.clock,
	)
	if err != nil {
		return BootstrapRuntime{}, err
	}
	progress, err := setupprogressapp.NewApplication(binding, authority, authority)
	if err != nil {
		return BootstrapRuntime{}, err
	}
	controller, err := f.setup(ctx, progress)
	if err != nil {
		return BootstrapRuntime{}, errors.New("native setup controller is unavailable")
	}
	lifecycle := &nativeRuntimeLifecycle{controller: controller, resources: f.resources}
	return BootstrapRuntime{
		Progress: progress, Setup: controller, Cancellation: cancellation,
		Ready: ready, Lifecycle: lifecycle,
	}, nil
}

type nativeResources struct {
	plans  interface{ Close() error }
	mu     sync.Mutex
	closed bool
}

func (r *nativeResources) Close(context.Context) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	if r.plans != nil && r.plans.Close() != nil {
		return errors.New("native plan repository close failed")
	}
	return nil
}

type nativeRuntimeLifecycle struct {
	controller nativeSetupController
	resources  *nativeResources
}

func (l *nativeRuntimeLifecycle) Close(ctx context.Context) error {
	if l == nil || ctx == nil {
		return errors.New("native runtime lifecycle is invalid")
	}
	var result error
	if l.controller != nil {
		result = l.controller.Close(ctx)
	}
	if l.resources != nil {
		result = errors.Join(result, l.resources.Close(ctx))
	}
	return result
}

// pendingReadySurface is the explicit PF-005 boundary. It is queried only
// after the authenticated operation itself reports Ready.
type pendingReadySurface struct{}

func (pendingReadySurface) ReadySurface(context.Context) (mcpbootstrap.ReadySurface, error) {
	return mcpbootstrap.ReadySurface{}, errors.New("product MCP session bridge is unavailable")
}

func nilAny(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid:
		return true
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128, reflect.Array,
		reflect.String, reflect.Struct, reflect.UnsafePointer:
		return false
	}
	return false
}

var (
	_ MCPFactory                       = (*NativeFactory)(nil)
	_ BootstrapRuntimeFactory          = (*nativeRuntimeFactory)(nil)
	_ mcpbootstrapapp.CancellationPort = (*boundCancellation)(nil)
	_ installprogress.DecisionEffect   = (*boundCancellation)(nil)
	_ RuntimeLifecycle                 = (*nativeRuntimeLifecycle)(nil)
	_ RuntimeLifecycle                 = (*nativeResources)(nil)
	_ installprogress.Clock            = setuphost.Clock{}
)
