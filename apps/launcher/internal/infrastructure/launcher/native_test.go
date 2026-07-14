package launcher

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/filesystem"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/mcpbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/setuphost"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpbootstrapapp"
	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/setupprogressapp"
	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001NativeRootsAreAbsolutePurposeSeparatedAndDeterministic(t *testing.T) {
	t.Parallel()
	roots, err := defaultNativeRoots()
	if err != nil || !roots.valid() {
		t.Fatalf("defaultNativeRoots()=%+v,%v", roots, err)
	}
	if roots.OperationState == roots.BootstrapPointer || roots.OperationState == roots.SetupDecisions ||
		roots.BootstrapPointer == roots.SetupDecisions || roots.PreparationState == roots.OperationState ||
		roots.PreparationState == roots.BootstrapPointer || roots.PreparationState == roots.SetupDecisions ||
		roots.RuntimeState == roots.OperationState || roots.ReleaseAnchorState == roots.OperationState ||
		roots.ReleaseAnchorState == roots.RuntimeState {
		t.Fatalf("default roots are not purpose separated: %+v", roots)
	}
	root := t.TempDir()
	valid := nativeTestRoots(root)
	if !valid.valid() {
		t.Fatalf("valid roots rejected: %+v", valid)
	}
	for name, candidate := range map[string]NativeRoots{
		"empty": {},
		"relative": {OperationState: "relative", BootstrapPointer: valid.BootstrapPointer, SetupDecisions: valid.SetupDecisions,
			PreparationState: valid.PreparationState, RuntimeState: valid.RuntimeState, ReleaseAnchorState: valid.ReleaseAnchorState, CanonicalPlans: valid.CanonicalPlans},
		"unclean": {OperationState: root + "/state/../other", BootstrapPointer: valid.BootstrapPointer, SetupDecisions: valid.SetupDecisions,
			PreparationState: valid.PreparationState, RuntimeState: valid.RuntimeState, ReleaseAnchorState: valid.ReleaseAnchorState, CanonicalPlans: valid.CanonicalPlans},
		"duplicate": {OperationState: valid.OperationState, BootstrapPointer: valid.OperationState, SetupDecisions: valid.SetupDecisions,
			PreparationState: valid.OperationState, RuntimeState: valid.OperationState, ReleaseAnchorState: valid.OperationState, CanonicalPlans: valid.CanonicalPlans},
		"missing preparation": {OperationState: valid.OperationState, BootstrapPointer: valid.BootstrapPointer,
			SetupDecisions: valid.SetupDecisions, RuntimeState: valid.RuntimeState, ReleaseAnchorState: valid.ReleaseAnchorState, CanonicalPlans: valid.CanonicalPlans},
		"missing runtime": {OperationState: valid.OperationState, BootstrapPointer: valid.BootstrapPointer,
			SetupDecisions: valid.SetupDecisions, PreparationState: valid.PreparationState, ReleaseAnchorState: valid.ReleaseAnchorState, CanonicalPlans: valid.CanonicalPlans},
		"missing release anchor": {OperationState: valid.OperationState, BootstrapPointer: valid.BootstrapPointer,
			SetupDecisions: valid.SetupDecisions, PreparationState: valid.PreparationState, RuntimeState: valid.RuntimeState, CanonicalPlans: valid.CanonicalPlans},
		"missing plan": {OperationState: valid.OperationState, BootstrapPointer: valid.BootstrapPointer,
			SetupDecisions: valid.SetupDecisions, PreparationState: valid.PreparationState, RuntimeState: valid.RuntimeState, ReleaseAnchorState: valid.ReleaseAnchorState},
	} {
		if candidate.valid() {
			t.Fatalf("%s roots accepted: %+v", name, candidate)
		}
	}
}

func TestPF001NativeCompositionUsesThreeDistinctJournalAuthoritiesAndResolvesMissing(t *testing.T) {
	t.Parallel()
	roots := nativeTestRoots(t.TempDir())
	var observed []string
	var mu sync.Mutex
	journalFactory := func(locator *bootstrapadapter.OperationLocator) (filesystem.OperationJournalProvider, error) {
		mu.Lock()
		observed = append(observed, locator.Root())
		mu.Unlock()
		return nativeMissingJournalProvider{}, nil
	}
	composition, err := composeNative(context.Background(), roots, journalFactory, pendingReadySurface{})
	if err != nil || composition.factory == nil || composition.resources == nil || composition.preparations == nil ||
		composition.releaseAnchor == nil {
		t.Fatalf("composeNative()=%+v,%v", composition, err)
	}
	if len(observed) != 6 || observed[0] != roots.OperationState ||
		observed[1] != roots.BootstrapPointer || observed[2] != roots.SetupDecisions ||
		observed[3] != roots.PreparationState || observed[4] != roots.RuntimeState ||
		observed[5] != roots.ReleaseAnchorState {
		t.Fatalf("journal roots=%q", observed)
	}
	if _, err := composition.factory.BuildMCP(context.Background(), agentconfigdomain.AgentHostCodex); !errors.Is(err, mcpbootstrapapp.ErrBootstrapNotFound) {
		t.Fatalf("missing protected pointer error=%v", err)
	}
	if err := composition.resources.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := composition.resources.Close(context.Background()); err != nil {
		t.Fatalf("idempotent resource close error=%v", err)
	}
}

func TestPF001NativeCompositionRejectsIncompleteAuthoritiesAtEveryBoundary(t *testing.T) {
	t.Parallel()
	roots := nativeTestRoots(t.TempDir())
	for name, run := range map[string]func() error{
		"nil context": func() error {
			//lint:ignore SA1012 Deliberate nil-context composition attack.
			//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
			_, err := composeNative(nil, roots, func(*bootstrapadapter.OperationLocator) (filesystem.OperationJournalProvider, error) {
				return nativeMissingJournalProvider{}, nil
			}, pendingReadySurface{})
			return err
		},
		"invalid roots": func() error {
			_, err := composeNative(context.Background(), NativeRoots{}, func(*bootstrapadapter.OperationLocator) (filesystem.OperationJournalProvider, error) {
				return nativeMissingJournalProvider{}, nil
			}, pendingReadySurface{})
			return err
		},
		"nil journal factory": func() error {
			_, err := composeNative(context.Background(), roots, nil, pendingReadySurface{})
			return err
		},
		"nil Ready": func() error {
			_, err := composeNative(context.Background(), roots, func(*bootstrapadapter.OperationLocator) (filesystem.OperationJournalProvider, error) {
				return nativeMissingJournalProvider{}, nil
			}, (*readyStub)(nil))
			return err
		},
	} {
		if err := run(); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
			t.Fatalf("%s error=%v", name, err)
		}
	}
	for failAt := 1; failAt <= 6; failAt++ {
		for _, returnNil := range []bool{false, true} {
			calls := 0
			_, err := composeNative(context.Background(), roots,
				func(*bootstrapadapter.OperationLocator) (filesystem.OperationJournalProvider, error) {
					calls++
					if calls == failAt {
						if returnNil {
							return nil, nil
						}
						return nil, errors.New("private journal failure")
					}
					return nativeMissingJournalProvider{}, nil
				}, pendingReadySurface{})
			if !errors.Is(err, mcpbootstrapapp.ErrBootstrapUnavailable) || calls != failAt {
				t.Fatalf("failAt=%d nil=%t calls=%d error=%v", failAt, returnNil, calls, err)
			}
		}
	}
	calls := 0
	_, err := composeNative(context.Background(), roots,
		func(*bootstrapadapter.OperationLocator) (filesystem.OperationJournalProvider, error) {
			calls++
			if calls == 6 {
				return nativePlainJournalProvider{}, nil
			}
			return nativeMissingJournalProvider{}, nil
		}, pendingReadySurface{})
	if err == nil || calls != 6 {
		t.Fatalf("ordinary release-anchor journal accepted: calls=%d error=%v", calls, err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = composeNative(cancelled, roots, func(*bootstrapadapter.OperationLocator) (filesystem.OperationJournalProvider, error) {
		return nativeMissingJournalProvider{}, nil
	}, pendingReadySurface{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled composition error=%v", err)
	}
}

func TestPF001NativeFactoryBuildMapsOnlyRealProtectedStateFailures(t *testing.T) {
	t.Parallel()
	if factory := NewNativeFactory(); factory == nil {
		t.Fatal("NewNativeFactory() returned nil")
	}
	roots := nativeTestRoots(t.TempDir())
	factory := &NativeFactory{
		roots: func() (NativeRoots, error) { return roots, nil },
		journals: func(*bootstrapadapter.OperationLocator) (filesystem.OperationJournalProvider, error) {
			return nativeMissingJournalProvider{}, nil
		},
		ready: pendingReadySurface{},
	}
	if _, err := factory.BuildMCP(context.Background(), agentconfigdomain.AgentHostCodex); !errors.Is(err, mcpbootstrapapp.ErrBootstrapNotFound) {
		t.Fatalf("BuildMCP(missing) error=%v", err)
	}
	for name, run := range map[string]func() error{
		"nil factory": func() error {
			var candidate *NativeFactory
			_, err := candidate.BuildMCP(context.Background(), agentconfigdomain.AgentHostCodex)
			return err
		},
		"nil context": func() error {
			//lint:ignore SA1012 Deliberate nil-context boundary attack.
			//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
			_, err := factory.BuildMCP(nil, agentconfigdomain.AgentHostCodex)
			return err
		},
		"invalid host": func() error {
			_, err := factory.BuildMCP(context.Background(), agentconfigdomain.AgentHost("invalid"))
			return err
		},
		"nil roots": func() error {
			candidate := *factory
			candidate.roots = nil
			_, err := candidate.BuildMCP(context.Background(), agentconfigdomain.AgentHostCodex)
			return err
		},
		"nil journals": func() error {
			candidate := *factory
			candidate.journals = nil
			_, err := candidate.BuildMCP(context.Background(), agentconfigdomain.AgentHostCodex)
			return err
		},
		"nil Ready": func() error {
			candidate := *factory
			candidate.ready = (*readyStub)(nil)
			_, err := candidate.BuildMCP(context.Background(), agentconfigdomain.AgentHostCodex)
			return err
		},
		"root failure": func() error {
			candidate := *factory
			candidate.roots = func() (NativeRoots, error) { return NativeRoots{}, errors.New("private") }
			_, err := candidate.BuildMCP(context.Background(), agentconfigdomain.AgentHostCodex)
			return err
		},
		"invalid resolved roots": func() error {
			candidate := *factory
			candidate.roots = func() (NativeRoots, error) { return NativeRoots{}, nil }
			_, err := candidate.BuildMCP(context.Background(), agentconfigdomain.AgentHostCodex)
			return err
		},
	} {
		if err := run(); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
			t.Fatalf("%s error=%v", name, err)
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := factory.BuildMCP(cancelled, agentconfigdomain.AgentHostCodex); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled factory error=%v", err)
	}
	compositionFailure := *factory
	compositionFailure.journals = func(*bootstrapadapter.OperationLocator) (filesystem.OperationJournalProvider, error) {
		return nil, errors.New("private")
	}
	if _, err := compositionFailure.BuildMCP(context.Background(), agentconfigdomain.AgentHostCodex); !errors.Is(err, mcpbootstrapapp.ErrBootstrapUnavailable) {
		t.Fatalf("composition failure error=%v", err)
	}
}

func TestPF001BoundCancellationUsesExactAggregateCASAuthority(t *testing.T) {
	t.Parallel()
	binding, operation := nativeCancellationFixture(t)
	repository := &nativeCancellationRepository{operation: operation}
	cancellation := &boundCancellation{binding: binding, repository: repository}
	if err := cancellation.RequestCancellation(context.Background()); err != nil {
		t.Fatalf("RequestCancellation() error=%v", err)
	}
	if repository.requests.Load() != 1 || repository.last.OperationID != binding.OperationID() ||
		!repository.last.PlanDigest.Equal(binding.PlanDigest()) || repository.last.ObservedAggregateVersion != 0 {
		t.Fatalf("cancellation request=%+v calls=%d", repository.last, repository.requests.Load())
	}

	cancelledOperation, _ := install.NewOperation(binding.OperationID(), binding.PlanDigest())
	if err := cancelledOperation.Cancel(binding.PlanDigest()); err != nil {
		t.Fatal(err)
	}
	repository.operation = cancelledOperation
	before := repository.requests.Load()
	if err := cancellation.RequestCancellation(context.Background()); err != nil || repository.requests.Load() != before {
		t.Fatalf("cancelled replay error=%v calls=%d", err, repository.requests.Load())
	}
	terminal, _ := install.NewOperation(binding.OperationID(), binding.PlanDigest())
	if err := terminal.MarkUnsupportedHost(binding.PlanDigest()); err != nil {
		t.Fatal(err)
	}
	repository.operation = terminal
	if err := cancellation.RequestCancellation(context.Background()); !errors.Is(err, setupprogressapp.ErrAuthorityConflict) {
		t.Fatalf("terminal cancellation error=%v", err)
	}
}

func TestPF001BoundAcceptAndRetryResumeOnlyTheExactPlanBoundInstaller(t *testing.T) {
	t.Parallel()
	binding, operation := nativeCancellationFixture(t)
	repository := &nativeCancellationRepository{operation: operation}
	supervisor := &nativeSupervisorStub{}
	canonical := []byte("canonical plan")
	control := &boundCancellation{
		binding: binding, repository: repository, supervisor: supervisor, canonical: canonical,
	}
	for _, decision := range []setupprogressapp.Decision{
		setupprogressapp.DecisionAccept, setupprogressapp.DecisionRetry,
	} {
		if err := invokeNativeDecision(t, control, binding, decision,
			"018f47ab-9a77-7df0-8f4c-3e934c0a7d41"); err != nil {
			t.Fatal(err)
		}
	}
	if supervisor.calls.Load() != 2 || supervisor.command.OperationID != binding.OperationID().String() ||
		string(supervisor.command.CanonicalPlan) != "canonical plan" {
		t.Fatalf("resume calls=%d command=%+v", supervisor.calls.Load(), supervisor.command)
	}
	canonical[0] = 'X'
	if string(supervisor.command.CanonicalPlan) != "canonical plan" {
		t.Fatal("resume command aliased caller plan bytes")
	}
	supervisor.err = errors.New("private")
	if err := invokeNativeDecision(t, control, binding, setupprogressapp.DecisionRetry,
		"018f47ab-9a77-7df0-8f4c-3e934c0a7d42"); err == nil {
		t.Fatal("failed supervisor accepted")
	}
}

func TestPF001BoundCancellationRejectsEveryInvalidAuthorityResponse(t *testing.T) {
	t.Parallel()
	binding, operation := nativeCancellationFixture(t)
	repository := &nativeCancellationRepository{operation: operation}
	cancellation := &boundCancellation{binding: binding, repository: repository}
	var nilRepository *nativeCancellationRepository
	invalidBinding := setupprogressapp.Binding{}
	for name, candidate := range map[string]*boundCancellation{
		"nil":              nil,
		"invalid binding":  {binding: invalidBinding, repository: repository},
		"typed repository": {binding: binding, repository: nilRepository},
	} {
		if err := candidate.RequestCancellation(context.Background()); !errors.Is(err, setupprogressapp.ErrAuthorityIntegrity) {
			t.Fatalf("%s error=%v", name, err)
		}
	}
	//lint:ignore SA1012 Deliberate nil-context boundary attack.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if err := cancellation.RequestCancellation(nil); !errors.Is(err, setupprogressapp.ErrAuthorityIntegrity) {
		t.Fatalf("nil context error=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := cancellation.RequestCancellation(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context error=%v", err)
	}

	foreignID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012399")
	foreignOperation, _ := install.NewOperation(foreignID, binding.PlanDigest())
	foreignPlan, _ := install.BindPlan([]byte("foreign-plan"))
	foreignPlanOperation, _ := install.NewOperation(binding.OperationID(), foreignPlan)
	for name, configure := range map[string]func(){
		"load error":        func() { repository.operation, repository.loadErr = operation, errors.New("private") },
		"nil aggregate":     func() { repository.operation, repository.loadErr = nil, nil },
		"foreign operation": func() { repository.operation, repository.loadErr = foreignOperation, nil },
		"foreign plan":      func() { repository.operation, repository.loadErr = foreignPlanOperation, nil },
	} {
		repository.operation, repository.loadErr = operation, nil
		configure()
		if err := cancellation.RequestCancellation(context.Background()); err == nil ||
			errors.Is(err, setupprogressapp.ErrAuthorityConflict) {
			t.Fatalf("%s error=%v", name, err)
		}
	}
	repository.operation, repository.loadErr = operation, nil
	repository.requestErr = errors.New("private")
	if err := cancellation.RequestCancellation(context.Background()); err == nil {
		t.Fatal("request failure accepted")
	}
	repository.requestErr, repository.invalidIntent = nil, true
	if err := cancellation.RequestCancellation(context.Background()); err == nil {
		t.Fatal("invalid intent accepted")
	}
}

func TestPF001BoundCancellationDispatchesOnlyClosedSetupDecisions(t *testing.T) {
	t.Parallel()
	for _, decision := range []setupprogressapp.Decision{
		setupprogressapp.DecisionCancel, setupprogressapp.DecisionDecline,
	} {
		binding, operation := nativeCancellationFixture(t)
		repository := &nativeCancellationRepository{operation: operation}
		cancellation := &boundCancellation{binding: binding, repository: repository}
		err := invokeNativeDecision(t, cancellation, binding, decision,
			"018f47ab-9a77-7df0-8f4c-3e934c0a7d41")
		if err != nil || repository.requests.Load() != 1 {
			t.Fatalf("decision=%s error=%v calls=%d", decision, err, repository.requests.Load())
		}
	}
	for _, decision := range []setupprogressapp.Decision{
		setupprogressapp.DecisionAccept, setupprogressapp.DecisionRetry,
	} {
		binding, operation := nativeCancellationFixture(t)
		cancellation := &boundCancellation{binding: binding, repository: &nativeCancellationRepository{operation: operation}}
		err := invokeNativeDecision(t, cancellation, binding, decision,
			"018f47ab-9a77-7df0-8f4c-3e934c0a7d42")
		if !setupprogressapp.IsConflictError(err) {
			t.Fatalf("decision=%s error=%v", decision, err)
		}
	}
	var nilCancellation *boundCancellation
	if err := nilCancellation.ApplySetupDecision(context.Background(), setupprogressapp.DecisionCommand{}); !errors.Is(err, setupprogressapp.ErrAuthorityIntegrity) {
		t.Fatalf("nil decision effect error=%v", err)
	}
}

func TestPF001NativeRuntimeFactoryBuildsBoundProgressSetupAndCancellation(t *testing.T) {
	t.Parallel()
	resolved, _ := launcherFixture(t)
	operation, _ := install.NewOperation(resolved.OperationID(), resolved.PlanDigest())
	repository := &nativeCancellationRepository{operation: operation}
	setup := &nativeSetupStub{}
	resources := &nativeResources{plans: &nativePlanCloser{}}
	factory := &nativeRuntimeFactory{
		operations: repository, decisions: nativeMissingJournalProvider{}, clock: fixedResolverClock{},
		ready: &readyStub{err: errors.New("not Ready")}, resources: resources,
		decodePlan: func([]byte) (runtimePlanProjection, error) {
			return runtimeProjection(resolved, agentconfigdomain.AgentHostCodex, 4096), nil
		},
		setup: func(_ context.Context, progress *setupprogressapp.Application) (nativeSetupController, error) {
			if progress == nil || progress.Binding().OperationID() != resolved.OperationID() {
				t.Fatal("setup received unbound progress application")
			}
			return setup, nil
		},
	}
	runtime, err := factory.BuildBootstrapRuntime(context.Background(), agentconfigdomain.AgentHostCodex, resolved)
	if err != nil || runtime.Progress == nil || runtime.Setup != setup || runtime.Cancellation == nil ||
		runtime.Ready == nil || runtime.Lifecycle == nil {
		t.Fatalf("BuildBootstrapRuntime()=%+v,%v", runtime, err)
	}
	status, err := runtime.Progress.Current(context.Background())
	if err != nil || status.OperationID() != resolved.OperationID() || status.Progress().TotalBytes != 4096 {
		t.Fatalf("progress.Current()=%+v,%v", status, err)
	}
	if err := runtime.Setup.OpenSetup(context.Background()); err != nil || setup.opens.Load() != 1 {
		t.Fatalf("OpenSetup() error=%v opens=%d", err, setup.opens.Load())
	}
	if err := runtime.Cancellation.RequestCancellation(context.Background()); err != nil || repository.requests.Load() != 1 {
		t.Fatalf("RequestCancellation() error=%v calls=%d", err, repository.requests.Load())
	}
	if err := runtime.Lifecycle.Close(context.Background()); err != nil || setup.closes.Load() != 1 {
		t.Fatalf("lifecycle.Close() error=%v closes=%d", err, setup.closes.Load())
	}
}

func TestPF001NativeRuntimeFactoryRejectsPlanAndDependencySubstitution(t *testing.T) {
	t.Parallel()
	resolved, _ := launcherFixture(t)
	operation, _ := install.NewOperation(resolved.OperationID(), resolved.PlanDigest())
	base := nativeRuntimeFactory{
		operations: &nativeCancellationRepository{operation: operation},
		decisions:  nativeMissingJournalProvider{}, clock: fixedResolverClock{},
		ready: &readyStub{err: errors.New("not Ready")}, resources: &nativeResources{plans: &nativePlanCloser{}},
		decodePlan: func([]byte) (runtimePlanProjection, error) {
			return runtimeProjection(resolved, agentconfigdomain.AgentHostCodex, 1), nil
		},
		setup: func(context.Context, *setupprogressapp.Application) (nativeSetupController, error) {
			return &nativeSetupStub{}, nil
		},
	}
	var nilFactory *nativeRuntimeFactory
	if _, err := nilFactory.BuildBootstrapRuntime(context.Background(), agentconfigdomain.AgentHostCodex, resolved); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("nil factory error=%v", err)
	}
	//lint:ignore SA1012 Deliberate nil-context boundary attack.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if _, err := base.BuildBootstrapRuntime(nil, agentconfigdomain.AgentHostCodex, resolved); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("nil context error=%v", err)
	}
	if _, err := base.BuildBootstrapRuntime(context.Background(), agentconfigdomain.AgentHost("invalid"), resolved); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("invalid host error=%v", err)
	}
	if _, err := base.BuildBootstrapRuntime(context.Background(), agentconfigdomain.AgentHostCodex, mcpbootstrapapp.ResolvedBootstrap{}); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("invalid resolved error=%v", err)
	}

	for name, mutate := range map[string]func(*nativeRuntimeFactory){
		"operations": func(f *nativeRuntimeFactory) { f.operations = (*nativeCancellationRepository)(nil) },
		"decisions":  func(f *nativeRuntimeFactory) { f.decisions = (*nativeMissingJournalProvider)(nil) },
		"clock":      func(f *nativeRuntimeFactory) { f.clock = nil },
		"Ready":      func(f *nativeRuntimeFactory) { f.ready = (*readyStub)(nil) },
		"resources":  func(f *nativeRuntimeFactory) { f.resources = nil },
		"decoder":    func(f *nativeRuntimeFactory) { f.decodePlan = nil },
		"setup":      func(f *nativeRuntimeFactory) { f.setup = nil },
	} {
		candidate := base
		mutate(&candidate)
		if _, err := candidate.BuildBootstrapRuntime(context.Background(), agentconfigdomain.AgentHostCodex, resolved); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
			t.Fatalf("missing %s error=%v", name, err)
		}
	}

	foreignID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012399")
	foreignDigest, _ := install.BindPlan([]byte("foreign-plan"))
	projections := map[string]runtimePlanProjection{
		"digest":       {digest: foreignDigest, operationID: resolved.OperationID(), installationID: resolved.InstallationID(), host: agentconfigdomain.AgentHostCodex},
		"operation":    {digest: resolved.PlanDigest(), operationID: foreignID, installationID: resolved.InstallationID(), host: agentconfigdomain.AgentHostCodex},
		"installation": {digest: resolved.PlanDigest(), operationID: resolved.OperationID(), installationID: "foreign", host: agentconfigdomain.AgentHostCodex},
		"host":         runtimeProjection(resolved, agentconfigdomain.AgentHostClaude, 1),
		"bytes":        runtimeProjection(resolved, agentconfigdomain.AgentHostCodex, setupprogressapp.MaximumSafeInteger+1),
	}
	for name, projection := range projections {
		candidate := base
		candidate.decodePlan = func([]byte) (runtimePlanProjection, error) { return projection, nil }
		if _, err := candidate.BuildBootstrapRuntime(context.Background(), agentconfigdomain.AgentHostCodex, resolved); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
			t.Fatalf("substituted %s error=%v", name, err)
		}
	}
	decoderFailure := base
	decoderFailure.decodePlan = func([]byte) (runtimePlanProjection, error) {
		return runtimePlanProjection{}, errors.New("private")
	}
	if _, err := decoderFailure.BuildBootstrapRuntime(context.Background(), agentconfigdomain.AgentHostCodex, resolved); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("decoder failure error=%v", err)
	}
	setupFailure := base
	setupFailure.setup = func(context.Context, *setupprogressapp.Application) (nativeSetupController, error) {
		return nil, errors.New("private")
	}
	if _, err := setupFailure.BuildBootstrapRuntime(context.Background(), agentconfigdomain.AgentHostCodex, resolved); err == nil ||
		errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("setup failure error=%v", err)
	}
}

func TestPF001NativeSetupLifecycleResourcesAndPendingReadyFailClosed(t *testing.T) {
	t.Parallel()
	resolved, _ := launcherFixture(t)
	binding, _ := setupprogressapp.NewBinding(resolved.OperationID(), resolved.PlanDigest())
	progress := progressApplication(t, binding)
	controller, err := newNativeSetupController(context.Background(), progress)
	if err == nil && controller != nil {
		if closeError := controller.Close(context.Background()); closeError != nil {
			t.Fatalf("native controller Close() error=%v", closeError)
		}
	} else if browser, browserError := setuphost.NewBrowserOpener(); browserError == nil || browser != nil {
		t.Fatalf("newNativeSetupController()=%T,%v", controller, err)
	}
	if _, err := newNativeSetupController(context.Background(), nil); err == nil {
		t.Fatal("nil progress setup controller succeeded")
	}
	if _, err := decodeRuntimePlan([]byte("not a canonical plan")); err == nil {
		t.Fatal("invalid canonical runtime plan decoded")
	}
	readyProjection := runtimePlanProjection{
		installationID: "019f5f20-1234-7abc-8123-0123456789ab",
		coreEndpoint:   "http://127.0.0.1:38765", credentialPath: filepath.Join(t.TempDir(), "credential"),
	}
	if ready, err := newNativeReadySurface(readyProjection); err != nil || ready == nil {
		t.Fatalf("newNativeReadySurface()=%T,%v", ready, err)
	}
	readyProjection.coreEndpoint = "https://remote.example"
	if ready, err := newNativeReadySurface(readyProjection); err == nil || ready != nil {
		t.Fatalf("remote newNativeReadySurface()=%T,%v", ready, err)
	}
	if surface, err := (pendingReadySurface{}).ReadySurface(context.Background()); err == nil ||
		len(surface.Tools) != 0 || len(surface.Resources) != 0 {
		t.Fatalf("pending Ready surface=%+v,%v", surface, err)
	}

	if err := (*nativeResources)(nil).Close(context.Background()); err != nil {
		t.Fatalf("nil resources close error=%v", err)
	}
	closer := &nativePlanCloser{}
	resources := &nativeResources{plans: closer}
	if err := resources.Close(context.Background()); err != nil || closer.calls.Load() != 1 {
		t.Fatalf("resources close error=%v calls=%d", err, closer.calls.Load())
	}
	if err := resources.Close(context.Background()); err != nil || closer.calls.Load() != 1 {
		t.Fatalf("resources replay error=%v calls=%d", err, closer.calls.Load())
	}
	failingResources := &nativeResources{plans: &nativePlanCloser{err: errors.New("private")}}
	if err := failingResources.Close(context.Background()); err == nil {
		t.Fatal("failing plan closer was hidden")
	}
	setup := &nativeSetupStub{closeErr: errors.New("setup close")}
	lifecycle := &nativeRuntimeLifecycle{
		controller: setup,
		resources:  &nativeResources{plans: &nativePlanCloser{err: errors.New("plan close")}},
	}
	if err := lifecycle.Close(context.Background()); err == nil || setup.closes.Load() != 1 {
		t.Fatalf("joined lifecycle error=%v closes=%d", err, setup.closes.Load())
	}
	var nilLifecycle *nativeRuntimeLifecycle
	if err := nilLifecycle.Close(context.Background()); err == nil {
		t.Fatal("nil lifecycle close succeeded")
	}
	//lint:ignore SA1012 Deliberate nil-context lifecycle attack.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if err := (&nativeRuntimeLifecycle{}).Close(nil); err == nil {
		t.Fatal("nil-context lifecycle close succeeded")
	}
	if err := (&nativeRuntimeLifecycle{}).Close(context.Background()); err != nil {
		t.Fatalf("empty lifecycle close error=%v", err)
	}
}

func TestPF001NativePlatformJournalProviderConstructsWithoutCreatingAuthority(t *testing.T) {
	t.Parallel()
	locator, err := bootstrapadapter.NewOperationLocator(filepath.Join(t.TempDir(), "native-journal"))
	if err != nil {
		t.Fatal(err)
	}
	provider, err := newPlatformJournalProvider(locator)
	if err != nil || provider == nil {
		t.Fatalf("newPlatformJournalProvider()=%T,%v", provider, err)
	}
}

func TestPF001NativeNilClassificationCoversEveryNilableKind(t *testing.T) {
	t.Parallel()
	var pointer *nativeSetupStub
	var mapping map[string]string
	var slice []string
	var function func()
	var channel chan struct{}
	for _, value := range []any{nil, pointer, mapping, slice, function, channel} {
		if !nilAny(value) {
			t.Fatalf("nilAny(%T)=false", value)
		}
	}
	for _, value := range []any{struct{}{}, 1, "value", make(chan struct{})} {
		if nilAny(value) {
			t.Fatalf("nilAny(%T)=true", value)
		}
	}
}

func nativeTestRoots(root string) NativeRoots {
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	return NativeRoots{
		OperationState: filepath.Join(root, "operation"), BootstrapPointer: filepath.Join(root, "pointer"),
		SetupDecisions: filepath.Join(root, "decisions"), PreparationState: filepath.Join(root, "preparation"),
		RuntimeState: filepath.Join(root, "runtime"), ReleaseAnchorState: filepath.Join(root, "release-anchor"),
		CanonicalPlans: filepath.Join(root, "plans"),
	}
}

type nativeMissingJournalProvider struct{}

func (nativeMissingJournalProvider) JournalFor(ctx context.Context, operationID install.OperationID) (journalport.Journal, error) {
	owner, err := install.BindOwner("native-test-machine", "native-test-principal")
	if err != nil {
		return nil, err
	}
	keys, err := bootstrapadapter.NewMemoryOperationKeySource(bytes.NewReader(bytes.Repeat([]byte{0x5a}, 64)))
	if err != nil {
		return nil, err
	}
	keyRef, err := keys.Ensure(ctx, operationID, owner)
	if err != nil {
		return nil, err
	}
	anchors, err := bootstrapadapter.NewMemoryRollbackAnchorStore(keys)
	if err != nil {
		return nil, err
	}
	return bootstrapadapter.NewAnchoredJournal(nativeMissingJournal{}, anchors, keyRef, operationID, owner)
}

type nativePlainJournalProvider struct{}

func (nativePlainJournalProvider) JournalFor(context.Context, install.OperationID) (journalport.Journal, error) {
	return nativeMissingJournal{}, nil
}

type nativeMissingJournal struct{}

func (nativeMissingJournal) Append(context.Context, uint64, journalport.Snapshot) error {
	return journalport.ErrConflict
}

func (nativeMissingJournal) LoadLatest(context.Context) (journalport.Snapshot, error) {
	return journalport.Snapshot{}, journalport.ErrNotFound
}

func (nativeMissingJournal) ConfirmDurable(context.Context, string, uint64) error {
	return journalport.ErrNotFound
}

func nativeCancellationFixture(t testing.TB) (setupprogressapp.Binding, *install.Operation) {
	t.Helper()
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	digest, _ := install.BindPlan([]byte("canonical-plan"))
	binding, err := setupprogressapp.NewBinding(operationID, digest)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := install.NewOperation(operationID, digest)
	if err != nil {
		t.Fatal(err)
	}
	return binding, operation
}

type nativeCancellationRepository struct {
	operation     *install.Operation
	loadErr       error
	requestErr    error
	invalidIntent bool
	requests      atomic.Int32
	last          installapp.CancellationRequest
}

type nativeSupervisorStub struct {
	command installapp.InstallCommand
	calls   atomic.Int32
	err     error
}

func (s *nativeSupervisorStub) EnsureRunning(_ context.Context, command installapp.InstallCommand) error {
	s.command = command
	s.calls.Add(1)
	return s.err
}

func (r *nativeCancellationRepository) Load(context.Context, install.OperationID) (*install.Operation, error) {
	return r.operation, r.loadErr
}

func (r *nativeCancellationRepository) Request(
	_ context.Context,
	request installapp.CancellationRequest,
) (installapp.CancellationIntent, error) {
	r.requests.Add(1)
	r.last = request
	if r.requestErr != nil || r.invalidIntent {
		return installapp.CancellationIntent{}, r.requestErr
	}
	return installapp.NewRequestedCancellationIntentForAdapter(request, request.ObservedAggregateVersion+1)
}

func invokeNativeDecision(
	t testing.TB,
	effect *boundCancellation,
	binding setupprogressapp.Binding,
	decision setupprogressapp.Decision,
	key string,
) error {
	t.Helper()
	snapshot, err := setupprogressapp.NewSnapshot(setupprogressapp.SnapshotInput{
		Sequence: 1, OperationID: binding.OperationID(), PlanDigest: binding.PlanDigest(),
		State: setupprogressapp.StateRunning, Phase: setupprogressapp.PhaseVerifyHost,
		MessageKey: setupprogressapp.MessageVerifying,
		Progress:   setupprogressapp.Progress{TotalStages: 14}, SafeAction: setupprogressapp.ActionCancel,
	})
	if err != nil {
		t.Fatal(err)
	}
	authority := &nativeDecisionForwarder{snapshot: snapshot, effect: effect}
	application, err := setupprogressapp.NewApplication(binding, authority, authority)
	if err != nil {
		t.Fatal(err)
	}
	_, err = application.Decide(context.Background(), setupprogressapp.DecisionInput{
		PlanDigest: binding.PlanDigest().String(), Decision: decision, IdempotencyKey: key,
	})
	return err
}

type nativeDecisionForwarder struct {
	snapshot setupprogressapp.Snapshot
	effect   *boundCancellation
}

func (a *nativeDecisionForwarder) CurrentSnapshot(context.Context, setupprogressapp.Binding) (setupprogressapp.Snapshot, error) {
	return a.snapshot, nil
}

func (a *nativeDecisionForwarder) WaitSnapshotAfter(context.Context, setupprogressapp.Binding, uint64) (setupprogressapp.Snapshot, error) {
	return a.snapshot, nil
}

func (a *nativeDecisionForwarder) ApplyDecision(
	ctx context.Context,
	command setupprogressapp.DecisionCommand,
) (setupprogressapp.DecisionReceipt, error) {
	if err := a.effect.ApplySetupDecision(ctx, command); err != nil {
		return setupprogressapp.DecisionReceipt{}, err
	}
	return setupprogressapp.NewDecisionReceipt(command.IdempotencyKey(), command.Decision(), a.snapshot)
}

type nativeSetupStub struct {
	opens    atomic.Int32
	closes   atomic.Int32
	openErr  error
	closeErr error
}

func (s *nativeSetupStub) OpenSetup(context.Context) error {
	s.opens.Add(1)
	return s.openErr
}

func (s *nativeSetupStub) Close(context.Context) error {
	s.closes.Add(1)
	return s.closeErr
}

type nativePlanCloser struct {
	calls atomic.Int32
	err   error
}

func (c *nativePlanCloser) Close() error {
	c.calls.Add(1)
	return c.err
}

func runtimeProjection(
	resolved mcpbootstrapapp.ResolvedBootstrap,
	host agentconfigdomain.AgentHost,
	total uint64,
) runtimePlanProjection {
	return runtimePlanProjection{
		digest: resolved.PlanDigest(), operationID: resolved.OperationID(),
		installationID: resolved.InstallationID(), host: host, totalBytes: total,
	}
}

var _ mcpbootstrap.ReadySurfaceProvider = pendingReadySurface{}
