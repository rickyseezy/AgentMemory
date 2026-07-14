package launcher

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/mcpbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpbootstrapapp"
	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/setupprogressapp"
	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/installplan"
)

func TestPF001LauncherCompositionBuildsAndRunsOfficialBootstrapMCP(t *testing.T) {
	t.Parallel()
	resolved, runtime := launcherFixture(t)
	resolver := &resolverStub{resolved: resolved}
	runtimeFactory := &runtimeFactoryStub{runtime: runtime}
	factory, err := NewFactory(resolver, runtimeFactory)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := factory.BuildMCP(context.Background(), agentconfigdomain.AgentHostCodex)
	if err != nil || runner == nil || runtimeFactory.host != agentconfigdomain.AgentHostCodex ||
		runtimeFactory.resolved.OperationID() != resolved.OperationID() {
		t.Fatalf("BuildMCP()=%T,%v host=%q", runner, err, runtimeFactory.host)
	}

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx, serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "launcher-test", Version: "1"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	listed, err := session.ListTools(ctx, nil)
	if err != nil || len(listed.Tools) != 3 {
		t.Fatalf("ListTools()=%+v,%v", listed, err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case runErr := <-done:
		if runErr != nil {
			t.Fatalf("Run() error=%v", runErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("managed MCP runner did not stop")
	}
	if runtime.Lifecycle.(*lifecycleStub).calls.Load() != 1 {
		t.Fatal("runtime lifecycle was not closed exactly once")
	}
}

func TestPF001LauncherFactoryRejectsIncompleteOrSubstitutedComposition(t *testing.T) {
	t.Parallel()
	resolved, runtime := launcherFixture(t)
	var nilResolver *resolverStub
	var nilRuntime *runtimeFactoryStub
	for name, dependencies := range map[string]struct {
		resolver mcpbootstrapapp.BootstrapResolver
		runtime  BootstrapRuntimeFactory
	}{
		"nil":            {},
		"typed resolver": {resolver: nilResolver, runtime: &runtimeFactoryStub{}},
		"typed runtime":  {resolver: &resolverStub{}, runtime: nilRuntime},
	} {
		if _, err := NewFactory(dependencies.resolver, dependencies.runtime); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
			t.Fatalf("%s NewFactory() error=%v", name, err)
		}
	}

	foreignOperation, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012399")
	foreignBinding, _ := setupprogressapp.NewBinding(foreignOperation, resolved.PlanDigest())
	foreignProgress := progressApplication(t, foreignBinding)
	typedNilSetup := (*setupStub)(nil)
	typedNilCancellation := (*cancellationStub)(nil)
	typedNilReady := (*readyStub)(nil)
	typedNilLifecycle := (*lifecycleStub)(nil)
	tests := []struct {
		name     string
		resolver *resolverStub
		runtime  *runtimeFactoryStub
		want     error
	}{
		{name: "resolver failure", resolver: &resolverStub{err: mcpbootstrapapp.ErrBootstrapNotFound}, runtime: &runtimeFactoryStub{}, want: mcpbootstrapapp.ErrBootstrapNotFound},
		{name: "invalid resolved", resolver: &resolverStub{}, runtime: &runtimeFactoryStub{}, want: mcpbootstrapapp.ErrBootstrapIntegrity},
		{name: "runtime failure", resolver: &resolverStub{resolved: resolved}, runtime: &runtimeFactoryStub{err: errors.New("private")}, want: mcpbootstrapapp.ErrBootstrapUnavailable},
		{name: "foreign progress", resolver: &resolverStub{resolved: resolved}, runtime: &runtimeFactoryStub{runtime: replaceProgress(runtime, foreignProgress)}, want: mcpbootstrapapp.ErrBootstrapIntegrity},
		{name: "nil progress", resolver: &resolverStub{resolved: resolved}, runtime: &runtimeFactoryStub{runtime: replaceProgress(runtime, nil)}, want: mcpbootstrapapp.ErrBootstrapIntegrity},
		{name: "typed setup", resolver: &resolverStub{resolved: resolved}, runtime: &runtimeFactoryStub{runtime: replaceSetup(runtime, typedNilSetup)}, want: mcpbootstrapapp.ErrBootstrapIntegrity},
		{name: "typed cancellation", resolver: &resolverStub{resolved: resolved}, runtime: &runtimeFactoryStub{runtime: replaceCancellation(runtime, typedNilCancellation)}, want: mcpbootstrapapp.ErrBootstrapIntegrity},
		{name: "typed Ready", resolver: &resolverStub{resolved: resolved}, runtime: &runtimeFactoryStub{runtime: replaceReady(runtime, typedNilReady)}, want: mcpbootstrapapp.ErrBootstrapIntegrity},
		{name: "typed lifecycle", resolver: &resolverStub{resolved: resolved}, runtime: &runtimeFactoryStub{runtime: replaceLifecycle(runtime, typedNilLifecycle)}, want: mcpbootstrapapp.ErrBootstrapIntegrity},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			factory, err := NewFactory(test.resolver, test.runtime)
			if err != nil {
				t.Fatal(err)
			}
			_, err = factory.BuildMCP(context.Background(), agentconfigdomain.AgentHostCodex)
			if !errors.Is(err, test.want) {
				t.Fatalf("BuildMCP() error=%v want=%v", err, test.want)
			}
		})
	}
}

func TestPF001LauncherFactoryValidatesCallsAndSanitizesLifecycleFailure(t *testing.T) {
	t.Parallel()
	resolved, runtime := launcherFixture(t)
	factory, _ := NewFactory(&resolverStub{resolved: resolved}, &runtimeFactoryStub{runtime: runtime})
	var nilFactory *Factory
	if _, err := nilFactory.BuildMCP(context.Background(), agentconfigdomain.AgentHostCodex); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("nil factory error=%v", err)
	}
	//lint:ignore SA1012 Deliberate nil-context boundary test.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if _, err := factory.BuildMCP(nil, agentconfigdomain.AgentHostCodex); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("nil context error=%v", err)
	}
	if _, err := factory.BuildMCP(context.Background(), agentconfigdomain.AgentHost("unknown")); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("invalid host error=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := factory.BuildMCP(cancelled, agentconfigdomain.AgentHostCodex); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context error=%v", err)
	}

	badLifecycle := &lifecycleStub{err: errors.New("/private/path secret")}
	runtime.Lifecycle = badLifecycle
	factory, _ = NewFactory(&resolverStub{resolved: resolved}, &runtimeFactoryStub{runtime: runtime})
	runner, err := factory.BuildMCP(context.Background(), agentconfigdomain.AgentHostCodex)
	if err != nil {
		t.Fatal(err)
	}
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx, serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "close-test", Version: "1"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = session.Close()
	if runErr := <-done; !errors.Is(runErr, mcpbootstrapapp.ErrBootstrapUnavailable) {
		t.Fatalf("lifecycle failure error=%v", runErr)
	}
	if badLifecycle.calls.Load() != 1 {
		t.Fatalf("lifecycle close calls=%d", badLifecycle.calls.Load())
	}

	managed := &managedRunner{}
	if err := managed.Run(context.Background(), nil); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("invalid managed runner error=%v", err)
	}
	if closeRuntime(context.Background(), nil) != nil {
		t.Fatal("nil lifecycle close failed")
	}
	if nilCapability(struct{}{}) || nilCapability(1) || !nilCapability(nil) {
		t.Fatal("nilCapability classification failed")
	}
}

func TestPF001ProtectedResolverCompositionRequiresEveryAuthority(t *testing.T) {
	t.Parallel()
	journals := &resolverJournalProviderStub{}
	plans := &resolverPlanRepositoryStub{}
	operations := &resolverOperationRepositoryStub{}
	clock := fixedResolverClock{}
	resolver, err := NewProtectedResolver(journals, plans, operations, clock)
	if err != nil || resolver == nil {
		t.Fatalf("NewProtectedResolver()=%T,%v", resolver, err)
	}
	for name, build := range map[string]func() error{
		"journals": func() error {
			_, err := NewProtectedResolver(nil, plans, operations, clock)
			return err
		},
		"plans": func() error {
			_, err := NewProtectedResolver(journals, nil, operations, clock)
			return err
		},
		"operations": func() error {
			_, err := NewProtectedResolver(journals, plans, nil, clock)
			return err
		},
		"clock": func() error {
			_, err := NewProtectedResolver(journals, plans, operations, nil)
			return err
		},
	} {
		if err := build(); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
			t.Fatalf("missing %s error=%v", name, err)
		}
	}
}

func launcherFixture(t testing.TB) (mcpbootstrapapp.ResolvedBootstrap, BootstrapRuntime) {
	t.Helper()
	canonical := []byte("canonical plan")
	digest, _ := install.BindPlan(canonical)
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	resolved, err := mcpbootstrapapp.NewResolvedBootstrap(
		"019f5f20-1234-7abc-8123-0123456789ab", operationID, digest, canonical,
	)
	if err != nil {
		t.Fatal(err)
	}
	binding, _ := setupprogressapp.NewBinding(operationID, digest)
	return resolved, BootstrapRuntime{
		Progress: progressApplication(t, binding), Setup: &setupStub{},
		Cancellation: &cancellationStub{}, Ready: &readyStub{err: errors.New("not Ready")},
		Lifecycle: &lifecycleStub{},
	}
}

func progressApplication(t testing.TB, binding setupprogressapp.Binding) *setupprogressapp.Application {
	t.Helper()
	snapshot, err := setupprogressapp.NewSnapshot(setupprogressapp.SnapshotInput{
		Sequence: 1, OperationID: binding.OperationID(), PlanDigest: binding.PlanDigest(),
		State: setupprogressapp.StateRunning, Phase: setupprogressapp.PhaseVerifyHost,
		MessageKey: setupprogressapp.MessageVerifying,
		Progress:   setupprogressapp.Progress{TotalStages: 14},
		SafeAction: setupprogressapp.ActionCancel,
	})
	if err != nil {
		t.Fatal(err)
	}
	authority := &progressStub{snapshot: snapshot}
	application, err := setupprogressapp.NewApplication(binding, authority, authority)
	if err != nil {
		t.Fatal(err)
	}
	return application
}

type resolverStub struct {
	resolved mcpbootstrapapp.ResolvedBootstrap
	err      error
}

func (r *resolverStub) ResolveBootstrap(context.Context, agentconfigdomain.AgentHost) (mcpbootstrapapp.ResolvedBootstrap, error) {
	return r.resolved, r.err
}

type runtimeFactoryStub struct {
	runtime  BootstrapRuntime
	err      error
	host     agentconfigdomain.AgentHost
	resolved mcpbootstrapapp.ResolvedBootstrap
}

func (f *runtimeFactoryStub) BuildBootstrapRuntime(
	_ context.Context,
	host agentconfigdomain.AgentHost,
	resolved mcpbootstrapapp.ResolvedBootstrap,
) (BootstrapRuntime, error) {
	f.host, f.resolved = host, resolved
	return f.runtime, f.err
}

type progressStub struct{ snapshot setupprogressapp.Snapshot }

func (p *progressStub) CurrentSnapshot(context.Context, setupprogressapp.Binding) (setupprogressapp.Snapshot, error) {
	return p.snapshot, nil
}

func (p *progressStub) WaitSnapshotAfter(ctx context.Context, _ setupprogressapp.Binding, _ uint64) (setupprogressapp.Snapshot, error) {
	<-ctx.Done()
	return setupprogressapp.Snapshot{}, ctx.Err()
}

func (p *progressStub) ApplyDecision(context.Context, setupprogressapp.DecisionCommand) (setupprogressapp.DecisionReceipt, error) {
	return setupprogressapp.DecisionReceipt{}, setupprogressapp.ErrAuthorityConflict
}

type setupStub struct{}

func (*setupStub) OpenSetup(context.Context) error { return nil }

type cancellationStub struct{}

func (*cancellationStub) RequestCancellation(context.Context) error { return nil }

type readyStub struct{ err error }

func (r *readyStub) ReadySurface(context.Context) (mcpbootstrap.ReadySurface, error) {
	return mcpbootstrap.ReadySurface{}, r.err
}

type lifecycleStub struct {
	calls atomic.Int32
	err   error
}

type resolverJournalProviderStub struct{}

func (*resolverJournalProviderStub) JournalFor(context.Context, install.OperationID) (journalport.Journal, error) {
	return nil, errors.New("not called during composition")
}

type resolverPlanRepositoryStub struct{}

func (*resolverPlanRepositoryStub) Load(context.Context, install.PlanDigest) (installplan.Plan, error) {
	return installplan.Plan{}, errors.New("not called during composition")
}

type resolverOperationRepositoryStub struct{}

func (*resolverOperationRepositoryStub) Load(context.Context, install.OperationID) (*install.Operation, error) {
	return nil, errors.New("not called during composition")
}

type fixedResolverClock struct{}

func (fixedResolverClock) Now() time.Time {
	return time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
}

func (l *lifecycleStub) Close(context.Context) error {
	l.calls.Add(1)
	return l.err
}

func replaceProgress(runtime BootstrapRuntime, progress *setupprogressapp.Application) BootstrapRuntime {
	runtime.Progress = progress
	return runtime
}

func replaceSetup(runtime BootstrapRuntime, setup mcpbootstrapapp.SetupPort) BootstrapRuntime {
	runtime.Setup = setup
	return runtime
}

func replaceCancellation(runtime BootstrapRuntime, cancellation mcpbootstrapapp.CancellationPort) BootstrapRuntime {
	runtime.Cancellation = cancellation
	return runtime
}

func replaceReady(runtime BootstrapRuntime, ready mcpbootstrap.ReadySurfaceProvider) BootstrapRuntime {
	runtime.Ready = ready
	return runtime
}

func replaceLifecycle(runtime BootstrapRuntime, lifecycle RuntimeLifecycle) BootstrapRuntime {
	runtime.Lifecycle = lifecycle
	return runtime
}
