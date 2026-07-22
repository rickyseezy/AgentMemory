// Package launcher is the only composition layer for the native launcher.
package launcher

import (
	"context"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/mcpbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpbootstrapapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/setupprogressapp"
	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
)

const closeTimeout = 5 * time.Second

// MCPRunner serves one host MCP connection.
type MCPRunner interface {
	Run(context.Context, mcp.Transport) error
}

// MCPFactory resolves protected bootstrap authority and builds one runner.
type MCPFactory interface {
	BuildMCP(context.Context, agentconfigdomain.AgentHost) (MCPRunner, error)
}

// InstallationResumeFactory is the native per-user login continuation entry.
type InstallationResumeFactory interface {
	ResumeInstallation(context.Context, string) error
}

// BootstrapInitializer creates the durable first-start authority from the
// verified packaged release. It is called only when no protected pointer exists.
type BootstrapInitializer interface {
	EnsureBootstrap(context.Context, agentconfigdomain.AgentHost) error
}

// RuntimeLifecycle closes process-owned setup listeners and phase resources.
type RuntimeLifecycle interface {
	Close(context.Context) error
}

// BootstrapRuntime contains only the already-composed capabilities required by
// the PF-001 bootstrap adapter. It cannot be valid without a Ready handoff.
type BootstrapRuntime struct {
	Progress     *setupprogressapp.Application
	Setup        mcpbootstrapapp.SetupPort
	Cancellation mcpbootstrapapp.CancellationPort
	Ready        mcpbootstrap.ReadySurfaceProvider
	Lifecycle    RuntimeLifecycle
}

// BootstrapRuntimeFactory constructs concrete phase/status/setup capabilities
// from one authenticated resolver result.
type BootstrapRuntimeFactory interface {
	BuildBootstrapRuntime(
		context.Context,
		agentconfigdomain.AgentHost,
		mcpbootstrapapp.ResolvedBootstrap,
	) (BootstrapRuntime, error)
}

// ProductSessionFactory constructs PF-005 only when durable state is already Ready.
// A false result preserves the PF-001 setup surface without guessing readiness.
type ProductSessionFactory interface {
	BuildReadySession(
		context.Context,
		agentconfigdomain.AgentHost,
		mcpbootstrapapp.ResolvedBootstrap,
	) (MCPRunner, bool, error)
}

// bootstrapSurface is the fully authenticated application/Ready/lifecycle
// unit consumed by one MCP server. Keeping it transport-free lets the signed
// portable package bridge adopt the native surface without proxying stdio.
type bootstrapSurface struct {
	application mcpbootstrap.BootstrapApplication
	ready       mcpbootstrap.ReadySurfaceProvider
	lifecycle   RuntimeLifecycle
	session     MCPRunner
}

func (s bootstrapSurface) valid() bool {
	if !nilCapability(s.session) {
		return nilCapability(s.application) && nilCapability(s.ready)
	}
	return !nilCapability(s.application) && !nilCapability(s.ready) && !nilCapability(s.lifecycle)
}

// Factory is the production PF-001 MCP composition root.
type Factory struct {
	resolver    mcpbootstrapapp.BootstrapResolver
	runtime     BootstrapRuntimeFactory
	initializer BootstrapInitializer
	sessions    ProductSessionFactory
}

// bindProductSessions is called only by the native production composition before publication.
func (f *Factory) bindProductSessions(sessions ProductSessionFactory) error {
	if f == nil || nilCapability(sessions) || !nilCapability(f.sessions) {
		return mcpbootstrapapp.ErrBootstrapIntegrity
	}
	f.sessions = sessions
	return nil
}

// NewFactory refuses a partial composition.
func NewFactory(
	resolver mcpbootstrapapp.BootstrapResolver,
	runtime BootstrapRuntimeFactory,
) (*Factory, error) {
	if nilCapability(resolver) || nilCapability(runtime) {
		return nil, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	return &Factory{resolver: resolver, runtime: runtime}, nil
}

// NewFirstStartFactory constructs the production path that can initialize a
// pristine host and then immediately resolve the resulting protected state.
func NewFirstStartFactory(
	resolver mcpbootstrapapp.BootstrapResolver,
	runtime BootstrapRuntimeFactory,
	initializer BootstrapInitializer,
) (*Factory, error) {
	if nilCapability(initializer) {
		return nil, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	factory, err := NewFactory(resolver, runtime)
	if err != nil {
		return nil, err
	}
	factory.initializer = initializer
	return factory, nil
}

// BuildMCP authenticates host-specific protected state before constructing any
// inbound MCP surface.
func (f *Factory) BuildMCP(
	ctx context.Context,
	host agentconfigdomain.AgentHost,
) (MCPRunner, error) {
	surface, err := f.buildBootstrapSurface(ctx, host)
	if err != nil {
		return nil, err
	}
	return newManagedRunner(ctx, surface)
}

func (f *Factory) buildBootstrapSurface(
	ctx context.Context,
	host agentconfigdomain.AgentHost,
) (bootstrapSurface, error) {
	if f == nil || ctx == nil || !host.Valid() || nilCapability(f.resolver) || nilCapability(f.runtime) {
		return bootstrapSurface{}, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	if err := ctx.Err(); err != nil {
		return bootstrapSurface{}, err
	}
	resolved, err := f.resolver.ResolveBootstrap(ctx, host)
	if errors.Is(err, mcpbootstrapapp.ErrBootstrapNotFound) && !nilCapability(f.initializer) {
		if initializeError := f.initializer.EnsureBootstrap(ctx, host); initializeError != nil {
			return bootstrapSurface{}, mcpbootstrapapp.ErrBootstrapUnavailable
		}
		resolved, err = f.resolver.ResolveBootstrap(ctx, host)
	}
	if err != nil {
		return bootstrapSurface{}, err
	}
	if !resolved.Valid() {
		return bootstrapSurface{}, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	if !nilCapability(f.sessions) {
		session, ready, sessionError := f.sessions.BuildReadySession(ctx, host, resolved)
		if sessionError != nil {
			return bootstrapSurface{}, mcpbootstrapapp.ErrBootstrapUnavailable
		}
		if ready {
			if nilCapability(session) {
				return bootstrapSurface{}, mcpbootstrapapp.ErrBootstrapIntegrity
			}
			return bootstrapSurface{session: session, lifecycle: sessionLifecycle(session)}, nil
		}
		if !nilCapability(session) {
			return bootstrapSurface{}, mcpbootstrapapp.ErrBootstrapIntegrity
		}
	}
	runtime, err := f.runtime.BuildBootstrapRuntime(ctx, host, resolved)
	if err != nil {
		return bootstrapSurface{}, mcpbootstrapapp.ErrBootstrapUnavailable
	}
	if runtime.Progress == nil || runtime.Progress.Binding().OperationID() != resolved.OperationID() ||
		!runtime.Progress.Binding().PlanDigest().Equal(resolved.PlanDigest()) ||
		nilCapability(runtime.Setup) || nilCapability(runtime.Cancellation) ||
		nilCapability(runtime.Ready) || nilCapability(runtime.Lifecycle) {
		_ = closeRuntime(ctx, runtime.Lifecycle)
		return bootstrapSurface{}, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	application, err := mcpbootstrapapp.New(
		resolved.InstallationID(), runtime.Progress, runtime.Setup, runtime.Cancellation,
	)
	if err != nil {
		_ = closeRuntime(ctx, runtime.Lifecycle)
		return bootstrapSurface{}, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	return bootstrapSurface{application: application, ready: runtime.Ready, lifecycle: runtime.Lifecycle}, nil
}

func sessionLifecycle(session MCPRunner) RuntimeLifecycle {
	if lifecycle, ok := session.(RuntimeLifecycle); ok && !nilCapability(lifecycle) {
		return lifecycle
	}
	return nil
}

func newManagedRunner(ctx context.Context, surface bootstrapSurface) (MCPRunner, error) {
	if ctx == nil || !surface.valid() {
		_ = closeRuntime(context.Background(), surface.lifecycle) //nolint:contextcheck // No caller context exists at this rejected boundary; owner=launcher expiry=2027-07-15.
		return nil, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	if !nilCapability(surface.session) {
		if nilCapability(surface.lifecycle) {
			return surface.session, nil
		}
		return &managedSessionRunner{session: surface.session, lifecycle: surface.lifecycle}, nil
	}
	server, err := mcpbootstrap.NewServer(surface.application, surface.ready)
	if err != nil {
		_ = closeRuntime(ctx, surface.lifecycle)
		return nil, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	return &managedRunner{server: server, lifecycle: surface.lifecycle}, nil
}

// managedSessionRunner transfers process-owned native resources to one Ready
// MCP session and closes them exactly after its raw stdio lifecycle ends.
type managedSessionRunner struct {
	session   MCPRunner
	lifecycle RuntimeLifecycle
}

func (r *managedSessionRunner) Run(ctx context.Context, transport mcp.Transport) error {
	if r == nil || ctx == nil || nilCapability(r.session) || nilCapability(r.lifecycle) {
		return mcpbootstrapapp.ErrBootstrapIntegrity
	}
	runError := r.session.Run(ctx, transport)
	return sessionCloseResult(ctx, r.lifecycle, runError)
}

func (r *managedSessionRunner) RunHostSession(
	ctx context.Context,
	workingDirectory string,
	input io.Reader,
	output io.Writer,
	diagnostics io.Writer,
) error {
	if r == nil || ctx == nil || nilCapability(r.session) || nilCapability(r.lifecycle) {
		return mcpbootstrapapp.ErrBootstrapIntegrity
	}
	host, ok := r.session.(HostSessionRunner)
	if !ok || nilCapability(host) {
		_ = closeRuntime(ctx, r.lifecycle)
		return mcpbootstrapapp.ErrBootstrapIntegrity
	}
	runError := host.RunHostSession(ctx, workingDirectory, input, output, diagnostics)
	return sessionCloseResult(ctx, r.lifecycle, runError)
}

func sessionCloseResult(ctx context.Context, lifecycle RuntimeLifecycle, runError error) error {
	closeError := closeRuntime(ctx, lifecycle)
	if runError != nil {
		return runError
	}
	if closeError != nil {
		return mcpbootstrapapp.ErrBootstrapUnavailable
	}
	return nil
}

var _ MCPRunner = (*managedSessionRunner)(nil)
var _ HostSessionRunner = (*managedSessionRunner)(nil)

type managedRunner struct {
	server    *mcpbootstrap.Server
	lifecycle RuntimeLifecycle
}

func (r *managedRunner) Run(ctx context.Context, transport mcp.Transport) error {
	if r == nil || ctx == nil || r.server == nil || nilCapability(r.lifecycle) || nilCapability(transport) {
		return mcpbootstrapapp.ErrBootstrapIntegrity
	}
	runError := r.server.Run(ctx, transport)
	closeError := closeRuntime(ctx, r.lifecycle)
	if runError != nil {
		return runError
	}
	if closeError != nil {
		return mcpbootstrapapp.ErrBootstrapUnavailable
	}
	return nil
}

func closeRuntime(parent context.Context, lifecycle RuntimeLifecycle) error {
	if nilCapability(lifecycle) {
		return nil
	}
	closeContext, cancel := context.WithTimeout(context.WithoutCancel(parent), closeTimeout)
	defer cancel()
	if err := lifecycle.Close(closeContext); err != nil {
		return errors.New("launcher runtime close failed")
	}
	return nil
}

func nilCapability(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Every non-nilable concrete kind is a valid capability.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid:
		return true
	default:
		return false
	}
}

var _ MCPFactory = (*Factory)(nil)
