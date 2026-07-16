package main

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpbootstrapapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/infrastructure/launcher"
)

func TestPF001PortableCommandRunsOnlyExactHostScopedMCP(t *testing.T) {
	t.Parallel()
	runner := &runnerStub{}
	factory := &factoryStub{runner: runner}
	transport := &transportStub{}
	var stderr bytes.Buffer
	code := run(
		context.Background(), []string{"mcp", "--agent", "gemini"}, &stderr, factory, transport,
	)
	if code != exitSuccess || stderr.Len() != 0 || factory.host != agentconfig.AgentHostGemini ||
		runner.transport != transport || runner.calls != 1 {
		t.Fatalf("run() = %d stderr=%q host=%q calls=%d", code, stderr.String(), factory.host, runner.calls)
	}
	if _, ok := newProductionFactory().(*launcher.PortableFactory); !ok {
		t.Fatal("production factory is not the portable composition")
	}
}

func TestPF001PortableExitCodesAreStable(t *testing.T) {
	t.Parallel()
	if exitSuccess != 0 || exitUsage != 2 || exitBootstrapIntegrity != 4 ||
		exitBootstrapUnavailable != 5 || exitMCPUnavailable != 6 {
		t.Fatal("portable process exit-code contract changed")
	}
}

func TestPF001PortableCommandRejectsArgumentsAndSanitizesFailures(t *testing.T) {
	t.Parallel()
	for name, fixture := range map[string]struct {
		args      []string
		factory   *factoryStub
		transport mcp.Transport
		wantCode  int
		wantError string
	}{
		"arguments":   {args: []string{"mcp"}, factory: &factoryStub{}, transport: &transportStub{}, wantCode: exitUsage, wantError: "AM_USAGE\n"},
		"host":        {args: []string{"mcp", "--agent", "unknown"}, factory: &factoryStub{}, transport: &transportStub{}, wantCode: exitUsage, wantError: "AM_USAGE\n"},
		"integrity":   {args: []string{"mcp", "--agent", "codex"}, factory: &factoryStub{err: mcpbootstrapapp.ErrBootstrapIntegrity}, transport: &transportStub{}, wantCode: exitBootstrapIntegrity, wantError: "AM_BOOTSTRAP_INTEGRITY\n"},
		"unavailable": {args: []string{"mcp", "--agent", "claude"}, factory: &factoryStub{err: errors.New("private path")}, transport: &transportStub{}, wantCode: exitBootstrapUnavailable, wantError: "AM_BOOTSTRAP_UNAVAILABLE\n"},
		"nil runner":  {args: []string{"mcp", "--agent", "gemini"}, factory: &factoryStub{}, transport: &transportStub{}, wantCode: exitBootstrapIntegrity, wantError: "AM_BOOTSTRAP_INTEGRITY\n"},
		"run":         {args: []string{"mcp", "--agent", "custom"}, factory: &factoryStub{runner: &runnerStub{err: errors.New("secret")}}, transport: &transportStub{}, wantCode: exitMCPUnavailable, wantError: "AM_MCP_UNAVAILABLE\n"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var stderr bytes.Buffer
			if code := run(context.Background(), fixture.args, &stderr, fixture.factory, fixture.transport); code != fixture.wantCode ||
				stderr.String() != fixture.wantError {
				t.Fatalf("run() = %d stderr=%q", code, stderr.String())
			}
		})
	}
}

func TestPF001PortableCommandHandlesCancellationAndInvalidCapabilities(t *testing.T) {
	t.Parallel()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	var stderr bytes.Buffer
	code := run(cancelled, []string{"mcp", "--agent", "codex"}, &stderr,
		&factoryStub{runner: &runnerStub{err: context.Canceled}}, &transportStub{})
	if code != exitSuccess || stderr.Len() != 0 {
		t.Fatalf("cancelled run = %d, %q", code, stderr.String())
	}
	nilContext := func() int {
		//lint:ignore SA1012 The command boundary must reject an adversarial nil context.
		return run(nil, []string{"mcp", "--agent", "codex"}, &stderr, &factoryStub{}, &transportStub{}) //nolint:staticcheck // Boundary fixture; owner=launcher expiry=2027-07-15.
	}
	for name, invoke := range map[string]func() int{
		"nil context": nilContext,
		"nil stderr": func() int {
			return run(context.Background(), []string{"mcp", "--agent", "codex"}, nil, &factoryStub{}, &transportStub{})
		},
		"nil factory": func() int {
			return run(context.Background(), []string{"mcp", "--agent", "codex"}, &stderr, nil, &transportStub{})
		},
		"nil transport": func() int {
			return run(context.Background(), []string{"mcp", "--agent", "codex"}, &stderr, &factoryStub{}, nil)
		},
	} {
		stderr.Reset()
		if code := invoke(); code != exitUsage {
			t.Fatalf("%s run = %d", name, code)
		}
	}
	var channel chan int
	var function func()
	var mapping map[string]string
	var pointer *int
	var slice []byte
	for name, value := range map[string]any{
		"nil": nil, "channel": channel, "function": function, "map": mapping, "pointer": pointer, "slice": slice,
	} {
		if !nilCapability(value) {
			t.Fatalf("%s nil capability accepted", name)
		}
	}
	for name, value := range map[string]any{
		"channel": make(chan int), "function": func() {}, "map": map[string]string{},
		"pointer": new(int), "slice": []byte{}, "value": 1,
	} {
		if nilCapability(value) {
			t.Fatalf("%s non-nil capability rejected", name)
		}
	}
}

func TestPF001PortableCommandPropagatesContextAndDistinguishesCancellation(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), portableContextKey{}, "exact")
	factory := &factoryStub{runner: &runnerStub{}}
	var stderr bytes.Buffer
	if code := run(ctx, []string{"mcp", "--agent", "codex"}, &stderr, factory, &transportStub{}); code != exitSuccess ||
		factory.ctx != ctx || factory.runner.(*runnerStub).ctx != ctx {
		t.Fatalf("context propagation code=%d factory=%v runner=%v", code, factory.ctx, factory.runner.(*runnerStub).ctx)
	}
	factory = &factoryStub{runner: &runnerStub{err: context.Canceled}}
	stderr.Reset()
	if code := run(context.Background(), []string{"mcp", "--agent", "codex"}, &stderr, factory, &transportStub{}); code != exitMCPUnavailable ||
		stderr.String() != "AM_MCP_UNAVAILABLE\n" {
		t.Fatalf("live cancellation code=%d stderr=%q", code, stderr.String())
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	factory = &factoryStub{runner: &runnerStub{err: errors.New("other")}}
	stderr.Reset()
	if code := run(cancelled, []string{"mcp", "--agent", "codex"}, &stderr, factory, &transportStub{}); code != exitMCPUnavailable ||
		stderr.String() != "AM_MCP_UNAVAILABLE\n" {
		t.Fatalf("non-cancellation error code=%d stderr=%q", code, stderr.String())
	}
}

type factoryStub struct {
	runner launcher.MCPRunner
	err    error
	host   agentconfig.AgentHost
	ctx    context.Context
}

func (f *factoryStub) BuildMCP(ctx context.Context, host agentconfig.AgentHost) (launcher.MCPRunner, error) {
	f.ctx = ctx
	f.host = host
	return f.runner, f.err
}

type runnerStub struct {
	transport mcp.Transport
	err       error
	calls     int
	ctx       context.Context
}

func (r *runnerStub) Run(ctx context.Context, transport mcp.Transport) error {
	r.calls++
	r.ctx = ctx
	r.transport = transport
	return r.err
}

type portableContextKey struct{}

type transportStub struct{}

func (*transportStub) Connect(context.Context) (mcp.Connection, error) {
	return nil, errors.New("unused")
}
