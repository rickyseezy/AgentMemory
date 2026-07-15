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
		return run(nil, nil, &stderr, &factoryStub{}, &transportStub{}) //nolint:staticcheck // Boundary fixture; owner=launcher expiry=2027-07-15.
	}
	for name, invoke := range map[string]func() int{
		"nil context":   nilContext,
		"nil stderr":    func() int { return run(context.Background(), nil, nil, &factoryStub{}, &transportStub{}) },
		"nil factory":   func() int { return run(context.Background(), nil, &stderr, nil, &transportStub{}) },
		"nil transport": func() int { return run(context.Background(), nil, &stderr, &factoryStub{}, nil) },
	} {
		stderr.Reset()
		if code := invoke(); code != exitUsage {
			t.Fatalf("%s run = %d", name, code)
		}
	}
	if nilCapability(struct{}{}) || nilCapability(1) || !nilCapability(nil) {
		t.Fatal("nil capability classification changed")
	}
}

type factoryStub struct {
	runner launcher.MCPRunner
	err    error
	host   agentconfig.AgentHost
}

func (f *factoryStub) BuildMCP(_ context.Context, host agentconfig.AgentHost) (launcher.MCPRunner, error) {
	f.host = host
	return f.runner, f.err
}

type runnerStub struct {
	transport mcp.Transport
	err       error
	calls     int
}

func (r *runnerStub) Run(_ context.Context, transport mcp.Transport) error {
	r.calls++
	r.transport = transport
	return r.err
}

type transportStub struct{}

func (*transportStub) Connect(context.Context) (mcp.Connection, error) {
	return nil, errors.New("unused")
}
