package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpbootstrapapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/infrastructure/launcher"
)

func TestPF001AgentMemoryCommandDispatchesExactMCPAgentWithoutDiagnosticOutput(t *testing.T) {
	t.Parallel()
	runner := &runnerStub{}
	factory := &factoryStub{runner: runner}
	transport, _ := mcp.NewInMemoryTransports()
	var stderr strings.Builder
	ctx := context.Background()
	exitCode := run(
		ctx, []string{"mcp", "--agent", "codex"}, &stderr, factory, transport,
	)
	if exitCode != exitSuccess || stderr.Len() != 0 || factory.calls != 1 ||
		factory.ctx != ctx || factory.host != agentconfig.AgentHostCodex || runner.calls != 1 ||
		runner.ctx != ctx || runner.transport != transport {
		t.Fatalf("exit=%d stderr=%q factory=%+v runner=%+v", exitCode, stderr.String(), factory, runner)
	}
}

func TestPF001AgentMemoryCommandAcceptsOnlyClosedHostAndArgumentGrammar(t *testing.T) {
	t.Parallel()
	for _, host := range []agentconfig.AgentHost{
		agentconfig.AgentHostGeneric, agentconfig.AgentHostCodex, agentconfig.AgentHostClaude,
		agentconfig.AgentHostGemini, agentconfig.AgentHostCursor, agentconfig.AgentHostGLM,
	} {
		parsed, ok := parseMCPCommand([]string{"mcp", "--agent", string(host)})
		if !ok || parsed != host {
			t.Fatalf("host %q parsed as %q, %t", host, parsed, ok)
		}
	}
	for _, args := range [][]string{
		nil,
		{"mcp"},
		{"mcp", "--agent"},
		{"mcp", "--agent", "unknown"},
		{"mcp", "--host", "codex"},
		{"install", "--agent", "codex"},
		{"mcp", "--agent", "codex", "extra"},
	} {
		if _, ok := parseMCPCommand(args); ok {
			t.Fatalf("invalid arguments accepted: %q", args)
		}
		transport, _ := mcp.NewInMemoryTransports()
		var stderr strings.Builder
		if exitCode := run(context.Background(), args, &stderr, &factoryStub{}, transport); exitCode != exitUsage ||
			stderr.String() != "AM_USAGE\n" {
			t.Fatalf("args=%q exit=%d stderr=%q", args, exitCode, stderr.String())
		}
	}
}

func TestPF001AgentMemoryCommandRunsOnlyTokenizedNativeContinuation(t *testing.T) {
	t.Parallel()
	token := strings.Repeat("a", 64)
	factory := &factoryStub{}
	transport, _ := mcp.NewInMemoryTransports()
	var stderr strings.Builder
	ctx := context.Background()
	if code := run(ctx, []string{"resume", "--continuation", token}, &stderr, factory, transport); code != exitSuccess ||
		stderr.Len() != 0 || factory.resumeCalls != 1 || factory.resumeToken != token || factory.calls != 0 {
		t.Fatalf("resume code=%d stderr=%q factory=%+v", code, stderr.String(), factory)
	}
	if parsed, ok := parseResumeCommand([]string{"resume", "--continuation", token}); !ok || parsed != token {
		t.Fatalf("parseResumeCommand() = (%q, %t)", parsed, ok)
	}
	for _, args := range [][]string{
		{"resume"}, {"resume", "--continuation"}, {"resume", "--continuation", strings.Repeat("A", 64)},
		{"resume", "--continuation", strings.Repeat("g", 64)}, {"resume", "--continuation", token, "extra"},
	} {
		if parsed, ok := parseResumeCommand(args); ok || parsed != "" {
			t.Fatalf("invalid resume arguments accepted: %q", args)
		}
	}
}

func TestPF001AgentMemoryCommandMapsContinuationFailuresToStableCodes(t *testing.T) {
	t.Parallel()
	token := strings.Repeat("b", 64)
	transport, _ := mcp.NewInMemoryTransports()
	for _, test := range []struct {
		err  error
		code string
		exit int
	}{
		{err: launcher.ErrResumeIntegrity, code: "AM_RESUME_INTEGRITY\n", exit: exitResumeIntegrity},
		{err: launcher.ErrResumeUnavailable, code: "AM_RESUME_UNAVAILABLE\n", exit: exitResumeUnavailable},
		{err: context.DeadlineExceeded, code: "AM_RESUME_UNAVAILABLE\n", exit: exitResumeUnavailable},
		{err: errors.New("private path"), code: "AM_RESUME_UNAVAILABLE\n", exit: exitResumeUnavailable},
	} {
		var stderr strings.Builder
		code := run(context.Background(), []string{"resume", "--continuation", token}, &stderr,
			&factoryStub{resumeErr: test.err}, transport)
		if code != test.exit || stderr.String() != test.code || strings.Contains(stderr.String(), "private") {
			t.Fatalf("error=%v code=%d stderr=%q", test.err, code, stderr.String())
		}
	}
}

func TestPF001AgentMemoryCommandMapsProtectedFactoryFailuresToStableStderr(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err  error
		code string
		exit int
	}{
		{err: mcpbootstrapapp.ErrBootstrapNotFound, code: "AM_BOOTSTRAP_NOT_FOUND\n", exit: exitBootstrapNotFound},
		{err: mcpbootstrapapp.ErrBootstrapConflict, code: "AM_BOOTSTRAP_INTEGRITY\n", exit: exitBootstrapIntegrity},
		{err: mcpbootstrapapp.ErrBootstrapIntegrity, code: "AM_BOOTSTRAP_INTEGRITY\n", exit: exitBootstrapIntegrity},
		{err: mcpbootstrapapp.ErrBootstrapUnavailable, code: "AM_BOOTSTRAP_UNAVAILABLE\n", exit: exitBootstrapUnavailable},
		{err: context.DeadlineExceeded, code: "AM_BOOTSTRAP_UNAVAILABLE\n", exit: exitBootstrapUnavailable},
		{err: errors.New("raw protected path detail"), code: "AM_BOOTSTRAP_UNAVAILABLE\n", exit: exitBootstrapUnavailable},
	}
	for _, test := range tests {
		test := test
		t.Run(test.code+test.err.Error(), func(t *testing.T) {
			t.Parallel()
			transport, _ := mcp.NewInMemoryTransports()
			var stderr strings.Builder
			exitCode := run(context.Background(), []string{"mcp", "--agent", "codex"}, &stderr,
				&factoryStub{err: test.err}, transport)
			if exitCode != test.exit || stderr.String() != test.code || strings.Contains(stderr.String(), "raw") {
				t.Fatalf("error=%v exit=%d stderr=%q", test.err, exitCode, stderr.String())
			}
		})
	}
}

func TestPF001AgentMemoryCommandFailsClosedForRunnerAndMissingComposition(t *testing.T) {
	t.Parallel()
	transport, _ := mcp.NewInMemoryTransports()
	var stderr strings.Builder
	if exitCode := run(context.Background(), []string{"mcp", "--agent", "codex"}, &stderr,
		&factoryStub{runner: &runnerStub{err: errors.New("raw MCP failure")}}, transport); exitCode != exitMCPUnavailable ||
		stderr.String() != "AM_MCP_UNAVAILABLE\n" {
		t.Fatalf("runner failure exit=%d stderr=%q", exitCode, stderr.String())
	}
	stderr.Reset()
	if exitCode := run(context.Background(), []string{"mcp", "--agent", "codex"}, &stderr,
		&factoryStub{}, transport); exitCode != exitBootstrapIntegrity || stderr.String() != "AM_BOOTSTRAP_INTEGRITY\n" {
		t.Fatalf("nil runner exit=%d stderr=%q", exitCode, stderr.String())
	}
	stderr.Reset()
	var nilFactory *factoryStub
	if exitCode := run(context.Background(), []string{"mcp", "--agent", "codex"}, &stderr,
		nilFactory, transport); exitCode != exitUsage || stderr.String() != "AM_USAGE\n" {
		t.Fatalf("nil factory exit=%d stderr=%q", exitCode, stderr.String())
	}
	if production := newProductionFactory(); production == nil {
		t.Fatal("production factory is nil")
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	stderr.Reset()
	if exitCode := run(cancelled, []string{"mcp", "--agent", "codex"}, &stderr,
		&factoryStub{runner: &runnerStub{err: context.Canceled}}, transport); exitCode != exitSuccess || stderr.Len() != 0 {
		t.Fatalf("signal shutdown exit=%d stderr=%q", exitCode, stderr.String())
	}
}

func TestPF001AgentMemoryCommandRequiresEveryInvocationCapability(t *testing.T) {
	t.Parallel()
	validArgs := []string{"mcp", "--agent", "codex"}
	transport, _ := mcp.NewInMemoryTransports()
	validFactory := &factoryStub{runner: &runnerStub{}}
	for _, test := range []struct {
		name      string
		ctx       context.Context
		stderr    *strings.Builder
		factory   launcher.MCPFactory
		transport mcp.Transport
	}{
		{name: "nil context", stderr: &strings.Builder{}, factory: validFactory, transport: transport},
		{name: "nil diagnostics", ctx: context.Background(), factory: validFactory, transport: transport},
		{name: "nil factory", ctx: context.Background(), stderr: &strings.Builder{}, transport: transport},
		{name: "nil transport", ctx: context.Background(), stderr: &strings.Builder{}, factory: validFactory},
	} {
		t.Run(test.name, func(t *testing.T) {
			if code := run(test.ctx, validArgs, test.stderr, test.factory, test.transport); code != exitUsage {
				t.Fatalf("run()=%d, want usage", code)
			}
		})
	}
}

func TestPF001AgentMemoryCommandDistinguishesSignalCancellationFromRunnerFailure(t *testing.T) {
	t.Parallel()
	transport, _ := mcp.NewInMemoryTransports()
	args := []string{"mcp", "--agent", "codex"}
	var stderr strings.Builder
	if code := run(context.Background(), args, &stderr,
		&factoryStub{runner: &runnerStub{err: context.Canceled}}, transport); code != exitMCPUnavailable ||
		stderr.String() != "AM_MCP_UNAVAILABLE\n" {
		t.Fatalf("live cancellation code=%d stderr=%q", code, stderr.String())
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	stderr.Reset()
	if code := run(cancelled, args, &stderr,
		&factoryStub{runner: &runnerStub{err: errors.New("runner failed")}}, transport); code != exitMCPUnavailable ||
		stderr.String() != "AM_MCP_UNAVAILABLE\n" {
		t.Fatalf("non-cancellation failure code=%d stderr=%q", code, stderr.String())
	}
}

func TestPF001AgentMemoryCommandAcceptsGracefulShutdownOnlyForSignalCancellation(t *testing.T) {
	t.Parallel()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for name, test := range map[string]struct {
		ctx  context.Context
		err  error
		want bool
	}{
		"signal cancellation": {ctx: cancelled, err: context.Canceled, want: true},
		"live cancellation":   {ctx: context.Background(), err: context.Canceled},
		"other error":         {ctx: cancelled, err: errors.New("failed")},
		"nil error":           {ctx: cancelled},
		"nil context":         {err: context.Canceled},
	} {
		if got := gracefulSignalShutdown(test.ctx, test.err); got != test.want {
			t.Fatalf("%s gracefulSignalShutdown()=%t, want %t", name, got, test.want)
		}
	}
}

type factoryStub struct {
	runner      launcher.MCPRunner
	err         error
	ctx         context.Context
	host        agentconfig.AgentHost
	calls       int
	resumeCalls int
	resumeToken string
	resumeErr   error
}

func (f *factoryStub) ResumeInstallation(_ context.Context, token string) error {
	f.resumeCalls++
	f.resumeToken = token
	return f.resumeErr
}

func (f *factoryStub) BuildMCP(ctx context.Context, host agentconfig.AgentHost) (launcher.MCPRunner, error) {
	f.calls++
	f.ctx = ctx
	f.host = host
	return f.runner, f.err
}

type runnerStub struct {
	err       error
	ctx       context.Context
	transport mcp.Transport
	calls     int
}

func (r *runnerStub) Run(ctx context.Context, transport mcp.Transport) error {
	r.calls++
	r.ctx = ctx
	r.transport = transport
	return r.err
}
