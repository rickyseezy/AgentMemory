// Command agentmemory is the signed native launcher and MCP stdio entry point.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"reflect"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpbootstrapapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/infrastructure/launcher"
)

// Go coverage cannot attribute execution to constant declarations. Their exact
// wire values are asserted by TestPF001AgentMemoryExitCodesAreStable.
const (
	// mutator-disable-next-line *
	exitSuccess = 0
	// mutator-disable-next-line *
	exitUsage = 2
	// mutator-disable-next-line *
	exitBootstrapNotFound = 3
	// mutator-disable-next-line *
	exitBootstrapIntegrity = 4
	// mutator-disable-next-line *
	exitBootstrapUnavailable = 5
	// mutator-disable-next-line *
	exitMCPUnavailable = 6
	// mutator-disable-next-line *
	exitResumeIntegrity = 7
	// mutator-disable-next-line *
	exitResumeUnavailable = 8
)

// main is an os.Exit boundary; run is tested directly across its complete MCP
// and resume contract while runMain owns production-only signal wiring.
// mutator-disable-func
func main() {
	os.Exit(runMain())
}

// runMain is process-only signal and transport wiring; run owns the tested
// behavioral contract and executable integration tests exercise this boundary.
// mutator-disable-func
func runMain() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx, os.Args[1:], os.Stderr, newProductionFactory(), &mcp.StdioTransport{})
}

// run never receives stdout: successful MCP protocol frames are owned solely
// by the SDK transport, and all launcher diagnostics are stable stderr codes.
func run(
	ctx context.Context,
	args []string,
	stderr io.Writer,
	factory launcher.MCPFactory,
	transport mcp.Transport,
) int {
	if ctx == nil || nilCapability(stderr) || nilCapability(factory) {
		writeCode(stderr, "AM_USAGE")
		return exitUsage
	}
	if token, resume := parseResumeCommand(args); resume {
		resumer, supported := factory.(launcher.InstallationResumeFactory)
		if !supported || nilCapability(resumer) {
			writeCode(stderr, "AM_RESUME_INTEGRITY")
			return exitResumeIntegrity
		}
		if err := resumer.ResumeInstallation(ctx, token); err != nil {
			return reportResumeError(stderr, err)
		}
		// statement/return would substitute the same integer zero represented by exitSuccess.
		// mutator-disable-next-line statement/return
		return exitSuccess
	}
	host, ok := parseMCPCommand(args)
	if !ok || nilCapability(transport) {
		writeCode(stderr, "AM_USAGE")
		return exitUsage
	}
	runner, err := factory.BuildMCP(ctx, host)
	if err != nil {
		return reportFactoryError(stderr, err)
	}
	if nilCapability(runner) {
		writeCode(stderr, "AM_BOOTSTRAP_INTEGRITY")
		return exitBootstrapIntegrity
	}
	if err := runner.Run(ctx, transport); err != nil {
		if gracefulSignalShutdown(ctx, err) {
			// statement/return would substitute the same integer zero represented by exitSuccess.
			// mutator-disable-next-line statement/return
			return exitSuccess
		}
		writeCode(stderr, "AM_MCP_UNAVAILABLE")
		return exitMCPUnavailable
	}
	// statement/return would substitute the same integer zero represented by exitSuccess.
	// mutator-disable-next-line statement/return
	return exitSuccess
}

func parseResumeCommand(args []string) (string, bool) {
	if len(args) != 3 || args[0] != "resume" || args[1] != "--continuation" || len(args[2]) != 64 {
		return "", false
	}
	for _, character := range args[2] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return "", false
		}
	}
	return args[2], true
}

func gracefulSignalShutdown(ctx context.Context, runError error) bool {
	return ctx != nil && errors.Is(runError, context.Canceled) && ctx.Err() != nil
}

func parseMCPCommand(args []string) (agentconfig.AgentHost, bool) {
	if len(args) != 3 || args[0] != "mcp" || args[1] != "--agent" {
		return "", false
	}
	host := agentconfig.AgentHost(args[2])
	return host, host.Valid()
}

func reportFactoryError(stderr io.Writer, err error) int {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		writeCode(stderr, "AM_BOOTSTRAP_UNAVAILABLE")
		return exitBootstrapUnavailable
	case errors.Is(err, mcpbootstrapapp.ErrBootstrapNotFound):
		writeCode(stderr, "AM_BOOTSTRAP_NOT_FOUND")
		return exitBootstrapNotFound
	case errors.Is(err, mcpbootstrapapp.ErrBootstrapConflict),
		errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity):
		writeCode(stderr, "AM_BOOTSTRAP_INTEGRITY")
		return exitBootstrapIntegrity
	default:
		writeCode(stderr, "AM_BOOTSTRAP_UNAVAILABLE")
		return exitBootstrapUnavailable
	}
}

func reportResumeError(stderr io.Writer, err error) int {
	if errors.Is(err, launcher.ErrResumeIntegrity) {
		writeCode(stderr, "AM_RESUME_INTEGRITY")
		return exitResumeIntegrity
	}
	writeCode(stderr, "AM_RESUME_UNAVAILABLE")
	return exitResumeUnavailable
}

func writeCode(stderr io.Writer, code string) {
	if !nilCapability(stderr) {
		_, _ = fmt.Fprintln(stderr, code)
	}
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
	default:
		return false
	}
}
