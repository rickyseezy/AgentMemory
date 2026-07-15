// Command agentmemory-bootstrap is the signed portable MCP first-invocation
// entry point shipped inside certified agent-host packages.
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

const (
	exitSuccess              = 0
	exitUsage                = 2
	exitBootstrapIntegrity   = 4
	exitBootstrapUnavailable = 5
	exitMCPUnavailable       = 6
)

func main() { os.Exit(runMain()) }

func runMain() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx, os.Args[1:], os.Stderr, newProductionFactory(), &mcp.StdioTransport{})
}

// run never receives stdout. The SDK transport exclusively owns successful
// MCP frames; stderr receives only stable non-sensitive codes.
func run(
	ctx context.Context,
	args []string,
	stderr io.Writer,
	factory launcher.MCPFactory,
	transport mcp.Transport,
) int {
	if ctx == nil || nilCapability(stderr) || nilCapability(factory) || nilCapability(transport) {
		writeCode(stderr, "AM_USAGE")
		return exitUsage
	}
	host, ok := parseMCPCommand(args)
	if !ok {
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
		if errors.Is(err, context.Canceled) && ctx.Err() != nil {
			return exitSuccess
		}
		writeCode(stderr, "AM_MCP_UNAVAILABLE")
		return exitMCPUnavailable
	}
	return exitSuccess
}

func parseMCPCommand(args []string) (agentconfig.AgentHost, bool) {
	if len(args) != 3 || args[0] != "mcp" || args[1] != "--agent" {
		return "", false
	}
	host := agentconfig.AgentHost(args[2])
	return host, host.Valid()
}

func reportFactoryError(stderr io.Writer, err error) int {
	if errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		writeCode(stderr, "AM_BOOTSTRAP_INTEGRITY")
		return exitBootstrapIntegrity
	}
	writeCode(stderr, "AM_BOOTSTRAP_UNAVAILABLE")
	return exitBootstrapUnavailable
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
	case reflect.Invalid:
		return true
	default:
		return false
	}
}
