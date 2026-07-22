// Command agentmemory-mcp-session is the immutable transient container entry point.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/corehttp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/mcpsessionbridge"
)

const sessionCredentialPath = "/run/secrets/agentmemory-session"

func main() {
	os.Exit(runMain())
}

func runMain() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx, os.Args[1:], os.Stderr)
}

func run(ctx context.Context, arguments []string, diagnostics *os.File) int {
	return runWithServer(ctx, arguments, diagnostics, func(runContext context.Context, server *mcpsessionbridge.Server) error {
		return server.Run(runContext, &mcp.StdioTransport{})
	})
}

func runWithServer(
	ctx context.Context,
	arguments []string,
	diagnostics *os.File,
	runServer func(context.Context, *mcpsessionbridge.Server) error,
) int {
	if diagnostics == nil {
		return 2
	}
	if ctx == nil || runServer == nil || len(arguments) != 2 || arguments[0] != "--session-id" {
		_, _ = fmt.Fprintln(diagnostics, "AM_SESSION_USAGE")
		return 2
	}
	client, err := corehttp.NewSessionStatusClient(
		mcpsessionbridge.MountedCredential{}, sessionCredentialPath, arguments[1],
	)
	if err != nil {
		_, _ = fmt.Fprintln(diagnostics, "AM_SESSION_INTEGRITY")
		return 4
	}
	server, err := mcpsessionbridge.NewServer(client, client)
	if err != nil {
		_, _ = fmt.Fprintln(diagnostics, "AM_SESSION_INTEGRITY")
		return 4
	}
	if err := runServer(ctx, server); err != nil && ctx.Err() == nil {
		_, _ = fmt.Fprintln(diagnostics, "AM_SESSION_UNAVAILABLE")
		return 6
	}
	return 0
}
