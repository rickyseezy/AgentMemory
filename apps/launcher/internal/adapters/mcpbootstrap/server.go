// Package mcpbootstrap exposes the protocol-valid PF-001 bootstrap surface
// through the official Model Context Protocol Go SDK.
package mcpbootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpbootstrapapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/setupprogressapp"
)

const (
	// ToolInstallationStatus is the only read-only bootstrap query.
	ToolInstallationStatus = "installation_status"
	// ToolInstallationOpenSetup opens a fresh local browser capability.
	ToolInstallationOpenSetup = "installation_open_setup"
	// ToolInstallationCancel requests durable cancellation.
	ToolInstallationCancel = "installation_cancel"

	serverName    = "agentmemory"
	serverVersion = "0.1.0"
)

var bootstrapToolNames = []string{
	ToolInstallationStatus,
	ToolInstallationOpenSetup,
	ToolInstallationCancel,
}

// ReadyTool binds one validated product tool to its handler.
type ReadyTool struct {
	Tool    *mcp.Tool
	Handler mcp.ToolHandler
}

// ReadyResource binds one product resource to its handler. Registering at
// least one resource causes the SDK to emit the required resource-list change
// notification during handoff.
type ReadyResource struct {
	Resource *mcp.Resource
	Handler  mcp.ResourceHandler
}

// ReadySurface is prepared without mutating the server, then installed before
// all bootstrap tools are removed in one debounced SDK notification window.
type ReadySurface struct {
	Tools     []ReadyTool
	Resources []ReadyResource
}

// ReadySurfaceProvider supplies the already-constructed PF-005 session bridge
// surface only after backend-authoritative Ready.
type ReadySurfaceProvider interface {
	ReadySurface(context.Context) (ReadySurface, error)
}

// BootstrapApplication is the transport-neutral setup use case consumed by
// the MCP adapter. The native durable application and the signed portable
// package bridge both implement this exact closed surface.
type BootstrapApplication interface {
	Status(context.Context) (mcpbootstrapapp.InstallationStatus, error)
	WaitAfter(context.Context, uint64) (mcpbootstrapapp.InstallationStatus, error)
	OpenSetup(context.Context) (mcpbootstrapapp.OpenSetupResult, error)
	Cancel(context.Context) (mcpbootstrapapp.CancelResult, error)
}

// Server owns one MCP server and the atomic bootstrap-to-product handoff.
type Server struct {
	application BootstrapApplication
	ready       ReadySurfaceProvider
	server      *mcp.Server

	runMu     sync.Mutex
	running   bool
	handoffMu sync.Mutex
	handedOff bool
}

// NewServer registers exactly the three PF-001 bootstrap tools. It rejects a
// missing Ready provider so a Ready installation cannot strand the session.
func NewServer(
	application BootstrapApplication,
	ready ReadySurfaceProvider,
) (*Server, error) {
	if nilCapability(application) || nilCapability(ready) {
		return nil, errors.New("MCP bootstrap dependencies are invalid")
	}
	server := mcp.NewServer(
		&mcp.Implementation{
			Name: serverName, Title: "AgentMemory", Version: serverVersion,
		},
		&mcp.ServerOptions{
			Instructions: "AgentMemory is completing private local setup. Use only the listed installation tools until the tool list changes.",
			Capabilities: &mcp.ServerCapabilities{
				Tools:     &mcp.ToolCapabilities{ListChanged: true},
				Resources: &mcp.ResourceCapabilities{ListChanged: true},
			},
		},
	)
	result := &Server{application: application, ready: ready, server: server}
	result.registerBootstrapTools()
	return result, nil
}

// Run serves exactly one persistent MCP connection and monitors the durable
// progress sequence for Ready. It writes no diagnostic data to MCP stdout.
func (s *Server) Run(ctx context.Context, transport mcp.Transport) error {
	if s == nil || ctx == nil || nilCapability(transport) || s.server == nil ||
		nilCapability(s.application) || nilCapability(s.ready) {
		return errors.New("MCP bootstrap server is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.runMu.Lock()
	if s.running {
		s.runMu.Unlock()
		return errors.New("MCP bootstrap server is already running")
	}
	s.running = true
	s.runMu.Unlock()
	defer func() {
		s.runMu.Lock()
		s.running = false
		s.runMu.Unlock()
	}()

	monitorContext, cancelMonitor := context.WithCancel(ctx)
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		s.monitorReady(monitorContext)
	}()
	err := s.server.Run(ctx, transport)
	cancelMonitor()
	<-monitorDone
	return err
}

func (s *Server) registerBootstrapTools() {
	closedWorld, additive, destructive := false, false, true
	mcp.AddTool(s.server, &mcp.Tool{
		Name:        ToolInstallationStatus,
		Title:       "Installation status",
		Description: "Return privacy-safe progress for the local AgentMemory installation.",
		Annotations: &mcp.ToolAnnotations{
			Title: "Installation status", ReadOnlyHint: true,
			OpenWorldHint: &closedWorld, DestructiveHint: &additive, IdempotentHint: true,
		},
	}, s.statusTool)
	mcp.AddTool(s.server, &mcp.Tool{
		Name:        ToolInstallationOpenSetup,
		Title:       "Open installation setup",
		Description: "Open the secure local setup window for required consent or recovery actions.",
		Annotations: &mcp.ToolAnnotations{
			Title: "Open installation setup", ReadOnlyHint: false,
			OpenWorldHint: &closedWorld, DestructiveHint: &additive, IdempotentHint: false,
		},
	}, s.openSetupTool)
	mcp.AddTool(s.server, &mcp.Tool{
		Name:        ToolInstallationCancel,
		Title:       "Cancel installation",
		Description: "Durably request cancellation of the current AgentMemory installation.",
		Annotations: &mcp.ToolAnnotations{
			Title: "Cancel installation", ReadOnlyHint: false,
			OpenWorldHint: &closedWorld, DestructiveHint: &destructive, IdempotentHint: true,
		},
	}, s.cancelTool)
}

type emptyInput struct{}

func (s *Server) statusTool(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	_ emptyInput,
) (*mcp.CallToolResult, mcpbootstrapapp.InstallationStatus, error) {
	status, err := s.application.Status(ctx)
	if err != nil {
		return nil, mcpbootstrapapp.InstallationStatus{}, err
	}
	if status.ReadyHandoffPending {
		if handoffError := s.handoff(ctx); handoffError == nil {
			status.ReadyHandoffPending = false
		} else {
			status.Error = &mcpbootstrapapp.StatusError{Code: "AM_DEPENDENCY_UNAVAILABLE", Retryable: true}
		}
	}
	return nil, status, nil
}

func (s *Server) openSetupTool(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	_ emptyInput,
) (*mcp.CallToolResult, mcpbootstrapapp.OpenSetupResult, error) {
	result, err := s.application.OpenSetup(ctx)
	return nil, result, err
}

func (s *Server) cancelTool(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	_ emptyInput,
) (*mcp.CallToolResult, mcpbootstrapapp.CancelResult, error) {
	result, err := s.application.Cancel(ctx)
	return nil, result, err
}

func (s *Server) monitorReady(ctx context.Context) {
	status, err := s.application.Status(ctx)
	if err != nil {
		return
	}
	for {
		if status.State == string(setupprogressapp.StateReady) {
			_ = s.handoff(ctx)
			return
		}
		status, err = s.application.WaitAfter(ctx, status.Sequence)
		if err != nil {
			return
		}
	}
}

func (s *Server) handoff(ctx context.Context) error {
	if ctx == nil {
		return errors.New("MCP Ready handoff context is invalid")
	}
	s.handoffMu.Lock()
	defer s.handoffMu.Unlock()
	if s.handedOff {
		return nil
	}
	surface, err := s.ready.ReadySurface(ctx)
	if err != nil {
		return errors.New("MCP Ready surface is unavailable")
	}
	if err := validateReadySurface(surface); err != nil {
		return err
	}
	for _, registration := range surface.Tools {
		s.server.AddTool(registration.Tool, registration.Handler)
	}
	for _, registration := range surface.Resources {
		s.server.AddResource(registration.Resource, registration.Handler)
	}
	s.server.RemoveTools(bootstrapToolNames...)
	s.handedOff = true
	return nil
}

func validateReadySurface(surface ReadySurface) error {
	if len(surface.Tools) == 0 {
		return errors.New("MCP Ready surface contains no product tool")
	}
	seenTools := make(map[string]struct{}, len(surface.Tools))
	for _, registration := range surface.Tools {
		if registration.Tool == nil || registration.Handler == nil ||
			!validToolName(registration.Tool.Name) || isBootstrapTool(registration.Tool.Name) ||
			!objectSchema(registration.Tool.InputSchema) ||
			registration.Tool.OutputSchema != nil && !objectSchema(registration.Tool.OutputSchema) {
			return errors.New("MCP Ready tool registration is invalid")
		}
		if _, duplicate := seenTools[registration.Tool.Name]; duplicate {
			return errors.New("MCP Ready tool names are not unique")
		}
		seenTools[registration.Tool.Name] = struct{}{}
	}
	seenResources := make(map[string]struct{}, len(surface.Resources))
	for _, registration := range surface.Resources {
		if registration.Resource == nil || registration.Handler == nil || registration.Resource.URI == "" {
			return errors.New("MCP Ready resource registration is invalid")
		}
		parsed, err := url.Parse(registration.Resource.URI)
		if err != nil || parsed.Scheme == "" || parsed.Fragment != "" {
			return errors.New("MCP Ready resource URI is invalid")
		}
		if _, duplicate := seenResources[registration.Resource.URI]; duplicate {
			return errors.New("MCP Ready resource URIs are not unique")
		}
		seenResources[registration.Resource.URI] = struct{}{}
	}
	return nil
}

func objectSchema(schema any) bool {
	if schema == nil {
		return false
	}
	encoded, err := json.Marshal(schema)
	if err != nil {
		return false
	}
	var document map[string]any
	return json.Unmarshal(encoded, &document) == nil && document["type"] == "object"
}

func validToolName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for _, character := range name {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("_.-", character) {
			continue
		}
		return false
	}
	return true
}

func isBootstrapTool(name string) bool {
	for _, bootstrapName := range bootstrapToolNames {
		if name == bootstrapName {
			return true
		}
	}
	return false
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
