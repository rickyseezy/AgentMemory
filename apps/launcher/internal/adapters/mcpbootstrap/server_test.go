package mcpbootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpbootstrapapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/setupprogressapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001OfficialMCPHandshakeBootstrapCallsAndReadyHandoff(t *testing.T) {
	fixture := newServerFixture(t, setupprogressapp.StateRunning)
	server, err := NewServer(fixture.application, fixture.ready)
	if err != nil {
		t.Fatal(err)
	}

	toolChanged := make(chan struct{}, 4)
	resourceChanged := make(chan struct{}, 4)
	client := mcp.NewClient(&mcp.Implementation{Name: "pf001-test", Version: "1"}, &mcp.ClientOptions{
		ToolListChangedHandler: func(context.Context, *mcp.ToolListChangedRequest) {
			toolChanged <- struct{}{}
		},
		ResourceListChangedHandler: func(context.Context, *mcp.ResourceListChangedRequest) {
			resourceChanged <- struct{}{}
		},
	})
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(ctx, serverTransport) }()
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}

	initialized := clientSession.InitializeResult()
	if initialized == nil || initialized.ServerInfo == nil || initialized.ServerInfo.Name != serverName ||
		initialized.ServerInfo.Version != serverVersion || initialized.Capabilities == nil ||
		initialized.Capabilities.Tools == nil || !initialized.Capabilities.Tools.ListChanged ||
		initialized.Capabilities.Resources == nil || !initialized.Capabilities.Resources.ListChanged {
		t.Fatalf("initialize result = %+v", initialized)
	}
	assertToolNames(t, clientSession, bootstrapToolNames...)

	statusResult, err := clientSession.CallTool(ctx, &mcp.CallToolParams{Name: ToolInstallationStatus})
	if err != nil || statusResult.IsError {
		t.Fatalf("installation_status = %+v, %v", statusResult, err)
	}
	var status mcpbootstrapapp.InstallationStatus
	decodeStructured(t, statusResult.StructuredContent, &status)
	if status.InstallationID != testMCPInstallationID || status.State != "running" ||
		status.CompletedStages != 1 || status.TotalStages != 14 || !status.Cancellable ||
		status.ReadyHandoffPending {
		t.Fatalf("installation status = %+v", status)
	}

	openResult, err := clientSession.CallTool(ctx, &mcp.CallToolParams{Name: ToolInstallationOpenSetup})
	if err != nil || openResult.IsError || fixture.setup.calls.Load() != 1 {
		t.Fatalf("installation_open_setup = %+v, %v, calls=%d", openResult, err, fixture.setup.calls.Load())
	}
	var opened mcpbootstrapapp.OpenSetupResult
	decodeStructured(t, openResult.StructuredContent, &opened)
	if !opened.Opened || opened.InstallationID != testMCPInstallationID {
		t.Fatalf("open result = %+v", opened)
	}

	cancelResult, err := clientSession.CallTool(ctx, &mcp.CallToolParams{Name: ToolInstallationCancel})
	if err != nil || cancelResult.IsError || fixture.cancellation.calls.Load() != 1 {
		t.Fatalf("installation_cancel = %+v, %v, calls=%d", cancelResult, err, fixture.cancellation.calls.Load())
	}
	var cancelled mcpbootstrapapp.CancelResult
	decodeStructured(t, cancelResult.StructuredContent, &cancelled)
	if !cancelled.CancellationRequested || cancelled.Status.State != "cancelled" {
		t.Fatalf("cancel result = %+v", cancelled)
	}

	fixture.progress.publish(fixture.snapshot(setupprogressapp.StateReady, 3))
	waitNotification(t, toolChanged, "tool list changed")
	waitNotification(t, resourceChanged, "resource list changed")
	assertToolNames(t, clientSession, "memory_recall")
	resources, err := clientSession.ListResources(ctx, nil)
	if err != nil || len(resources.Resources) != 1 || resources.Resources[0].URI != "agentmemory://ready" {
		t.Fatalf("Ready resources = %+v, %v", resources, err)
	}
	productResult, err := clientSession.CallTool(ctx, &mcp.CallToolParams{Name: "memory_recall"})
	if err != nil || productResult.IsError || fixture.ready.calls.Load() != 1 {
		t.Fatalf("memory_recall = %+v, %v, provider calls=%d", productResult, err, fixture.ready.calls.Load())
	}

	if err := clientSession.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case runError := <-serverDone:
		if runError != nil {
			t.Fatalf("server Run() error = %v", runError)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop after MCP client close")
	}
}

func TestPF001OfficialMCPRejectsArgumentsBeforeToolSideEffects(t *testing.T) {
	fixture := newServerFixture(t, setupprogressapp.StateRunning)
	server, _ := NewServer(fixture.application, fixture.ready)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx, serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "strict-client", Version: "1"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: ToolInstallationOpenSetup, Arguments: map[string]any{"path": "/secret"},
	})
	if err != nil || result == nil || !result.IsError || fixture.setup.calls.Load() != 0 {
		t.Fatalf("unknown arguments result = %+v, %v, setup calls=%d", result, err, fixture.setup.calls.Load())
	}
	_ = session.Close()
	<-done
}

func TestPF001ReadyHandoffFailureKeepsBootstrapToolsAndTypedPendingStatus(t *testing.T) {
	fixture := newServerFixture(t, setupprogressapp.StateReady)
	fixture.ready.err = errors.New("secret bridge detail")
	server, _ := NewServer(fixture.application, fixture.ready)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx, serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "handoff-client", Version: "1"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertToolNames(t, session, bootstrapToolNames...)
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: ToolInstallationStatus})
	if err != nil || result.IsError {
		t.Fatalf("Ready status = %+v, %v", result, err)
	}
	var status mcpbootstrapapp.InstallationStatus
	decodeStructured(t, result.StructuredContent, &status)
	if !status.ReadyHandoffPending || status.Error == nil ||
		status.Error.Code != "AM_DEPENDENCY_UNAVAILABLE" || !status.Error.Retryable {
		t.Fatalf("pending Ready status = %+v", status)
	}
	assertToolNames(t, session, bootstrapToolNames...)
	_ = session.Close()
	<-done
}

func TestPF001MCPBootstrapConstructionRunAndReadySurfaceFailClosed(t *testing.T) {
	t.Parallel()
	fixture := newServerFixture(t, setupprogressapp.StateRunning)
	var nilReady *readyProviderStub
	if server, err := NewServer(nil, fixture.ready); server != nil || err == nil {
		t.Fatalf("nil application server = %#v, %v", server, err)
	}
	if server, err := NewServer(fixture.application, nilReady); server != nil || err == nil {
		t.Fatalf("nil Ready provider server = %#v, %v", server, err)
	}
	server, err := NewServer(fixture.application, fixture.ready)
	if err != nil {
		t.Fatal(err)
	}
	var nilContext context.Context
	if err := server.Run(nilContext, nil); err == nil {
		t.Fatal("nil Run inputs were accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	transport, _ := mcp.NewInMemoryTransports()
	if err := server.Run(cancelled, transport); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Run error = %v", err)
	}
	server.running = true
	if err := server.Run(context.Background(), transport); err == nil {
		t.Fatal("concurrent Run was accepted")
	}
	server.running = false
	var nilServer *Server
	if err := nilServer.Run(context.Background(), transport); err == nil {
		t.Fatal("nil server Run was accepted")
	}

	valid := fixture.ready.surface
	tests := map[string]ReadySurface{
		"no tool":      {},
		"nil tool":     {Tools: []ReadyTool{{}}},
		"bootstrap":    {Tools: []ReadyTool{{Tool: &mcp.Tool{Name: ToolInstallationStatus, InputSchema: objectJSON()}, Handler: productTool}}},
		"bad name":     {Tools: []ReadyTool{{Tool: &mcp.Tool{Name: "bad name", InputSchema: objectJSON()}, Handler: productTool}}},
		"bad input":    {Tools: []ReadyTool{{Tool: &mcp.Tool{Name: "product", InputSchema: json.RawMessage(`{"type":"array"}`)}, Handler: productTool}}},
		"invalid JSON": {Tools: []ReadyTool{{Tool: &mcp.Tool{Name: "product", InputSchema: json.RawMessage(`{`)}, Handler: productTool}}},
		"marshal error": {Tools: []ReadyTool{{
			Tool: &mcp.Tool{Name: "product", InputSchema: make(chan int)}, Handler: productTool,
		}}},
		"bad output":   {Tools: []ReadyTool{{Tool: &mcp.Tool{Name: "product", InputSchema: objectJSON(), OutputSchema: json.RawMessage(`{"type":"string"}`)}, Handler: productTool}}},
		"duplicate":    {Tools: append(append([]ReadyTool(nil), valid.Tools...), valid.Tools[0])},
		"nil resource": {Tools: valid.Tools, Resources: []ReadyResource{{}}},
		"relative URI": {Tools: valid.Tools, Resources: []ReadyResource{{Resource: &mcp.Resource{URI: "relative"}, Handler: productResource}}},
		"fragment URI": {Tools: valid.Tools, Resources: []ReadyResource{{Resource: &mcp.Resource{URI: "agentmemory://ready#secret"}, Handler: productResource}}},
		"duplicate URI": {Tools: valid.Tools, Resources: []ReadyResource{
			{Resource: &mcp.Resource{URI: "agentmemory://ready"}, Handler: productResource},
			{Resource: &mcp.Resource{URI: "agentmemory://ready"}, Handler: productResource},
		}},
	}
	for name, surface := range tests {
		surface := surface
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := validateReadySurface(surface); err == nil {
				t.Fatalf("invalid Ready surface accepted: %+v", surface)
			}
		})
	}
	if err := validateReadySurface(valid); err != nil {
		t.Fatalf("valid Ready surface error = %v", err)
	}
	readyFixture := newServerFixture(t, setupprogressapp.StateReady)
	readyServer, _ := NewServer(readyFixture.application, readyFixture.ready)
	statusResult, status, err := readyServer.statusTool(context.Background(), nil, emptyInput{})
	if err != nil || statusResult != nil || status.ReadyHandoffPending || !readyServer.handedOff {
		t.Fatalf("direct Ready handoff = %+v, %+v, %v", statusResult, status, err)
	}
	if err := readyServer.handoff(context.Background()); err != nil || readyFixture.ready.calls.Load() != 1 {
		t.Fatalf("idempotent handoff error=%v provider calls=%d", err, readyFixture.ready.calls.Load())
	}
	if err := readyServer.handoff(nilContext); err == nil {
		t.Fatal("nil handoff context accepted")
	}
	for _, name := range []string{"a", "A_0.-z"} {
		if !validToolName(name) {
			t.Fatalf("valid tool name rejected: %q", name)
		}
	}
	for _, name := range []string{"", "bad/name", string(make([]byte, 129))} {
		if validToolName(name) {
			t.Fatalf("invalid tool name accepted: %q", name)
		}
	}
}

const testMCPInstallationID = "019f5f20-1234-7abc-8123-0123456789ab"

type serverFixture struct {
	application  *mcpbootstrapapp.Application
	binding      setupprogressapp.Binding
	progress     *progressAuthorityStub
	setup        *mcpSetupStub
	cancellation *mcpCancellationStub
	ready        *readyProviderStub
}

func newServerFixture(t testing.TB, state setupprogressapp.State) *serverFixture {
	t.Helper()
	operationID, err := install.NewOperationID("019f5f20-1234-7abc-8123-0123456789ac")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := install.BindPlan([]byte(`{"schema":1}`))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := setupprogressapp.NewBinding(operationID, plan)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &serverFixture{binding: binding}
	fixture.progress = &progressAuthorityStub{updates: make(chan setupprogressapp.Snapshot, 8)}
	fixture.progress.current = fixture.snapshot(state, 1)
	fixture.setup = &mcpSetupStub{}
	fixture.cancellation = &mcpCancellationStub{fixture: fixture}
	progressApplication, err := setupprogressapp.NewApplication(binding, fixture.progress, mcpDecisionStub{})
	if err != nil {
		t.Fatal(err)
	}
	fixture.application, err = mcpbootstrapapp.New(
		testMCPInstallationID, progressApplication, fixture.setup, fixture.cancellation,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.ready = &readyProviderStub{surface: ReadySurface{
		Tools: []ReadyTool{{
			Tool: &mcp.Tool{
				Name: "memory_recall", Description: "Recall from the ready local Brain", InputSchema: objectJSON(),
			},
			Handler: productTool,
		}},
		Resources: []ReadyResource{{
			Resource: &mcp.Resource{URI: "agentmemory://ready", Name: "AgentMemory ready state"},
			Handler:  productResource,
		}},
	}}
	return fixture
}

func (f *serverFixture) snapshot(state setupprogressapp.State, sequence uint64) setupprogressapp.Snapshot {
	message, action := setupprogressapp.MessagePreparingRuntime, setupprogressapp.ActionCancel
	//nolint:exhaustive // All other setup states intentionally use the running projection.
	switch state {
	case setupprogressapp.StateReady:
		message, action = setupprogressapp.MessageReady, setupprogressapp.ActionNone
	case setupprogressapp.StateCancelled:
		message, action = setupprogressapp.MessageCancelled, setupprogressapp.ActionNone
	}
	snapshot, err := setupprogressapp.NewSnapshot(setupprogressapp.SnapshotInput{
		Sequence: sequence, OperationID: f.binding.OperationID(), PlanDigest: f.binding.PlanDigest(),
		State: state, Phase: setupprogressapp.PhaseEnsureContainerRuntime,
		MessageKey: message, SafeAction: action,
		Progress: setupprogressapp.Progress{CompletedStages: 1, TotalStages: 14, TotalBytes: 1024},
	})
	if err != nil {
		panic(err)
	}
	return snapshot
}

type progressAuthorityStub struct {
	mu      sync.RWMutex
	current setupprogressapp.Snapshot
	updates chan setupprogressapp.Snapshot
}

func (p *progressAuthorityStub) CurrentSnapshot(ctx context.Context, _ setupprogressapp.Binding) (setupprogressapp.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return setupprogressapp.Snapshot{}, err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.current, nil
}

func (p *progressAuthorityStub) WaitSnapshotAfter(
	ctx context.Context,
	_ setupprogressapp.Binding,
	after uint64,
) (setupprogressapp.Snapshot, error) {
	for {
		p.mu.RLock()
		current := p.current
		p.mu.RUnlock()
		if current.Sequence() > after {
			return current, nil
		}
		select {
		case snapshot := <-p.updates:
			if snapshot.Sequence() > after {
				return snapshot, nil
			}
		case <-ctx.Done():
			return setupprogressapp.Snapshot{}, ctx.Err()
		}
	}
}

func (p *progressAuthorityStub) publish(snapshot setupprogressapp.Snapshot) {
	p.mu.Lock()
	p.current = snapshot
	p.mu.Unlock()
	p.updates <- snapshot
}

type mcpDecisionStub struct{}

func (mcpDecisionStub) ApplyDecision(context.Context, setupprogressapp.DecisionCommand) (setupprogressapp.DecisionReceipt, error) {
	return setupprogressapp.DecisionReceipt{}, errors.New("unused")
}

type mcpSetupStub struct{ calls atomic.Int32 }

func (s *mcpSetupStub) OpenSetup(context.Context) error {
	s.calls.Add(1)
	return nil
}

type mcpCancellationStub struct {
	fixture *serverFixture
	calls   atomic.Int32
}

func (c *mcpCancellationStub) RequestCancellation(ctx context.Context) error {
	c.calls.Add(1)
	current, _ := c.fixture.progress.CurrentSnapshot(ctx, c.fixture.binding)
	c.fixture.progress.publish(c.fixture.snapshot(setupprogressapp.StateCancelled, current.Sequence()+1))
	return nil
}

type readyProviderStub struct {
	surface ReadySurface
	err     error
	calls   atomic.Int32
}

func (r *readyProviderStub) ReadySurface(context.Context) (ReadySurface, error) {
	r.calls.Add(1)
	return r.surface, r.err
}

func productTool(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ready"}}}, nil
}

func productResource(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{
		URI: "agentmemory://ready", MIMEType: "application/json", Text: `{"ready":true}`,
	}}}, nil
}

func objectJSON() json.RawMessage {
	return json.RawMessage(`{"type":"object","additionalProperties":false}`)
}

func assertToolNames(t testing.TB, session *mcp.ClientSession, wanted ...string) {
	t.Helper()
	listed, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	wantedSet := make(map[string]struct{}, len(wanted))
	for _, name := range wanted {
		wantedSet[name] = struct{}{}
	}
	if len(listed.Tools) != len(wantedSet) {
		t.Fatalf("tool count = %d, want %d: %+v", len(listed.Tools), len(wantedSet), listed.Tools)
	}
	for _, tool := range listed.Tools {
		if _, found := wantedSet[tool.Name]; !found || tool.InputSchema == nil {
			t.Fatalf("unexpected or schemaless tool: %+v", tool)
		}
		delete(wantedSet, tool.Name)
	}
	if len(wantedSet) != 0 {
		t.Fatalf("missing tools: %+v", wantedSet)
	}
}

func decodeStructured(t testing.TB, value any, destination any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, destination); err != nil {
		t.Fatal(err)
	}
}

func waitNotification(t testing.TB, channel <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-channel:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}
