package mcpsessionbridge

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/corehttp"
)

func TestPF005BridgeExposesOnlyAuthenticatedSessionScopedSurface(t *testing.T) {
	t.Parallel()
	status := &statusPort{value: corehttp.SessionStatus{
		SessionID: "019d2b4e-7a10-7def-8abc-0123456789ab", AgentID: "codex",
		BrainID:              "019d2b4e-7a12-7def-8abc-0123456789ab",
		WorkspaceFingerprint: strings.Repeat("a", 64), GitCoverage: "partial",
		IndexCoverage: "partial", State: "active",
	}}
	status.recall = corehttp.SessionRecall{
		Status: "ready", ScopeFingerprint: strings.Repeat("b", 64),
		ContextEventID: "019d2b4e-7a13-7def-8abc-0123456789ab",
		PolicyVersion:  "session-briefing.v1", UsedItems: 1,
		Items: []corehttp.RecallItem{{
			ItemID: "decision-auth", SemanticID: "decision-auth", Kind: "decision",
			Content: "Use the shared API.", Category: "decision", Freshness: "current",
			RevisionCompatibility: "unknown", Rank: 1, Classification: "internal",
			EvidenceEventID: "019d2b4e-7a11-7def-8abc-0123456789ab",
			OccurredAt:      "2026-07-20T10:12:13Z",
			Provenance: corehttp.RecallProvenance{
				ProducerHost: "claude_code", ModelID: "claude-sonnet",
				AdapterID: "agentmemory.claude-code", AdapterVersion: "1.0.0",
				CaptureMethod: "native",
			},
		}},
	}
	server, err := NewServer(status, status)
	if err != nil {
		t.Fatal(err)
	}
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx, serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	tools, err := session.ListTools(ctx, nil)
	if err != nil || len(tools.Tools) != 2 || tools.Tools[0].Name != toolBrainStatus ||
		tools.Tools[1].Name != toolRecallContext {
		t.Fatalf("tools=%+v/%v", tools, err)
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: toolBrainStatus})
	if err != nil || result.IsError {
		t.Fatalf("brain_status=%+v/%v", result, err)
	}
	payload, err := json.Marshal(result.StructuredContent)
	if err != nil || !strings.Contains(string(payload), status.value.SessionID) ||
		strings.Contains(string(payload), "/workspace") {
		t.Fatalf("status payload=%s/%v", payload, err)
	}
	resources, err := session.ListResources(ctx, nil)
	if err != nil || len(resources.Resources) != 1 || resources.Resources[0].URI != resourceSession {
		t.Fatalf("resources=%+v/%v", resources, err)
	}
	read, err := session.ReadResource(ctx, &mcp.ReadResourceParams{URI: resourceSession})
	if err != nil || len(read.Contents) != 1 || !strings.Contains(read.Contents[0].Text, status.value.SessionID) {
		t.Fatalf("resource=%+v/%v", read, err)
	}
	if status.calls != 2 {
		t.Fatalf("status calls=%d", status.calls)
	}
	recalled, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      toolRecallContext,
		Arguments: map[string]any{"operation_id": "turn-42", "mode": "global"},
	})
	if err != nil || recalled.IsError {
		t.Fatalf("recall_context=%+v/%v", recalled, err)
	}
	recallPayload, err := json.Marshal(recalled.StructuredContent)
	if err != nil || !strings.Contains(string(recallPayload), "Use the shared API") ||
		!strings.Contains(string(recallPayload), `"untrusted_historical_data":true`) ||
		strings.Contains(string(recallPayload), "/workspace") {
		t.Fatalf("recall payload=%s/%v", recallPayload, err)
	}
	if status.recallCalls != 1 || status.request.Mode != "global" ||
		status.request.OperationID != "turn-42" || status.request.Budget.MaxTokens != 1200 {
		t.Fatalf("recall request=%+v calls=%d", status.request, status.recallCalls)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bridge did not stop after EOF")
	}
}

func TestPF005BridgeRejectsPartialCompositionAndPropagatesStatusFailure(t *testing.T) {
	t.Parallel()
	valid := &statusPort{}
	if _, err := NewServer(nil, valid); err == nil {
		t.Fatal("nil status port accepted")
	}
	var typedNil *statusPort
	if _, err := NewServer(typedNil, valid); err == nil {
		t.Fatal("typed nil status port accepted")
	}
	if _, err := NewServer(valid, typedNil); err == nil {
		t.Fatal("typed nil recall port accepted")
	}
	server, _ := NewServer(
		&statusPort{err: context.DeadlineExceeded},
		&statusPort{recallErr: context.DeadlineExceeded},
	)
	if _, _, err := server.handleStatus(t.Context(), nil, emptyInput{}); err == nil {
		t.Fatal("status failure hidden")
	}
	if _, _, err := server.handleRecall(t.Context(), nil, recallInput{OperationID: "turn"}); err == nil {
		t.Fatal("recall failure hidden")
	}
	if _, err := server.handleResource(t.Context(), nil); err == nil {
		t.Fatal("resource failure hidden")
	}
}

func TestPF005BridgeDefaultsRecallAndEmitsArraysForEmptyHistory(t *testing.T) {
	t.Parallel()
	port := &statusPort{recall: corehttp.SessionRecall{Status: "no_answer"}}
	server, err := NewServer(port, port)
	if err != nil {
		t.Fatal(err)
	}
	_, output, err := server.handleRecall(
		t.Context(), nil, recallInput{OperationID: "turn-empty"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if port.request.Mode != "current" || port.request.MaxRelatedDepth != 3 ||
		port.request.MaxRelatedCost != 10 || port.request.Budget.MaxTokens != 1200 ||
		port.request.Budget.MaxItems != 12 || port.request.Budget.MaxBytes != 20480 {
		t.Fatalf("default request=%+v", port.request)
	}
	if output.Items == nil || output.Procedures == nil || output.ExcludedItems == nil ||
		output.ExcludedProcedures == nil || !output.UntrustedHistoricalData {
		t.Fatalf("empty output=%+v", output)
	}
}

func TestPF005BridgeRunAndNilCapabilityGuardsAreClosed(t *testing.T) {
	t.Parallel()
	port := &statusPort{}
	server, err := NewServer(port, port)
	if err != nil {
		t.Fatal(err)
	}
	//lint:ignore SA1012 Deliberately verifies the public nil-context boundary.
	if err := server.Run(nil, nil); err == nil { //nolint:staticcheck // Deliberate invalid boundary.
		t.Fatal("Run(nil) error=nil")
	}
	broken := &Server{status: port, recall: port}
	if err := broken.Run(t.Context(), nil); err == nil {
		t.Fatal("Run(missing server) error=nil")
	}
	var nilMap map[string]string
	var nilSlice []string
	var nilFunction func()
	if !nilCapability(nilMap) || !nilCapability(nilSlice) || !nilCapability(nilFunction) ||
		!nilCapability(nil) || nilCapability(1) {
		t.Fatal("nil capability classification diverged")
	}
}

func TestPF005MountedCredentialRejectsPathContextAndAbsentSecret(t *testing.T) {
	t.Parallel()
	reader := MountedCredential{}
	//lint:ignore SA1012 Deliberately verifies the public nil-context boundary.
	if _, err := reader.ReadCredential(nil, credentialPath); err == nil { //nolint:staticcheck // Deliberate invalid boundary.
		t.Fatal("nil context accepted")
	}
	if _, err := reader.ReadCredential(t.Context(), "/tmp/foreign"); err == nil {
		t.Fatal("foreign credential path accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := reader.ReadCredential(ctx, credentialPath); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled credential read=%v", err)
	}
	if _, err := reader.ReadCredential(t.Context(), credentialPath); err == nil {
		t.Fatal("absent fixed credential accepted")
	}
}

func TestPF005RecallOutputSchemaClosesEveryNestedObject(t *testing.T) {
	t.Parallel()
	var root map[string]any
	if err := json.Unmarshal([]byte(recallOutputSchema), &root); err != nil {
		t.Fatal(err)
	}
	properties := objectSchema(t, root["properties"])
	for _, name := range []string{"items", "procedures", "excluded_items", "excluded_procedures"} {
		array := objectSchema(t, properties[name])
		item := objectSchema(t, array["items"])
		if closed, ok := item["additionalProperties"].(bool); !ok || closed {
			t.Fatalf("%s item schema is open: %+v", name, item)
		}
	}
	items := objectSchema(t, objectSchema(t, properties["items"])["items"])
	itemProperties := objectSchema(t, items["properties"])
	provenance := objectSchema(t, itemProperties["provenance"])
	if closed, ok := provenance["additionalProperties"].(bool); !ok || closed {
		t.Fatalf("provenance schema is open: %+v", provenance)
	}
}

func objectSchema(t testing.TB, value any) map[string]any {
	t.Helper()
	resolved, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("schema value=%T", value)
	}
	return resolved
}

type statusPort struct {
	value       corehttp.SessionStatus
	err         error
	calls       int
	recall      corehttp.SessionRecall
	recallErr   error
	recallCalls int
	request     corehttp.SessionRecallRequest
}

func (p *statusPort) Recall(
	_ context.Context,
	request corehttp.SessionRecallRequest,
) (corehttp.SessionRecall, error) {
	p.recallCalls++
	p.request = request
	return p.recall, p.recallErr
}

func (p *statusPort) Status(context.Context) (corehttp.SessionStatus, error) {
	p.calls++
	return p.value, p.err
}
