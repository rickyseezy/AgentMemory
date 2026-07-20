package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	memoryExplainMemoryID   = "018f0000-0000-7000-8000-000000000401"
	memoryExplainBrainID    = "018f0000-0000-7000-8000-000000000004"
	memoryExplainActorID    = "018f0000-0000-7000-8000-000000000002"
	memoryExplainGrantID    = "018f0000-0000-7000-8000-000000000003"
	memoryExplainValidAt    = "2026-07-21T10:00:00.000000Z"
	memoryExplainRecordedAt = "2026-07-21T11:00:00.000000Z"
)

func TestPF001CoreReadySurfacePreflightsAndServesAuthenticatedLiveState(t *testing.T) {
	t.Parallel()
	status := &coreStatusStub{ready: true}
	provider, err := newCoreReadySurface("019f5f20-1234-7abc-8123-0123456789ab", status)
	if err != nil {
		t.Fatal(err)
	}
	surface, err := provider.ReadySurface(context.Background())
	if err != nil || len(surface.Tools) != 1 || len(surface.Resources) != 1 || status.calls != 1 {
		t.Fatalf("ReadySurface()=%+v,%v calls=%d", surface, err, status.calls)
	}
	if surface.Tools[0].Tool.Name != toolBrainStatus || surface.Tools[0].Tool.InputSchema == nil ||
		surface.Tools[0].Tool.OutputSchema == nil || surface.Resources[0].Resource.URI != resourceReady {
		t.Fatalf("surface=%+v", surface)
	}
	toolResult, err := surface.Tools[0].Handler(context.Background(), &mcp.CallToolRequest{})
	if err != nil || toolResult == nil || len(toolResult.Content) != 1 || status.calls != 2 {
		t.Fatalf("tool=%+v,%v calls=%d", toolResult, err, status.calls)
	}
	encoded, _ := json.Marshal(toolResult.StructuredContent)
	if string(encoded) != `{"contract_version":1,"installation_id":"019f5f20-1234-7abc-8123-0123456789ab","ready":true}` {
		t.Fatalf("structured=%s", encoded)
	}
	resourceResult, err := surface.Resources[0].Handler(context.Background(), &mcp.ReadResourceRequest{})
	if err != nil || resourceResult == nil || len(resourceResult.Contents) != 1 ||
		resourceResult.Contents[0].URI != resourceReady || status.calls != 3 {
		t.Fatalf("resource=%+v,%v calls=%d", resourceResult, err, status.calls)
	}
}

func TestMEM002ReadySurfacePublishesStrictMemoryExplainTool(t *testing.T) {
	t.Parallel()
	status := &coreMemoryStub{
		coreStatusStub: coreStatusStub{ready: true},
		response:       json.RawMessage(`{"memory_id":"018f0000-0000-7000-8000-000000000401","effective":true}`),
	}
	provider, err := newCoreReadySurface("installation", status)
	if err != nil {
		t.Fatal(err)
	}
	surface, err := provider.ReadySurface(context.Background())
	if err != nil || len(surface.Tools) != 2 || surface.Tools[1].Tool.Name != toolMemoryExplain {
		t.Fatalf("ReadySurface()=%+v,%v", surface, err)
	}
	inputSchema, inputOK := surface.Tools[1].Tool.InputSchema.(json.RawMessage)
	outputSchema, outputOK := surface.Tools[1].Tool.OutputSchema.(json.RawMessage)
	if !inputOK || !outputOK || !json.Valid(inputSchema) || !json.Valid(outputSchema) ||
		rejectReadyDuplicateJSONKeys(inputSchema) != nil ||
		rejectReadyDuplicateJSONKeys(outputSchema) != nil ||
		surface.Tools[1].Tool.Annotations == nil || !surface.Tools[1].Tool.Annotations.ReadOnlyHint ||
		surface.Tools[1].Tool.Annotations.OpenWorldHint == nil ||
		*surface.Tools[1].Tool.Annotations.OpenWorldHint {
		t.Fatalf("memory tool contract=%+v", surface.Tools[1].Tool)
	}
	result, err := surface.Tools[1].Handler(context.Background(), &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{Arguments: json.RawMessage(`{
			"memory_id":"018f0000-0000-7000-8000-000000000401",
			"brain_id":"018f0000-0000-7000-8000-000000000004",
			"actor_id":"018f0000-0000-7000-8000-000000000002",
			"grant_id":"018f0000-0000-7000-8000-000000000003",
			"valid_at":"2026-07-21T10:00:00.000000Z",
			"recorded_at":"2026-07-21T11:00:00.000000Z"
		}`)},
	})
	if err != nil || status.calls != 1 || result == nil || len(result.Content) != 1 {
		t.Fatalf("memory_explain=%+v,%v calls=%d", result, err, status.calls)
	}
	encoded, _ := json.Marshal(result.StructuredContent)
	if string(encoded) != `{"effective":true,"memory_id":"018f0000-0000-7000-8000-000000000401"}` {
		t.Fatalf("structured=%s", encoded)
	}
	if status.input.MemoryID != memoryExplainMemoryID || status.input.BrainID != memoryExplainBrainID ||
		status.input.ActorID != memoryExplainActorID || status.input.GrantID != memoryExplainGrantID ||
		status.input.ValidAt != memoryExplainValidAt || status.input.RecordedAt != memoryExplainRecordedAt {
		t.Fatalf("input=%+v", status.input)
	}
	for name, arguments := range map[string]json.RawMessage{
		"duplicate": json.RawMessage(`{"memory_id":"018f0000-0000-7000-8000-000000000401","memory_id":"018f0000-0000-7000-8000-000000000401","brain_id":"018f0000-0000-7000-8000-000000000004","actor_id":"018f0000-0000-7000-8000-000000000002","grant_id":"018f0000-0000-7000-8000-000000000003","valid_at":"2026-07-21T10:00:00.000000Z","recorded_at":"2026-07-21T11:00:00.000000Z"}`),
		"unknown":   json.RawMessage(`{"memory_id":"x","unknown":true}`),
		"missing":   json.RawMessage(`{}`),
		"unsafe":    json.RawMessage(`{"memory_id":"../../status","brain_id":"018f0000-0000-7000-8000-000000000004","actor_id":"018f0000-0000-7000-8000-000000000002","grant_id":"018f0000-0000-7000-8000-000000000003","valid_at":"2026-07-21T10:00:00.000000Z","recorded_at":"2026-07-21T11:00:00.000000Z"}`),
	} {
		if rejected, callErr := surface.Tools[1].Handler(context.Background(), &mcp.CallToolRequest{
			Params: &mcp.CallToolParamsRaw{Arguments: arguments},
		}); rejected != nil || callErr == nil {
			t.Fatalf("%s=%+v,%v", name, rejected, callErr)
		}
	}
}

func TestMEM002ReadyMemoryHandlerFailsClosedOnCoreRegressionOrAmbiguousOutput(t *testing.T) {
	t.Parallel()
	status := &coreMemoryStub{
		coreStatusStub: coreStatusStub{ready: true},
		response:       json.RawMessage(`{"memory_id":"first","memory_id":"second"}`),
	}
	provider, err := newCoreReadySurface("installation", status)
	if err != nil {
		t.Fatal(err)
	}
	surface, err := provider.ReadySurface(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	request := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Arguments: json.RawMessage(`{
		"memory_id":"018f0000-0000-7000-8000-000000000401",
		"brain_id":"018f0000-0000-7000-8000-000000000004",
		"actor_id":"018f0000-0000-7000-8000-000000000002",
		"grant_id":"018f0000-0000-7000-8000-000000000003",
		"valid_at":"2026-07-21T10:00:00.000000Z",
		"recorded_at":"2026-07-21T11:00:00.000000Z"
	}`)}}
	if result, callErr := surface.Tools[1].Handler(context.Background(), request); result != nil || callErr == nil {
		t.Fatalf("ambiguous output=%+v,%v", result, callErr)
	}
	status.response = json.RawMessage(`[]`)
	if result, callErr := surface.Tools[1].Handler(context.Background(), request); result != nil || callErr == nil {
		t.Fatalf("non-object output=%+v,%v", result, callErr)
	}
	status.response = json.RawMessage(`{"memory_id":"safe"}`)
	status.err = errors.New("private core error")
	if result, callErr := surface.Tools[1].Handler(context.Background(), request); result != nil || callErr == nil ||
		callErr.Error() != "memory explanation is unavailable" {
		t.Fatalf("private error=%+v,%v", result, callErr)
	}
	status.err = nil
	status.ready = false
	if result, callErr := surface.Tools[1].Handler(context.Background(), request); result != nil || callErr == nil {
		t.Fatalf("regressed core=%+v,%v", result, callErr)
	}
}

func TestPF001CoreReadySurfaceRejectsMissingAndRegressedAuthority(t *testing.T) {
	t.Parallel()
	if _, err := newCoreReadySurface("", &coreStatusStub{ready: true}); err == nil {
		t.Fatal("empty installation identity accepted")
	}
	if _, err := newCoreReadySurface("valid", (*coreStatusStub)(nil)); err == nil {
		t.Fatal("typed nil status accepted")
	}
	provider, _ := newCoreReadySurface("installation", &coreStatusStub{})
	if _, err := provider.ReadySurface(context.Background()); err == nil {
		t.Fatal("not-Ready Core accepted")
	}
	provider.status = &coreStatusStub{ready: true, err: errors.New("private")}
	if _, err := provider.ReadySurface(context.Background()); err == nil {
		t.Fatal("failed Core status accepted")
	}
	var nilProvider *coreReadySurface
	if _, err := nilProvider.ReadySurface(context.Background()); err == nil {
		t.Fatal("nil surface accepted")
	}
	var nilContext context.Context
	if _, err := provider.ReadySurface(nilContext); err == nil {
		t.Fatal("nil context accepted")
	}
}

func TestPF001CoreReadyHandlersFailClosedAfterCoreRegression(t *testing.T) {
	t.Parallel()
	status := &coreStatusStub{ready: true}
	provider, _ := newCoreReadySurface("installation", status)
	surface, _ := provider.ReadySurface(context.Background())
	status.ready = false
	if result, err := surface.Tools[0].Handler(context.Background(), nil); result != nil || err == nil {
		t.Fatalf("regressed tool=%+v,%v", result, err)
	}
	if result, err := surface.Resources[0].Handler(context.Background(), nil); result != nil || err == nil {
		t.Fatalf("regressed resource=%+v,%v", result, err)
	}
	var nilContext context.Context
	if _, err := provider.statusPayload(nilContext); err == nil {
		t.Fatal("nil status context accepted")
	}
}

func TestPF001CoreReadySurfacePublishesTwoStepManagedRuntimeRemoval(t *testing.T) {
	t.Parallel()
	removal := &managedRuntimeRemovalStub{plan: managedRuntimeRemovalPlan{
		OperationID: "019f5f20-1234-7abc-8123-0123456789ac",
		PlanDigest:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Impact:      "remove-managed-runtime-and-local-runtime-data",
		Platform:    "darwin", Product: "docker-desktop", Version: "4.43.2",
	}}
	provider, err := newCoreReadySurfaceWithRemoval("installation", &coreStatusStub{ready: true}, removal)
	if err != nil {
		t.Fatal(err)
	}
	surface, err := provider.ReadySurface(context.Background())
	if err != nil || len(surface.Tools) != 3 {
		t.Fatalf("ReadySurface()=%+v,%v", surface, err)
	}
	prepareTool, removeTool := surface.Tools[1], surface.Tools[2]
	if prepareTool.Tool.Name != toolManagedRuntimeRemovalPlan || removeTool.Tool.Name != toolRemoveManagedRuntime ||
		prepareTool.Tool.Annotations == nil || prepareTool.Tool.Annotations.ReadOnlyHint ||
		removeTool.Tool.Annotations == nil || removeTool.Tool.Annotations.DestructiveHint == nil ||
		!*removeTool.Tool.Annotations.DestructiveHint {
		t.Fatalf("removal tools=%+v,%+v", prepareTool.Tool, removeTool.Tool)
	}
	prepared, err := prepareTool.Handler(context.Background(), &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{Arguments: json.RawMessage(`{}`)},
	})
	if err != nil || removal.prepareCalls != 1 {
		t.Fatalf("prepare=%+v,%v calls=%d", prepared, err, removal.prepareCalls)
	}
	encoded, _ := json.Marshal(prepared.StructuredContent)
	if string(encoded) != `{"contract_version":1,"explicit_confirmation_preselected":false,"impact":"remove-managed-runtime-and-local-runtime-data","operation_id":"019f5f20-1234-7abc-8123-0123456789ac","plan_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":"darwin","product":"docker-desktop","version":"4.43.2"}` {
		t.Fatalf("prepared=%s", encoded)
	}
	removed, err := removeTool.Handler(context.Background(), &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{Arguments: json.RawMessage(`{"operation_id":"019f5f20-1234-7abc-8123-0123456789ac","plan_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","impact":"remove-managed-runtime-and-local-runtime-data","approved":true,"explicit_confirmation":true}`)},
	})
	if err != nil || removal.removeCalls != 1 || !removal.input.Approved || !removal.input.ExplicitConfirmation {
		t.Fatalf("remove=%+v,%v stub=%+v", removed, err, removal)
	}
	encoded, _ = json.Marshal(removed.StructuredContent)
	if string(encoded) != `{"contract_version":1,"operation_id":"019f5f20-1234-7abc-8123-0123456789ac","outcome":"removed","plan_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}` {
		t.Fatalf("removed=%s", encoded)
	}
}

func TestPF001ManagedRuntimeRemovalReadyHandlersRejectImplicitOrSubstitutedDecisions(t *testing.T) {
	t.Parallel()
	if (managedRuntimeRemovalPlan{}).valid() || (managedRuntimeRemovalPlan{
		OperationID: " operation", PlanDigest: "digest", Impact: "impact",
		Platform: "linux", Product: "docker-ce", Version: "1",
	}).valid() {
		t.Fatal("invalid public removal plan accepted")
	}
	removal := &managedRuntimeRemovalStub{plan: managedRuntimeRemovalPlan{
		OperationID: "operation", PlanDigest: "digest", Impact: "impact",
		Platform: "linux", Product: "docker-ce", Version: "1",
	}}
	provider, _ := newCoreReadySurfaceWithRemoval("installation", &coreStatusStub{ready: true}, removal)
	surface, _ := provider.ReadySurface(context.Background())
	for name, raw := range map[string]string{
		"missing request":          "",
		"implicit approval":        `{"operation_id":"operation","plan_digest":"digest","impact":"impact","approved":true,"explicit_confirmation":false}`,
		"substituted impact":       `{"operation_id":"operation","plan_digest":"digest","impact":"other","approved":true,"explicit_confirmation":true}`,
		"unknown input":            `{"operation_id":"operation","plan_digest":"digest","impact":"impact","approved":false,"explicit_confirmation":false,"extra":true}`,
		"non-object prepare input": `[]`,
	} {
		var handler mcp.ToolHandler
		var request *mcp.CallToolRequest
		if name == "non-object prepare input" {
			handler = surface.Tools[1].Handler
			request = &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Arguments: json.RawMessage(raw)}}
		} else {
			handler = surface.Tools[2].Handler
			if raw != "" {
				request = &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Arguments: json.RawMessage(raw)}}
			}
		}
		if result, err := handler(context.Background(), request); result != nil || err == nil {
			t.Fatalf("%s result=%+v error=%v", name, result, err)
		}
	}
	if result, err := surface.Tools[1].Handler(context.Background(), &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{Arguments: json.RawMessage(`{}{}`)},
	}); result != nil || err == nil {
		t.Fatalf("trailing prepare input result=%+v error=%v", result, err)
	}
	if removal.removeCalls != 0 {
		t.Fatalf("destructive boundary calls=%d", removal.removeCalls)
	}
	removal.prepareErr = errors.New("private prepare")
	if result, err := surface.Tools[1].Handler(context.Background(), &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{Arguments: json.RawMessage(`{}`)},
	}); result != nil || err == nil {
		t.Fatalf("private prepare result=%+v error=%v", result, err)
	}
	removal.prepareErr = nil
	removal.removeErr = errors.New("private removal")
	if result, err := surface.Tools[2].Handler(context.Background(), &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{Arguments: json.RawMessage(`{"operation_id":"operation","plan_digest":"digest","impact":"impact","approved":false,"explicit_confirmation":false}`)},
	}); result != nil || err == nil {
		t.Fatalf("private removal result=%+v error=%v", result, err)
	}
	if _, err := newCoreReadySurfaceWithRemoval("installation", &coreStatusStub{ready: true}, (*managedRuntimeRemovalStub)(nil)); err == nil {
		t.Fatal("typed nil removal controller accepted")
	}
	if result, err := readyToolResult(make(chan int)); result != nil || err == nil {
		t.Fatalf("unencodable response=%+v error=%v", result, err)
	}
}

type coreStatusStub struct {
	ready bool
	err   error
	calls int
}

type coreMemoryStub struct {
	coreStatusStub
	response json.RawMessage
	input    memoryExplainInput
	calls    int
	err      error
}

func (s *coreMemoryStub) ExplainMemory(
	_ context.Context,
	memoryID string,
	brainID string,
	actorID string,
	grantID string,
	validAt string,
	recordedAt string,
) (json.RawMessage, error) {
	s.calls++
	s.input = memoryExplainInput{
		MemoryID: memoryID, BrainID: brainID, ActorID: actorID, GrantID: grantID,
		ValidAt: validAt, RecordedAt: recordedAt,
	}
	return append(json.RawMessage(nil), s.response...), s.err
}

type managedRuntimeRemovalStub struct {
	plan         managedRuntimeRemovalPlan
	input        managedRuntimeRemovalDecision
	prepareCalls int
	removeCalls  int
	prepareErr   error
	removeErr    error
}

func (s *managedRuntimeRemovalStub) PrepareManagedRuntimeRemoval(context.Context) (managedRuntimeRemovalPlan, error) {
	s.prepareCalls++
	return s.plan, s.prepareErr
}

func (s *managedRuntimeRemovalStub) DecideManagedRuntimeRemoval(
	_ context.Context,
	input managedRuntimeRemovalDecision,
) (managedRuntimeRemovalResult, error) {
	s.removeCalls++
	s.input = input
	return managedRuntimeRemovalResult{
		OperationID: s.plan.OperationID, PlanDigest: s.plan.PlanDigest, Outcome: "removed",
	}, s.removeErr
}

func (s *coreStatusStub) Ready(context.Context) (bool, error) {
	s.calls++
	return s.ready, s.err
}
