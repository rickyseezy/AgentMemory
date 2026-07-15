package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
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
