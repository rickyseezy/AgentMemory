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

type coreStatusStub struct {
	ready bool
	err   error
	calls int
}

func (s *coreStatusStub) Ready(context.Context) (bool, error) {
	s.calls++
	return s.ready, s.err
}
