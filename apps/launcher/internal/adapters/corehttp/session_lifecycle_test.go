package corehttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpsessionapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/mcpsession"
)

func TestPF005SessionLifecycleRepositorySendsExactBoundedTransitions(t *testing.T) {
	t.Parallel()
	plan := dockerExecutionPlan(t)
	paths := []string{beginSessionPath, heartbeatSessionPath, finishSessionPath}
	states := []string{"active", "active", "completed"}
	revisions := []string{"1", "2", "3"}
	call := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if call >= len(paths) || request.Method != http.MethodPost || request.URL.Path != paths[call] ||
			request.Header.Get("Idempotency-Key") != plan.SessionID() ||
			request.Header.Get("X-Correlation-ID") != plan.SessionID() ||
			request.Header.Get("Authorization") == "" {
			t.Errorf("unexpected lifecycle request %d: %s %s", call, request.Method, request.URL.Path)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body["session_id"] != plan.SessionID() {
			t.Errorf("request body=%v error=%v", body, err)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"session_id":"` + plan.SessionID() + `","state":"` +
			states[call] + `","revision":` + revisions[call] + `}`))
		call++
	}))
	defer server.Close()
	repository, err := NewSessionLifecycleRepository(
		&memoryCredentialSource{value: []byte("01234567890123456789012345678901")},
		server.URL,
		"/owner/root.credential",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Begin(t.Context(), plan, 120*time.Second); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 7, 22, 12, 0, 30, 123456000, time.UTC)
	if err := repository.Heartbeat(t.Context(), plan.SessionID(), at); err != nil {
		t.Fatal(err)
	}
	if err := repository.Finish(
		t.Context(), plan.SessionID(), mcpsessionapp.StatusCompleted, at.Add(time.Second),
	); err != nil {
		t.Fatal(err)
	}
	if call != len(paths) {
		t.Fatalf("calls=%d", call)
	}
}

func dockerExecutionPlan(t testing.TB) mcpsession.ExecutionPlan {
	t.Helper()
	workspace, err := mcpsession.NewWorkspaceIdentity(mcpsession.WorkspaceIdentityInput{
		LogicalPath: "/workspace", RealPath: "/workspace", DeviceIdentity: "dev:1",
		PathFingerprint: strings.Repeat("a", 64), GitCoverage: mcpsession.GitCoverageNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	credential, err := mcpsession.NewCredentialLease(
		strings.Repeat("c", 64), "/owner/session.key", issued, issued.Add(12*time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := mcpsession.NewExecutionPlan(mcpsession.ExecutionPlanInput{
		SessionID: "019d2b4e-7a10-7def-8abc-0123456789ab", InstallationID: "019d2b4e-7a11-7def-8abc-0123456789ab",
		AgentID: "codex", ReleaseID: "v1.0.0", ManifestDigest: strings.Repeat("d", 64),
		SecurityEpoch: 7, RuntimeEndpoint: "unix:///var/run/docker.sock", Workspace: workspace,
		Image:   "registry.local/agentmemory/mcp-session@sha256:" + strings.Repeat("b", 64),
		Network: "agentmemory_019d2b4e7a117def8abc0123456789ab_internal", Credential: credential,
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestPF005SessionLifecycleRepositoryRejectsRemoteInvalidAndDivergentResponses(t *testing.T) {
	t.Parallel()
	credentials := &memoryCredentialSource{value: []byte("01234567890123456789012345678901")}
	if _, err := NewSessionLifecycleRepository(credentials, "https://example.com", "/owner/root"); err == nil {
		t.Fatal("remote endpoint error=nil")
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"session_id":"foreign","state":"active","revision":1}`))
	}))
	defer server.Close()
	repository, _ := NewSessionLifecycleRepository(credentials, server.URL, "/owner/root")
	plan := dockerExecutionPlan(t)
	if err := repository.Begin(t.Context(), plan, 120*time.Second); err == nil {
		t.Fatal("divergent response error=nil")
	}
	if err := repository.Begin(t.Context(), plan, 121*time.Second); err == nil {
		t.Fatal("unbounded lease error=nil")
	}
	if err := repository.Finish(t.Context(), plan.SessionID(), "unknown", time.Now()); err == nil {
		t.Fatal("invalid status error=nil")
	}
}
