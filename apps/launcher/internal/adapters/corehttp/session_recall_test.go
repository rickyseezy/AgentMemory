package corehttp

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestPF005SessionRecallUsesScopedCredentialAndSendsNoIdentityClaims(t *testing.T) {
	t.Parallel()
	sessionID := "019d2b4e-7a10-7def-8abc-0123456789ab"
	secret := []byte("01234567890123456789012345678901")
	roundTrip := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost ||
			request.URL.String() != "http://core:9411/v1/session/recall:brief" ||
			request.Host != "core:9411" ||
			request.Header.Get("X-AgentMemory-Session-ID") != sessionID ||
			request.Header.Get("Authorization") != "Bearer "+hex.EncodeToString(secret) ||
			request.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("request=%s %s headers=%v", request.Method, request.URL, request.Header)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		if json.Unmarshal(body, &document) != nil || len(document) != 5 ||
			document["operation_id"] != "turn-42" || document["mode"] != "global" {
			t.Fatalf("body=%s", body)
		}
		for _, forbidden := range []string{
			"brain_id", "actor_id", "grant_id", "project_id", "repository_id", "checkout_id",
		} {
			if _, exists := document[forbidden]; exists {
				t.Fatalf("identity claim %q reached Core", forbidden)
			}
		}
		return sessionHTTPResponse(validSessionRecallJSON()), nil
	})
	client, err := newSessionStatusClient(
		&memoryCredentialSource{value: secret}, "/run/secrets/agentmemory-session", sessionID,
		&http.Client{Transport: roundTrip},
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Recall(t.Context(), validSessionRecallRequest())
	if err != nil || result.Status != "ready" || len(result.Items) != 1 ||
		result.Items[0].Provenance.ProducerHost != "claude_code" {
		t.Fatalf("Recall()=%+v/%v", result, err)
	}
}

func TestPF005SessionRecallRejectsInvalidRequestsAndResponses(t *testing.T) {
	t.Parallel()
	sessionID := "019d2b4e-7a10-7def-8abc-0123456789ab"
	client, _ := newSessionStatusClient(
		&memoryCredentialSource{value: []byte("01234567890123456789012345678901")},
		"/run/secrets/agentmemory-session", sessionID,
		&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return sessionHTTPResponse(validSessionRecallJSON()), nil
		})},
	)
	invalid := validSessionRecallRequest()
	invalid.Mode = "selected"
	if _, err := client.Recall(t.Context(), invalid); err == nil {
		t.Fatal("selected session scope accepted")
	}

	responses := []string{
		strings.Replace(validSessionRecallJSON(), `"consumer_host":"generic"`, `"consumer_host":"codex"`, 1),
		strings.Replace(validSessionRecallJSON(), `"scope_fingerprint":"`+strings.Repeat("a", 64)+`"`, `"scope_fingerprint":"bad"`, 1),
		strings.Replace(validSessionRecallJSON(), `"producer_host":"claude_code"`, `"producer_host":"claude_code\rforged"`, 1),
		strings.Replace(validSessionRecallJSON(), `"producer_host":"claude_code"`, `"producer_host":"claude_code\nforged"`, 1),
		strings.Replace(validSessionRecallJSON(), `"used_items":1`, `"used_items":2`, 1),
		strings.Replace(validSessionRecallJSON(), `"status":"ready"`, `"status":"secret"`, 1),
	}
	for _, payload := range responses {
		candidate, _ := newSessionStatusClient(
			&memoryCredentialSource{value: []byte("01234567890123456789012345678901")},
			"/run/secrets/agentmemory-session", sessionID,
			&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return sessionHTTPResponse(payload), nil
			})},
		)
		if _, err := candidate.Recall(t.Context(), validSessionRecallRequest()); err == nil {
			t.Fatalf("malformed response accepted: %s", payload)
		}
	}
}

func TestPF005SessionRecallAllowsMultilineContentButRejectsMultilineTokens(t *testing.T) {
	t.Parallel()
	if !safeRecallText("first\nsecond", 64) || safeRecallToken("first\nsecond", 64) ||
		!safeRecallToken("session-briefing.v1", 64) {
		t.Fatal("recall text and token validation diverged")
	}
}

func validSessionRecallRequest() SessionRecallRequest {
	return SessionRecallRequest{
		OperationID: "turn-42", Mode: "global", MaxRelatedDepth: 3, MaxRelatedCost: 10,
		Budget: SessionRecallBudget{MaxTokens: 1200, MaxItems: 12, MaxBytes: 20480},
	}
}

func validSessionRecallJSON() string {
	return `{"consumer_host":"generic","media_type":"application/json",` +
		`"rendered_context":"{\"status\":\"ready\"}",` +
		`"items":[{"item_id":"decision-auth","semantic_id":"decision-auth",` +
		`"kind":"decision","content":"Use the shared user API.","category":"decision",` +
		`"freshness":"current","revision_compatibility":"unknown","rank":1,` +
		`"classification":"internal",` +
		`"evidence_event_id":"019d2b4e-7a11-7def-8abc-0123456789ab",` +
		`"occurred_at":"2026-07-20T10:12:13Z",` +
		`"provenance":{"producer_host":"claude_code","model_id":"claude-sonnet",` +
		`"adapter_id":"agentmemory.claude-code","adapter_version":"1.0.0",` +
		`"capture_method":"native"}}],"procedures":[],"excluded_procedures":[],` +
		`"excluded_items":[],"used_tokens":64,"used_items":1,"used_bytes":128,` +
		`"truncated":false,"scope_fingerprint":"` + strings.Repeat("a", 64) + `",` +
		`"status":"ready","context_event_id":"019d2b4e-7a13-7def-8abc-0123456789ab",` +
		`"policy_version":"session-briefing.v1"}`
}
