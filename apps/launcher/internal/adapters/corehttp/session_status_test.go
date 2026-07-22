package corehttp

import (
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestPF005SessionStatusUsesOnlyScopedCredentialAndExactInternalEndpoint(t *testing.T) {
	t.Parallel()
	sessionID := "019d2b4e-7a10-7def-8abc-0123456789ab"
	brainID := "019d2b4e-7a12-7def-8abc-0123456789ab"
	secret := []byte("01234567890123456789012345678901")
	roundTrip := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.String() != "http://core:9411/v1/session/status" ||
			request.Host != "core:9411" || request.Header.Get("X-AgentMemory-Session-ID") != sessionID ||
			request.Header.Get("Authorization") != "Bearer "+hex.EncodeToString(secret) {
			t.Fatalf("request=%s %s headers=%v", request.Method, request.URL, request.Header)
		}
		return sessionHTTPResponse(`{"session_id":"` + sessionID + `","brain_id":"` + brainID + `","agent_id":"codex","workspace_fingerprint":"` + strings.Repeat("a", 64) + `","git_coverage":"partial","index_coverage":"indexing","state":"active"}`), nil
	})
	client, err := newSessionStatusClient(
		&memoryCredentialSource{value: secret}, "/run/secrets/agentmemory-session", sessionID,
		&http.Client{Transport: roundTrip},
	)
	if err != nil {
		t.Fatal(err)
	}
	status, err := client.Status(t.Context())
	if err != nil || status.SessionID != sessionID || status.BrainID != brainID ||
		status.AgentID != "codex" || status.GitCoverage != "partial" ||
		status.IndexCoverage != "indexing" || status.State != "active" {
		t.Fatalf("Status()=%+v/%v", status, err)
	}
}

func TestPF005SessionStatusRejectsSubstitutionAndMalformedAuthority(t *testing.T) {
	t.Parallel()
	sessionID := "019d2b4e-7a10-7def-8abc-0123456789ab"
	if _, err := NewSessionStatusClient(nil, "/run/secrets/agentmemory-session", sessionID); err == nil {
		t.Fatal("nil credentials accepted")
	}
	if _, err := NewSessionStatusClient(
		&memoryCredentialSource{}, "/foreign", sessionID,
	); err == nil {
		t.Fatal("foreign credential path accepted")
	}
	responses := []string{
		`{"session_id":"019d2b4e-7a10-7def-8abc-0123456789ac","brain_id":"019d2b4e-7a12-7def-8abc-0123456789ab","agent_id":"codex","workspace_fingerprint":"` + strings.Repeat("a", 64) + `","state":"active"}`,
		`{"session_id":"` + sessionID + `","brain_id":"bad","agent_id":"codex","workspace_fingerprint":"` + strings.Repeat("a", 64) + `","state":"active"}`,
		`{"session_id":"` + sessionID + `","brain_id":"019d2b4e-7a12-7def-8abc-0123456789ab","agent_id":"codex","workspace_fingerprint":"bad","state":"active"}`,
		`{"session_id":"` + sessionID + `","brain_id":"019d2b4e-7a12-7def-8abc-0123456789ab","agent_id":"codex","workspace_fingerprint":"` + strings.Repeat("a", 64) + `","state":"completed"}`,
	}
	for _, payload := range responses {
		client, _ := newSessionStatusClient(
			&memoryCredentialSource{value: []byte("01234567890123456789012345678901")},
			"/run/secrets/agentmemory-session", sessionID,
			&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return sessionHTTPResponse(payload), nil
			})},
		)
		if _, err := client.Status(context.Background()); err == nil {
			t.Fatalf("malformed response accepted: %s", payload)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func sessionHTTPResponse(payload string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(payload)),
	}
}
