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

func TestPF005SessionCredentialRegistrarRegistersHashOnlyAuthority(t *testing.T) {
	t.Parallel()
	registration := coreRegistration()
	var received registerSessionCredentialRequest
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != registerSessionCredentialPath ||
			request.Header.Get("Idempotency-Key") != registration.Scope.SessionID ||
			request.Header.Get("X-Correlation-ID") != registration.Scope.SessionID ||
			request.Header.Get("Authorization") == "" || request.Header.Get("Origin") != "" {
			t.Errorf("unexpected request boundary: %s %s", request.Method, request.URL.Path)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&received); err != nil {
			t.Errorf("decode registration: %v", err)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte(`{"session_id":"` + registration.Scope.SessionID +
			`","credential_digest":"` + registration.Digest + `","status":"registered"}`))
	}))
	defer server.Close()
	registrar, err := NewSessionCredentialRegistrar(
		&memoryCredentialSource{value: []byte("01234567890123456789012345678901")},
		server.URL, "/owner/root.credential",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := registrar.Register(t.Context(), registration); err != nil {
		t.Fatal(err)
	}
	if received.SessionID != registration.Scope.SessionID ||
		received.WorkspaceFingerprint != registration.Scope.WorkspaceFingerprint ||
		received.CredentialDigest != registration.Digest || received.SecurityEpoch != 7 ||
		received.IssuedAt != "2026-07-22T12:00:00.000000Z" ||
		received.ExpiresAt != "2026-07-23T00:00:00.000000Z" {
		t.Fatalf("received=%#v", received)
	}
}

func TestPF005SessionCredentialRegistrarRevokesIdempotently(t *testing.T) {
	t.Parallel()
	registration := coreRegistration()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != revokeSessionCredentialPath ||
			request.Header.Get("Idempotency-Key") != registration.Digest {
			t.Errorf("unexpected revoke request")
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		var received revokeSessionCredentialRequest
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil ||
			received.CredentialDigest != registration.Digest {
			t.Errorf("revoke body=%#v error=%v", received, err)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"credential_digest":"` + registration.Digest +
			`","status":"already_revoked"}`))
	}))
	defer server.Close()
	registrar, _ := NewSessionCredentialRegistrar(
		&memoryCredentialSource{value: []byte("01234567890123456789012345678901")},
		server.URL, "/owner/root.credential",
	)
	if err := registrar.Revoke(t.Context(), registration.Digest); err != nil {
		t.Fatal(err)
	}
}

func TestPF005SessionCredentialRegistrarRejectsRemoteInvalidAndDivergentAuthority(t *testing.T) {
	t.Parallel()
	if _, err := NewSessionCredentialRegistrar(
		&memoryCredentialSource{}, "https://example.com", "/owner/root.credential",
	); err == nil {
		t.Fatal("remote registrar error=nil")
	}
	if _, err := NewSessionCredentialRegistrar(nil, "http://127.0.0.1:9411", "/owner/root"); err == nil {
		t.Fatal("nil credential source error=nil")
	}
	registration := coreRegistration()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"session_id":"foreign","credential_digest":"` +
			registration.Digest + `","status":"registered"}`))
	}))
	defer server.Close()
	registrar, _ := NewSessionCredentialRegistrar(
		&memoryCredentialSource{value: []byte("01234567890123456789012345678901")},
		server.URL, "/owner/root.credential",
	)
	if err := registrar.Register(t.Context(), registration); err == nil {
		t.Fatal("divergent registration response error=nil")
	}
	invalid := registration
	invalid.Digest = "invalid"
	if err := registrar.Register(t.Context(), invalid); err == nil {
		t.Fatal("invalid registration error=nil")
	}
}

func TestPF005SessionCredentialRegistrarRejectsRevocationFailureMatrix(t *testing.T) {
	t.Parallel()
	registration := coreRegistration()
	var nilRegistrar *SessionCredentialRegistrar
	if err := nilRegistrar.Revoke(t.Context(), registration.Digest); err == nil {
		t.Fatal("nil registrar revoke accepted")
	}

	statusServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer statusServer.Close()
	registrar, err := NewSessionCredentialRegistrar(
		&memoryCredentialSource{value: []byte("01234567890123456789012345678901")},
		statusServer.URL,
		"/owner/root.credential",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := registrar.Revoke(t.Context(), registration.Digest); err == nil {
		t.Fatal("unavailable revoke accepted")
	}
	if err := registrar.Revoke(t.Context(), "invalid"); err == nil {
		t.Fatal("invalid digest revoke accepted")
	}

	divergentServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"session_id":"foreign","credential_digest":"` +
			registration.Digest + `","status":"revoked"}`))
	}))
	defer divergentServer.Close()
	registrar, _ = NewSessionCredentialRegistrar(
		&memoryCredentialSource{value: []byte("01234567890123456789012345678901")},
		divergentServer.URL,
		"/owner/root.credential",
	)
	if err := registrar.Revoke(t.Context(), registration.Digest); err == nil {
		t.Fatal("divergent revoke response accepted")
	}
}

func TestPF005SessionCredentialGitScopeValidationIsClosed(t *testing.T) {
	t.Parallel()
	digest := strings.Repeat("a", 64)
	if !validGitScope(digest, digest, mcpsession.GitCoverageComplete) ||
		!validGitScope(digest, digest, mcpsession.GitCoveragePartial) ||
		validGitScope("", "", mcpsession.GitCoverage("foreign")) ||
		validGitScope(strings.Repeat("a", 513), "", mcpsession.GitCoverageNone) ||
		validGitScope("a\nforeign", digest, mcpsession.GitCoverageComplete) {
		t.Fatal("Git scope validation diverged")
	}
}

func coreRegistration() mcpsessionapp.CredentialRegistration {
	issued := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	return mcpsessionapp.CredentialRegistration{
		Scope: mcpsessionapp.CredentialScope{
			SessionID:            "019d2b4e-7a10-7def-8abc-0123456789ab",
			InstallationID:       "019d2b4e-7a11-7def-8abc-0123456789ab",
			BrainID:              "019d2b4e-7a12-7def-8abc-0123456789ab",
			ActorID:              "019d2b4e-7a13-7def-8abc-0123456789ab",
			GrantID:              "019d2b4e-7a14-7def-8abc-0123456789ab",
			AgentID:              "codex",
			WorkspaceFingerprint: strings.Repeat("a", 64), DeviceIdentity: "dev:1",
			GitCoverage: mcpsession.GitCoverageNone, SecurityEpoch: 7, TTL: 12 * time.Hour,
		},
		Digest: strings.Repeat("b", 64), IssuedAt: issued, ExpiresAt: issued.Add(12 * time.Hour),
	}
}
