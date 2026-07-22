package corehttp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/mcpsessioncheckpoint"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/mcpsession"
)

func TestPF005WorkspaceCheckpointClientRequiresDurableExactAcknowledgement(t *testing.T) {
	t.Parallel()
	content := []byte("package brain\n")
	digest := sha256.Sum256(content)
	batch := mcpsessioncheckpoint.Batch{
		SessionID:            "019d2b4e-7a10-7def-8abc-0123456789ab",
		WorkspaceFingerprint: strings.Repeat("a", 64),
		Changes: []mcpsessioncheckpoint.Change{{
			RelativePath: "internal/brain.go", SHA256: hex.EncodeToString(digest[:]), Content: content,
		}},
	}
	var received workspaceCheckpointRequest
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != workspaceCheckpointPath ||
			request.Header.Get("Authorization") == "" || request.Header.Get("Idempotency-Key") == "" ||
			request.Header.Get("Idempotency-Key") != request.Header.Get("X-Correlation-ID") {
			t.Errorf("unexpected checkpoint request: %s %s", request.Method, request.URL.Path)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&received); err != nil {
			t.Errorf("decode checkpoint: %v", err)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte(`{"session_id":"` + received.SessionID +
			`","batch_digest":"` + received.BatchDigest + `","status":"checkpointed"}`))
	}))
	defer server.Close()
	client, err := NewWorkspaceCheckpointClient(
		&memoryCredentialSource{value: []byte("01234567890123456789012345678901")},
		server.URL, "/owner/root.credential",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Upload(t.Context(), batch); err != nil {
		t.Fatal(err)
	}
	if received.SessionID != batch.SessionID || received.WorkspaceFingerprint != batch.WorkspaceFingerprint ||
		!mcpsession.ValidSHA256Digest(received.BatchDigest) || len(received.Changes) != 1 ||
		received.Changes[0].RelativePath != "internal/brain.go" ||
		received.Changes[0].ContentBase64 != "cGFja2FnZSBicmFpbgo=" {
		t.Fatalf("received=%+v", received)
	}
}

func TestPF005WorkspaceCheckpointClientRejectsTamperingAndRemoteCore(t *testing.T) {
	t.Parallel()
	credentials := &memoryCredentialSource{value: []byte("01234567890123456789012345678901")}
	if client, err := NewWorkspaceCheckpointClient(credentials, "https://example.com", "/owner/root"); err == nil || client != nil {
		t.Fatalf("remote client=%T/%v", client, err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"session_id":"foreign","batch_digest":"` +
			strings.Repeat("b", 64) + `","status":"checkpointed"}`))
	}))
	defer server.Close()
	client, _ := NewWorkspaceCheckpointClient(credentials, server.URL, "/owner/root")
	batch := mcpsessioncheckpoint.Batch{
		SessionID:            "019d2b4e-7a10-7def-8abc-0123456789ab",
		WorkspaceFingerprint: strings.Repeat("a", 64),
		Changes: []mcpsessioncheckpoint.Change{{
			RelativePath: "file.go", SHA256: strings.Repeat("c", 64), Content: []byte("tampered"),
		}},
	}
	if err := client.Upload(t.Context(), batch); err == nil {
		t.Fatal("tampered content was accepted")
	}
}
