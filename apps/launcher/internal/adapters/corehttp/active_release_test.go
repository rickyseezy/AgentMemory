package corehttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/readinessapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/activerelease"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/readiness"
)

func TestPF001CoreActiveReleaseClientExecutesExactAuthenticatedTransaction(t *testing.T) {
	t.Parallel()
	command := readinessCommand(t, "http://127.0.0.1:1")
	receipt := readinessReceiptForCommand(t, command)
	pointer := coreActiveReleasePointer(t, receipt.Digest(), command)
	stageDigest, err := activerelease.StageDigest(command.OperationID, pointer)
	if err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 0, 3)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		paths = append(paths, request.URL.Path)
		if request.Method != http.MethodPost || request.Header.Get("Authorization") == "" ||
			request.Header.Get("Idempotency-Key") == "" || request.ContentLength <= 0 {
			t.Errorf("invalid Core activation request")
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/active-release:stage":
			var body activeReleaseStageRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil ||
				body.OperationID != command.OperationID.String() ||
				body.Pointer.PointerDigest != pointer.Digest().String() {
				t.Errorf("stage request = %#v/%v", body, err)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			writer.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(writer).Encode(activeReleaseStageResponse{StageDigest: stageDigest.String()})
		case "/v1/active-release:commit":
			var body activeReleaseCommitRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil ||
				body.StageDigest != stageDigest.String() || body.Pointer.PointerDigest != pointer.Digest().String() {
				t.Errorf("commit request = %#v/%v", body, err)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(writer).Encode(activeReleaseCommitResponse{PointerDigest: pointer.Digest().String()})
		case "/v1/active-release:matches":
			var body activeReleaseMatchesRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil ||
				body.Pointer.PointerDigest != pointer.Digest().String() {
				t.Errorf("matches request = %#v/%v", body, err)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(writer).Encode(activeReleaseMatchesResponse{Matches: true})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client, err := NewActiveReleaseClient(
		&memoryCredentialSource{value: []byte("01234567890123456789012345678901")},
		server.URL,
		"/owner/.agentmemory/secrets/api-credential",
	)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := client.Stage(context.Background(), command.OperationID, pointer, receipt)
	if err != nil || !staged.Equal(stageDigest) {
		t.Fatalf("Stage() = %s/%v", staged.String(), err)
	}
	committed, err := client.Commit(context.Background(), command.OperationID, staged, pointer)
	if err != nil || !committed.Equal(pointer.Digest()) {
		t.Fatalf("Commit() = %s/%v", committed.String(), err)
	}
	matches, err := client.Matches(context.Background(), pointer)
	if err != nil || !matches {
		t.Fatalf("Matches() = %t/%v", matches, err)
	}
	if len(paths) != 3 || paths[0] != "/v1/active-release:stage" ||
		paths[1] != "/v1/active-release:commit" || paths[2] != "/v1/active-release:matches" {
		t.Fatalf("request order = %v", paths)
	}
}

func TestPF001CoreActiveReleaseClientRejectsTamperAndInvalidAuthority(t *testing.T) {
	t.Parallel()
	command := readinessCommand(t, "http://127.0.0.1:1")
	receipt := readinessReceiptForCommand(t, command)
	pointer := coreActiveReleasePointer(t, receipt.Digest(), command)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/active-release:stage":
			_, _ = writer.Write([]byte(`{"stage_digest":"` + install.DigestBytes([]byte("wrong")).String() + `"}`))
		case "/v1/active-release:matches":
			_, _ = writer.Write([]byte(`{"matches":true,"matches":false}`))
		default:
			t.Error("network reached for locally invalid commit")
		}
	}))
	defer server.Close()
	client, err := NewActiveReleaseClient(
		&memoryCredentialSource{value: []byte("01234567890123456789012345678901")},
		server.URL,
		"/owner/.agentmemory/secrets/api-credential",
	)
	if err != nil {
		t.Fatal(err)
	}
	if stage, err := client.Stage(context.Background(), command.OperationID, pointer, receipt); !stage.IsZero() || !errors.Is(err, errCoreActiveReleaseUnavailable) {
		t.Fatalf("tampered Stage() = %s/%v", stage.String(), err)
	}
	if digest, err := client.Commit(
		context.Background(), command.OperationID, install.DigestBytes([]byte("wrong")), pointer,
	); !digest.IsZero() || !errors.Is(err, errCoreActiveReleaseUnavailable) {
		t.Fatalf("invalid Commit() = %s/%v", digest.String(), err)
	}
	if matches, err := client.Matches(context.Background(), pointer); matches ||
		!errors.Is(err, errCoreActiveReleaseUnavailable) {
		t.Fatalf("ambiguous Matches() = %t/%v", matches, err)
	}
	for _, endpoint := range []string{"http://example.com:9411", "https://127.0.0.1:9411"} {
		if _, err := NewActiveReleaseClient(&memoryCredentialSource{}, endpoint, "/secret"); err == nil {
			t.Fatalf("constructor accepted endpoint %q", endpoint)
		}
	}
	if _, err := NewActiveReleaseClient(nil, server.URL, "/secret"); err == nil {
		t.Fatal("constructor accepted nil credentials")
	}
	if _, err := NewActiveReleaseClient(&memoryCredentialSource{}, server.URL, "bad\npath"); err == nil {
		t.Fatal("constructor accepted invalid credential path")
	}
}

func TestPF001CoreActiveReleaseClientFailsClosedForEveryLocalAndRemoteFailure(t *testing.T) {
	t.Parallel()
	command := readinessCommand(t, "http://127.0.0.1:1")
	receipt := readinessReceiptForCommand(t, command)
	pointer := coreActiveReleasePointer(t, receipt.Digest(), command)
	stageDigest, _ := activerelease.StageDigest(command.OperationID, pointer)
	commitCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/active-release:stage", "/v1/active-release:matches":
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write([]byte(`{"code":"unavailable"}`))
		case "/v1/active-release:commit":
			commitCalls++
			switch commitCalls {
			case 1:
				_, _ = writer.Write([]byte(`{"pointer_digest":"` + install.DigestBytes([]byte("wrong")).String() + `"}`))
			case 2:
				writer.WriteHeader(http.StatusServiceUnavailable)
				_, _ = writer.Write([]byte(`{"code":"unavailable"}`))
			default:
				_, _ = writer.Write([]byte(`{"unknown":true}`))
			}
		}
	}))
	defer server.Close()
	client, err := NewActiveReleaseClient(
		&memoryCredentialSource{value: []byte("01234567890123456789012345678901")},
		server.URL,
		"/owner/.agentmemory/secrets/api-credential",
	)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := client.Stage(context.Background(), command.OperationID, pointer, receipt); !result.IsZero() || !errors.Is(err, errCoreActiveReleaseUnavailable) {
		t.Fatalf("unavailable Stage() = %s/%v", result.String(), err)
	}
	if result, err := client.Commit(context.Background(), command.OperationID, stageDigest, pointer); !result.IsZero() || !errors.Is(err, errCoreActiveReleaseUnavailable) {
		t.Fatalf("tampered Commit() = %s/%v", result.String(), err)
	}
	for _, failure := range []string{"unavailable", "invalid response"} {
		if result, err := client.Commit(context.Background(), command.OperationID, stageDigest, pointer); !result.IsZero() || !errors.Is(err, errCoreActiveReleaseUnavailable) {
			t.Fatalf("%s Commit() = %s/%v", failure, result.String(), err)
		}
	}
	if matches, err := client.Matches(context.Background(), pointer); matches ||
		!errors.Is(err, errCoreActiveReleaseUnavailable) {
		t.Fatalf("unavailable Matches() = %t/%v", matches, err)
	}

	client.stageDigest = func(install.OperationID, activerelease.Pointer) (install.Digest, error) {
		return install.Digest{}, errors.New("digest failure")
	}
	if result, err := client.Stage(context.Background(), command.OperationID, pointer, receipt); !result.IsZero() || err == nil {
		t.Fatalf("stage digest failure = %s/%v", result.String(), err)
	}
	if result, err := client.Commit(context.Background(), command.OperationID, stageDigest, pointer); !result.IsZero() || err == nil {
		t.Fatalf("commit digest failure = %s/%v", result.String(), err)
	}
	client.stageDigest = activerelease.StageDigest
	client.marshal = func(any) ([]byte, error) { return nil, errors.New("marshal failure") }
	if result, err := client.Stage(context.Background(), command.OperationID, pointer, receipt); !result.IsZero() || err == nil {
		t.Fatalf("stage marshal failure = %s/%v", result.String(), err)
	}
	if result, err := client.Commit(context.Background(), command.OperationID, stageDigest, pointer); !result.IsZero() || err == nil {
		t.Fatalf("commit marshal failure = %s/%v", result.String(), err)
	}
	if matches, err := client.Matches(context.Background(), pointer); matches || err == nil {
		t.Fatalf("matches marshal failure = %t/%v", matches, err)
	}

	client.marshal = json.Marshal
	var nilClient *ActiveReleaseClient
	if result, err := nilClient.Stage(context.Background(), command.OperationID, pointer, receipt); !result.IsZero() || err == nil {
		t.Fatalf("nil Stage() = %s/%v", result.String(), err)
	}
	var nilContext context.Context
	if result, err := client.Stage(nilContext, command.OperationID, pointer, receipt); !result.IsZero() || err == nil {
		t.Fatalf("nil-context Stage() = %s/%v", result.String(), err)
	}
	if result, err := client.Stage(context.Background(), install.OperationID{}, pointer, receipt); !result.IsZero() || err == nil {
		t.Fatalf("empty-operation Stage() = %s/%v", result.String(), err)
	}
	if result, err := client.Stage(context.Background(), command.OperationID, pointer, readiness.Receipt{}); !result.IsZero() || err == nil {
		t.Fatalf("empty-receipt Stage() = %s/%v", result.String(), err)
	}
	if result, err := nilClient.Commit(context.Background(), command.OperationID, stageDigest, pointer); !result.IsZero() || err == nil {
		t.Fatalf("nil Commit() = %s/%v", result.String(), err)
	}
	if matches, err := nilClient.Matches(context.Background(), pointer); matches || err == nil {
		t.Fatalf("nil Matches() = %t/%v", matches, err)
	}
	if matches, err := client.Matches(context.Background(), activerelease.Pointer{}); matches || err == nil {
		t.Fatalf("empty Matches() = %t/%v", matches, err)
	}
	if decodeStrictCoreResponse([]byte(`{"unknown":true}`), &activeReleaseStageResponse{}) == nil {
		t.Fatal("strict decoder accepted an unknown field")
	}
	if decodeStrictCoreResponse([]byte(`{"stage_digest":"x"} {}`), &activeReleaseStageResponse{}) == nil {
		t.Fatal("strict decoder accepted trailing JSON")
	}
}

func coreActiveReleasePointer(
	t testing.TB,
	readinessDigest install.Digest,
	command readinessapp.Command,
) activerelease.Pointer {
	t.Helper()
	pointer, err := activerelease.NewPointer(activerelease.PointerInput{
		InstallationID: "019f5f20-1234-7abc-8123-0123456789ab",
		ReleaseID:      command.ReleaseID, GenerationID: command.GenerationID,
		ManifestDigest: command.ManifestDigest, ComposeDigest: command.ComposeDigest,
		ReadinessReceiptDigest: readinessDigest,
		RuntimeEndpoint:        "unix:///var/run/docker.sock", ReleaseSequence: 7,
		ResourceInventoryVersion: 9, ResourceInventoryDigest: install.DigestBytes([]byte("inventory")),
		SecurityEpoch: 3, ActivatedAt: time.Date(2026, 7, 13, 12, 0, 1, 123456000, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	return pointer
}
