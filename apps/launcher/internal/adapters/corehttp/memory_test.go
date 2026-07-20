package corehttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	memoryID   = "018f0000-0000-7000-8000-000000000401"
	brainID    = "018f0000-0000-7000-8000-000000000004"
	actorID    = "018f0000-0000-7000-8000-000000000002"
	grantID    = "018f0000-0000-7000-8000-000000000003"
	validAt    = "2026-07-21T10:00:00.000000Z"
	recordedAt = "2026-07-21T11:00:00.000000Z"
)

func TestMEM002CoreClientExplainsMemoryThroughAuthenticatedLiteralLoopback(t *testing.T) {
	t.Parallel()
	credential := []byte("01234567890123456789012345678901")
	response := `{"memory_id":"018f0000-0000-7000-8000-000000000401","effective":true}`
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/memories/"+memoryID ||
			request.Header.Get("Authorization") != "Bearer 3031323334353637383930313233343536373839303132333435363738393031" ||
			request.URL.Query().Get("brain_id") != brainID || request.URL.Query().Get("actor_id") != actorID ||
			request.URL.Query().Get("grant_id") != grantID || request.URL.Query().Get("valid_at") != validAt ||
			request.URL.Query().Get("recorded_at") != recordedAt {
			t.Errorf("unexpected memory request: %s %s", request.Method, request.URL.String())
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(response))
	}))
	defer server.Close()
	client, err := NewStatusClient(&memoryCredentialSource{value: credential}, server.URL, "/protected/api")
	if err != nil {
		t.Fatal(err)
	}
	actual, err := client.ExplainMemory(
		context.Background(), memoryID, brainID, actorID, grantID, validAt, recordedAt,
	)
	if err != nil || string(actual) != response {
		t.Fatalf("ExplainMemory()=%s,%v", actual, err)
	}
}

func TestMEM002CoreClientRejectsUnsafeCoordinatesMalformedResponsesAndCancellation(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"memory_id":"first","memory_id":"second"}`))
	}))
	defer server.Close()
	client, _ := NewStatusClient(
		&memoryCredentialSource{value: []byte("01234567890123456789012345678901")},
		server.URL,
		"/protected/api",
	)
	for name, value := range map[string]string{
		"path injection": memoryID + "/../status",
		"wrong UUID":     "memory",
		"control":        memoryID + "\n",
	} {
		if body, err := client.ExplainMemory(
			context.Background(), value, brainID, actorID, grantID, validAt, recordedAt,
		); body != nil || !errors.Is(err, errCoreStatusUnavailable) {
			t.Fatalf("%s ExplainMemory()=%s,%v", name, body, err)
		}
	}
	if body, err := client.ExplainMemory(
		context.Background(), memoryID, "brain", actorID, grantID, validAt, recordedAt,
	); body != nil || !errors.Is(err, errCoreStatusUnavailable) {
		t.Fatalf("invalid brain response=%s,%v", body, err)
	}
	if body, err := client.ExplainMemory(
		context.Background(), memoryID, brainID, actorID, grantID, "2026-07-21T10:00:00Z", recordedAt,
	); body != nil || !errors.Is(err, errCoreStatusUnavailable) {
		t.Fatalf("invalid time response=%s,%v", body, err)
	}
	if body, err := client.ExplainMemory(
		context.Background(), memoryID, brainID, actorID, grantID, validAt, recordedAt,
	); body != nil || !errors.Is(err, errCoreStatusUnavailable) {
		t.Fatalf("duplicate response=%s,%v", body, err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if body, err := client.ExplainMemory(
		cancelled, memoryID, brainID, actorID, grantID, validAt, recordedAt,
	); body != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled response=%s,%v", body, err)
	}
	var nilClient *StatusClient
	if body, err := nilClient.ExplainMemory(
		context.Background(), memoryID, brainID, actorID, grantID, validAt, recordedAt,
	); body != nil || !errors.Is(err, errCoreStatusUnavailable) {
		t.Fatalf("nil response=%s,%v", body, err)
	}
}

func TestMEM002CoreMemoryCoordinateValidationIsCanonicalAndClosed(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		memoryID,
		"ffffffff-ffff-7fff-bfff-ffffffffffff",
	} {
		if !validUUIDv7(value) {
			t.Fatalf("valid UUIDv7 rejected: %q", value)
		}
	}
	for _, value := range []string{
		"018f0000-0000-6000-8000-000000000401",
		"018F0000-0000-7000-8000-000000000401",
		"018f0000-0000-7000-7000-000000000401",
		"018f0000-0000-7000-8000-00000000040g",
		"018f0000000070008000000000000401",
	} {
		if validUUIDv7(value) {
			t.Fatalf("invalid UUIDv7 accepted: %q", value)
		}
	}
	if !validMemoryTime(validAt) {
		t.Fatalf("valid timestamp rejected: %q", validAt)
	}
	for _, value := range []string{
		"2026-07-21T10:00:00Z",
		"2026-07-21T10:00:00.000000+00:00",
		"2026-02-30T10:00:00.000000Z",
		"2026-07-21T10:00:00.00000aZ",
	} {
		if validMemoryTime(value) {
			t.Fatalf("invalid timestamp accepted: %q", value)
		}
	}
}

func TestMEM002CoreClientRejectsNonObjectAndNonSuccessMemoryDocuments(t *testing.T) {
	t.Parallel()
	for name, testCase := range map[string]struct {
		status int
		body   string
	}{
		"array":     {status: http.StatusOK, body: `[]`},
		"null":      {status: http.StatusOK, body: `null`},
		"malformed": {status: http.StatusOK, body: `{`},
		"not found": {status: http.StatusNotFound, body: `{"code":"AM_NOT_FOUND"}`},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(testCase.status)
				_, _ = writer.Write([]byte(testCase.body))
			}))
			defer server.Close()
			client, err := NewStatusClient(
				&memoryCredentialSource{value: []byte("01234567890123456789012345678901")},
				server.URL,
				"/protected/api",
			)
			if err != nil {
				t.Fatal(err)
			}
			body, explainErr := client.ExplainMemory(
				context.Background(), memoryID, brainID, actorID, grantID, validAt, recordedAt,
			)
			if body != nil || !errors.Is(explainErr, errCoreStatusUnavailable) {
				t.Fatalf("ExplainMemory()=%s,%v", body, explainErr)
			}
		})
	}
}
