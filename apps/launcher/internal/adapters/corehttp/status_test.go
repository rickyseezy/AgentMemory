package corehttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPF001CoreStatusClientRequiresAuthenticatedReceiptBackedReady(t *testing.T) {
	t.Parallel()
	credential := []byte("01234567890123456789012345678901")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/v1/status" ||
			request.Header.Get("Authorization") != "Bearer 3031323334353637383930313233343536373839303132333435363738393031" {
			t.Errorf("unexpected status request: %s %s", request.Method, request.URL.Path)
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"ready":true,"receipt":{"receipt_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`))
	}))
	defer server.Close()
	client, err := NewStatusClient(&memoryCredentialSource{value: credential}, server.URL, "/protected/api")
	if err != nil {
		t.Fatal(err)
	}
	ready, err := client.Ready(context.Background())
	if err != nil || !ready {
		t.Fatalf("Ready()=%t,%v", ready, err)
	}
}

func TestPF001CoreStatusClientRejectsNegativeAmbiguousAndUnavailableStatus(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		statusCode int
		content    string
		wantError  bool
	}{
		{name: "not ready", statusCode: http.StatusOK, content: `{"ready":false,"receipt":null}`},
		{name: "not ready with receipt", statusCode: http.StatusOK, content: `{"ready":false,"receipt":{}}`, wantError: true},
		{name: "ready without receipt", statusCode: http.StatusOK, content: `{"ready":true,"receipt":null}`, wantError: true},
		{name: "duplicate root", statusCode: http.StatusOK, content: `{"ready":true,"ready":true,"receipt":{}}`, wantError: true},
		{name: "duplicate receipt", statusCode: http.StatusOK, content: `{"ready":true,"receipt":{"x":1,"x":2}}`, wantError: true},
		{name: "unknown", statusCode: http.StatusOK, content: `{"ready":true,"receipt":{},"future":1}`, wantError: true},
		{name: "server failure", statusCode: http.StatusServiceUnavailable, content: `{}`, wantError: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(test.statusCode)
				_, _ = writer.Write([]byte(test.content))
			}))
			defer server.Close()
			client, _ := NewStatusClient(
				&memoryCredentialSource{value: []byte("01234567890123456789012345678901")},
				server.URL, "/protected/api",
			)
			ready, err := client.Ready(context.Background())
			if ready || (err != nil) != test.wantError {
				t.Fatalf("Ready()=%t,%v", ready, err)
			}
		})
	}
}

func TestPF001CoreStatusClientRejectsInvalidConstructionAndCancellation(t *testing.T) {
	t.Parallel()
	if _, err := NewStatusClient(nil, "http://127.0.0.1:9411", "/protected/api"); err == nil {
		t.Fatal("nil credential source accepted")
	}
	if _, err := NewStatusClient(&memoryCredentialSource{}, "https://example.com", "/protected/api"); err == nil {
		t.Fatal("remote endpoint accepted")
	}
	if _, err := NewStatusClient(&memoryCredentialSource{}, "http://127.0.0.1:9411", "relative\npath"); err == nil {
		t.Fatal("invalid credential path accepted")
	}
	var nilClient *StatusClient
	if _, err := nilClient.Ready(context.Background()); !errors.Is(err, errCoreStatusUnavailable) {
		t.Fatalf("nil client error=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	client, _ := NewStatusClient(
		&memoryCredentialSource{}, "http://127.0.0.1:9411", "/protected/api",
	)
	if _, err := client.Ready(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Ready error=%v", err)
	}
}
