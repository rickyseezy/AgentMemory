package corehttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/brainbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001CoreClientBootstrapsExactPlanBoundIdentityOverAuthenticatedLoopback(t *testing.T) {
	t.Parallel()
	credential := []byte("01234567890123456789012345678901")
	var received bootstrapRequest
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/bootstrap" ||
			request.Header.Get("Authorization") != "Bearer 3031323334353637383930313233343536373839303132333435363738393031" ||
			request.Header.Get("Idempotency-Key") == "" || request.Header.Get("Origin") != "" ||
			request.ContentLength <= 0 || request.TransferEncoding != nil {
			t.Errorf("unexpected Core request method/path/headers/framing")
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&received); err != nil {
			t.Errorf("decode request: %v", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte(`{"installation_id":"` + received.InstallationID +
			`","brain_id":"` + received.BrainID + `","disposition":"created"}`))
	}))
	defer server.Close()

	authorization := coreBootstrapAuthorization(t, server.URL)
	client, err := New(&memoryCredentialSource{value: credential})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := client.BootstrapLocalBrain(context.Background(), authorization)
	if err != nil || !receipt.ValidFor(authorization) || receipt.Disposition() != brainbootstrap.DispositionCreated {
		t.Fatalf("BootstrapLocalBrain() = %#v/%v", receipt, err)
	}
	if received.CommandID != authorization.OperationID().String() ||
		received.OwnerPrincipalID != authorization.OwnerPrincipalID() ||
		received.OwnerSubjectDigest != authorization.OwnerSubjectDigest().String() ||
		received.BrainName != authorization.BrainName() ||
		received.ReleaseDigest != authorization.ReleaseDigest().String() {
		t.Fatalf("request lost authorization fields: %#v", received)
	}
}

func TestPF001CoreClientAcceptsOnlyExactIdempotentResponse(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
	}{
		{name: "already initialized", status: http.StatusOK, contentType: "application/json", body: `{"installation_id":"%s","brain_id":"%s","disposition":"already_initialized"}`},
		{name: "wrong status disposition", status: http.StatusCreated, contentType: "application/json", body: `{"installation_id":"%s","brain_id":"%s","disposition":"already_initialized"}`},
		{name: "foreign installation", status: http.StatusCreated, contentType: "application/json", body: `{"installation_id":"019f5f30-5678-7def-9123-abcdef012360","brain_id":"%s","disposition":"created"}`},
		{name: "duplicate key", status: http.StatusCreated, contentType: "application/json", body: `{"installation_id":"%s","installation_id":"%s","brain_id":"%s","disposition":"created"}`},
		{name: "unknown field", status: http.StatusCreated, contentType: "application/json", body: `{"installation_id":"%s","brain_id":"%s","disposition":"created","extra":true}`},
		{name: "wrong media type", status: http.StatusCreated, contentType: "text/plain", body: `{"installation_id":"%s","brain_id":"%s","disposition":"created"}`},
		{name: "problem", status: http.StatusServiceUnavailable, contentType: "application/problem+json", body: `{}`},
		{name: "oversized", status: http.StatusCreated, contentType: "application/json", body: strings.Repeat("x", maximumCoreResponseBytes+1)},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var endpoint string
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", test.contentType)
				writer.WriteHeader(test.status)
				authorization := coreBootstrapAuthorization(t, endpoint)
				body := test.body
				switch strings.Count(body, "%s") {
				case 3:
					body = formatThree(body, authorization.InstallationID(), authorization.InstallationID(), authorization.BrainID())
				case 2:
					body = formatTwo(body, authorization.InstallationID(), authorization.BrainID())
				case 1:
					body = strings.Replace(body, "%s", authorization.BrainID(), 1)
				}
				_, _ = writer.Write([]byte(body))
			}))
			defer server.Close()
			endpoint = server.URL
			authorization := coreBootstrapAuthorization(t, endpoint)
			client, _ := New(&memoryCredentialSource{value: []byte("01234567890123456789012345678901")})
			receipt, err := client.BootstrapLocalBrain(context.Background(), authorization)
			if test.name == "already initialized" {
				if err != nil || !receipt.ValidFor(authorization) ||
					receipt.Disposition() != brainbootstrap.DispositionAlreadyInitialized {
					t.Fatalf("already initialized result = %#v/%v", receipt, err)
				}
				return
			}
			if !errors.Is(err, brainbootstrap.ErrIntegrity) && !errors.Is(err, brainbootstrap.ErrUnavailable) {
				t.Fatalf("invalid response error = %v", err)
			}
			if !receipt.OutputDigest().IsZero() {
				t.Fatal("invalid response produced a receipt")
			}
		})
	}
}

func TestPF001CoreClientFailsClosedBeforeNetworkForCredentialOrBindingFailure(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("network reached after local authorization failure")
	}))
	defer server.Close()
	for _, source := range []*memoryCredentialSource{
		{err: errors.New("/private/path")},
		{value: []byte("short")},
	} {
		client, _ := New(source)
		if _, err := client.BootstrapLocalBrain(context.Background(), coreBootstrapAuthorization(t, server.URL)); !errors.Is(err, brainbootstrap.ErrUnavailable) && !errors.Is(err, brainbootstrap.ErrIntegrity) {
			t.Fatalf("credential failure error = %v", err)
		}
	}
	client, _ := New(&memoryCredentialSource{value: []byte("01234567890123456789012345678901")})
	if _, err := client.BootstrapLocalBrain(context.Background(), brainbootstrap.Authorization{}); !errors.Is(err, brainbootstrap.ErrIntegrity) {
		t.Fatalf("invalid authorization error = %v", err)
	}
	if _, err := New(nil); err == nil {
		t.Fatal("New accepted nil credential source")
	}
	var typedNil *memoryCredentialSource
	if _, err := New(typedNil); err == nil {
		t.Fatal("New accepted typed nil credential source")
	}
}

func TestPF001CoreClientStrictJSONAndLoopbackHelpersRejectAmbiguity(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		`{"outer":[{"one":1},{"two":2}]}`,
		`[true,false,null,"value",1]`,
	} {
		if err := rejectDuplicateJSONKeys([]byte(raw)); err != nil {
			t.Fatalf("valid strict JSON %q: %v", raw, err)
		}
	}
	for _, raw := range []string{
		`{"outer":{"same":1,"same":2}}`,
		`{"outer":[1,2]}}`,
		`{"outer":[1,2}`,
		`{1:true}`,
	} {
		if err := rejectDuplicateJSONKeys([]byte(raw)); err == nil {
			t.Fatalf("ambiguous JSON accepted: %q", raw)
		}
	}
	for _, endpoint := range []string{
		"https://127.0.0.1:9411", "http://example.com:9411", "http://127.0.0.1:9411/path",
		"http://user@127.0.0.1:9411", "http://127.0.0.1:9411?query=true",
	} {
		if client, closeIdle, err := literalLoopbackClient(endpoint); err == nil || client != nil || closeIdle != nil {
			t.Fatalf("literalLoopbackClient accepted %q", endpoint)
		}
	}
}

type memoryCredentialSource struct {
	value []byte
	err   error
}

func (s *memoryCredentialSource) ReadCredential(context.Context, string) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	return append([]byte(nil), s.value...), nil
}

func coreBootstrapAuthorization(t testing.TB, endpoint string) brainbootstrap.Authorization {
	t.Helper()
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	plan, _ := install.BindPlan([]byte("canonical plan"))
	authorization, err := brainbootstrap.NewAuthorization(brainbootstrap.AuthorizationInput{ // #nosec G101 -- field contains a protected path, never credential material.
		OperationID: operationID, ParentPlan: plan, Attempt: 1,
		RuntimeOwnership: install.RuntimeOwnershipReusedExternal, CoreEndpoint: endpoint,
		APICredentialPath:  "/owner/.agentmemory/secrets/api-credential",
		InstallationID:     "019f5f20-1234-7abc-8123-0123456789ab",
		OwnerPrincipalID:   "019f5f24-5678-7def-9123-abcdef012348",
		OwnerGrantID:       "019f5f25-5678-7def-9123-abcdef012349",
		OwnerSubjectDigest: install.DigestBytes([]byte("owner subject")),
		BrainID:            "019f5f26-5678-7def-9123-abcdef012350", BrainName: "local",
		ReleaseDigest: install.DigestBytes([]byte("release manifest")),
		GenerationID:  "019f5f21-5678-7def-9123-abcdef012345",
	})
	if err != nil {
		t.Fatal(err)
	}
	return authorization
}

func formatTwo(format, first, second string) string {
	format = strings.Replace(format, "%s", first, 1)
	return strings.Replace(format, "%s", second, 1)
}

func formatThree(format, first, second, third string) string {
	format = strings.Replace(format, "%s", first, 1)
	format = strings.Replace(format, "%s", second, 1)
	return strings.Replace(format, "%s", third, 1)
}
