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
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/readiness"
)

func TestPF001CoreReadinessClientRestoresAndPersistsCompleteLiveReceipt(t *testing.T) {
	t.Parallel()
	var command readinessapp.Command
	repository := &readinessReceiptRepository{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/readiness:verify" ||
			request.Header.Get("Idempotency-Key") != command.OperationID.String() {
			t.Errorf("unexpected readiness request")
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		var actual readinessRequest
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&actual); err != nil || actual.ComposeDigest != command.ComposeDigest.String() {
			t.Errorf("readiness request = %#v/%v", actual, err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		receipt := readinessReceiptForCommand(t, command)
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(readinessVerificationResponse{
			Ready: true, Receipt: responseFromRecord(receipt.Record()), Failures: []readinessFailureResponse{},
		})
	}))
	defer server.Close()
	command = readinessCommand(t, server.URL)
	client, err := NewReadinessClient(
		&memoryCredentialSource{value: []byte("01234567890123456789012345678901")}, repository,
	)
	if err != nil {
		t.Fatal(err)
	}
	verification, err := client.Verify(context.Background(), command)
	if err != nil || !verification.Ready() || verification.Receipt().IsZero() ||
		repository.saved.IsZero() || !repository.saved.Digest().Equal(verification.Receipt().Digest()) {
		t.Fatalf("Verify() = %#v/%v, saved=%#v", verification, err, repository.saved)
	}
}

func TestPF001CoreReadinessClientReturnsExactNegativeGateWithoutReceipt(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(readinessVerificationResponse{
			Ready: false, Receipt: nil, Failures: []readinessFailureResponse{{
				Probe: readiness.ProbeSemanticWriteIndexRecall.String(), Code: string(readiness.FailureProbeFailed),
			}},
		})
	}))
	defer server.Close()
	repository := &readinessReceiptRepository{}
	client, _ := NewReadinessClient(
		&memoryCredentialSource{value: []byte("01234567890123456789012345678901")}, repository,
	)
	verification, err := client.Verify(context.Background(), readinessCommand(t, server.URL))
	if err != nil || verification.Ready() || len(verification.Failures()) != 1 ||
		verification.Failures()[0].Probe != readiness.ProbeSemanticWriteIndexRecall || !repository.saved.IsZero() {
		t.Fatalf("negative Verify() = %#v/%v", verification, err)
	}
}

func TestPF001CoreReadinessClientRejectsTamperAmbiguityAndPersistenceFailure(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		response   func(testing.TB, readinessapp.Command) readinessVerificationResponse
		repository *readinessReceiptRepository
	}{
		{name: "receipt digest tamper", repository: &readinessReceiptRepository{}, response: func(t testing.TB, command readinessapp.Command) readinessVerificationResponse {
			record := readinessReceiptForCommand(t, command).Record()
			record.ReceiptDigest = install.DigestBytes([]byte("tampered")).String()
			return readinessVerificationResponse{Ready: true, Receipt: responseFromRecord(record)}
		}},
		{name: "ready with failures", repository: &readinessReceiptRepository{}, response: func(t testing.TB, command readinessapp.Command) readinessVerificationResponse {
			return readinessVerificationResponse{Ready: true, Receipt: responseFromRecord(readinessReceiptForCommand(t, command).Record()),
				Failures: []readinessFailureResponse{{Probe: readiness.ProbeKeyAccess.String(), Code: string(readiness.FailureProbeFailed)}}}
		}},
		{name: "unknown negative probe", repository: &readinessReceiptRepository{}, response: func(testing.TB, readinessapp.Command) readinessVerificationResponse {
			return readinessVerificationResponse{Ready: false, Failures: []readinessFailureResponse{{Probe: "future", Code: "probe_failed"}}}
		}},
		{name: "persistence failure", repository: &readinessReceiptRepository{err: errors.New("/private/path")}, response: func(t testing.TB, command readinessapp.Command) readinessVerificationResponse {
			return readinessVerificationResponse{Ready: true, Receipt: responseFromRecord(readinessReceiptForCommand(t, command).Record())}
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var command readinessapp.Command
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(writer).Encode(test.response(t, command))
			}))
			defer server.Close()
			command = readinessCommand(t, server.URL)
			client, _ := NewReadinessClient(
				&memoryCredentialSource{value: []byte("01234567890123456789012345678901")}, test.repository,
			)
			verification, err := client.Verify(context.Background(), command)
			if !errors.Is(err, errCoreReadinessUnavailable) || verification.Ready() || !verification.Receipt().IsZero() {
				t.Fatalf("tampered Verify() = %#v/%v", verification, err)
			}
		})
	}
	if _, err := NewReadinessClient(nil, &readinessReceiptRepository{}); err == nil {
		t.Fatal("constructor accepted nil credential source")
	}
	if _, err := NewReadinessClient(&memoryCredentialSource{}, nil); err == nil {
		t.Fatal("constructor accepted nil repository")
	}
}

type readinessReceiptRepository struct {
	saved readiness.Receipt
	err   error
}

func (r *readinessReceiptRepository) SaveReadinessReceipt(_ context.Context, receipt readiness.Receipt) error {
	if r.err != nil {
		return r.err
	}
	r.saved = receipt
	return nil
}

func readinessCommand(t testing.TB, endpoint string) readinessapp.Command {
	t.Helper()
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	plan, _ := install.BindPlan([]byte("canonical plan"))
	return readinessapp.Command{ // #nosec G101 -- field contains a protected path, never credential material.
		OperationID: operationID, PlanDigest: plan, ReleaseID: "agentmemory-1.0.0",
		GenerationID:   "019f5f21-5678-7def-9123-abcdef012345",
		ManifestDigest: install.DigestBytes([]byte("manifest")),
		ComposeDigest:  install.DigestBytes([]byte("normalized compose")),
		CoreEndpoint:   endpoint, APICredentialPath: "/owner/.agentmemory/secrets/api-credential",
	}
}

func readinessReceiptForCommand(t testing.TB, command readinessapp.Command) readiness.Receipt {
	t.Helper()
	now := time.Date(2026, 7, 13, 12, 0, 0, 123456000, time.UTC)
	results := make([]readiness.Result, 0, len(readiness.RequiredProbes()))
	for _, probe := range readiness.RequiredProbes() {
		result, err := readiness.NewResult(readiness.ResultInput{
			Probe: probe, Status: readiness.StatusPassed, OperationID: command.OperationID,
			PlanDigest: command.PlanDigest, ReleaseID: command.ReleaseID, GenerationID: command.GenerationID,
			ManifestDigest: command.ManifestDigest, ComposeDigest: command.ComposeDigest,
			EvidenceDigest: install.DigestBytes([]byte(probe.String())), ObservedAt: now,
		})
		if err != nil {
			t.Fatal(err)
		}
		results = append(results, result)
	}
	receipt, failures := readiness.NewGate().Evaluate(readiness.GateInput{
		OperationID: command.OperationID, PlanDigest: command.PlanDigest, ReleaseID: command.ReleaseID,
		GenerationID: command.GenerationID, ManifestDigest: command.ManifestDigest,
		ComposeDigest: command.ComposeDigest, EvaluatedAt: now, Results: results,
	})
	if len(failures) != 0 {
		t.Fatal(failures)
	}
	return receipt
}

func responseFromRecord(record readiness.ReceiptRecord) *readinessReceiptResponse {
	results := make([]readinessResultResponse, 0, len(record.Results))
	for _, result := range record.Results {
		results = append(results, readinessResultResponse{
			Probe: result.Probe, Status: result.Status, OperationID: result.OperationID,
			PlanDigest: result.PlanDigest, ReleaseID: result.ReleaseID, GenerationID: result.GenerationID,
			ManifestDigest: result.ManifestDigest, ComposeDigest: result.ComposeDigest,
			EvidenceDigest: result.EvidenceDigest, ObservedAt: result.ObservedAt,
		})
	}
	return &readinessReceiptResponse{
		SchemaVersion: record.SchemaVersion, OperationID: record.OperationID, PlanDigest: record.PlanDigest,
		ReleaseID: record.ReleaseID, GenerationID: record.GenerationID,
		ManifestDigest: record.ManifestDigest, ComposeDigest: record.ComposeDigest,
		EvaluatedAt: record.EvaluatedAt, Results: results, ReceiptDigest: record.ReceiptDigest,
	}
}
