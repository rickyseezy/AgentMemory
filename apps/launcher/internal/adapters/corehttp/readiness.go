package corehttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/readinessapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/readiness"
)

var errCoreReadinessUnavailable = errors.New("core readiness verification unavailable")

// ReadinessClient executes the complete Core-owned eleven-probe gate and
// durably mirrors only its independently restored successful receipt for the
// host activation transaction.
type ReadinessClient struct {
	credentials CredentialSource
	receipts    readinessapp.ReceiptRepository
}

// NewReadinessClient requires both protected authentication and durable host
// receipt storage. A Core receipt that is not persisted cannot authorize Ready.
func NewReadinessClient(
	credentials CredentialSource,
	receipts readinessapp.ReceiptRepository,
) (*ReadinessClient, error) {
	if nilCapability(credentials) || nilCapability(receipts) {
		return nil, errors.New("core readiness credential and receipt capabilities are required")
	}
	return &ReadinessClient{credentials: credentials, receipts: receipts}, nil
}

type readinessRequest struct {
	OperationID    string `json:"operation_id"`
	PlanDigest     string `json:"plan_digest"`
	ReleaseID      string `json:"release_id"`
	GenerationID   string `json:"generation_id"`
	ManifestDigest string `json:"manifest_digest"`
	ComposeDigest  string `json:"compose_digest"`
}

type readinessFailureResponse struct {
	Probe string `json:"probe"`
	Code  string `json:"code"`
}

type readinessResultResponse struct {
	Probe          string `json:"probe"`
	Status         string `json:"status"`
	OperationID    string `json:"operation_id"`
	PlanDigest     string `json:"plan_digest"`
	ReleaseID      string `json:"release_id"`
	GenerationID   string `json:"generation_id"`
	ManifestDigest string `json:"manifest_digest"`
	ComposeDigest  string `json:"compose_digest"`
	EvidenceDigest string `json:"evidence_digest"`
	ObservedAt     string `json:"observed_at"`
}

type readinessReceiptResponse struct {
	SchemaVersion  uint16                    `json:"schema_version"`
	OperationID    string                    `json:"operation_id"`
	PlanDigest     string                    `json:"plan_digest"`
	ReleaseID      string                    `json:"release_id"`
	GenerationID   string                    `json:"generation_id"`
	ManifestDigest string                    `json:"manifest_digest"`
	ComposeDigest  string                    `json:"compose_digest"`
	EvaluatedAt    string                    `json:"evaluated_at"`
	Results        []readinessResultResponse `json:"results"`
	ReceiptDigest  string                    `json:"receipt_digest"`
}

type readinessVerificationResponse struct {
	Ready    bool                       `json:"ready"`
	Receipt  *readinessReceiptResponse  `json:"receipt"`
	Failures []readinessFailureResponse `json:"failures"`
}

// Verify delegates live dependency checks to Core, then independently restores
// the Go-compatible receipt digest before durable host persistence.
func (c *ReadinessClient) Verify(
	ctx context.Context,
	command readinessapp.Command,
) (readinessapp.Verification, error) {
	if c == nil || ctx == nil || command.OperationID.IsZero() || command.PlanDigest.IsZero() ||
		command.ReleaseID == "" || command.GenerationID == "" || command.ManifestDigest.IsZero() ||
		command.ComposeDigest.IsZero() || command.CoreEndpoint == "" || command.APICredentialPath == "" {
		return readinessapp.Verification{}, errCoreReadinessUnavailable
	}
	body, err := json.Marshal(readinessRequest{
		OperationID: command.OperationID.String(), PlanDigest: command.PlanDigest.String(),
		ReleaseID: command.ReleaseID, GenerationID: command.GenerationID,
		ManifestDigest: command.ManifestDigest.String(), ComposeDigest: command.ComposeDigest.String(),
	})
	if err != nil {
		return readinessapp.Verification{}, errCoreReadinessUnavailable
	}
	defer clear(body)
	responseBody, statusCode, err := authenticatedPost(
		ctx, c.credentials, command.CoreEndpoint, command.APICredentialPath,
		command.OperationID.String(), "/v1/readiness:verify", body,
	)
	if err != nil || statusCode != http.StatusOK || rejectDuplicateJSONKeys(responseBody) != nil {
		clear(responseBody)
		return readinessapp.Verification{}, errCoreReadinessUnavailable
	}
	defer clear(responseBody)
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()
	var response readinessVerificationResponse
	if err := decoder.Decode(&response); err != nil || requireJSONEOF(decoder) != nil {
		return readinessapp.Verification{}, errCoreReadinessUnavailable
	}
	if !response.Ready {
		failures, err := restoreReadinessFailures(response)
		if err != nil {
			return readinessapp.Verification{}, errCoreReadinessUnavailable
		}
		return readinessapp.NewNotReadyVerification(failures), nil
	}
	if response.Receipt == nil || len(response.Failures) != 0 {
		return readinessapp.Verification{}, errCoreReadinessUnavailable
	}
	receipt, err := readiness.RestoreReceipt(response.Receipt.record())
	if err != nil || receipt.OperationID() != command.OperationID ||
		!receipt.PlanDigest().Equal(command.PlanDigest) || receipt.ReleaseID() != command.ReleaseID ||
		receipt.GenerationID() != command.GenerationID ||
		!receipt.ManifestDigest().Equal(command.ManifestDigest) || !receipt.ComposeDigest().Equal(command.ComposeDigest) {
		return readinessapp.Verification{}, errCoreReadinessUnavailable
	}
	if err := c.receipts.SaveReadinessReceipt(ctx, receipt); err != nil {
		return readinessapp.Verification{}, errCoreReadinessUnavailable
	}
	return readinessapp.NewReadyVerification(receipt), nil
}

func restoreReadinessFailures(response readinessVerificationResponse) ([]readiness.Failure, error) {
	if response.Receipt != nil || len(response.Failures) == 0 {
		return nil, errCoreReadinessUnavailable
	}
	byProbe := make(map[readiness.Probe]struct{}, len(response.Failures))
	result := make([]readiness.Failure, 0, len(response.Failures))
	for _, failure := range response.Failures {
		probe := readinessProbe(failure.Probe)
		if !probe.Valid() || failure.Code != string(readiness.FailureProbeFailed) {
			return nil, errCoreReadinessUnavailable
		}
		if _, duplicate := byProbe[probe]; duplicate {
			return nil, errCoreReadinessUnavailable
		}
		byProbe[probe] = struct{}{}
		result = append(result, readiness.Failure{Probe: probe, Code: readiness.FailureProbeFailed})
	}
	return result, nil
}

func readinessProbe(value string) readiness.Probe {
	for _, probe := range readiness.RequiredProbes() {
		if probe.String() == value {
			return probe
		}
	}
	return readiness.ProbeUnknown
}

func (response readinessReceiptResponse) record() readiness.ReceiptRecord {
	results := make([]readiness.ResultRecord, 0, len(response.Results))
	for _, result := range response.Results {
		results = append(results, readiness.ResultRecord{
			Probe: result.Probe, Status: result.Status, OperationID: result.OperationID,
			PlanDigest: result.PlanDigest, ReleaseID: result.ReleaseID, GenerationID: result.GenerationID,
			ManifestDigest: result.ManifestDigest, ComposeDigest: result.ComposeDigest,
			EvidenceDigest: result.EvidenceDigest, ObservedAt: result.ObservedAt,
		})
	}
	return readiness.ReceiptRecord{
		SchemaVersion: response.SchemaVersion, OperationID: response.OperationID,
		PlanDigest: response.PlanDigest, ReleaseID: response.ReleaseID, GenerationID: response.GenerationID,
		ManifestDigest: response.ManifestDigest, ComposeDigest: response.ComposeDigest,
		EvaluatedAt: response.EvaluatedAt, Results: results, ReceiptDigest: response.ReceiptDigest,
	}
}

var _ interface {
	Verify(context.Context, readinessapp.Command) (readinessapp.Verification, error)
} = (*ReadinessClient)(nil)
