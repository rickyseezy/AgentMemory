package corehttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/activereleaseapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/activerelease"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/readiness"
)

var errCoreActiveReleaseUnavailable = errors.New("core active-release transaction unavailable")

// ActiveReleaseClient binds the governed activation transaction to one exact
// authenticated literal-loopback Core endpoint. It exposes no generic Core API.
type ActiveReleaseClient struct {
	credentials    CredentialSource
	endpoint       string
	credentialPath string
	marshal        func(any) ([]byte, error)
	stageDigest    func(install.OperationID, activerelease.Pointer) (install.Digest, error)
}

// NewActiveReleaseClient validates immutable Core authority before any stage,
// commit, or reconciliation request can be sent.
func NewActiveReleaseClient(
	credentials CredentialSource,
	endpoint string,
	credentialPath string,
) (*ActiveReleaseClient, error) {
	if nilCapability(credentials) || credentialPath == "" || credentialPath != strings.TrimSpace(credentialPath) ||
		len(credentialPath) > 4096 || strings.ContainsAny(credentialPath, "\x00\r\n") {
		return nil, errors.New("core active-release authority is required")
	}
	client, closeIdle, err := literalLoopbackClient(endpoint)
	if err != nil || client == nil || closeIdle == nil {
		return nil, errors.New("core active-release endpoint is invalid")
	}
	closeIdle()
	return &ActiveReleaseClient{
		credentials: credentials, endpoint: endpoint, credentialPath: credentialPath,
		marshal: json.Marshal, stageDigest: activerelease.StageDigest,
	}, nil
}

type activeReleasePointerRecord struct {
	SchemaVersion            uint16 `json:"schema_version"`
	InstallationID           string `json:"installation_id"`
	ReleaseID                string `json:"release_id"`
	GenerationID             string `json:"generation_id"`
	ManifestDigest           string `json:"manifest_digest"`
	ComposeDigest            string `json:"compose_digest"`
	ReadinessReceiptDigest   string `json:"readiness_receipt_digest"`
	RuntimeEndpoint          string `json:"runtime_endpoint"`
	ReleaseSequence          uint64 `json:"release_sequence"`
	ResourceInventoryVersion uint64 `json:"resource_inventory_version"`
	ResourceInventoryDigest  string `json:"resource_inventory_digest"`
	SecurityEpoch            uint64 `json:"security_epoch"`
	ActivatedAt              string `json:"activated_at"`
	PointerDigest            string `json:"pointer_digest"`
}

type activeReleaseStageRequest struct {
	OperationID string                     `json:"operation_id"`
	Pointer     activeReleasePointerRecord `json:"pointer"`
}

type activeReleaseCommitRequest struct {
	OperationID string                     `json:"operation_id"`
	Pointer     activeReleasePointerRecord `json:"pointer"`
	StageDigest string                     `json:"stage_digest"`
}

type activeReleaseMatchesRequest struct {
	Pointer activeReleasePointerRecord `json:"pointer"`
}

type activeReleaseStageResponse struct {
	StageDigest string `json:"stage_digest"`
}

type activeReleaseCommitResponse struct {
	PointerDigest string `json:"pointer_digest"`
}

type activeReleaseMatchesResponse struct {
	Matches bool `json:"matches"`
}

// Stage asks Core to durably prepare the same exact readiness-authorized
// pointer, then independently verifies Core's deterministic stage receipt.
func (c *ActiveReleaseClient) Stage(
	ctx context.Context,
	operationID install.OperationID,
	pointer activerelease.Pointer,
	receipt readiness.Receipt,
) (install.Digest, error) {
	if c == nil || ctx == nil || operationID.IsZero() || !receiptAuthorizesPointer(operationID, pointer, receipt) {
		return install.Digest{}, errCoreActiveReleaseUnavailable
	}
	expected, err := c.stageDigest(operationID, pointer)
	if err != nil {
		return install.Digest{}, errCoreActiveReleaseUnavailable
	}
	body, err := c.marshal(activeReleaseStageRequest{
		OperationID: operationID.String(), Pointer: activeReleaseRecord(pointer),
	})
	if err != nil {
		return install.Digest{}, errCoreActiveReleaseUnavailable
	}
	defer clear(body)
	response, statusCode, err := authenticatedPost(
		ctx, c.credentials, c.endpoint, c.credentialPath, operationID.String(),
		"/v1/active-release:stage", body,
	)
	if err != nil || (statusCode != http.StatusCreated && statusCode != http.StatusOK) {
		clear(response)
		return install.Digest{}, errCoreActiveReleaseUnavailable
	}
	defer clear(response)
	var decoded activeReleaseStageResponse
	if decodeStrictCoreResponse(response, &decoded) != nil {
		return install.Digest{}, errCoreActiveReleaseUnavailable
	}
	actual, err := install.ParseDigest(decoded.StageDigest)
	if err != nil || !actual.Equal(expected) {
		return install.Digest{}, errCoreActiveReleaseUnavailable
	}
	return actual, nil
}

// Commit supplies the stage receipt only after the host pointer CAS is
// durable, and accepts only an exact pointer-digest acknowledgement.
func (c *ActiveReleaseClient) Commit(
	ctx context.Context,
	operationID install.OperationID,
	stageDigest install.Digest,
	pointer activerelease.Pointer,
) (install.Digest, error) {
	if c == nil || ctx == nil || operationID.IsZero() || stageDigest.IsZero() || pointer.IsZero() {
		return install.Digest{}, errCoreActiveReleaseUnavailable
	}
	expectedStage, err := c.stageDigest(operationID, pointer)
	if err != nil || !expectedStage.Equal(stageDigest) {
		return install.Digest{}, errCoreActiveReleaseUnavailable
	}
	body, err := c.marshal(activeReleaseCommitRequest{
		OperationID: operationID.String(), Pointer: activeReleaseRecord(pointer),
		StageDigest: stageDigest.String(),
	})
	if err != nil {
		return install.Digest{}, errCoreActiveReleaseUnavailable
	}
	defer clear(body)
	response, statusCode, err := authenticatedPost(
		ctx, c.credentials, c.endpoint, c.credentialPath, operationID.String(),
		"/v1/active-release:commit", body,
	)
	if err != nil || statusCode != http.StatusOK {
		clear(response)
		return install.Digest{}, errCoreActiveReleaseUnavailable
	}
	defer clear(response)
	var decoded activeReleaseCommitResponse
	if decodeStrictCoreResponse(response, &decoded) != nil {
		return install.Digest{}, errCoreActiveReleaseUnavailable
	}
	actual, err := install.ParseDigest(decoded.PointerDigest)
	if err != nil || !actual.Equal(pointer.Digest()) {
		return install.Digest{}, errCoreActiveReleaseUnavailable
	}
	return actual, nil
}

// Matches re-authenticates Core's exact pointer mirror after the host/Core
// saga reports committed; false remains an integrity failure to the caller.
func (c *ActiveReleaseClient) Matches(
	ctx context.Context,
	pointer activerelease.Pointer,
) (bool, error) {
	if c == nil || ctx == nil || pointer.IsZero() {
		return false, errCoreActiveReleaseUnavailable
	}
	body, err := c.marshal(activeReleaseMatchesRequest{Pointer: activeReleaseRecord(pointer)})
	if err != nil {
		return false, errCoreActiveReleaseUnavailable
	}
	defer clear(body)
	response, statusCode, err := authenticatedPost(
		ctx, c.credentials, c.endpoint, c.credentialPath, pointer.Digest().String(),
		"/v1/active-release:matches", body,
	)
	if err != nil || statusCode != http.StatusOK {
		clear(response)
		return false, errCoreActiveReleaseUnavailable
	}
	defer clear(response)
	var decoded activeReleaseMatchesResponse
	if decodeStrictCoreResponse(response, &decoded) != nil {
		return false, errCoreActiveReleaseUnavailable
	}
	return decoded.Matches, nil
}

func receiptAuthorizesPointer(
	operationID install.OperationID,
	pointer activerelease.Pointer,
	receipt readiness.Receipt,
) bool {
	return !pointer.IsZero() && !receipt.IsZero() && receipt.OperationID() == operationID &&
		receipt.Digest().Equal(pointer.ReadinessReceiptDigest()) && receipt.ReleaseID() == pointer.ReleaseID() &&
		receipt.GenerationID() == pointer.GenerationID() && receipt.ManifestDigest().Equal(pointer.ManifestDigest()) &&
		receipt.ComposeDigest().Equal(pointer.ComposeDigest())
}

func activeReleaseRecord(pointer activerelease.Pointer) activeReleasePointerRecord {
	record := pointer.Record()
	return activeReleasePointerRecord{
		SchemaVersion: record.SchemaVersion, InstallationID: record.InstallationID,
		ReleaseID: record.ReleaseID, GenerationID: record.GenerationID,
		ManifestDigest: record.ManifestDigest, ComposeDigest: record.ComposeDigest,
		ReadinessReceiptDigest: record.ReadinessReceiptDigest, RuntimeEndpoint: record.RuntimeEndpoint,
		ReleaseSequence: record.ReleaseSequence, ResourceInventoryVersion: record.ResourceInventoryVersion,
		ResourceInventoryDigest: record.ResourceInventoryDigest, SecurityEpoch: record.SecurityEpoch,
		ActivatedAt: record.ActivatedAt, PointerDigest: record.PointerDigest,
	}
}

func decodeStrictCoreResponse(raw []byte, target any) error {
	if rejectDuplicateJSONKeys(raw) != nil {
		return errCoreActiveReleaseUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errCoreActiveReleaseUnavailable
	}
	return requireJSONEOF(decoder)
}

var _ activereleaseapp.CorePointerPort = (*ActiveReleaseClient)(nil)
