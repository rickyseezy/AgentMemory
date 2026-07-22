package corehttp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/mcpsessioncheckpoint"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/mcpsession"
)

const workspaceCheckpointPath = "/v1/launcher/sessions:checkpoint"

var errWorkspaceCheckpointAPI = errors.New("PF-005 Core workspace checkpoint API is unavailable")

// WorkspaceCheckpointClient durably stages one bounded privacy-filtered delta
// through the root-authenticated loopback Core. It never receives or persists
// an absolute host path.
type WorkspaceCheckpointClient struct {
	credentials    CredentialSource
	endpoint       string
	credentialPath string
}

// NewWorkspaceCheckpointClient binds the sink to one literal-loopback Core authority.
func NewWorkspaceCheckpointClient(
	credentials CredentialSource,
	endpoint string,
	credentialPath string,
) (*WorkspaceCheckpointClient, error) {
	if nilCapability(credentials) || credentialPath == "" ||
		credentialPath != strings.TrimSpace(credentialPath) || len(credentialPath) > 4096 ||
		strings.ContainsAny(credentialPath, "\x00\r\n") {
		return nil, errWorkspaceCheckpointAPI
	}
	client, closeIdle, err := literalLoopbackClient(endpoint)
	if err != nil || client == nil || closeIdle == nil {
		return nil, errWorkspaceCheckpointAPI
	}
	closeIdle()
	return &WorkspaceCheckpointClient{
		credentials: credentials, endpoint: endpoint, credentialPath: credentialPath,
	}, nil
}

type workspaceCheckpointChange struct {
	RelativePath  string `json:"relative_path"`
	SHA256        string `json:"sha256"`
	ContentBase64 string `json:"content_base64"`
	Deleted       bool   `json:"deleted"`
}

type workspaceCheckpointRequest struct {
	SessionID            string                      `json:"session_id"`
	WorkspaceFingerprint string                      `json:"workspace_fingerprint"`
	BatchDigest          string                      `json:"batch_digest"`
	Partial              bool                        `json:"partial"`
	Changes              []workspaceCheckpointChange `json:"changes"`
}

type workspaceCheckpointResponse struct {
	SessionID   string `json:"session_id"`
	BatchDigest string `json:"batch_digest"`
	Status      string `json:"status"`
}

// Upload receives success only after Core has durably staged the exact batch.
func (c *WorkspaceCheckpointClient) Upload(
	ctx context.Context,
	batch mcpsessioncheckpoint.Batch,
) error {
	request, canonical, err := encodeWorkspaceCheckpoint(batch)
	if c == nil || ctx == nil || err != nil || nilCapability(c.credentials) {
		return errWorkspaceCheckpointAPI
	}
	digest := sha256.Sum256(canonical)
	request.BatchDigest = hex.EncodeToString(digest[:])
	body, err := json.Marshal(request)
	if err != nil {
		return errWorkspaceCheckpointAPI
	}
	defer clear(body)
	response, statusCode, err := authenticatedPost(
		ctx, c.credentials, c.endpoint, c.credentialPath, request.BatchDigest,
		workspaceCheckpointPath, body,
	)
	if err != nil || (statusCode != http.StatusCreated && statusCode != http.StatusOK) {
		clear(response)
		return errWorkspaceCheckpointAPI
	}
	defer clear(response)
	var decoded workspaceCheckpointResponse
	wantedStatus := "checkpointed"
	if statusCode == http.StatusOK {
		wantedStatus = "already_checkpointed"
	}
	if rejectDuplicateJSONKeys(response) != nil || decodeStrictJSON(response, &decoded) != nil ||
		decoded.SessionID != request.SessionID || decoded.BatchDigest != request.BatchDigest ||
		decoded.Status != wantedStatus {
		return errWorkspaceCheckpointAPI
	}
	return nil
}

func encodeWorkspaceCheckpoint(
	batch mcpsessioncheckpoint.Batch,
) (workspaceCheckpointRequest, []byte, error) {
	if !mcpsession.ValidUUIDv7(batch.SessionID) ||
		!mcpsession.ValidSHA256Digest(batch.WorkspaceFingerprint) || len(batch.Changes) > 10_000 {
		return workspaceCheckpointRequest{}, nil, errWorkspaceCheckpointAPI
	}
	changes := make([]workspaceCheckpointChange, 0, len(batch.Changes))
	for _, change := range batch.Changes {
		if change.RelativePath == "" || len(change.RelativePath) > 4096 ||
			strings.ContainsAny(change.RelativePath, "\x00\r\n") ||
			!mcpsession.ValidSHA256Digest(change.SHA256) ||
			(change.Deleted && len(change.Content) != 0) {
			return workspaceCheckpointRequest{}, nil, errWorkspaceCheckpointAPI
		}
		if !change.Deleted {
			digest := sha256.Sum256(change.Content)
			if hex.EncodeToString(digest[:]) != change.SHA256 {
				return workspaceCheckpointRequest{}, nil, errWorkspaceCheckpointAPI
			}
		}
		changes = append(changes, workspaceCheckpointChange{
			RelativePath: change.RelativePath, SHA256: change.SHA256,
			ContentBase64: base64.StdEncoding.EncodeToString(change.Content), Deleted: change.Deleted,
		})
	}
	request := workspaceCheckpointRequest{
		SessionID: batch.SessionID, WorkspaceFingerprint: batch.WorkspaceFingerprint,
		Partial: batch.Partial, Changes: changes,
	}
	canonical, err := json.Marshal(request)
	if err != nil {
		return workspaceCheckpointRequest{}, nil, errWorkspaceCheckpointAPI
	}
	return request, canonical, nil
}

var _ mcpsessioncheckpoint.Sink = (*WorkspaceCheckpointClient)(nil)
