package corehttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpsessionapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/mcpsession"
)

const (
	//nolint:gosec // This is an API route, not credential material.
	registerSessionCredentialPath = "/v1/launcher/sessions/credentials"
	//nolint:gosec // This is an API route, not credential material.
	revokeSessionCredentialPath = "/v1/launcher/sessions/credentials:revoke"
)

var errSessionCredentialAPI = errors.New("PF-005 Core credential API is unavailable")

// SessionCredentialRegistrar registers credential hashes through the root-authenticated loopback API.
type SessionCredentialRegistrar struct {
	credentials    CredentialSource
	endpoint       string
	credentialPath string
}

// NewSessionCredentialRegistrar rejects remote endpoints and absent protected root authority.
func NewSessionCredentialRegistrar(
	credentials CredentialSource,
	endpoint string,
	credentialPath string,
) (*SessionCredentialRegistrar, error) {
	if nilCapability(credentials) || credentialPath == "" || strings.ContainsAny(credentialPath, "\x00\r\n") {
		return nil, errSessionCredentialAPI
	}
	client, closeIdle, err := literalLoopbackClient(endpoint)
	if client != nil && closeIdle != nil {
		closeIdle()
	}
	if err != nil {
		return nil, errSessionCredentialAPI
	}
	return &SessionCredentialRegistrar{
		credentials: credentials, endpoint: endpoint, credentialPath: credentialPath,
	}, nil
}

type registerSessionCredentialRequest struct {
	SessionID            string `json:"session_id"`
	InstallationID       string `json:"installation_id"`
	BrainID              string `json:"brain_id"`
	ActorID              string `json:"actor_id"`
	GrantID              string `json:"grant_id"`
	AgentID              string `json:"agent_id"`
	WorkspaceFingerprint string `json:"workspace_fingerprint"`
	DeviceIdentity       string `json:"device_identity"`
	GitRepositoryID      string `json:"git_repository_id"`
	GitWorktreeID        string `json:"git_worktree_id"`
	GitCoverage          string `json:"git_coverage"`
	SecurityEpoch        uint64 `json:"security_epoch"`
	CredentialDigest     string `json:"credential_digest"`
	IssuedAt             string `json:"issued_at"`
	ExpiresAt            string `json:"expires_at"`
}

type sessionCredentialResponse struct {
	SessionID        string `json:"session_id"`
	CredentialDigest string `json:"credential_digest"`
	Status           string `json:"status"`
}

// Register persists only an opaque SHA-256 digest and its exact session scope.
func (r *SessionCredentialRegistrar) Register(
	ctx context.Context,
	registration mcpsessionapp.CredentialRegistration,
) error {
	if r == nil || ctx == nil || !r.valid() || !validRegistration(registration) {
		return errSessionCredentialAPI
	}
	body, err := json.Marshal(registerSessionCredentialRequest{
		SessionID: registration.Scope.SessionID, InstallationID: registration.Scope.InstallationID,
		BrainID: registration.Scope.BrainID, ActorID: registration.Scope.ActorID,
		GrantID: registration.Scope.GrantID, AgentID: registration.Scope.AgentID,
		WorkspaceFingerprint: registration.Scope.WorkspaceFingerprint,
		DeviceIdentity:       registration.Scope.DeviceIdentity,
		GitRepositoryID:      registration.Scope.GitRepositoryID,
		GitWorktreeID:        registration.Scope.GitWorktreeID,
		GitCoverage:          string(registration.Scope.GitCoverage),
		SecurityEpoch:        registration.Scope.SecurityEpoch, CredentialDigest: registration.Digest,
		IssuedAt:  registration.IssuedAt.UTC().Format("2006-01-02T15:04:05.000000Z"),
		ExpiresAt: registration.ExpiresAt.UTC().Format("2006-01-02T15:04:05.000000Z"),
	})
	if err != nil {
		return errSessionCredentialAPI
	}
	response, statusCode, err := authenticatedPost(
		ctx, r.credentials, r.endpoint, r.credentialPath, registration.Scope.SessionID,
		registerSessionCredentialPath, body,
	)
	if err != nil {
		return errSessionCredentialAPI
	}
	if statusCode != http.StatusCreated && statusCode != http.StatusOK {
		return errSessionCredentialAPI
	}
	wantedStatus := "registered"
	if statusCode == http.StatusOK {
		wantedStatus = "already_registered"
	}
	return validateSessionCredentialResponse(
		response, registration.Scope.SessionID, registration.Digest, wantedStatus,
	)
}

type revokeSessionCredentialRequest struct {
	CredentialDigest string `json:"credential_digest"`
}

// Revoke makes a credential unusable before the launcher removes its protected file.
func (r *SessionCredentialRegistrar) Revoke(ctx context.Context, digest string) error {
	if r == nil || ctx == nil || !r.valid() || !mcpsession.ValidSHA256Digest(digest) {
		return errSessionCredentialAPI
	}
	body, err := json.Marshal(revokeSessionCredentialRequest{CredentialDigest: digest})
	if err != nil {
		return errSessionCredentialAPI
	}
	response, statusCode, err := authenticatedPost(
		ctx, r.credentials, r.endpoint, r.credentialPath, digest,
		revokeSessionCredentialPath, body,
	)
	if err != nil || statusCode != http.StatusOK {
		return errSessionCredentialAPI
	}
	var decoded sessionCredentialResponse
	if rejectDuplicateJSONKeys(response) != nil || decodeStrictJSON(response, &decoded) != nil ||
		decoded.SessionID != "" || decoded.CredentialDigest != digest ||
		(decoded.Status != "revoked" && decoded.Status != "already_revoked") {
		return errSessionCredentialAPI
	}
	return nil
}

func (r *SessionCredentialRegistrar) valid() bool {
	return !nilCapability(r.credentials) && r.endpoint != "" && r.credentialPath != ""
}

func validRegistration(registration mcpsessionapp.CredentialRegistration) bool {
	scope := registration.Scope
	return mcpsession.ValidUUIDv7(scope.SessionID) && mcpsession.ValidUUIDv7(scope.InstallationID) &&
		mcpsession.ValidUUIDv7(scope.BrainID) && mcpsession.ValidUUIDv7(scope.ActorID) &&
		mcpsession.ValidUUIDv7(scope.GrantID) &&
		mcpsession.ValidAgentID(scope.AgentID) &&
		mcpsession.ValidSHA256Digest(scope.WorkspaceFingerprint) && validDeviceIdentity(scope.DeviceIdentity) &&
		validGitScope(scope.GitRepositoryID, scope.GitWorktreeID, scope.GitCoverage) &&
		scope.SecurityEpoch > 0 &&
		mcpsession.ValidSHA256Digest(registration.Digest) && !registration.IssuedAt.IsZero() &&
		registration.ExpiresAt.After(registration.IssuedAt) &&
		registration.ExpiresAt.Sub(registration.IssuedAt) <= maximumCredentialTTL
}

func validDeviceIdentity(value string) bool {
	return value != "" && len(value) <= 512 && !strings.ContainsAny(value, "\x00\r\n")
}

func validGitScope(repositoryID string, worktreeID string, coverage mcpsession.GitCoverage) bool {
	if len(repositoryID) > 512 || len(worktreeID) > 512 ||
		strings.ContainsAny(repositoryID, "\x00\r\n") || strings.ContainsAny(worktreeID, "\x00\r\n") {
		return false
	}
	switch coverage {
	case mcpsession.GitCoverageNone:
		return repositoryID == "" && worktreeID == ""
	case mcpsession.GitCoveragePartial, mcpsession.GitCoverageComplete:
		return mcpsession.ValidSHA256Digest(repositoryID) &&
			mcpsession.ValidSHA256Digest(worktreeID)
	default:
		return false
	}
}

func validateSessionCredentialResponse(
	response []byte,
	sessionID string,
	digest string,
	status string,
) error {
	var decoded sessionCredentialResponse
	if rejectDuplicateJSONKeys(response) != nil || decodeStrictJSON(response, &decoded) != nil ||
		decoded.SessionID != sessionID || decoded.CredentialDigest != digest || decoded.Status != status {
		return errSessionCredentialAPI
	}
	return nil
}

func decodeStrictJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

const maximumCredentialTTL = 12 * time.Hour

var _ interface {
	Register(context.Context, mcpsessionapp.CredentialRegistration) error
	Revoke(context.Context, string) error
} = (*SessionCredentialRegistrar)(nil)
