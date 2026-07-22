package corehttp

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/mcpsession"
)

const sessionStatusPath = "/v1/session/status"

var errSessionStatusAPI = errors.New("PF-005 session status API is unavailable")

// SessionStatus is the content-free scope proof returned to the transient bridge.
type SessionStatus struct {
	SessionID            string `json:"session_id"`
	BrainID              string `json:"brain_id"`
	AgentID              string `json:"agent_id"`
	WorkspaceFingerprint string `json:"workspace_fingerprint"`
	GitCoverage          string `json:"git_coverage"`
	IndexCoverage        string `json:"index_coverage"`
	State                string `json:"state"`
}

// SessionStatusClient is restricted to the fixed Core service on the internal network.
type SessionStatusClient struct {
	credentials    CredentialSource
	credentialPath string
	sessionID      string
	client         *http.Client
}

// NewSessionStatusClient constructs the only Core client admitted inside mcp-session.
func NewSessionStatusClient(
	credentials CredentialSource,
	credentialPath string,
	sessionID string,
) (*SessionStatusClient, error) {
	if nilCapability(credentials) || credentialPath != "/run/secrets/agentmemory-session" ||
		!mcpsession.ValidUUIDv7(sessionID) {
		return nil, errSessionStatusAPI
	}
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false,
		DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: -1}).DialContext,
	}
	return newSessionStatusClient(credentials, credentialPath, sessionID, &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("core redirects are forbidden")
		},
	})
}

func newSessionStatusClient(
	credentials CredentialSource,
	credentialPath string,
	sessionID string,
	client *http.Client,
) (*SessionStatusClient, error) {
	if nilCapability(credentials) || credentialPath != "/run/secrets/agentmemory-session" ||
		!mcpsession.ValidUUIDv7(sessionID) || client == nil || client.Transport == nil {
		return nil, errSessionStatusAPI
	}
	return &SessionStatusClient{
		credentials: credentials, credentialPath: credentialPath, sessionID: sessionID,
		client: client,
	}, nil
}

// Status authenticates with only the scoped credential and rejects substituted scope.
func (c *SessionStatusClient) Status(ctx context.Context) (SessionStatus, error) {
	if c == nil || ctx == nil || nilCapability(c.credentials) || c.client == nil ||
		!mcpsession.ValidUUIDv7(c.sessionID) {
		return SessionStatus{}, errSessionStatusAPI
	}
	credential, err := c.credentials.ReadCredential(ctx, c.credentialPath)
	if err != nil || len(credential) != protectedCredentialBytes {
		clear(credential)
		return SessionStatus{}, errSessionStatusAPI
	}
	defer clear(credential)
	requestContext, cancel := context.WithTimeout(ctx, coreRequestTimeout)
	defer cancel()
	endpoint := "http://core:9411" + sessionStatusPath
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, endpoint, nil)
	if err != nil {
		return SessionStatus{}, errSessionStatusAPI
	}
	header := make([]byte, len("Bearer ")+hex.EncodedLen(len(credential)))
	copy(header, "Bearer ")
	hex.Encode(header[len("Bearer "):], credential)
	request.Header.Set("Authorization", string(header))
	clear(header)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-AgentMemory-Session-ID", c.sessionID)
	response, err := c.client.Do(request)
	if err != nil {
		return SessionStatus{}, errSessionStatusAPI
	}
	defer func() { _ = response.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(response.Body, maximumCoreResponseBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > maximumCoreResponseBytes ||
		response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" ||
		rejectDuplicateJSONKeys(payload) != nil {
		clear(payload)
		return SessionStatus{}, errSessionStatusAPI
	}
	defer clear(payload)
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var status SessionStatus
	if err := decoder.Decode(&status); err != nil || requireJSONEOF(decoder) != nil ||
		status.SessionID != c.sessionID || !mcpsession.ValidUUIDv7(status.BrainID) ||
		!mcpsession.ValidAgentID(status.AgentID) ||
		!mcpsession.ValidSHA256Digest(status.WorkspaceFingerprint) ||
		!validGitCoverage(status.GitCoverage) || !validIndexCoverage(status.IndexCoverage) ||
		(status.State != "registered" && status.State != "active") {
		return SessionStatus{}, errSessionStatusAPI
	}
	return status, nil
}

func validGitCoverage(value string) bool {
	return value == "none" || value == "partial" || value == "complete"
}

func validIndexCoverage(value string) bool {
	return value == "pending" || value == "indexing" || value == "complete" ||
		value == "partial" || value == "degraded"
}
