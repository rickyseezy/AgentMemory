package corehttp

import (
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
	beginSessionPath     = "/v1/launcher/sessions:begin"
	heartbeatSessionPath = "/v1/launcher/sessions:heartbeat"
	finishSessionPath    = "/v1/launcher/sessions:finish"
	maximumSessionLease  = 120 * time.Second
)

var errSessionLifecycleAPI = errors.New("PF-005 Core session lifecycle API is unavailable")

// SessionLifecycleRepository persists lease and terminal state through the root-authenticated Core.
type SessionLifecycleRepository struct {
	credentials    CredentialSource
	endpoint       string
	credentialPath string
}

// NewSessionLifecycleRepository binds lifecycle calls to one literal-loopback Core authority.
func NewSessionLifecycleRepository(
	credentials CredentialSource,
	endpoint string,
	credentialPath string,
) (*SessionLifecycleRepository, error) {
	if nilCapability(credentials) || credentialPath == "" ||
		credentialPath != strings.TrimSpace(credentialPath) || len(credentialPath) > 4096 ||
		strings.ContainsAny(credentialPath, "\x00\r\n") {
		return nil, errSessionLifecycleAPI
	}
	client, closeIdle, err := literalLoopbackClient(endpoint)
	if err != nil || client == nil || closeIdle == nil {
		return nil, errSessionLifecycleAPI
	}
	closeIdle()
	return &SessionLifecycleRepository{
		credentials: credentials, endpoint: endpoint, credentialPath: credentialPath,
	}, nil
}

type beginSessionRequest struct {
	SessionID    string `json:"session_id"`
	StartedAt    string `json:"started_at"`
	LeaseSeconds int64  `json:"lease_seconds"`
}

type heartbeatSessionRequest struct {
	SessionID   string `json:"session_id"`
	HeartbeatAt string `json:"heartbeat_at"`
}

type finishSessionRequest struct {
	SessionID  string `json:"session_id"`
	Status     string `json:"status"`
	FinishedAt string `json:"finished_at"`
}

type sessionLifecycleResponse struct {
	SessionID string `json:"session_id"`
	State     string `json:"state"`
	Revision  uint64 `json:"revision"`
}

// Begin starts the lease at the exact credential issue instant used by session preparation.
func (r *SessionLifecycleRepository) Begin(
	ctx context.Context,
	plan mcpsession.ExecutionPlan,
	lease time.Duration,
) error {
	if r == nil || ctx == nil || !r.valid() || !plan.Valid() || lease <= 0 ||
		lease > maximumSessionLease || lease%time.Second != 0 {
		return errSessionLifecycleAPI
	}
	request := beginSessionRequest{
		SessionID: plan.SessionID(), StartedAt: formatSessionTime(plan.Credential().IssuedAt()),
		LeaseSeconds: int64(lease / time.Second),
	}
	return r.post(ctx, plan.SessionID(), beginSessionPath, request, "active", 1)
}

// Heartbeat renews one lease at the exact launcher clock timestamp.
func (r *SessionLifecycleRepository) Heartbeat(
	ctx context.Context,
	sessionID string,
	at time.Time,
) error {
	if r == nil || ctx == nil || !r.valid() || !mcpsession.ValidUUIDv7(sessionID) || at.IsZero() {
		return errSessionLifecycleAPI
	}
	request := heartbeatSessionRequest{SessionID: sessionID, HeartbeatAt: formatSessionTime(at)}
	return r.post(ctx, sessionID, heartbeatSessionPath, request, "active", 2)
}

// Finish records only a completed or interrupted terminal state.
func (r *SessionLifecycleRepository) Finish(
	ctx context.Context,
	sessionID string,
	result mcpsessionapp.Status,
	at time.Time,
) error {
	if r == nil || ctx == nil || !r.valid() || !mcpsession.ValidUUIDv7(sessionID) || at.IsZero() ||
		(result != mcpsessionapp.StatusCompleted && result != mcpsessionapp.StatusInterrupted) {
		return errSessionLifecycleAPI
	}
	request := finishSessionRequest{
		SessionID: sessionID, Status: string(result), FinishedAt: formatSessionTime(at),
	}
	return r.post(ctx, sessionID, finishSessionPath, request, string(result), 2)
}

func (r *SessionLifecycleRepository) post(
	ctx context.Context,
	sessionID string,
	path string,
	request any,
	wantedState string,
	minimumRevision uint64,
) error {
	body, err := json.Marshal(request)
	if err != nil {
		return errSessionLifecycleAPI
	}
	defer clear(body)
	response, statusCode, err := authenticatedPost(
		ctx, r.credentials, r.endpoint, r.credentialPath, sessionID, path, body,
	)
	if err != nil || statusCode != http.StatusOK {
		clear(response)
		return errSessionLifecycleAPI
	}
	defer clear(response)
	var decoded sessionLifecycleResponse
	if decodeStrictJSON(response, &decoded) != nil || decoded.SessionID != sessionID ||
		decoded.State != wantedState || decoded.Revision < minimumRevision {
		return errSessionLifecycleAPI
	}
	return nil
}

func (r *SessionLifecycleRepository) valid() bool {
	return !nilCapability(r.credentials) && r.endpoint != "" && r.credentialPath != ""
}

func formatSessionTime(value time.Time) string {
	return value.UTC().Truncate(time.Microsecond).Format("2006-01-02T15:04:05.000000Z")
}

var _ mcpsessionapp.SessionRepository = (*SessionLifecycleRepository)(nil)
