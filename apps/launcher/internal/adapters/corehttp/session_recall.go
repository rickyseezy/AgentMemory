package corehttp

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/mcpsession"
)

const sessionRecallPath = "/v1/session/recall:brief"

var (
	errSessionRecallAPI = errors.New("PF-005 session recall API is unavailable")
	recallOperation     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

// SessionRecallBudget bounds every Core and MCP response dimension.
type SessionRecallBudget struct {
	MaxTokens int `json:"max_tokens"`
	MaxItems  int `json:"max_items"`
	MaxBytes  int `json:"max_bytes"`
}

// SessionRecallRequest contains no caller-controlled identity coordinate.
type SessionRecallRequest struct {
	OperationID     string              `json:"operation_id"`
	Mode            string              `json:"mode"`
	MaxRelatedDepth int                 `json:"max_related_depth"`
	MaxRelatedCost  int                 `json:"max_related_cost"`
	TemporalFrom    *int64              `json:"temporal_from,omitempty"`
	TemporalTo      *int64              `json:"temporal_to,omitempty"`
	Budget          SessionRecallBudget `json:"budget"`
}

// RecallProvenance preserves the original producer instead of the consuming host.
type RecallProvenance struct {
	ProducerHost   string `json:"producer_host"`
	ModelID        string `json:"model_id"`
	AdapterID      string `json:"adapter_id"`
	AdapterVersion string `json:"adapter_version"`
	CaptureMethod  string `json:"capture_method"`
}

// RecallItem is one evidence-backed, explicitly untrusted continuity atom.
type RecallItem struct {
	ItemID                string           `json:"item_id"`
	SemanticID            string           `json:"semantic_id"`
	Kind                  string           `json:"kind"`
	Content               string           `json:"content"`
	Category              string           `json:"category"`
	Freshness             string           `json:"freshness"`
	RevisionCompatibility string           `json:"revision_compatibility"`
	Rank                  int              `json:"rank"`
	Classification        string           `json:"classification"`
	EvidenceEventID       string           `json:"evidence_event_id"`
	OccurredAt            string           `json:"occurred_at"`
	Provenance            RecallProvenance `json:"provenance"`
}

// RecallProcedure is one authorized environment-neutral generic procedure.
type RecallProcedure struct {
	ProcedureID string `json:"procedure_id"`
	Content     string `json:"content"`
}

// RecallExclusion explains an omission without returning its semantic content.
type RecallExclusion struct {
	ItemID string `json:"item_id"`
	Reason string `json:"reason"`
}

// RecallProcedureExclusion explains an incompatible procedure without its content.
type RecallProcedureExclusion struct {
	ProcedureID string `json:"procedure_id"`
	Reason      string `json:"reason"`
}

// SessionRecall is a verified generic delivery from the shared local Brain.
type SessionRecall struct {
	ConsumerHost       string                     `json:"consumer_host"`
	MediaType          string                     `json:"media_type"`
	RenderedContext    string                     `json:"rendered_context"`
	Items              []RecallItem               `json:"items"`
	Procedures         []RecallProcedure          `json:"procedures"`
	ExcludedProcedures []RecallProcedureExclusion `json:"excluded_procedures"`
	ExcludedItems      []RecallExclusion          `json:"excluded_items"`
	UsedTokens         int                        `json:"used_tokens"`
	UsedItems          int                        `json:"used_items"`
	UsedBytes          int                        `json:"used_bytes"`
	Truncated          bool                       `json:"truncated"`
	ScopeFingerprint   string                     `json:"scope_fingerprint"`
	Status             string                     `json:"status"`
	ContextEventID     string                     `json:"context_event_id"`
	PolicyVersion      string                     `json:"policy_version"`
}

// Recall authenticates with only the mounted session secret and derives scope in Core.
func (c *SessionStatusClient) Recall(
	ctx context.Context,
	request SessionRecallRequest,
) (SessionRecall, error) {
	if c == nil || ctx == nil || nilCapability(c.credentials) || c.client == nil ||
		!validRecallRequest(request) || !mcpsession.ValidUUIDv7(c.sessionID) {
		return SessionRecall{}, errSessionRecallAPI
	}
	body, err := json.Marshal(request)
	if err != nil {
		return SessionRecall{}, errSessionRecallAPI
	}
	defer clear(body)
	credential, err := c.credentials.ReadCredential(ctx, c.credentialPath)
	if err != nil || len(credential) != protectedCredentialBytes {
		clear(credential)
		return SessionRecall{}, errSessionRecallAPI
	}
	defer clear(credential)
	requestContext, cancel := context.WithTimeout(ctx, coreRequestTimeout)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(
		requestContext,
		http.MethodPost,
		"http://core:9411"+sessionRecallPath,
		bytes.NewReader(body),
	)
	if err != nil {
		return SessionRecall{}, errSessionRecallAPI
	}
	header := make([]byte, len("Bearer ")+hex.EncodedLen(len(credential)))
	copy(header, "Bearer ")
	hex.Encode(header[len("Bearer "):], credential)
	httpRequest.Header.Set("Authorization", string(header))
	clear(header)
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("X-AgentMemory-Session-ID", c.sessionID)
	response, err := c.client.Do(httpRequest)
	if err != nil {
		return SessionRecall{}, errSessionRecallAPI
	}
	defer func() { _ = response.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(response.Body, maximumCoreResponseBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > maximumCoreResponseBytes ||
		response.StatusCode != http.StatusOK ||
		response.Header.Get("Content-Type") != "application/json" ||
		rejectDuplicateJSONKeys(payload) != nil {
		clear(payload)
		return SessionRecall{}, errSessionRecallAPI
	}
	defer clear(payload)
	var recalled SessionRecall
	if decodeStrictJSON(payload, &recalled) != nil || !validRecallResponse(recalled, request.Budget) {
		return SessionRecall{}, errSessionRecallAPI
	}
	return recalled, nil
}

func validRecallRequest(request SessionRecallRequest) bool {
	return recallOperation.MatchString(request.OperationID) &&
		(request.Mode == "current" || request.Mode == "related" || request.Mode == "global") &&
		request.MaxRelatedDepth >= 1 && request.MaxRelatedDepth <= 3 &&
		request.MaxRelatedCost >= 1 && request.MaxRelatedCost <= 100 &&
		(request.TemporalFrom == nil || *request.TemporalFrom >= 0) &&
		(request.TemporalTo == nil || *request.TemporalTo >= 1) &&
		(request.TemporalFrom == nil || request.TemporalTo == nil ||
			*request.TemporalTo > *request.TemporalFrom) &&
		request.Budget.MaxTokens >= 64 && request.Budget.MaxTokens <= 8192 &&
		request.Budget.MaxItems >= 1 && request.Budget.MaxItems <= 100 &&
		request.Budget.MaxBytes >= 512 && request.Budget.MaxBytes <= 32*1024
}

func validRecallResponse(response SessionRecall, budget SessionRecallBudget) bool {
	if response.ConsumerHost != "generic" || response.MediaType != "application/json" ||
		(response.Status != "ready" && response.Status != "no_answer") ||
		!mcpsession.ValidSHA256Digest(response.ScopeFingerprint) ||
		!mcpsession.ValidUUIDv7(response.ContextEventID) ||
		!safeRecallToken(response.PolicyVersion, 128) ||
		response.UsedTokens < 0 || response.UsedTokens > budget.MaxTokens ||
		response.UsedItems < 0 || response.UsedItems > budget.MaxItems ||
		response.UsedBytes < 0 || response.UsedBytes > budget.MaxBytes ||
		len(response.Items)+len(response.Procedures) != response.UsedItems ||
		len(response.Items) > budget.MaxItems || len(response.Procedures) > budget.MaxItems ||
		len(response.RenderedContext) > budget.MaxBytes ||
		rejectDuplicateJSONKeys([]byte(response.RenderedContext)) != nil {
		return false
	}
	for _, item := range response.Items {
		if !validRecallItem(item) {
			return false
		}
	}
	for _, procedure := range response.Procedures {
		if !safeRecallToken(procedure.ProcedureID, 256) || !safeRecallText(procedure.Content, 8192) {
			return false
		}
	}
	for _, excluded := range response.ExcludedItems {
		if !safeRecallToken(excluded.ItemID, 256) ||
			(excluded.Reason != "branch_incompatible" && excluded.Reason != "stale_beyond_horizon") {
			return false
		}
	}
	for _, excluded := range response.ExcludedProcedures {
		if !safeRecallToken(excluded.ProcedureID, 256) || !safeRecallToken(excluded.Reason, 128) {
			return false
		}
	}
	return true
}

func validRecallItem(item RecallItem) bool {
	return safeRecallToken(item.ItemID, 256) && safeRecallToken(item.SemanticID, 256) &&
		(item.Kind == "fact" || item.Kind == "decision" || item.Kind == "change" ||
			item.Kind == "failure" || item.Kind == "next_step") &&
		safeRecallText(item.Content, 8192) && validRecallCategory(item.Category) &&
		(item.Freshness == "current" || item.Freshness == "stale") &&
		(item.RevisionCompatibility == "compatible" ||
			item.RevisionCompatibility == "unknown" ||
			item.RevisionCompatibility == "branch_incompatible") &&
		item.Rank >= 1 && safeRecallToken(item.Classification, 64) &&
		mcpsession.ValidUUIDv7(item.EvidenceEventID) && safeRecallToken(item.OccurredAt, 64) &&
		safeRecallToken(item.Provenance.ProducerHost, 128) &&
		safeRecallToken(item.Provenance.ModelID, 256) &&
		safeRecallToken(item.Provenance.AdapterID, 128) &&
		safeRecallToken(item.Provenance.AdapterVersion, 128) &&
		safeRecallToken(item.Provenance.CaptureMethod, 128)
}

func validRecallCategory(value string) bool {
	switch value {
	case "safety_constraint", "blocker", "unresolved_work", "decision", "failure",
		"validation", "change", "supporting":
		return true
	default:
		return false
	}
}

func safeRecallText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && !strings.ContainsAny(value, "\x00\r")
}

func safeRecallToken(value string, maximum int) bool {
	return safeRecallText(value, maximum) && !strings.ContainsRune(value, '\n')
}
