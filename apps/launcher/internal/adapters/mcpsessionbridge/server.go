package mcpsessionbridge

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/corehttp"
)

const (
	toolBrainStatus    = "brain_status"
	toolRecallContext  = "recall_context"
	resourceSession    = "agentmemory://session"
	recallOutputSchema = `{"type":"object","additionalProperties":false,"properties":{` +
		`"contract_version":{"type":"integer","const":1},` +
		`"untrusted_historical_data":{"type":"boolean","const":true},` +
		`"status":{"type":"string","enum":["ready","no_answer"]},` +
		`"scope_fingerprint":{"type":"string","pattern":"^[0-9a-f]{64}$"},` +
		`"context_event_id":{"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"},` +
		`"policy_version":{"type":"string","minLength":1,"maxLength":128},` +
		`"used_tokens":{"type":"integer","minimum":0,"maximum":8192},` +
		`"used_items":{"type":"integer","minimum":0,"maximum":100},` +
		`"used_bytes":{"type":"integer","minimum":0,"maximum":32768},` +
		`"truncated":{"type":"boolean"},` +
		`"items":{"type":"array","maxItems":100,"items":` + recallItemSchema + `},` +
		`"procedures":{"type":"array","maxItems":100,"items":` + recallProcedureSchema + `},` +
		`"excluded_items":{"type":"array","maxItems":100,"items":` + recallExclusionSchema + `},` +
		`"excluded_procedures":{"type":"array","maxItems":100,"items":` + recallProcedureExclusionSchema + `}` +
		`},"required":["contract_version","untrusted_historical_data","status","scope_fingerprint",` +
		`"context_event_id","policy_version","used_tokens","used_items","used_bytes","truncated",` +
		`"items","procedures","excluded_items","excluded_procedures"]}`
	recallItemSchema = `{"type":"object","additionalProperties":false,"properties":{` +
		`"item_id":{"type":"string","minLength":1,"maxLength":256},` +
		`"semantic_id":{"type":"string","minLength":1,"maxLength":256},` +
		`"kind":{"type":"string","enum":["fact","decision","change","failure","next_step"]},` +
		`"content":{"type":"string","minLength":1,"maxLength":8192},` +
		`"category":{"type":"string","enum":["safety_constraint","blocker","unresolved_work","decision","failure","validation","change","supporting"]},` +
		`"freshness":{"type":"string","enum":["current","stale"]},` +
		`"revision_compatibility":{"type":"string","enum":["compatible","unknown","branch_incompatible"]},` +
		`"rank":{"type":"integer","minimum":1},` +
		`"classification":{"type":"string","minLength":1,"maxLength":64},` +
		`"evidence_event_id":{"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"},` +
		`"occurred_at":{"type":"string","minLength":1,"maxLength":64},` +
		`"provenance":{"type":"object","additionalProperties":false,"properties":{` +
		`"producer_host":{"type":"string","minLength":1,"maxLength":128},` +
		`"model_id":{"type":"string","minLength":1,"maxLength":256},` +
		`"adapter_id":{"type":"string","minLength":1,"maxLength":128},` +
		`"adapter_version":{"type":"string","minLength":1,"maxLength":128},` +
		`"capture_method":{"type":"string","minLength":1,"maxLength":128}},` +
		`"required":["producer_host","model_id","adapter_id","adapter_version","capture_method"]}` +
		`},"required":["item_id","semantic_id","kind","content","category","freshness",` +
		`"revision_compatibility","rank","classification","evidence_event_id","occurred_at","provenance"]}`
	recallProcedureSchema = `{"type":"object","additionalProperties":false,"properties":{` +
		`"procedure_id":{"type":"string","minLength":1,"maxLength":256},` +
		`"content":{"type":"string","minLength":1,"maxLength":8192}},` +
		`"required":["procedure_id","content"]}`
	recallExclusionSchema = `{"type":"object","additionalProperties":false,"properties":{` +
		`"item_id":{"type":"string","minLength":1,"maxLength":256},` +
		`"reason":{"type":"string","enum":["branch_incompatible","stale_beyond_horizon"]}},` +
		`"required":["item_id","reason"]}`
	recallProcedureExclusionSchema = `{"type":"object","additionalProperties":false,"properties":{` +
		`"procedure_id":{"type":"string","minLength":1,"maxLength":256},` +
		`"reason":{"type":"string","minLength":1,"maxLength":128}},` +
		`"required":["procedure_id","reason"]}`
)

// StatusPort is the bridge's only Core authority in PF-005.
type StatusPort interface {
	Status(context.Context) (corehttp.SessionStatus, error)
}

// RecallPort is the session-derived continuity capability; it accepts no scope IDs.
type RecallPort interface {
	Recall(context.Context, corehttp.SessionRecallRequest) (corehttp.SessionRecall, error)
}

// Server exposes session-scoped MCP without any root credential or database access.
type Server struct {
	status StatusPort
	recall RecallPort
	server *mcp.Server
}

// NewServer builds the closed transient surface.
func NewServer(status StatusPort, recall RecallPort) (*Server, error) {
	if nilCapability(status) || nilCapability(recall) {
		return nil, errors.New("session status authority is invalid")
	}
	server := mcp.NewServer(
		&mcp.Implementation{Name: "agentmemory-session", Title: "AgentMemory", Version: "1.0.0"},
		&mcp.ServerOptions{
			Instructions: "Use AgentMemory tools to access only the active authorized local Brain session.",
			Capabilities: &mcp.ServerCapabilities{
				Tools: &mcp.ToolCapabilities{}, Resources: &mcp.ResourceCapabilities{},
			},
		},
	)
	result := &Server{status: status, recall: recall, server: server}
	closedWorld, additive := false, false
	mcp.AddTool(server, &mcp.Tool{
		Name: toolBrainStatus, Title: "Local Brain session status",
		Description:  "Prove the active session, agent, and workspace scope without exposing a host path.",
		InputSchema:  json.RawMessage(`{"type":"object","additionalProperties":false}`),
		OutputSchema: json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"contract_version":{"type":"integer","const":1},"session_id":{"type":"string"},"brain_id":{"type":"string"},"agent_id":{"type":"string"},"workspace_fingerprint":{"type":"string"},"git_coverage":{"type":"string","enum":["none","partial","complete"]},"index_coverage":{"type":"string","enum":["pending","indexing","complete","partial","degraded"]},"state":{"type":"string","enum":["registered","active"]}},"required":["contract_version","session_id","brain_id","agent_id","workspace_fingerprint","git_coverage","index_coverage","state"]}`),
		Annotations: &mcp.ToolAnnotations{
			Title: "Local Brain session status", ReadOnlyHint: true,
			OpenWorldHint: &closedWorld, DestructiveHint: &additive, IdempotentHint: true,
		},
	}, result.handleStatus)
	mcp.AddTool(server, &mcp.Tool{
		Name: toolRecallContext, Title: "Recall authorized Brain context",
		Description:  "Retrieve untrusted historical context from the current, related, or globally authorized local Brain scope. Identity and project scope are derived from the active session.",
		InputSchema:  json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"operation_id":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]*$"},"mode":{"type":"string","enum":["current","related","global"],"default":"current"},"max_related_depth":{"type":"integer","minimum":1,"maximum":3,"default":3},"max_related_cost":{"type":"integer","minimum":1,"maximum":100,"default":10},"temporal_from":{"type":["integer","null"],"minimum":0},"temporal_to":{"type":["integer","null"],"minimum":1},"max_tokens":{"type":"integer","minimum":64,"maximum":8192,"default":1200},"max_items":{"type":"integer","minimum":1,"maximum":100,"default":12},"max_bytes":{"type":"integer","minimum":512,"maximum":32768,"default":20480}},"required":["operation_id"]}`),
		OutputSchema: json.RawMessage(recallOutputSchema),
		Annotations: &mcp.ToolAnnotations{
			Title: "Recall authorized Brain context", ReadOnlyHint: true,
			OpenWorldHint: &closedWorld, DestructiveHint: &additive, IdempotentHint: true,
		},
	}, result.handleRecall)
	server.AddResource(&mcp.Resource{
		URI: resourceSession, Name: "AgentMemory session scope",
		Description: "Content-free authenticated scope for this transient MCP session.",
		MIMEType:    "application/json",
	}, result.handleResource)
	return result, nil
}

type emptyInput struct{}

type statusOutput struct {
	ContractVersion      uint16 `json:"contract_version"`
	SessionID            string `json:"session_id"`
	BrainID              string `json:"brain_id"`
	AgentID              string `json:"agent_id"`
	WorkspaceFingerprint string `json:"workspace_fingerprint"`
	GitCoverage          string `json:"git_coverage"`
	IndexCoverage        string `json:"index_coverage"`
	State                string `json:"state"`
}

type recallInput struct {
	OperationID     string `json:"operation_id"`
	Mode            string `json:"mode,omitempty"`
	MaxRelatedDepth int    `json:"max_related_depth,omitempty"`
	MaxRelatedCost  int    `json:"max_related_cost,omitempty"`
	TemporalFrom    *int64 `json:"temporal_from,omitempty"`
	TemporalTo      *int64 `json:"temporal_to,omitempty"`
	MaxTokens       int    `json:"max_tokens,omitempty"`
	MaxItems        int    `json:"max_items,omitempty"`
	MaxBytes        int    `json:"max_bytes,omitempty"`
}

type recallOutput struct {
	ContractVersion         uint16                              `json:"contract_version"`
	UntrustedHistoricalData bool                                `json:"untrusted_historical_data"`
	Status                  string                              `json:"status"`
	ScopeFingerprint        string                              `json:"scope_fingerprint"`
	ContextEventID          string                              `json:"context_event_id"`
	PolicyVersion           string                              `json:"policy_version"`
	UsedTokens              int                                 `json:"used_tokens"`
	UsedItems               int                                 `json:"used_items"`
	UsedBytes               int                                 `json:"used_bytes"`
	Truncated               bool                                `json:"truncated"`
	Items                   []corehttp.RecallItem               `json:"items"`
	Procedures              []corehttp.RecallProcedure          `json:"procedures"`
	ExcludedItems           []corehttp.RecallExclusion          `json:"excluded_items"`
	ExcludedProcedures      []corehttp.RecallProcedureExclusion `json:"excluded_procedures"`
}

// Run owns exactly one stdio MCP connection.
func (s *Server) Run(ctx context.Context, transport mcp.Transport) error {
	if s == nil || ctx == nil || nilCapability(transport) || nilCapability(s.status) ||
		nilCapability(s.recall) || s.server == nil {
		return errors.New("session MCP server is unavailable")
	}
	return s.server.Run(ctx, transport)
}

func (s *Server) handleRecall(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	input recallInput,
) (*mcp.CallToolResult, recallOutput, error) {
	request := recallRequest(input)
	recalled, err := s.recall.Recall(ctx, request)
	if err != nil {
		return nil, recallOutput{}, errors.New("session recall is unavailable")
	}
	if recalled.Items == nil {
		recalled.Items = []corehttp.RecallItem{}
	}
	if recalled.Procedures == nil {
		recalled.Procedures = []corehttp.RecallProcedure{}
	}
	if recalled.ExcludedItems == nil {
		recalled.ExcludedItems = []corehttp.RecallExclusion{}
	}
	if recalled.ExcludedProcedures == nil {
		recalled.ExcludedProcedures = []corehttp.RecallProcedureExclusion{}
	}
	return nil, recallOutput{
		ContractVersion: 1, UntrustedHistoricalData: true,
		Status: recalled.Status, ScopeFingerprint: recalled.ScopeFingerprint,
		ContextEventID: recalled.ContextEventID, PolicyVersion: recalled.PolicyVersion,
		UsedTokens: recalled.UsedTokens, UsedItems: recalled.UsedItems,
		UsedBytes: recalled.UsedBytes, Truncated: recalled.Truncated,
		Items: recalled.Items, Procedures: recalled.Procedures,
		ExcludedItems:      recalled.ExcludedItems,
		ExcludedProcedures: recalled.ExcludedProcedures,
	}, nil
}

func (s *Server) handleStatus(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	_ emptyInput,
) (*mcp.CallToolResult, statusOutput, error) {
	status, err := s.status.Status(ctx)
	if err != nil {
		return nil, statusOutput{}, errors.New("session status is unavailable")
	}
	return nil, output(status), nil
}

func (s *Server) handleResource(
	ctx context.Context,
	_ *mcp.ReadResourceRequest,
) (*mcp.ReadResourceResult, error) {
	status, err := s.status.Status(ctx)
	if err != nil {
		return nil, errors.New("session status is unavailable")
	}
	payload, err := json.Marshal(output(status))
	if err != nil {
		return nil, errors.New("session status is unavailable")
	}
	return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{
		URI: resourceSession, MIMEType: "application/json", Text: string(payload),
	}}}, nil
}

func output(status corehttp.SessionStatus) statusOutput {
	return statusOutput{
		ContractVersion: 1, SessionID: status.SessionID, AgentID: status.AgentID,
		BrainID:              status.BrainID,
		WorkspaceFingerprint: status.WorkspaceFingerprint, GitCoverage: status.GitCoverage,
		IndexCoverage: status.IndexCoverage, State: status.State,
	}
}

func recallRequest(input recallInput) corehttp.SessionRecallRequest {
	if input.Mode == "" {
		input.Mode = "current"
	}
	if input.MaxRelatedDepth == 0 {
		input.MaxRelatedDepth = 3
	}
	if input.MaxRelatedCost == 0 {
		input.MaxRelatedCost = 10
	}
	if input.MaxTokens == 0 {
		input.MaxTokens = 1200
	}
	if input.MaxItems == 0 {
		input.MaxItems = 12
	}
	if input.MaxBytes == 0 {
		input.MaxBytes = 20480
	}
	return corehttp.SessionRecallRequest{
		OperationID: input.OperationID, Mode: input.Mode,
		MaxRelatedDepth: input.MaxRelatedDepth, MaxRelatedCost: input.MaxRelatedCost,
		TemporalFrom: input.TemporalFrom, TemporalTo: input.TemporalTo,
		Budget: corehttp.SessionRecallBudget{
			MaxTokens: input.MaxTokens, MaxItems: input.MaxItems, MaxBytes: input.MaxBytes,
		},
	}
}

func nilCapability(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Non-nilable concrete capabilities are valid.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid:
		return true
	default:
		return false
	}
}
