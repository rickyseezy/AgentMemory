package launcher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/mcpbootstrap"
)

const (
	toolBrainStatus               = "brain_status"
	toolMemoryExplain             = "memory_explain"
	toolManagedRuntimeRemovalPlan = "managed_runtime_removal_plan"
	toolRemoveManagedRuntime      = "remove_managed_runtime"
	resourceReady                 = "agentmemory://ready"
	memoryExplainOutputSchema     = `{"type":"object","additionalProperties":false,"properties":{"memory_id":{"$ref":"#/$defs/uuid7"},"memory_class":{"type":"string"},"scope":{"type":"object","additionalProperties":false,"properties":{"brain_id":{"$ref":"#/$defs/uuid7"},"project_id":{"$ref":"#/$defs/uuid7"},"repository_id":{"$ref":"#/$defs/uuid7"},"checkout_id":{"anyOf":[{"$ref":"#/$defs/uuid7"},{"type":"null"}]}},"required":["brain_id","project_id","repository_id","checkout_id"]},"status":{"type":"string"},"statement":{"type":"string"},"content_sha256":{"$ref":"#/$defs/digest"},"confidence":{"type":"object","additionalProperties":false,"properties":{"evidence_support":{"type":"integer","minimum":0,"maximum":10000},"source_reliability":{"type":"integer","minimum":0,"maximum":10000},"extraction_quality":{"type":"integer","minimum":0,"maximum":10000}},"required":["evidence_support","source_reliability","extraction_quality"]},"valid_time":{"$ref":"#/$defs/time_range"},"recorded_time":{"$ref":"#/$defs/time_range"},"provenance":{"type":"object","additionalProperties":false,"properties":{"actor_id":{"$ref":"#/$defs/uuid7"},"agent_id":{"$ref":"#/$defs/uuid7"},"source_task_id":{"$ref":"#/$defs/uuid7"},"created_by_event":{"$ref":"#/$defs/uuid7"},"extractor":{"type":"object","additionalProperties":false,"properties":{"extractor_id":{"type":"string"},"extractor_version":{"type":"string"},"model_id":{"type":"string"},"model_revision":{"type":"string"},"output_schema":{"type":"string"},"fingerprint":{"$ref":"#/$defs/digest"}},"required":["extractor_id","extractor_version","model_id","model_revision","output_schema","fingerprint"]},"evidence_watermark_sha256":{"$ref":"#/$defs/digest"},"extractor_input_sha256":{"$ref":"#/$defs/digest"},"content_sha256":{"$ref":"#/$defs/digest"},"promotion_policy_version":{"type":"string"},"provenance_sha256":{"$ref":"#/$defs/digest"}},"required":["actor_id","agent_id","source_task_id","created_by_event","extractor","evidence_watermark_sha256","extractor_input_sha256","content_sha256","promotion_policy_version","provenance_sha256"]},"classification":{"type":"string"},"retention_policy_id":{"type":"string"},"aggregate_version":{"type":"integer","minimum":1},"evidence":{"type":"array","items":{"type":"object","additionalProperties":false,"properties":{"event_id":{"$ref":"#/$defs/uuid7"},"canonical_event_sha256":{"$ref":"#/$defs/digest"},"availability":{"type":"string","enum":["available","purged","missing"]},"event_type":{"type":["string","null"]},"occurred_at":{"anyOf":[{"$ref":"#/$defs/instant"},{"type":"null"}]},"resource_uri":{"type":["string","null"]}},"required":["event_id","canonical_event_sha256","availability","event_type","occurred_at","resource_uri"]}},"evaluated_valid_at":{"$ref":"#/$defs/instant"},"evaluated_recorded_at":{"$ref":"#/$defs/instant"},"effective":{"type":"boolean"}},"required":["memory_id","memory_class","scope","status","statement","content_sha256","confidence","valid_time","recorded_time","provenance","classification","retention_policy_id","aggregate_version","evidence","evaluated_valid_at","evaluated_recorded_at","effective"],"$defs":{"time_range":{"type":"object","additionalProperties":false,"properties":{"from":{"$ref":"#/$defs/instant"},"to":{"anyOf":[{"$ref":"#/$defs/instant"},{"type":"null"}]}},"required":["from","to"]},"uuid7":{"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"},"digest":{"type":"string","pattern":"^[0-9a-f]{64}$"},"instant":{"type":"string","pattern":"^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{6}Z$"}}}`
)

type coreStatus interface {
	Ready(context.Context) (bool, error)
}

type memoryExplanationClient interface {
	ExplainMemory(context.Context, string, string, string, string, string, string) (json.RawMessage, error)
}

type memoryExplainInput struct {
	MemoryID   string `json:"memory_id"`
	BrainID    string `json:"brain_id"`
	ActorID    string `json:"actor_id"`
	GrantID    string `json:"grant_id"`
	ValidAt    string `json:"valid_at"`
	RecordedAt string `json:"recorded_at"`
}

type managedRuntimeRemovalPlan struct {
	OperationID string
	PlanDigest  string
	Impact      string
	Platform    string
	Product     string
	Version     string
}

func (p managedRuntimeRemovalPlan) valid() bool {
	values := []string{p.OperationID, p.PlanDigest, p.Impact, p.Platform, p.Product, p.Version}
	for _, value := range values {
		if value == "" || value != strings.TrimSpace(value) || len(value) > 256 {
			return false
		}
	}
	return true
}

type managedRuntimeRemovalDecision struct {
	OperationID          string `json:"operation_id"`
	PlanDigest           string `json:"plan_digest"`
	Impact               string `json:"impact"`
	Approved             bool   `json:"approved"`
	ExplicitConfirmation bool   `json:"explicit_confirmation"`
}

type managedRuntimeRemovalResult struct {
	OperationID string
	PlanDigest  string
	Outcome     string
}

type managedRuntimeRemovalController interface {
	PrepareManagedRuntimeRemoval(context.Context) (managedRuntimeRemovalPlan, error)
	DecideManagedRuntimeRemoval(context.Context, managedRuntimeRemovalDecision) (managedRuntimeRemovalResult, error)
}

// coreReadySurface is the minimal product-mode PF-001 handoff. It proves the
// live authenticated Core receipt before registration and on every product
// query; later stories may add memory tools without changing this boundary.
type coreReadySurface struct {
	installationID string
	status         coreStatus
	memory         memoryExplanationClient
	removal        managedRuntimeRemovalController
}

func newCoreReadySurface(installationID string, status coreStatus) (*coreReadySurface, error) {
	return newCoreReadySurfaceInternal(installationID, status, nil)
}

func newCoreReadySurfaceWithRemoval(
	installationID string,
	status coreStatus,
	removal managedRuntimeRemovalController,
) (*coreReadySurface, error) {
	if nilReadyCapability(removal) {
		return nil, errors.New("managed runtime removal authority is invalid")
	}
	return newCoreReadySurfaceInternal(installationID, status, removal)
}

func newCoreReadySurfaceInternal(
	installationID string,
	status coreStatus,
	removal managedRuntimeRemovalController,
) (*coreReadySurface, error) {
	if installationID == "" || installationID != strings.TrimSpace(installationID) ||
		len(installationID) > 128 || nilAny(status) {
		return nil, errors.New("core Ready surface authority is invalid")
	}
	memory, _ := status.(memoryExplanationClient)
	if nilReadyCapability(memory) {
		memory = nil
	}
	return &coreReadySurface{
		installationID: installationID, status: status, memory: memory, removal: removal,
	}, nil
}

func (s *coreReadySurface) ReadySurface(ctx context.Context) (mcpbootstrap.ReadySurface, error) {
	if s == nil || ctx == nil || nilAny(s.status) {
		return mcpbootstrap.ReadySurface{}, errors.New("core Ready surface is unavailable")
	}
	ready, err := s.status.Ready(ctx)
	if err != nil || !ready {
		return mcpbootstrap.ReadySurface{}, errors.New("core is not Ready")
	}
	closedWorld, additive := false, false
	tools := []mcpbootstrap.ReadyTool{{
		Tool: &mcp.Tool{
			Name: toolBrainStatus, Title: "Local Brain status",
			Description:  "Prove that the authenticated local AgentMemory Brain remains ready.",
			InputSchema:  json.RawMessage(`{"type":"object","additionalProperties":false}`),
			OutputSchema: json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"contract_version":{"type":"integer","const":1},"installation_id":{"type":"string"},"ready":{"type":"boolean","const":true}},"required":["contract_version","installation_id","ready"]}`),
			Annotations: &mcp.ToolAnnotations{
				Title: "Local Brain status", ReadOnlyHint: true,
				OpenWorldHint: &closedWorld, DestructiveHint: &additive, IdempotentHint: true,
			},
		},
		Handler: s.handleStatus,
	}}
	if !nilReadyCapability(s.memory) {
		tools = append(tools, mcpbootstrap.ReadyTool{
			Tool: &mcp.Tool{
				Name: toolMemoryExplain, Title: "Explain memory provenance",
				Description:  "Return the authorized provenance, evidence availability, and bitemporal state of one local Brain memory.",
				InputSchema:  json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"memory_id":{"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"},"brain_id":{"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"},"actor_id":{"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"},"grant_id":{"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"},"valid_at":{"type":"string","pattern":"^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{6}Z$"},"recorded_at":{"type":"string","pattern":"^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{6}Z$"}},"required":["memory_id","brain_id","actor_id","grant_id","valid_at","recorded_at"]}`),
				OutputSchema: json.RawMessage(memoryExplainOutputSchema),
				Annotations: &mcp.ToolAnnotations{
					Title: "Explain memory provenance", ReadOnlyHint: true,
					OpenWorldHint: &closedWorld, DestructiveHint: &additive, IdempotentHint: true,
				},
			},
			Handler: s.handleMemoryExplain,
		})
	}
	if !nilReadyCapability(s.removal) {
		destructive := true
		tools = append(tools,
			mcpbootstrap.ReadyTool{
				Tool: &mcp.Tool{
					Name: toolManagedRuntimeRemovalPlan, Title: "Inspect managed runtime removal",
					Description:  "Perform the first exhaustive local dependency scan, durably prepare the exact managed-runtime removal plan, and return it. This does not remove software or data.",
					InputSchema:  json.RawMessage(`{"type":"object","additionalProperties":false}`),
					OutputSchema: json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"contract_version":{"type":"integer","const":1},"operation_id":{"type":"string"},"plan_digest":{"type":"string"},"impact":{"type":"string"},"platform":{"type":"string"},"product":{"type":"string"},"version":{"type":"string"},"explicit_confirmation_preselected":{"type":"boolean","const":false}},"required":["contract_version","operation_id","plan_digest","impact","platform","product","version","explicit_confirmation_preselected"]}`),
					Annotations: &mcp.ToolAnnotations{
						Title: "Inspect managed runtime removal", ReadOnlyHint: false,
						OpenWorldHint: &closedWorld, DestructiveHint: &additive, IdempotentHint: true,
					},
				},
				Handler: s.handleRemovalPlan,
			},
			mcpbootstrap.ReadyTool{
				Tool: &mcp.Tool{
					Name: toolRemoveManagedRuntime, Title: "Remove managed runtime",
					Description:  "Submit a non-preselected second decision bound to the exact inspected plan. Approval removes only the runtime AgentMemory provisioned; decline preserves it.",
					InputSchema:  json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"operation_id":{"type":"string"},"plan_digest":{"type":"string"},"impact":{"type":"string"},"approved":{"type":"boolean"},"explicit_confirmation":{"type":"boolean"}},"required":["operation_id","plan_digest","impact","approved","explicit_confirmation"]}`),
					OutputSchema: json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"contract_version":{"type":"integer","const":1},"operation_id":{"type":"string"},"plan_digest":{"type":"string"},"outcome":{"type":"string","enum":["declined","removed"]}},"required":["contract_version","operation_id","plan_digest","outcome"]}`),
					Annotations: &mcp.ToolAnnotations{
						Title: "Remove managed runtime", ReadOnlyHint: false,
						OpenWorldHint: &closedWorld, DestructiveHint: &destructive, IdempotentHint: true,
					},
				},
				Handler: s.handleManagedRuntimeRemoval,
			},
		)
	}
	return mcpbootstrap.ReadySurface{
		Tools: tools,
		Resources: []mcpbootstrap.ReadyResource{{
			Resource: &mcp.Resource{
				URI: resourceReady, Name: "AgentMemory Ready state",
				Description: "Authenticated live state for the local AgentMemory Brain.",
				MIMEType:    "application/json",
			},
			Handler: s.handleResource,
		}},
	}, nil
}

func (s *coreReadySurface) handleMemoryExplain(
	ctx context.Context,
	request *mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	var input memoryExplainInput
	if err := decodeReadyArguments(request, &input); err != nil || nilReadyCapability(s.memory) ||
		!validReadyUUIDv7(input.MemoryID) || !validReadyUUIDv7(input.BrainID) ||
		!validReadyUUIDv7(input.ActorID) || !validReadyUUIDv7(input.GrantID) ||
		!validReadyMemoryTime(input.ValidAt) || !validReadyMemoryTime(input.RecordedAt) {
		return nil, errors.New("memory explanation request is invalid")
	}
	if _, err := s.statusPayload(ctx); err != nil {
		return nil, err
	}
	payload, err := s.memory.ExplainMemory(
		ctx,
		input.MemoryID,
		input.BrainID,
		input.ActorID,
		input.GrantID,
		input.ValidAt,
		input.RecordedAt,
	)
	trimmed := bytes.TrimSpace(payload)
	if err != nil || len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' ||
		rejectReadyDuplicateJSONKeys(trimmed) != nil {
		return nil, errors.New("memory explanation is unavailable")
	}
	return readyToolResult(json.RawMessage(trimmed))
}

func (s *coreReadySurface) handleRemovalPlan(
	ctx context.Context,
	request *mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	if err := decodeReadyArguments(request, &struct{}{}); err != nil || nilReadyCapability(s.removal) {
		return nil, errors.New("managed runtime removal request is invalid")
	}
	if _, err := s.statusPayload(ctx); err != nil {
		return nil, err
	}
	plan, err := s.removal.PrepareManagedRuntimeRemoval(ctx)
	if err != nil || !plan.valid() {
		return nil, errors.New("managed runtime removal plan is unavailable")
	}
	return readyToolResult(struct {
		ContractVersion                 uint16 `json:"contract_version"`
		OperationID                     string `json:"operation_id"`
		PlanDigest                      string `json:"plan_digest"`
		Impact                          string `json:"impact"`
		Platform                        string `json:"platform"`
		Product                         string `json:"product"`
		Version                         string `json:"version"`
		ExplicitConfirmationPreselected bool   `json:"explicit_confirmation_preselected"`
	}{
		ContractVersion: 1, OperationID: plan.OperationID, PlanDigest: plan.PlanDigest,
		Impact: plan.Impact, Platform: plan.Platform, Product: plan.Product, Version: plan.Version,
		ExplicitConfirmationPreselected: false,
	})
}

func (s *coreReadySurface) handleManagedRuntimeRemoval(
	ctx context.Context,
	request *mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	var input managedRuntimeRemovalDecision
	if err := decodeReadyArguments(request, &input); err != nil || nilReadyCapability(s.removal) ||
		input.OperationID == "" || input.PlanDigest == "" || input.Impact == "" ||
		input.Approved != input.ExplicitConfirmation {
		return nil, errors.New("managed runtime removal decision is invalid")
	}
	if _, err := s.statusPayload(ctx); err != nil {
		return nil, err
	}
	plan, err := s.removal.PrepareManagedRuntimeRemoval(ctx)
	if err != nil || !plan.valid() || input.OperationID != plan.OperationID ||
		input.PlanDigest != plan.PlanDigest || input.Impact != plan.Impact {
		return nil, errors.New("managed runtime removal decision does not match the inspected plan")
	}
	result, err := s.removal.DecideManagedRuntimeRemoval(ctx, input)
	if err != nil || result.OperationID != plan.OperationID || result.PlanDigest != plan.PlanDigest ||
		(result.Outcome != "declined" && result.Outcome != "removed") {
		return nil, errors.New("managed runtime removal result is unavailable")
	}
	return readyToolResult(struct {
		ContractVersion uint16 `json:"contract_version"`
		OperationID     string `json:"operation_id"`
		PlanDigest      string `json:"plan_digest"`
		Outcome         string `json:"outcome"`
	}{ContractVersion: 1, OperationID: result.OperationID, PlanDigest: result.PlanDigest, Outcome: result.Outcome})
}

func decodeReadyArguments(request *mcp.CallToolRequest, destination any) error {
	if request == nil || request.Params == nil || len(request.Params.Arguments) == 0 || destination == nil {
		return errors.New("tool arguments are unavailable")
	}
	if err := rejectReadyDuplicateJSONKeys(request.Params.Arguments); err != nil {
		return errors.New("tool arguments are ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(request.Params.Arguments))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("tool arguments contain trailing data")
	}
	return nil
}

func rejectReadyDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanReadyJSONValue(decoder); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON has trailing content")
	}
	return nil
}

func scanReadyJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, keyError := decoder.Token()
			key, ok := keyToken.(string)
			if keyError != nil || !ok {
				return errors.New("JSON object key is invalid")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("JSON object contains a duplicate key")
			}
			seen[key] = struct{}{}
			if err := scanReadyJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, closeError := decoder.Token()
		if closeError != nil || closing != json.Delim('}') {
			return errors.New("JSON object is incomplete")
		}
	case '[':
		for decoder.More() {
			if err := scanReadyJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, closeError := decoder.Token()
		if closeError != nil || closing != json.Delim(']') {
			return errors.New("JSON array is incomplete")
		}
	default:
		return errors.New("JSON delimiter is invalid")
	}
	return nil
}

func validReadyUUIDv7(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' ||
		value[14] != '7' || !strings.ContainsRune("89ab", rune(value[19])) {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validReadyMemoryTime(value string) bool {
	const layout = "2006-01-02T15:04:05.000000Z"
	parsed, err := time.Parse(layout, value)
	return err == nil && parsed.UTC().Format(layout) == value
}

func readyToolResult(payload any) (*mcp.CallToolResult, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.New("tool response is unavailable")
	}
	var structured map[string]any
	if err := json.Unmarshal(encoded, &structured); err != nil {
		return nil, errors.New("tool response is unavailable")
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(encoded)}}, StructuredContent: structured,
	}, nil
}

func nilReadyCapability(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Concrete non-nilable capabilities are valid.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func (s *coreReadySurface) handleStatus(
	ctx context.Context,
	_ *mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	payload, err := s.statusPayload(ctx)
	if err != nil {
		return nil, err
	}
	var structured map[string]any
	if err := json.Unmarshal(payload, &structured); err != nil {
		return nil, errors.New("core Ready response is unavailable")
	}
	return &mcp.CallToolResult{
		Content:           []mcp.Content{&mcp.TextContent{Text: string(payload)}},
		StructuredContent: structured,
	}, nil
}

func (s *coreReadySurface) handleResource(
	ctx context.Context,
	_ *mcp.ReadResourceRequest,
) (*mcp.ReadResourceResult, error) {
	payload, err := s.statusPayload(ctx)
	if err != nil {
		return nil, err
	}
	return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{
		URI: resourceReady, MIMEType: "application/json", Text: string(payload),
	}}}, nil
}

func (s *coreReadySurface) statusPayload(ctx context.Context) ([]byte, error) {
	if s == nil || ctx == nil || nilAny(s.status) {
		return nil, errors.New("core Ready status is unavailable")
	}
	ready, err := s.status.Ready(ctx)
	if err != nil || !ready {
		return nil, errors.New("core is not Ready")
	}
	payload, err := json.Marshal(struct {
		ContractVersion uint16 `json:"contract_version"`
		InstallationID  string `json:"installation_id"`
		Ready           bool   `json:"ready"`
	}{ContractVersion: 1, InstallationID: s.installationID, Ready: true})
	if err != nil {
		return nil, errors.New("core Ready response is unavailable")
	}
	return payload, nil
}

var _ mcpbootstrap.ReadySurfaceProvider = (*coreReadySurface)(nil)
