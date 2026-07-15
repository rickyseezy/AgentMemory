package launcher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/mcpbootstrap"
)

const (
	toolBrainStatus               = "brain_status"
	toolManagedRuntimeRemovalPlan = "managed_runtime_removal_plan"
	toolRemoveManagedRuntime      = "remove_managed_runtime"
	resourceReady                 = "agentmemory://ready"
)

type coreStatus interface {
	Ready(context.Context) (bool, error)
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
	return &coreReadySurface{installationID: installationID, status: status, removal: removal}, nil
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
