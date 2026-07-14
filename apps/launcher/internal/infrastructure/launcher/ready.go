package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/mcpbootstrap"
)

const (
	toolBrainStatus = "brain_status"
	resourceReady   = "agentmemory://ready"
)

type coreStatus interface {
	Ready(context.Context) (bool, error)
}

// coreReadySurface is the minimal product-mode PF-001 handoff. It proves the
// live authenticated Core receipt before registration and on every product
// query; later stories may add memory tools without changing this boundary.
type coreReadySurface struct {
	installationID string
	status         coreStatus
}

func newCoreReadySurface(installationID string, status coreStatus) (*coreReadySurface, error) {
	if installationID == "" || installationID != strings.TrimSpace(installationID) ||
		len(installationID) > 128 || nilAny(status) {
		return nil, errors.New("core Ready surface authority is invalid")
	}
	return &coreReadySurface{installationID: installationID, status: status}, nil
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
	return mcpbootstrap.ReadySurface{
		Tools: []mcpbootstrap.ReadyTool{{
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
		}},
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
