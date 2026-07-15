package agentconfigadapter

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"

	port "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	domain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
)

const (
	maximumHandshakeOutputBytes = 1024 * 1024
	maximumHandshakeMessages    = 32
	preferredHandshakeVersion   = "2025-11-25"
)

var supportedHandshakeVersions = map[string]struct{}{
	"2024-11-05": {},
	"2025-03-26": {},
	"2025-06-18": {},
	"2025-11-25": {},
}

// InvocationVerifier proves that the exact signed launcher can complete a
// real MCP initialize and tool-discovery exchange without a command shell.
type InvocationVerifier struct {
	runner argvprocess.ConversationRunner
}

// NewInvocationVerifier accepts only an immutable launcher-role authority.
func NewInvocationVerifier(runner argvprocess.ConversationRunner) (*InvocationVerifier, error) {
	if nilRunner(runner) || !runner.ExecutableAuthority().Valid() ||
		runner.ExecutableAuthority().Role() != argvprocess.ExecutableRoleAgentMemoryLauncher {
		return nil, port.ErrInvalidArgument
	}
	return &InvocationVerifier{runner: runner}, nil
}

// Verify feeds one bounded initialize/initialized/tools-list transcript to
// the exact configured launcher and rejects any non-protocol stdout.
func (v *InvocationVerifier) Verify(ctx context.Context, target domain.Target) error {
	if v == nil || ctx == nil || nilRunner(v.runner) || target.Command() == "" ||
		target.LauncherDigest().IsZero() || target.Command() != v.runner.ExecutableAuthority().CanonicalPath() ||
		target.LauncherDigest() != domain.Digest(v.runner.ExecutableAuthority().SHA256()) {
		return port.ErrInvalidArgument
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	conversation, err := bootstrapHandshakeConversation()
	if err != nil {
		return port.ErrInvalidArgument
	}
	invocation, err := argvprocess.NewInvocation(target.Command(), target.Arguments())
	if err != nil {
		return port.ErrInvalidArgument
	}
	result, err := v.runner.RunLineConversation(ctx, invocation, conversation)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return port.ErrIntegrity
	}
	if result.ExitCode != 0 || result.OutputTruncated || len(result.StandardOutput) == 0 ||
		len(result.StandardOutput) > maximumHandshakeOutputBytes {
		return port.ErrIntegrity
	}
	if err := verifyHandshakeTranscript(result.StandardOutput); err != nil {
		return port.ErrIntegrity
	}
	return nil
}

func bootstrapHandshakeConversation() (argvprocess.LineConversation, error) {
	requests := []struct {
		message       string
		awaitResponse bool
	}{
		{
			message:       `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"` + preferredHandshakeVersion + `","capabilities":{},"clientInfo":{"name":"agentmemory-installer-verifier","version":"1"}}}` + "\n",
			awaitResponse: true,
		},
		{message: `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"},
		{message: `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}` + "\n", awaitResponse: true},
	}
	steps := make([]argvprocess.ConversationStep, 0, len(requests))
	for _, request := range requests {
		step, err := argvprocess.NewConversationStep([]byte(request.message), request.awaitResponse)
		if err != nil {
			return argvprocess.LineConversation{}, err
		}
		steps = append(steps, step)
	}
	return argvprocess.NewLineConversation(steps)
}

type handshakeEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

type initializeResult struct {
	ProtocolVersion string          `json:"protocolVersion"`
	Capabilities    json.RawMessage `json:"capabilities"`
	Instructions    string          `json:"instructions,omitempty"`
	ServerInfo      struct {
		Name        string `json:"name"`
		Version     string `json:"version"`
		Title       string `json:"title,omitempty"`
		Description string `json:"description,omitempty"`
		WebsiteURL  string `json:"websiteUrl,omitempty"`
		Icons       any    `json:"icons,omitempty"`
	} `json:"serverInfo"`
}

type listedTool struct {
	Name         string          `json:"name"`
	Title        string          `json:"title,omitempty"`
	Description  string          `json:"description,omitempty"`
	InputSchema  json.RawMessage `json:"inputSchema"`
	OutputSchema json.RawMessage `json:"outputSchema,omitempty"`
	Annotations  json.RawMessage `json:"annotations,omitempty"`
	Meta         json.RawMessage `json:"_meta,omitempty"`
	Icons        json.RawMessage `json:"icons,omitempty"`
}

type listToolsResult struct {
	Tools      []listedTool `json:"tools"`
	NextCursor string       `json:"nextCursor,omitempty"`
}

func verifyHandshakeTranscript(output []byte) error {
	if !bytes.HasSuffix(output, []byte{'\n'}) {
		return errors.New("MCP transcript is not newline terminated")
	}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 4096), maximumHandshakeOutputBytes)
	initialized, listed, count := false, false, 0
	for scanner.Scan() {
		count++
		if count > maximumHandshakeMessages || len(scanner.Bytes()) == 0 {
			return errors.New("MCP transcript message bound exceeded")
		}
		var envelope handshakeEnvelope
		if err := strictDecode(scanner.Bytes(), &envelope); err != nil || envelope.JSONRPC != "2.0" {
			return errors.New("invalid MCP response")
		}
		switch string(envelope.ID) {
		case "1":
			if initialized || len(envelope.Error) != 0 || len(envelope.Result) == 0 || envelope.Method != "" {
				return errors.New("invalid MCP initialize response")
			}
			var result initializeResult
			if err := strictDecode(envelope.Result, &result); err != nil || result.ServerInfo.Name != "agentmemory" ||
				result.ServerInfo.Version == "" || len(result.Capabilities) == 0 {
				return errors.New("invalid MCP server identity")
			}
			if _, supported := supportedHandshakeVersions[result.ProtocolVersion]; !supported {
				return errors.New("unsupported MCP version")
			}
			initialized = true
		case "2":
			if !initialized || listed || len(envelope.Error) != 0 || len(envelope.Result) == 0 || envelope.Method != "" {
				return errors.New("invalid MCP tools response")
			}
			var result listToolsResult
			if err := strictDecode(envelope.Result, &result); err != nil || result.NextCursor != "" ||
				!exactBootstrapTools(result.Tools) {
				return errors.New("invalid MCP bootstrap tool list")
			}
			listed = true
		default:
			if len(envelope.ID) != 0 || (envelope.Method != "notifications/tools/list_changed" &&
				envelope.Method != "notifications/resources/list_changed") {
				return errors.New("unexpected MCP message")
			}
		}
	}
	if err := scanner.Err(); err != nil || !initialized || !listed {
		return errors.New("incomplete MCP transcript")
	}
	return nil
}

func strictDecode(encoded []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func exactBootstrapTools(tools []listedTool) bool {
	if len(tools) != 3 {
		return false
	}
	wanted := map[string]bool{
		"installation_status":     false,
		"installation_open_setup": false,
		"installation_cancel":     false,
	}
	for _, tool := range tools {
		seen, exists := wanted[tool.Name]
		if !exists || seen || len(tool.InputSchema) == 0 {
			return false
		}
		wanted[tool.Name] = true
	}
	return true
}

func nilRunner(runner argvprocess.ConversationRunner) bool {
	if runner == nil {
		return true
	}
	value := reflect.ValueOf(runner)
	return value.Kind() == reflect.Pointer && value.IsNil()
}

var _ port.InvocationVerifier = (*InvocationVerifier)(nil)
