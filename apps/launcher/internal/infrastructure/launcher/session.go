package launcher

import (
	"context"
	"errors"
	"io"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpsessionapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
)

// HostSessionRunner is the production-only raw stdio boundary used by a transient container.
// The generic MCP transport remains the bootstrap path until installation reaches Ready.
type HostSessionRunner interface {
	RunHostSession(context.Context, string, io.Reader, io.Writer, io.Writer) error
}

type sessionApplication interface {
	Start(context.Context, mcpsessionapp.Command) (mcpsessionapp.Result, error)
}

// sessionRunner binds one configured agent host to StartMcpSessionApplication.
type sessionRunner struct {
	application sessionApplication
	agent       agentconfig.AgentHost
	lifecycle   RuntimeLifecycle
}

// NewSessionRunner rejects a partial production composition.
func NewSessionRunner(
	application sessionApplication,
	agent agentconfig.AgentHost,
) (MCPRunner, error) {
	if nilCapability(application) || !agent.Valid() {
		return nil, errors.New("PF-005 session runner is invalid")
	}
	return &sessionRunner{application: application, agent: agent}, nil
}

// NewManagedSessionRunner transfers a concrete native composition lifecycle
// to one Ready PF-005 session. The outer managed runner closes it after stdio.
func NewManagedSessionRunner(
	application sessionApplication,
	agent agentconfig.AgentHost,
	lifecycle RuntimeLifecycle,
) (MCPRunner, error) {
	if nilCapability(lifecycle) {
		return nil, errors.New("PF-005 session lifecycle is invalid")
	}
	raw, err := NewSessionRunner(application, agent)
	if err != nil {
		return nil, err
	}
	runner := raw.(*sessionRunner)
	runner.lifecycle = lifecycle
	return runner, nil
}

// Run is deliberately unavailable: the host command must provide raw stdio and cwd.
func (*sessionRunner) Run(context.Context, mcp.Transport) error {
	return errors.New("PF-005 session requires the raw host stdio boundary")
}

// RunHostSession delegates exact streams and the host-observed current directory.
func (r *sessionRunner) RunHostSession(
	ctx context.Context,
	workingDirectory string,
	input io.Reader,
	output io.Writer,
	diagnostics io.Writer,
) error {
	if r == nil || nilCapability(r.application) || ctx == nil || !r.agent.Valid() {
		return errors.New("PF-005 session runner is unavailable")
	}
	_, err := r.application.Start(ctx, mcpsessionapp.Command{
		AgentID: string(r.agent), WorkingDirectory: workingDirectory,
		Input: input, Output: output, Diagnostics: diagnostics,
	})
	return err
}

// Close releases native composition resources after the session terminates.
// A standalone unit-composed runner owns no process resource and closes as a no-op.
func (r *sessionRunner) Close(ctx context.Context) error {
	if r == nil || ctx == nil {
		return errors.New("PF-005 session runner is unavailable")
	}
	if nilCapability(r.lifecycle) {
		return nil
	}
	return r.lifecycle.Close(ctx)
}

var _ MCPRunner = (*sessionRunner)(nil)
var _ HostSessionRunner = (*sessionRunner)(nil)
var _ RuntimeLifecycle = (*sessionRunner)(nil)
