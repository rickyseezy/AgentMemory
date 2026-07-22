package mcpsessiondocker

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpsessionapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

// Process adapts the signed Docker CLI runner to PF-005 capture and stream operations.
type Process struct {
	runner     argvprocess.StreamingRunner
	executable string
}

// ComposeProcess is the deliberately narrower PF-005 boundary for the signed
// standalone Compose executable. It cannot attach session stdio or execute a
// Docker CLI operation.
type ComposeProcess struct {
	runner     argvprocess.Runner
	executable string
}

// NewProcess accepts only a complete Docker-CLI executable authority.
func NewProcess(runner argvprocess.StreamingRunner) (*Process, error) {
	if nilCapability(runner) {
		return nil, errInvalidContainer
	}
	authority := runner.ExecutableAuthority()
	if !authority.Valid() || authority.Role() != argvprocess.ExecutableRoleDockerCLI {
		return nil, errInvalidContainer
	}
	return &Process{runner: runner, executable: authority.CanonicalPath()}, nil
}

// NewComposeProcess accepts only a complete Compose-plugin executable authority.
func NewComposeProcess(runner argvprocess.Runner) (*ComposeProcess, error) {
	if nilCapability(runner) {
		return nil, errInvalidRuntimeAuthority
	}
	authority := runner.ExecutableAuthority()
	if !authority.Valid() || authority.Role() != argvprocess.ExecutableRoleComposePlugin {
		return nil, errInvalidRuntimeAuthority
	}
	return &ComposeProcess{runner: runner, executable: authority.CanonicalPath()}, nil
}

// Capture runs exact Compose argv and returns only bounded stdout.
func (p *ComposeProcess) Capture(ctx context.Context, arguments []string) ([]byte, error) {
	if p == nil || nilCapability(p.runner) || ctx == nil {
		return nil, errInvalidRuntimeAuthority
	}
	invocation, err := argvprocess.NewInvocation(p.executable, arguments)
	if err != nil {
		return nil, errInvalidRuntimeAuthority
	}
	result, err := p.runner.Run(ctx, invocation)
	if err != nil {
		return nil, err
	}
	return result.StandardOutput, nil
}

// Capture runs exact Docker argv and returns only bounded stdout.
func (p *Process) Capture(ctx context.Context, arguments []string) ([]byte, error) {
	if p == nil || nilCapability(p.runner) || ctx == nil {
		return nil, errInvalidContainer
	}
	invocation, err := argvprocess.NewInvocation(p.executable, arguments)
	if err != nil {
		return nil, errInvalidContainer
	}
	result, err := p.runner.Run(ctx, invocation)
	if err != nil {
		if missingContainer(arguments, result) {
			return nil, ErrContainerNotFound
		}
		return nil, err
	}
	return result.StandardOutput, nil
}

// Stream attaches MCP stdio directly while retaining the signed process authority.
func (p *Process) Stream(
	ctx context.Context,
	arguments []string,
	streams mcpsessionapp.Streams,
) error {
	if p == nil || nilCapability(p.runner) || ctx == nil {
		return errInvalidContainer
	}
	invocation, err := argvprocess.NewInvocation(p.executable, arguments)
	if err != nil {
		return errInvalidContainer
	}
	processStreams, err := argvprocess.NewStreams(streams.Input, streams.Output, streams.Diagnostics)
	if err != nil {
		return errInvalidContainer
	}
	return p.runner.RunStreaming(ctx, invocation, processStreams)
}

func missingContainer(arguments []string, result argvprocess.Result) bool {
	if result.ExitCode != 1 || len(arguments) != 7 ||
		!slicesEqualPrefix(arguments, []string{"--host", arguments[1], "container", "rm", "--force", "--volumes"}) {
		return false
	}
	name := arguments[len(arguments)-1]
	wanted := "Error response from daemon: No such container: " + name + "\n"
	return string(result.StandardError) == wanted && len(result.StandardOutput) == 0
}

func slicesEqualPrefix(actual, prefix []string) bool {
	if len(actual) != len(prefix)+1 {
		return false
	}
	for index := range prefix {
		if actual[index] != prefix[index] {
			return false
		}
	}
	return true
}

var _ DockerProcessPort = (*Process)(nil)
var _ ComposeProcessPort = (*ComposeProcess)(nil)
