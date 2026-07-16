//go:build darwin || windows

package launcher

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"os/exec"

	processadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/process"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeprovision"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
)

const maximumDesktopMutationProcessOutput = 1024 * 1024

type nativeDesktopMutationCommandRunner struct{}

func (nativeDesktopMutationCommandRunner) RunDesktopMutationCommand(
	ctx context.Context,
	command runtimeprovision.DesktopMutationCommand,
) (uint32, error) {
	if ctx == nil || command.Executable() == "" || command.Directory() == "" {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	process := exec.CommandContext(ctx, command.Executable(), command.Arguments()...) // #nosec G204 -- helper-generated closed command contract.
	process.Env = command.Environment()
	process.Dir = command.Directory()
	stdout := &nativeDesktopMutationBoundedWriter{remaining: maximumDesktopMutationProcessOutput}
	stderr := &nativeDesktopMutationBoundedWriter{remaining: maximumDesktopMutationProcessOutput}
	process.Stdout = stdout
	process.Stderr = stderr
	runError := processadapter.RunCommandInProcessTree(ctx, process)
	if stdout.exceeded || stderr.exceeded {
		return 0, runtimeport.ErrDesktopMutationIntegrity
	}
	if runError == nil {
		return 0, nil
	}
	if contextError := ctx.Err(); contextError != nil {
		return 0, contextError
	}
	if exitCode, ok := nativeDesktopMutationExitCode(runError); ok {
		return exitCode, nil
	}
	return 0, runtimeport.ErrDesktopMutationIntegrity
}

func nativeDesktopMutationExitCode(runError error) (uint32, bool) {
	var exit interface{ ExitCode() int }
	if !errors.As(runError, &exit) {
		return 0, false
	}
	exitCode := int64(exit.ExitCode())
	if exitCode < 0 || exitCode > math.MaxUint32 {
		return 0, false
	}
	return uint32(exitCode), true // #nosec G115 -- exact non-negative uint32 range is proven above.
}

type nativeDesktopMutationBoundedWriter struct {
	buffer    bytes.Buffer
	remaining int
	exceeded  bool
}

func (w *nativeDesktopMutationBoundedWriter) Write(value []byte) (int, error) {
	if w == nil {
		return 0, io.ErrClosedPipe
	}
	if len(value) > w.remaining {
		w.exceeded = true
		if w.remaining > 0 {
			_, _ = w.buffer.Write(value[:w.remaining])
			w.remaining = 0
		}
		return len(value), nil
	}
	w.remaining -= len(value)
	return w.buffer.Write(value)
}

var _ runtimeprovision.DesktopMutationCommandRunner = nativeDesktopMutationCommandRunner{}
