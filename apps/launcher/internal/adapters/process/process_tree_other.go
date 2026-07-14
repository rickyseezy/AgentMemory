//go:build !darwin && !linux && !windows

package process

import (
	"context"
	"os/exec"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

func runCommandInProcessTree(context.Context, *exec.Cmd) error {
	return argvprocess.ErrInvalidInvocation
}
