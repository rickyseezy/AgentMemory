package process

import (
	"context"
	"os/exec"
)

// RunCommandInProcessTree executes one already-authorized exact command in the
// platform's bounded process-tree primitive. On Windows the leader is born in
// a non-breakaway Job Object; on Unix the complete process group is settled.
// Callers remain responsible for executable/publisher/argv authorization.
func RunCommandInProcessTree(ctx context.Context, command *exec.Cmd) error {
	return runCommandInProcessTree(ctx, command)
}
