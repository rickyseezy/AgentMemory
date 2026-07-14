//go:build !darwin && !linux && !windows

package process

import (
	"context"
	"os/exec"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

type executableLease struct{}

func acquireExecutableLease(context.Context, argvprocess.ExecutableAuthority, bool) (*executableLease, error) {
	return nil, argvprocess.ErrInvalidInvocation
}

func (*executableLease) verify(context.Context, argvprocess.ExecutableAuthority) error {
	return argvprocess.ErrInvalidInvocation
}
func (*executableLease) evidence(argvprocess.ExecutableAuthority) ExecutableEvidence {
	return ExecutableEvidence{}
}
func (*executableLease) command(context.Context, []string) (*exec.Cmd, error) {
	return nil, argvprocess.ErrInvalidInvocation
}
func (*executableLease) trustedWorkingDirectory() string { return "" }
func (*executableLease) close()                          {}
