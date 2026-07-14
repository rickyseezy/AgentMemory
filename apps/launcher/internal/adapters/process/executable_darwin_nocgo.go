//go:build darwin && !cgo

package process

import (
	"context"
	"os"
	"os/exec"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

func executableACLFree(*os.File) bool { return false }

func platformExecutableIdentity(os.FileInfo) (string, error) { return "", os.ErrPermission }

func platformExecutablePathSupported(
	argvprocess.ExecutableAuthority, []executableAncestor, os.FileInfo, uint32, bool,
) bool {
	return false
}

func platformExecutableCommand(context.Context, *executableLease, []string) (*exec.Cmd, error) {
	return nil, os.ErrPermission
}
