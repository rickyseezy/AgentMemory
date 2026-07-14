//go:build linux

package process

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"golang.org/x/sys/unix"
)

func executableACLFree(file *os.File) bool {
	if file == nil {
		return false
	}
	for _, attribute := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		_, err := unix.Fgetxattr(int(file.Fd()), attribute, nil)
		if err == nil || !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) {
			return false
		}
	}
	return true
}

func platformExecutableIdentity(info os.FileInfo) (string, error) {
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", os.ErrInvalid
	}
	return executableIdentityText(
		status.Dev, status.Ino, status.Ctim.Sec, status.Ctim.Nsec, info.Size(),
	), nil
}

func platformExecutablePathSupported(
	argvprocess.ExecutableAuthority, []executableAncestor, os.FileInfo, uint32, bool,
) bool {
	return true
}

func platformExecutableCommand(
	ctx context.Context,
	lease *executableLease,
	arguments []string,
) (*exec.Cmd, error) {
	if lease == nil || lease.file == nil {
		return nil, os.ErrInvalid
	}
	path := "/proc/self/fd/" + strconv.FormatUint(uint64(lease.file.Fd()), 10)
	info, err := os.Stat(path)
	if err != nil || !os.SameFile(lease.identity, info) {
		return nil, os.ErrPermission
	}
	command := exec.CommandContext(ctx, "/proc/self/fd/3", arguments...) // #nosec G204 -- fd 3 is the retained, digest-bound executable object.
	command.ExtraFiles = []*os.File{lease.file}
	return command, nil
}
