//go:build darwin && cgo

package process

/*
#include <sys/acl.h>
#include <errno.h>

static int am_process_has_extended_acl(int descriptor) {
	errno = 0;
	acl_t acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED);
	if (acl == NULL) {
		if (errno == ENOENT) return 0;
		return -errno;
	}
	acl_free(acl);
	return 1;
}
*/
import "C"

import (
	"context"
	"os"
	"os/exec"
	"syscall"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

func executableACLFree(file *os.File) bool {
	return file != nil && int(C.am_process_has_extended_acl(C.int(file.Fd()))) == 0
}

func platformExecutableIdentity(info os.FileInfo) (string, error) {
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", os.ErrInvalid
	}
	return executableIdentityText(
		uint64(status.Dev), status.Ino, status.Ctimespec.Sec, status.Ctimespec.Nsec, info.Size(),
	), nil
}

func platformExecutablePathSupported(
	authority argvprocess.ExecutableAuthority,
	ancestors []executableAncestor,
	fileInfo os.FileInfo,
	expectedUID uint32,
	allowMutableTestPath bool,
) bool {
	if allowMutableTestPath {
		return true
	}
	expectedPath := ""
	switch authority.Role() {
	case argvprocess.ExecutableRoleDockerCLI:
		expectedPath = "/Applications/Docker.app/Contents/Resources/bin/docker"
	case argvprocess.ExecutableRoleComposePlugin:
		expectedPath = "/Applications/Docker.app/Contents/Resources/cli-plugins/docker-compose"
	case argvprocess.ExecutableRoleRootlessSetup:
		// Rootless Engine setup is a Linux-only package capability.
		return false
	case argvprocess.ExecutableRoleAgentMemoryLauncher:
		// Launcher verification is performed against its release-specific app bundle.
		return false
	default:
		return false
	}
	if authority.CanonicalPath() != expectedPath || expectedUID != 0 || fileInfo == nil {
		return false
	}
	status, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok || status.Uid != 0 || status.Gid != 0 || fileInfo.Mode().Perm()&0o022 != 0 {
		return false
	}
	for _, ancestor := range ancestors {
		ancestorStatus, valid := ancestor.identity.Sys().(*syscall.Stat_t)
		if !valid || ancestorStatus.Uid != 0 || ancestorStatus.Gid != 0 ||
			ancestor.identity.Mode().Perm()&0o022 != 0 {
			return false
		}
	}
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
	// macOS has no fd-exec primitive. The acquisition policy therefore accepts
	// only root-owned, non-writable ancestry and retains/rechecks every object
	// while the mandatory native codesign/notarization verifier runs.
	return exec.CommandContext(ctx, lease.path, arguments...), nil // #nosec G204 -- immutable root-owned path plus mandatory publisher proof.
}
