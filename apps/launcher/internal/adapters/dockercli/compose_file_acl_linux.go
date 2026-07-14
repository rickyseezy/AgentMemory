//go:build linux

package dockercli

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func composeACLFree(path string) bool {
	for _, attribute := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		_, err := unix.Getxattr(path, attribute, nil)
		if err == nil || !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) {
			return false
		}
	}
	return true
}

func composeACLFreeOpened(file *os.File) bool {
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
