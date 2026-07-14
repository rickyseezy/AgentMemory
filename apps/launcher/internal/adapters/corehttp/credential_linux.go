//go:build linux

package corehttp

import (
	"errors"

	"golang.org/x/sys/unix"
)

func verifyCredentialACL(fd int, directory bool) error {
	if presentLinuxACL(fd, "system.posix_acl_access") {
		return errCredentialIntegrity
	}
	if directory && presentLinuxACL(fd, "system.posix_acl_default") {
		return errCredentialIntegrity
	}
	return nil
}

func presentLinuxACL(fd int, name string) bool {
	_, err := unix.Fgetxattr(fd, name, nil)
	return err == nil || !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP)
}
