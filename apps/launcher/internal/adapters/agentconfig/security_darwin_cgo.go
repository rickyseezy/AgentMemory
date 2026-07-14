//go:build darwin && cgo

package agentconfigadapter

/*
#include <errno.h>
#include <sys/acl.h>

static int am_agentconfig_has_extended_acl(int descriptor) {
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
	"errors"
	"os"
)

func darwinACLFree(file *os.File) error {
	if file == nil {
		return errors.New("darwin ACL descriptor is absent")
	}
	if int(C.am_agentconfig_has_extended_acl(C.int(file.Fd()))) != 0 {
		return errors.New("darwin filesystem object has an extended ACL")
	}
	return nil
}
