//go:build darwin && cgo

package corehttp

/*
#include <errno.h>
#include <sys/acl.h>

static int agentmemory_corehttp_has_extended_acl(int fd) {
	errno = 0;
	acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
	if (acl == NULL) {
		if (errno == ENOENT) return 0;
		return -errno;
	}
	acl_free(acl);
	return 1;
}
*/
import "C"

func verifyCredentialACL(fd int, _ bool) error {
	if C.agentmemory_corehttp_has_extended_acl(C.int(fd)) != 0 {
		return errCredentialIntegrity
	}
	return nil
}
