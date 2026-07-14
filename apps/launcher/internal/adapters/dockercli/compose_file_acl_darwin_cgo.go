//go:build darwin && cgo

package dockercli

/*
#include <sys/acl.h>
#include <errno.h>

static int am_compose_has_extended_acl(int descriptor) {
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

import "os"

func composeACLFree(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = file.Close() }()
	return composeACLFreeOpened(file)
}

func composeACLFreeOpened(file *os.File) bool {
	return file != nil && int(C.am_compose_has_extended_acl(C.int(file.Fd()))) == 0
}
