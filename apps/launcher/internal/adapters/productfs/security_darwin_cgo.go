//go:build darwin && cgo

package productfs

/*
#include <errno.h>
#include <fcntl.h>
#include <sys/acl.h>

static int am_productfs_has_extended_acl(int descriptor) {
	errno = 0;
	acl_t acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED);
	if (acl == NULL) {
		if (errno == ENOENT) return 0;
		return -errno;
	}
	acl_free(acl);
	return 1;
}

static int am_productfs_full_fsync(int descriptor) {
	int result;
	do {
		result = fcntl(descriptor, F_FULLFSYNC, 0);
	} while (result == -1 && errno == EINTR);
	if (result == -1) return errno;
	return 0;
}
*/
import "C"

import (
	"fmt"
	"os"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productinstall"
)

func verifyNativeACL(file *os.File) error {
	if file == nil {
		return productinstall.ErrIntegrity
	}
	state := int(C.am_productfs_has_extended_acl(C.int(file.Fd())))
	switch {
	case state == 0:
		return nil
	case state > 0:
		return productinstall.ErrIntegrity
	default:
		return unavailable(fmt.Errorf("inspect native ACL: errno %d", -state))
	}
}

func syncNativeFile(file *os.File) error {
	if file == nil {
		return productinstall.ErrUnavailable
	}
	if status := int(C.am_productfs_full_fsync(C.int(file.Fd()))); status != 0 {
		return fmt.Errorf("native full sync failed: errno %d", status)
	}
	return nil
}
