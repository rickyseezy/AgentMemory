//go:build darwin && cgo

package filesystem

/*
#include <errno.h>
#include <fcntl.h>
#include <sys/acl.h>
#include <unistd.h>

static int am_darwin_has_extended_acl(int descriptor) {
	errno = 0;
	acl_t acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED);
	if (acl == NULL) {
		if (errno == ENOENT) return 0;
		return -errno;
	}
	acl_free(acl);
	return 1;
}

static int am_darwin_full_fsync(int descriptor) {
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
	"context"
	"errors"
	"fmt"
	"os"
)

func verifyPlatformDescriptor(_ context.Context, file *os.File) error {
	if file == nil {
		return errors.New("macOS filesystem descriptor is absent")
	}
	state := int(C.am_darwin_has_extended_acl(C.int(file.Fd())))
	switch {
	case state == 0:
		return nil
	case state > 0:
		return errors.New("macOS filesystem object has a nontrivial extended ACL")
	default:
		return fmt.Errorf("inspect Darwin extended ACL: errno %d", -state)
	}
}

func platformDurableSync(file *os.File) error {
	if file == nil {
		return errors.New("macOS durability descriptor is absent")
	}
	if status := int(C.am_darwin_full_fsync(C.int(file.Fd()))); status != 0 {
		return fmt.Errorf("macOS F_FULLFSYNC failed: errno %d", status)
	}
	return nil
}
