//go:build linux

package productfs

import (
	"errors"
	"os"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productinstall"
	"golang.org/x/sys/unix"
)

func verifyNativeACL(file *os.File) error {
	if file == nil {
		return productinstall.ErrIntegrity
	}
	for _, name := range [...]string{"system.posix_acl_access", "system.posix_acl_default"} {
		size, err := unix.Fgetxattr(int(file.Fd()), name, nil)
		if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) {
			continue
		}
		if err != nil {
			return unavailable(err)
		}
		if size > 0 {
			return productinstall.ErrIntegrity
		}
	}
	return nil
}

func syncNativeFile(file *os.File) error {
	if file == nil {
		return productinstall.ErrUnavailable
	}
	return file.Sync()
}
