//go:build darwin

package artifactfs

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// durableSync uses F_FULLFSYNC on macOS so success means the filesystem has
// been asked to flush through volatile device caches, not merely fsync(2).
func durableSync(file *os.File) error {
	if file == nil {
		return errors.New("macOS durability descriptor is absent")
	}
	for {
		_, err := unix.FcntlInt(file.Fd(), unix.F_FULLFSYNC, 0)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}
