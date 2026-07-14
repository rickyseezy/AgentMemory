//go:build linux

package productfs

import (
	"errors"

	"golang.org/x/sys/unix"
)

func publishExclusive(directory int, temporary, target string) (bool, error) {
	err := unix.Renameat2(directory, temporary, directory, target, unix.RENAME_NOREPLACE)
	if errors.Is(err, unix.EEXIST) {
		return false, nil
	}
	return err == nil, err
}
