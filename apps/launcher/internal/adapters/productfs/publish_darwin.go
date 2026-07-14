//go:build darwin

package productfs

import (
	"errors"

	"golang.org/x/sys/unix"
)

func publishExclusive(directory int, temporary, target string) (bool, error) {
	err := unix.RenameatxNp(directory, temporary, directory, target, unix.RENAME_EXCL)
	if errors.Is(err, unix.EEXIST) {
		return false, nil
	}
	return err == nil, err
}
