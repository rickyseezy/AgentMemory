//go:build linux

package artifactfs

import (
	"os"

	"golang.org/x/sys/unix"
)

func renameNoReplace(fromDirectory *os.File, from string, toDirectory *os.File, to string) error {
	return unix.Renameat2(
		int(fromDirectory.Fd()), from, int(toDirectory.Fd()), to, unix.RENAME_NOREPLACE,
	)
}

func renameSecureNoReplace(from *secureFile, toDirectory *os.File, to string) error {
	if from == nil || from.verifyPathIdentity() != nil {
		return os.ErrInvalid
	}
	return renameNoReplace(from.directory, from.leaf, toDirectory, to)
}
