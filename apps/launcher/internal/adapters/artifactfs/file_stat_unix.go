//go:build darwin || linux

package artifactfs

import (
	"errors"
	"os"
	"syscall"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"golang.org/x/sys/unix"
)

func safeFileInfo(info os.FileInfo, size uint64) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return false
	}
	observed, valid := nonNegativeInt64(info.Size())
	if !valid || observed != size {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid() && stat.Nlink == 1
}

func allocatedFileBytes(info os.FileInfo) (uint64, bool) {
	if info == nil {
		return 0, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Blocks < 0 {
		return 0, false
	}
	blocks := uint64(stat.Blocks) // #nosec G115 -- non-negativity is proven above.
	if blocks > ^uint64(0)/512 {
		return 0, false
	}
	return blocks * 512, true
}

func allocatedFileBytesDescriptor(_ *os.File, info os.FileInfo) (uint64, bool) {
	return allocatedFileBytes(info)
}

func isNotDirectoryError(err error) bool { return errors.Is(err, syscall.ENOTDIR) }

func removeOpenSecureFile(opened *secureFile) error {
	if opened == nil || opened.verifyPathIdentity() != nil {
		return artifactapp.ErrStoreIntegrity
	}
	if err := unix.Unlinkat(int(opened.directory.Fd()), opened.leaf, 0); err != nil && !errors.Is(err, os.ErrNotExist) {
		return artifactapp.ErrStoreOperation
	}
	return opened.syncDirectory()
}
