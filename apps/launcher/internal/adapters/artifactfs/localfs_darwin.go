//go:build darwin

package artifactfs

import (
	"fmt"
	"os"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"golang.org/x/sys/unix"
)

func localFilesystem(path string) (bool, string, error) {
	directory, err := openSecureDirectory(path)
	if err != nil {
		return false, "", err
	}
	defer func() { _ = directory.Close() }()
	return localFilesystemDescriptor(directory)
}

func localFilesystemDescriptor(directory *os.File) (bool, string, error) {
	if !safeDirectoryDescriptor(directory) {
		return false, "", artifactapp.ErrStoreIntegrity
	}
	var stat unix.Statfs_t
	if err := unix.Fstatfs(int(directory.Fd()), &stat); err != nil {
		return false, "", err
	}
	var typeName strings.Builder
	for _, character := range stat.Fstypename {
		if character == 0 {
			break
		}
		_, _ = fmt.Fprintf(&typeName, "%c", character)
	}
	local := stat.Flags&unix.MNT_LOCAL != 0 && (typeName.String() == "apfs" || typeName.String() == "hfs")
	identity := fmt.Sprintf("fs-%d-%d", stat.Fsid.Val[0], stat.Fsid.Val[1])
	return local, identity, nil
}

// reservationFilesystemSafeDescriptor currently rejects every Darwin mount.
// APFS preallocation does not exclude extents from snapshots; HFS may be on a
// removable device and fstatfs cannot prove a non-removable backing pool.
// A future Disk Arbitration-backed dedicated-volume adapter may opt in only
// after proving both properties.
func reservationFilesystemSafeDescriptor(directory *os.File) (bool, error) {
	if !safeDirectoryDescriptor(directory) {
		return false, artifactapp.ErrStoreIntegrity
	}
	var stat unix.Statfs_t
	if err := unix.Fstatfs(int(directory.Fd()), &stat); err != nil {
		return false, err
	}
	return false, nil
}

func availableBytes(path string) (uint64, error) {
	directory, err := openSecureDirectory(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = directory.Close() }()
	return availableBytesDescriptor(directory)
}

func availableBytesDescriptor(directory *os.File) (uint64, error) {
	if !safeDirectoryDescriptor(directory) {
		return 0, artifactapp.ErrStoreIntegrity
	}
	var stat unix.Statfs_t
	if err := unix.Fstatfs(int(directory.Fd()), &stat); err != nil {
		return 0, err
	}
	if stat.Bsize <= 0 || stat.Bavail != 0 && uint64(stat.Bsize) > ^uint64(0)/stat.Bavail { // #nosec G115 -- positivity is checked first.
		return 0, artifactapp.ErrStoreIntegrity
	}
	return stat.Bavail * uint64(stat.Bsize), nil // #nosec G115 -- positivity and multiplication bounds are proven above.
}
