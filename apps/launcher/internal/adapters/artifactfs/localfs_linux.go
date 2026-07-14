//go:build linux

package artifactfs

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"golang.org/x/sys/unix"
)

const (
	extFilesystemMagic = 0xef53
	xfsFilesystemMagic = 0x58465342
	btrfsMagic         = 0x9123683e
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
	typeValue, typeValid := nonNegativeFilesystemType(stat.Type)
	if !typeValid {
		return false, "", artifactapp.ErrStoreIntegrity
	}
	localType := typeValue == extFilesystemMagic || typeValue == xfsFilesystemMagic || typeValue == btrfsMagic
	local := localType && provenLocalBlockDevice(directory)
	identity := fmt.Sprintf("fs-%d-%d", stat.Fsid.Val[0], stat.Fsid.Val[1])
	return local, identity, nil
}

// reservationFilesystemSafeDescriptor excludes Btrfs. NOCOW is not a
// reservation guarantee: after a snapshot, the first write is CoW and needs
// fresh space. ext4 and XFS preallocation remains charged to the same backing
// filesystem and is safe from that snapshot-specific invalidation.
func reservationFilesystemSafeDescriptor(directory *os.File) (bool, error) {
	if !safeDirectoryDescriptor(directory) {
		return false, artifactapp.ErrStoreIntegrity
	}
	var stat unix.Statfs_t
	if err := unix.Fstatfs(int(directory.Fd()), &stat); err != nil {
		return false, err
	}
	typeValue, typeValid := nonNegativeFilesystemType(stat.Type)
	if !typeValid {
		return false, artifactapp.ErrStoreIntegrity
	}
	return (typeValue == extFilesystemMagic || typeValue == xfsFilesystemMagic) && provenLocalBlockDevice(directory), nil
}

func provenLocalBlockDevice(directory *os.File) bool {
	var stat unix.Stat_t
	if unix.Fstat(int(directory.Fd()), &stat) != nil {
		return false
	}
	device := strconv.FormatUint(uint64(unix.Major(stat.Dev)), 10) + ":" + strconv.FormatUint(uint64(unix.Minor(stat.Dev)), 10)
	resolved, err := filepath.EvalSymlinks(filepath.Join("/sys/dev/block", device))
	if err != nil || !strings.HasPrefix(resolved, "/sys/devices/") {
		return false
	}
	for _, component := range strings.Split(resolved, string(filepath.Separator)) {
		for _, unsafe := range []string{"loop", "nbd", "rbd", "drbd", "zram", "ram", "virtio"} {
			if strings.HasPrefix(component, unsafe) {
				return false
			}
		}
	}
	// At least one block-device ancestor must explicitly attest non-removable.
	// Missing/ambiguous sysfs data fails closed.
	for current := resolved; strings.HasPrefix(current, "/sys/devices/"); current = filepath.Dir(current) {
		value, readError := os.ReadFile(filepath.Join(current, "removable")) // #nosec G304 -- path is rooted in descriptor-derived sysfs identity.
		if readError == nil {
			return strings.TrimSpace(string(value)) == "0"
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return false
}

func nonNegativeFilesystemType(value int64) (uint64, bool) {
	if value < 0 {
		return 0, false
	}
	return uint64(value), true // #nosec G115 -- non-negativity is proven above.
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
