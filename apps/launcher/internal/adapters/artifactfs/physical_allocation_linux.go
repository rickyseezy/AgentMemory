//go:build linux

package artifactfs

import (
	"context"
	"os"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"golang.org/x/sys/unix"
)

const fsNoCowFlag = 0x00800000

func physicalAllocationAttribute() string { return "user.agentmemory.physical-allocation" }

func allocatePhysical(ctx context.Context, file *os.File, size uint64) error {
	length, valid := uint64ToInt64(size)
	if ctx == nil || ctx.Err() != nil || file == nil || !valid || size == 0 {
		return artifactapp.ErrReservationOperation
	}
	if physicallyAllocated(file, size) {
		return nil
	}
	var stat unix.Statfs_t
	if unix.Fstatfs(int(file.Fd()), &stat) != nil {
		return artifactapp.ErrReservationOperation
	}
	typeValue, typeValid := nonNegativeFilesystemType(stat.Type)
	if !typeValid || typeValue != extFilesystemMagic && typeValue != xfsFilesystemMagic && typeValue != btrfsMagic {
		return artifactapp.ErrReservationUnsupported
	}
	info, err := file.Stat()
	currentSize, sizeValid := nonNegativeInt64(infoSize(info, err))
	if err != nil || !sizeValid {
		return artifactapp.ErrReservationOperation
	}
	if typeValue == btrfsMagic {
		flags, flagError := unix.IoctlGetInt(int(file.Fd()), unix.FS_IOC_GETFLAGS)
		if flagError != nil {
			return artifactapp.ErrReservationUnsupported
		}
		if flags&fsNoCowFlag == 0 {
			if currentSize != 0 || unix.IoctlSetPointerInt(int(file.Fd()), unix.FS_IOC_SETFLAGS, flags|fsNoCowFlag) != nil {
				return artifactapp.ErrReservationUnsupported
			}
		}
	}
	if err := writePhysicalAllocationMarker(file, size); err != nil || unix.Fallocate(int(file.Fd()), 0, 0, length) != nil ||
		file.Truncate(length) != nil || durableSync(file) != nil || !physicallyAllocated(file, size) {
		return artifactapp.ErrReservationOperation
	}
	return nil
}

func platformAllocationInvariant(file *os.File) bool {
	if file == nil {
		return false
	}
	var stat unix.Statfs_t
	if unix.Fstatfs(int(file.Fd()), &stat) != nil {
		return false
	}
	typeValue, typeValid := nonNegativeFilesystemType(stat.Type)
	if !typeValid {
		return false
	}
	if typeValue != extFilesystemMagic && typeValue != xfsFilesystemMagic && typeValue != btrfsMagic {
		return false
	}
	if typeValue != btrfsMagic {
		return true
	}
	flags, err := unix.IoctlGetInt(int(file.Fd()), unix.FS_IOC_GETFLAGS)
	return err == nil && flags&fsNoCowFlag != 0
}
