//go:build windows

package artifactfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"golang.org/x/sys/windows"
)

const windowsAllocationWriteBlock = 1 << 20

type windowsFileAllocationInfo struct {
	allocationSize int64
}

type windowsFileStandardInfo struct {
	allocationSize int64
	endOfFile      int64
	numberOfLinks  uint32
	deletePending  byte
	directory      byte
	reserved       [2]byte
}

func allocatePhysical(ctx context.Context, file *os.File, size uint64) error {
	length, valid := uint64ToInt64(size)
	if ctx == nil || ctx.Err() != nil || file == nil || !valid || size == 0 || !platformAllocationInvariant(file) {
		return artifactapp.ErrReservationOperation
	}
	if physicallyAllocated(file, size) {
		return nil
	}
	info, err := file.Stat()
	current, currentValid := nonNegativeInt64(infoSize(info, err))
	if err != nil || !currentValid || current > size {
		return artifactapp.ErrReservationOperation
	}
	if current == size {
		if err := windows.Ftruncate(windows.Handle(file.Fd()), 0); err != nil {
			return artifactapp.ErrReservationOperation
		}
		current = 0
	}
	allocation := windowsFileAllocationInfo{allocationSize: length}
	if err := windows.SetFileInformationByHandle(
		windows.Handle(file.Fd()), windows.FileAllocationInfo,
		//nolint:gosec // G103: SetFileInformationByHandle synchronously reads the reviewed fixed-size FILE_ALLOCATION_INFO layout; owner=security expiry=2027-07-14.
		(*byte)(unsafe.Pointer(&allocation)), uint32(unsafe.Sizeof(allocation)),
	); err != nil || windows.Ftruncate(windows.Handle(file.Fd()), length) != nil {
		return artifactapp.ErrReservationOperation
	}
	zeros := make([]byte, windowsAllocationWriteBlock)
	offset := current
	for offset < size {
		if err := ctx.Err(); err != nil {
			return errors.Join(artifactapp.ErrReservationOperation, err)
		}
		remaining := size - offset
		block := uint64(len(zeros))
		if remaining < block {
			block = remaining
		}
		chunk := zeros[:block]
		count, err := file.WriteAt(chunk, int64(offset)) // #nosec G115 -- size is bounded by int64 above.
		if err != nil || count != len(chunk) {
			return artifactapp.ErrReservationOperation
		}
		offset += block
	}
	if durableSync(file) != nil || !physicallyAllocated(file, size) {
		return artifactapp.ErrReservationOperation
	}
	return nil
}

func physicallyAllocated(file *os.File, expected uint64) bool {
	if file == nil || expected == 0 || !platformAllocationInvariant(file) {
		return false
	}
	info, err := file.Stat()
	allocated, proven := allocatedFileBytesDescriptor(file, info)
	return err == nil && safeFileInfo(info, expected) && proven && allocated >= expected
}

func allocatedFileBytesDescriptor(file *os.File, info os.FileInfo) (uint64, bool) {
	if file == nil || info == nil {
		return 0, false
	}
	standard, err := windowsStandardFileInfo(file)
	if err != nil || standard.allocationSize < 0 || standard.endOfFile < 0 || standard.numberOfLinks != 1 ||
		standard.deletePending != 0 || standard.directory != 0 || standard.endOfFile != info.Size() {
		return 0, false
	}
	return uint64(standard.allocationSize), true // #nosec G115 -- non-negativity is proven above.
}

func safeFileInfo(info os.FileInfo, size uint64) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	observed, valid := nonNegativeInt64(info.Size())
	return valid && observed == size
}

//nolint:contextcheck,nolintlint // Allocation evidence is a synchronous, non-cancelable filesystem proof used by recovery as well as live requests.
func platformAllocationInvariant(file *os.File) bool {
	if file == nil || !windowsSafeRegularFile(file) {
		return false
	}
	if _, err := windowssecurity.VerifyOpened(windowsArtifactContext(), file, false, true); err != nil {
		return false
	}
	path, err := windowsPathByHandle(file)
	if err != nil || windowssecurity.ValidateLocalPath(path) != nil {
		return false
	}
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	volumePath := make([]uint16, maximumWindowsVolumePath)
	if windows.GetVolumePathName(pathPointer, &volumePath[0], uint32(maximumWindowsVolumePath)) != nil {
		return false
	}
	root := windows.UTF16ToString(volumePath)
	rootPointer, err := windows.UTF16PtrFromString(root)
	if err != nil || windows.GetDriveType(rootPointer) != windows.DRIVE_FIXED {
		return false
	}
	filesystem := make([]uint16, windowsFilesystemNameUTF16Size)
	var serial, maximumComponent, flags uint32
	if windows.GetVolumeInformationByHandle(
		windows.Handle(file.Fd()), nil, 0, &serial, &maximumComponent, &flags,
		&filesystem[0], uint32(windowsFilesystemNameUTF16Size),
	) != nil {
		return false
	}
	return windowsSupportedVolume(windowsVolumeDescriptor{
		root: root, filesystem: windows.UTF16ToString(filesystem), serial: serial, flags: flags,
	})
}

func windowsStandardFileInfo(file *os.File) (windowsFileStandardInfo, error) {
	if file == nil {
		return windowsFileStandardInfo{}, os.ErrInvalid
	}
	var standard windowsFileStandardInfo
	err := windows.GetFileInformationByHandleEx(
		windows.Handle(file.Fd()), windows.FileStandardInfo,
		//nolint:gosec // G103: GetFileInformationByHandleEx synchronously fills the reviewed fixed-size FILE_STANDARD_INFO layout; owner=security expiry=2027-07-14.
		(*byte)(unsafe.Pointer(&standard)), uint32(unsafe.Sizeof(standard)),
	)
	return standard, err
}

func windowsPathByHandle(file *os.File) (string, error) {
	if file == nil {
		return "", os.ErrInvalid
	}
	buffer := make([]uint16, maximumWindowsVolumePath)
	length, err := windows.GetFinalPathNameByHandle(
		windows.Handle(file.Fd()), &buffer[0], uint32(maximumWindowsVolumePath), 0,
	)
	if err != nil || length == 0 || length >= uint32(maximumWindowsVolumePath) {
		return "", artifactapp.ErrStoreIntegrity
	}
	path := windows.UTF16ToString(buffer[:length])
	path = strings.TrimPrefix(path, `\\?\`)
	if strings.HasPrefix(path, `UNC\`) || filepath.Clean(path) != path {
		return "", artifactapp.ErrStoreIntegrity
	}
	return path, nil
}
