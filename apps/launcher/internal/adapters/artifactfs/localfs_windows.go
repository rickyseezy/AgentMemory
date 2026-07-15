//go:build windows

package artifactfs

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"golang.org/x/sys/windows"
)

const (
	maximumWindowsVolumePath       = 32768
	windowsFilesystemNameUTF16Size = 32
)

type windowsVolumeDescriptor struct {
	root       string
	filesystem string
	serial     uint32
	flags      uint32
}

func localFilesystem(path string) (bool, string, error) {
	directory, err := openSecureDirectory(path)
	if err != nil {
		return false, "", err
	}
	defer func() { _ = directory.Close() }()
	return localFilesystemDescriptor(directory)
}

func localFilesystemDescriptor(directory *os.File) (bool, string, error) {
	return localBundleFilesystemDescriptor(directory, bundleAccessOwnerPrivate)
}

func localBundleFilesystemDescriptor(
	directory *os.File,
	policy bundleAccessPolicy,
) (bool, string, error) {
	descriptor, err := inspectWindowsBundleVolume(directory, policy)
	if err != nil {
		return false, "", err
	}
	local := windowsSupportedVolume(descriptor)
	digest := sha256.Sum256([]byte(fmt.Sprintf(
		"agentmemory-windows-volume-v1\x00%s\x00%s\x00%08x", strings.ToUpper(descriptor.root),
		descriptor.filesystem, descriptor.serial,
	)))
	return local, fmt.Sprintf("fs-%x", digest), nil
}

func reservationFilesystemSafeDescriptor(directory *os.File) (bool, error) {
	descriptor, err := inspectWindowsVolume(directory)
	if err != nil {
		return false, err
	}
	if !windowsSupportedVolume(descriptor) || !windowsSafeAllocationDirectory(directory) {
		return false, nil
	}
	return descriptor.filesystem == "NTFS" || descriptor.filesystem == "ReFS", nil
}

func availableBytesDescriptor(directory *os.File) (uint64, error) {
	if !safeDirectoryDescriptor(directory) {
		return 0, artifactapp.ErrStoreIntegrity
	}
	descriptor, err := inspectWindowsVolume(directory)
	if err != nil || !windowsSupportedVolume(descriptor) {
		return 0, artifactapp.ErrStoreIntegrity
	}
	pointer, err := windows.UTF16PtrFromString(directory.Name())
	if err != nil {
		return 0, artifactapp.ErrStoreIntegrity
	}
	var available, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(pointer, &available, &total, &totalFree); err != nil || total == 0 {
		return 0, artifactapp.ErrStoreOperation
	}
	return available, nil
}

func inspectWindowsVolume(directory *os.File) (windowsVolumeDescriptor, error) {
	return inspectWindowsBundleVolume(directory, bundleAccessOwnerPrivate)
}

func inspectWindowsBundleVolume(
	directory *os.File,
	policy bundleAccessPolicy,
) (windowsVolumeDescriptor, error) {
	if directory == nil || !safeBundleDirectoryDescriptor(directory, policy) ||
		windowssecurity.ValidateLocalPath(directory.Name()) != nil || filepath.Clean(directory.Name()) != directory.Name() {
		return windowsVolumeDescriptor{}, artifactapp.ErrStoreIntegrity
	}
	pathPointer, err := windows.UTF16PtrFromString(directory.Name())
	if err != nil {
		return windowsVolumeDescriptor{}, artifactapp.ErrStoreIntegrity
	}
	volumePath := make([]uint16, maximumWindowsVolumePath)
	if err := windows.GetVolumePathName(pathPointer, &volumePath[0], uint32(maximumWindowsVolumePath)); err != nil {
		return windowsVolumeDescriptor{}, err
	}
	root := windows.UTF16ToString(volumePath)
	rootPointer, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return windowsVolumeDescriptor{}, err
	}
	if windows.GetDriveType(rootPointer) != windows.DRIVE_FIXED {
		return windowsVolumeDescriptor{root: root}, nil
	}
	filesystem := make([]uint16, windowsFilesystemNameUTF16Size)
	var serial, maximumComponent, flags uint32
	if err := windows.GetVolumeInformationByHandle(
		windows.Handle(directory.Fd()), nil, 0, &serial, &maximumComponent, &flags,
		&filesystem[0], uint32(windowsFilesystemNameUTF16Size),
	); err != nil {
		return windowsVolumeDescriptor{}, err
	}
	return windowsVolumeDescriptor{
		root: root, filesystem: windows.UTF16ToString(filesystem), serial: serial, flags: flags,
	}, nil
}

func windowsSupportedVolume(descriptor windowsVolumeDescriptor) bool {
	if descriptor.root == "" || descriptor.serial == 0 ||
		descriptor.filesystem != "NTFS" && descriptor.filesystem != "ReFS" {
		return false
	}
	required := uint32(windows.FILE_PERSISTENT_ACLS | windows.FILE_UNICODE_ON_DISK | windows.FILE_NAMED_STREAMS)
	forbidden := uint32(windows.FILE_READ_ONLY_VOLUME | windows.FILE_VOLUME_IS_COMPRESSED | windows.FILE_SEQUENTIAL_WRITE_ONCE)
	return descriptor.flags&required == required && descriptor.flags&forbidden == 0
}

func windowsSafeAllocationDirectory(directory *os.File) bool {
	if directory == nil {
		return false
	}
	var information windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(windows.Handle(directory.Fd()), &information) != nil ||
		information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return false
	}
	forbidden := uint32(windows.FILE_ATTRIBUTE_DEVICE | windows.FILE_ATTRIBUTE_REPARSE_POINT |
		windows.FILE_ATTRIBUTE_COMPRESSED | windows.FILE_ATTRIBUTE_OFFLINE | windows.FILE_ATTRIBUTE_ENCRYPTED |
		windows.FILE_ATTRIBUTE_INTEGRITY_STREAM | windows.FILE_ATTRIBUTE_VIRTUAL |
		windows.FILE_ATTRIBUTE_RECALL_ON_OPEN | windows.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)
	return information.FileAttributes&forbidden == 0
}
