//go:build windows

package artifactfs

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"golang.org/x/sys/windows"
)

type windowsFileRenameInformation struct {
	replaceIfExists uint32
	rootDirectory   windows.Handle
	fileNameLength  uint32
	fileName        [1]uint16
}

//nolint:contextcheck,nolintlint // Atomic publication and its post-rename identity/durability proof must finish despite request cancellation.
func renameSecureNoReplace(from *secureFile, toDirectory *os.File, to string) error {
	if from == nil || from.file == nil || from.directory == nil || from.verifyPathIdentity() != nil ||
		!safeLeaf(to) || !safeDirectoryDescriptor(toDirectory) {
		return artifactapp.ErrStoreIntegrity
	}
	ctx := windowsArtifactContext()
	fromDirectoryIdentity, err := windowssecurity.VerifyOpened(ctx, from.directory, true, true)
	if err != nil {
		return artifactapp.ErrStoreIntegrity
	}
	toDirectoryIdentity, err := windowssecurity.VerifyOpened(ctx, toDirectory, true, true)
	if err != nil || fromDirectoryIdentity.VolumeSerial != toDirectoryIdentity.VolumeSerial {
		return artifactapp.ErrStoreIntegrity
	}
	fromIdentity, err := windowssecurity.VerifyOpened(ctx, from.file, false, true)
	if err != nil {
		return artifactapp.ErrStoreIntegrity
	}
	fromGuard, err := windowssecurity.AcquireDirectoryPathGuard(ctx, from.directory.Name())
	if err != nil {
		return artifactapp.ErrStoreIntegrity
	}
	defer func() { _ = fromGuard.Close() }()
	toGuard, err := windowssecurity.AcquireDirectoryPathGuard(ctx, toDirectory.Name())
	if err != nil {
		return artifactapp.ErrStoreIntegrity
	}
	defer func() { _ = toGuard.Close() }()
	targetPath := filepath.Join(toDirectory.Name(), to)
	if target, _, openErr := windowssecurity.OpenVerified(ctx, targetPath, false, false, true); openErr == nil {
		_ = target.Close()
		return os.ErrExist
	} else if !errors.Is(openErr, os.ErrNotExist) {
		return artifactapp.ErrStoreIntegrity
	}
	name, err := windows.UTF16FromString(to)
	if err != nil || len(name) <= 1 {
		return artifactapp.ErrStoreIntegrity
	}
	name = name[:len(name)-1]
	var layout windowsFileRenameInformation
	bufferSize := int(unsafe.Offsetof(layout.fileName)) + len(name)*2
	buffer := make([]byte, bufferSize)
	//nolint:gosec // G103: the buffer uses the reviewed native FILE_RENAME_INFORMATION layout and remains alive through NtSetInformationFile; owner=security expiry=2027-07-14.
	information := (*windowsFileRenameInformation)(unsafe.Pointer(&buffer[0]))
	information.replaceIfExists = 0
	information.rootDirectory = windows.Handle(toDirectory.Fd())
	information.fileNameLength = uint32(len(name) * 2) // #nosec G115 -- safeLeaf bounds one component to 255 UTF-16 code units.
	//nolint:gosec // G103: safeLeaf bounds name to the 255-element native trailing array view; owner=security expiry=2027-07-14.
	copy((*[255]uint16)(unsafe.Pointer(&information.fileName[0]))[:len(name):len(name)], name)
	mutation, err := reopenWindowsMutationFile(from.file)
	if err != nil {
		return artifactapp.ErrStoreIntegrity
	}
	defer func() {
		if mutation != nil {
			_ = mutation.Close()
		}
	}()
	var status windows.IO_STATUS_BLOCK
	//nolint:gosec // G115: safeLeaf and the fixed native header bound this buffer far below uint32; owner=security expiry=2027-07-14.
	bufferLength := uint32(len(buffer))
	err = windows.NtSetInformationFile(
		windows.Handle(mutation.Fd()), &status, &buffer[0], bufferLength, windows.FileRenameInformation,
	)
	runtime.KeepAlive(buffer)
	if windowsAlreadyExists(err) {
		return os.ErrExist
	}
	if err != nil {
		return err
	}
	if durableSync(mutation) != nil || durableSync(from.directory) != nil || durableSync(toDirectory) != nil ||
		fromGuard.Verify(ctx) != nil || toGuard.Verify(ctx) != nil {
		return artifactapp.ErrStoreOperation
	}
	if err := mutation.Close(); err != nil {
		return artifactapp.ErrStoreOperation
	}
	mutation = nil
	if err := from.file.Close(); err != nil {
		return artifactapp.ErrStoreOperation
	}
	from.file = nil
	published, _, err := openSecureLeafAt(toDirectory, to, false)
	if err != nil {
		return artifactapp.ErrStoreIntegrity
	}
	publishedIdentity, verifyError := windowssecurity.VerifyOpened(ctx, published.file, false, true)
	published.close()
	if verifyError != nil || publishedIdentity != fromIdentity {
		return artifactapp.ErrStoreIntegrity
	}
	oldPath := filepath.Join(from.directory.Name(), from.leaf)
	if _, err := os.Lstat(oldPath); !errors.Is(err, os.ErrNotExist) {
		return artifactapp.ErrStoreIntegrity
	}
	return nil
}
