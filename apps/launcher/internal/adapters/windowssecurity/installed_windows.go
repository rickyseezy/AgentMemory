//go:build windows

package windowssecurity

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

const trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

const installedMutationMask = windows.ACCESS_MASK(
	windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
		windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | 0x40,
)

// OpenInstalledReadOnly retains a no-write/no-delete handle to one system-
// installed object and proves its type, path policy, owner, DACL, link count,
// and alternate-stream policy before returning it.
func OpenInstalledReadOnly(
	ctx context.Context,
	path string,
	wantDirectory bool,
) (*os.File, FileIdentity, error) {
	if ctx == nil {
		return nil, FileIdentity{}, errors.New("installed Windows context is absent")
	}
	if err := ctx.Err(); err != nil {
		return nil, FileIdentity{}, err
	}
	if err := ValidateLocalPath(path); err != nil || filepath.Clean(path) != path {
		return nil, FileIdentity{}, errors.New("installed Windows path is invalid")
	}
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, FileIdentity{}, err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if wantDirectory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(
		pointer, windows.GENERIC_READ|windows.READ_CONTROL,
		windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, flags, 0,
	)
	if err != nil {
		return nil, FileIdentity{}, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, FileIdentity{}, errors.New("installed Windows descriptor is invalid")
	}
	identity, err := verifyInstalledReadOnlyHandle(ctx, handle, wantDirectory)
	if err != nil {
		_ = file.Close()
		return nil, FileIdentity{}, err
	}
	return file, identity, nil
}

// VerifyInstalledReadOnlyOpened re-verifies a retained installed-software
// handle without consulting the caller's token as an ownership authority.
func VerifyInstalledReadOnlyOpened(
	ctx context.Context,
	file *os.File,
	wantDirectory bool,
) (FileIdentity, error) {
	if file == nil {
		return FileIdentity{}, errors.New("installed Windows descriptor is absent")
	}
	return verifyInstalledReadOnlyHandle(ctx, windows.Handle(file.Fd()), wantDirectory)
}

func verifyInstalledReadOnlyHandle(
	ctx context.Context,
	handle windows.Handle,
	wantDirectory bool,
) (FileIdentity, error) {
	if ctx == nil {
		return FileIdentity{}, errors.New("installed Windows context is absent")
	}
	if err := ctx.Err(); err != nil {
		return FileIdentity{}, err
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return FileIdentity{}, fmt.Errorf("inspect installed Windows handle: %w", err)
	}
	isDirectory := information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if isDirectory != wantDirectory || information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		information.FileAttributes&windows.FILE_ATTRIBUTE_DEVICE != 0 {
		return FileIdentity{}, errUnsafeFilesystem
	}
	if !isDirectory {
		if information.NumberOfLinks != 1 {
			return FileIdentity{}, errors.New("installed Windows file has multiple hard links")
		}
		if err := verifyNoAlternateStreams(handle); err != nil {
			return FileIdentity{}, err
		}
	}
	descriptor, err := windows.GetSecurityInfo(
		handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil {
		return FileIdentity{}, fmt.Errorf("read installed Windows security descriptor: %w", err)
	}
	if err := verifyInstalledReadOnlyDescriptor(descriptor); err != nil {
		return FileIdentity{}, err
	}
	return FileIdentity{
		VolumeSerial: information.VolumeSerialNumber,
		FileIndex:    uint64(information.FileIndexHigh)<<32 | uint64(information.FileIndexLow),
		Directory:    isDirectory,
	}, nil
}

func verifyInstalledReadOnlyDescriptor(descriptor *windows.SECURITY_DESCRIPTOR) error {
	if descriptor == nil {
		return errors.New("installed Windows security descriptor is absent")
	}
	owner, defaulted, err := descriptor.Owner()
	if err != nil || owner == nil || defaulted || !trustedInstalledPrincipal(owner) {
		return errors.New("installed Windows object owner is not a trusted system principal")
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PRESENT == 0 {
		return errors.New("installed Windows DACL is absent")
	}
	dacl, defaulted, err := descriptor.DACL()
	if err != nil || dacl == nil || defaulted || dacl.AceCount == 0 {
		return errors.New("installed Windows DACL is unavailable")
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil {
			return errors.New("installed Windows DACL ACE cannot be inspected")
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE &&
			ace.Header.AceType != windows.ACCESS_DENIED_ACE_TYPE {
			return errors.New("installed Windows DACL contains an unsupported ACE")
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE || ace.Mask&installedMutationMask == 0 {
			continue
		}
		// An inherit-only ACE cannot mutate this retained object. Every traversed
		// descendant is independently re-opened and subjected to this same proof.
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		//nolint:gosec // G103: GetAce documents SidStart as the variable-length SID boundary; owner=security expiry=2027-07-15.
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !trustedInstalledPrincipal(sid) {
			return errors.New("installed Windows DACL grants mutation to an untrusted principal")
		}
	}
	return nil
}

func trustedInstalledPrincipal(sid *windows.SID) bool {
	if sid == nil || !sid.IsValid() {
		return false
	}
	if sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return true
	}
	return sid.String() == trustedInstallerSID
}
