//go:build windows

// Package windowssecurity centralizes the reviewed native Windows identity,
// DPAPI, DACL, reparse-point, file-identity, and durability boundaries used by
// PF-001 adapters.
package windowssecurity

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	maximumDPAPIBytes       = 64 << 10
	maximumStreamInfoBytes  = 64 << 10
	fileAllAccessMask       = windows.ACCESS_MASK(0x001f01ff)
	fileStreamInfoClass     = uint32(7)
	replaceFileNoFlags      = uintptr(0)
	defaultDataStreamName   = "::$DATA"
	machineGUIDRegistryPath = `SOFTWARE\Microsoft\Cryptography`
	operationDigestPrefix   = "sha256-"
)

var (
	kernel32            = windows.NewLazySystemDLL("kernel32.dll")
	replaceFileW        = kernel32.NewProc("ReplaceFileW")
	errUnsafeFilesystem = errors.New("unsafe Windows filesystem object")
)

// FileIdentity is the stable volume/file index returned by Windows for an
// opened object. It is used to detect name-based path substitution.
type FileIdentity struct {
	VolumeSerial uint32
	FileIndex    uint64
	Directory    bool
}

// OperationDirectoryGuard keeps the configuration boundary and every
// controlled directory component open without FILE_SHARE_DELETE. Windows then
// rejects renaming, deleting, or substituting any guarded path component until
// Close releases the handles.
type OperationDirectoryGuard struct {
	handles []*os.File
}

type guardedDirectoryPath struct {
	path     string
	file     *os.File
	identity FileIdentity
}

// DirectoryPathGuard walks a local absolute directory path one component at a
// time through retained no-delete handles. Reparse points are rejected and a
// parent cannot be renamed between child opens.
type DirectoryPathGuard struct {
	entries []guardedDirectoryPath
}

// AcquireDirectoryPathGuard retains the local volume root and every directory
// component through path. It grants no mutation authority.
func AcquireDirectoryPathGuard(ctx context.Context, path string) (*DirectoryPathGuard, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := ValidateLocalPath(path); err != nil {
		return nil, err
	}
	clean := filepath.Clean(path)
	if clean != path {
		return nil, errors.New("guarded Windows directory path is not canonical")
	}
	volume := filepath.VolumeName(clean)
	rootPath := volume + `\`
	root, rootIdentity, err := openAbsoluteDirectoryGuard(ctx, rootPath)
	if err != nil {
		return nil, err
	}
	guard := &DirectoryPathGuard{entries: []guardedDirectoryPath{{
		path: rootPath, file: root, identity: rootIdentity,
	}}}
	fail := func(cause error) (*DirectoryPathGuard, error) {
		return nil, errors.Join(cause, guard.Close())
	}
	relative, err := filepath.Rel(rootPath, clean)
	if err != nil || relative == ".." || strings.HasPrefix(relative, `..\`) {
		return fail(errors.New("guarded Windows directory is outside its local volume"))
	}
	currentPath := rootPath
	parent := root
	if relative != "." {
		for _, component := range strings.Split(relative, `\`) {
			if component == "" || component == "." || component == ".." || strings.ContainsAny(component, `/\:`) {
				return fail(errors.New("guarded Windows directory component is invalid"))
			}
			opened, identity, openError := openRelativeDirectoryGuard(ctx, parent, component)
			if openError != nil {
				return fail(openError)
			}
			currentPath = filepath.Join(currentPath, component)
			guard.entries = append(guard.entries, guardedDirectoryPath{
				path: currentPath, file: opened, identity: identity,
			})
			parent = opened
		}
	}
	if err := guard.Verify(ctx); err != nil {
		return fail(err)
	}
	return guard, nil
}

// Verify proves every held object still owns its original absolute name.
func (g *DirectoryPathGuard) Verify(ctx context.Context) error {
	if g == nil || len(g.entries) == 0 {
		return errors.New("windows directory path guard is absent")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, entry := range g.entries {
		if entry.file == nil {
			return errors.New("windows directory path guard handle is absent")
		}
		observed, err := directoryGuardIdentity(windows.Handle(entry.file.Fd()))
		if err != nil || observed != entry.identity {
			return errors.New("windows guarded directory handle changed identity")
		}
		pathFile, pathIdentity, err := openAbsoluteDirectoryGuard(ctx, entry.path)
		if err != nil {
			return err
		}
		closeError := pathFile.Close()
		if closeError != nil || pathIdentity != entry.identity {
			return errors.Join(errors.New("windows guarded directory path was substituted"), closeError)
		}
	}
	return nil
}

// Close releases guarded directory handles from leaf to volume root.
func (g *DirectoryPathGuard) Close() error {
	if g == nil {
		return nil
	}
	var result error
	for index := len(g.entries) - 1; index >= 0; index-- {
		if g.entries[index].file != nil {
			result = errors.Join(result, g.entries[index].file.Close())
			g.entries[index].file = nil
		}
	}
	return result
}

func openAbsoluteDirectoryGuard(ctx context.Context, path string) (*os.File, FileIdentity, error) {
	if err := ctx.Err(); err != nil {
		return nil, FileIdentity{}, err
	}
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, FileIdentity{}, err
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, FileIdentity{}, err
	}
	file := os.NewFile(uintptr(handle), filepath.Base(path))
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, FileIdentity{}, errors.New("windows directory guard handle is invalid")
	}
	identity, err := directoryGuardIdentity(handle)
	if err != nil {
		_ = file.Close()
		return nil, FileIdentity{}, err
	}
	return file, identity, nil
}

func openRelativeDirectoryGuard(
	ctx context.Context,
	parent *os.File,
	name string,
) (*os.File, FileIdentity, error) {
	if err := ctx.Err(); err != nil {
		return nil, FileIdentity{}, err
	}
	if parent == nil {
		return nil, FileIdentity{}, errors.New("windows directory guard parent is absent")
	}
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, FileIdentity{}, err
	}
	attributes := &windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: windows.Handle(parent.Fd()),
		ObjectName:    objectName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	var status windows.IO_STATUS_BLOCK
	var handle windows.Handle
	err = windows.NtCreateFile(
		&handle,
		windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.SYNCHRONIZE,
		attributes,
		&status,
		nil,
		0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		windows.FILE_OPEN,
		windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0,
	)
	runtime.KeepAlive(objectName)
	if err != nil {
		return nil, FileIdentity{}, err
	}
	file := os.NewFile(uintptr(handle), name)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, FileIdentity{}, errors.New("relative Windows directory guard handle is invalid")
	}
	identity, err := directoryGuardIdentity(handle)
	if err != nil {
		_ = file.Close()
		return nil, FileIdentity{}, err
	}
	return file, identity, nil
}

func directoryGuardIdentity(handle windows.Handle) (FileIdentity, error) {
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return FileIdentity{}, err
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
		information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		information.FileAttributes&windows.FILE_ATTRIBUTE_DEVICE != 0 {
		return FileIdentity{}, errUnsafeFilesystem
	}
	return FileIdentity{
		VolumeSerial: information.VolumeSerialNumber,
		FileIndex:    uint64(information.FileIndexHigh)<<32 | uint64(information.FileIndexLow),
		Directory:    true,
	}, nil
}

// Close releases the path guard in leaf-to-root order. It is idempotent.
func (g *OperationDirectoryGuard) Close() error {
	if g == nil {
		return nil
	}
	var result error
	for index := len(g.handles) - 1; index >= 0; index-- {
		if g.handles[index] == nil {
			continue
		}
		result = errors.Join(result, g.handles[index].Close())
		g.handles[index] = nil
	}
	return result
}

// EnsureOperationDirectory creates and proves AgentMemory/bootstrap/<digest>
// beneath the platform-selected configuration boundary.
func EnsureOperationDirectory(ctx context.Context, configRoot, operationDirectory string) error {
	guard, err := AcquireOperationDirectory(ctx, configRoot, operationDirectory, true)
	if err != nil {
		return err
	}
	return guard.Close()
}

// VerifyOperationDirectory proves the controlled tree without creating state.
func VerifyOperationDirectory(ctx context.Context, configRoot, operationDirectory string) error {
	guard, err := AcquireOperationDirectory(ctx, configRoot, operationDirectory, false)
	if err != nil {
		return err
	}
	return guard.Close()
}

// AcquireOperationDirectory creates when requested, validates, and holds the
// complete fixed digest path against junction/symlink/path substitution races.
func AcquireOperationDirectory(
	ctx context.Context,
	configRoot string,
	operationDirectory string,
	create bool,
) (*OperationDirectoryGuard, error) {
	if err := ValidateLocalPath(configRoot); err != nil {
		return nil, err
	}
	if err := ValidateLocalPath(operationDirectory); err != nil {
		return nil, err
	}
	rootPath := filepath.Clean(configRoot)
	directoryPath := filepath.Clean(operationDirectory)
	relative, err := filepath.Rel(rootPath, directoryPath)
	if err != nil {
		return nil, fmt.Errorf("relate Windows operation directory: %w", err)
	}
	components := strings.Split(relative, string(filepath.Separator))
	if len(components) != 3 || components[0] != "AgentMemory" || components[1] != "bootstrap" ||
		!validOperationDigestSegment(components[2]) {
		return nil, errors.New("windows operation path is outside the closed bootstrap tree")
	}
	if create {
		if _, _, err := EnsurePrivateDirectoryTree(ctx, rootPath, rootPath); err != nil {
			return nil, err
		}
	}
	root, rootIdentity, err := OpenVerified(ctx, rootPath, true, create, false)
	if err != nil {
		return nil, err
	}
	guard := &OperationDirectoryGuard{handles: []*os.File{root}}
	fail := func(cause error) (*OperationDirectoryGuard, error) {
		return nil, errors.Join(cause, guard.Close())
	}
	currentPath := rootPath
	identities := make([]struct {
		path     string
		identity FileIdentity
	}, 0, len(components))
	for _, component := range components {
		currentPath = filepath.Join(currentPath, component)
		created := false
		if _, err := os.Lstat(currentPath); errors.Is(err, os.ErrNotExist) {
			if !create {
				return fail(os.ErrNotExist)
			}
			createError := CreatePrivateDirectory(ctx, currentPath)
			if createError != nil && !errors.Is(createError, windows.ERROR_ALREADY_EXISTS) {
				return fail(createError)
			}
			created = createError == nil
		} else if err != nil {
			return fail(err)
		}
		opened, identity, err := OpenVerified(ctx, currentPath, true, create, true)
		if err != nil {
			return fail(err)
		}
		guard.handles = append(guard.handles, opened)
		if created {
			if err := Flush(opened); err != nil {
				return fail(err)
			}
			parent := guard.handles[len(guard.handles)-2]
			if syncError := Flush(parent); syncError != nil {
				return fail(syncError)
			}
		}
		identities = append(identities, struct {
			path     string
			identity FileIdentity
		}{path: currentPath, identity: identity})
	}
	if err := VerifyPathIdentity(ctx, rootPath, rootIdentity, false); err != nil {
		return fail(err)
	}
	for _, controlled := range identities {
		if err := VerifyPathIdentity(ctx, controlled.path, controlled.identity, true); err != nil {
			return fail(err)
		}
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	return guard, nil
}

// WithOperationDirectory holds the complete path guard for one action and
// reports both action and handle-release failures.
func WithOperationDirectory(
	ctx context.Context,
	configRoot string,
	operationDirectory string,
	create bool,
	action func() error,
) (result error) {
	if action == nil {
		return errors.New("windows operation directory action is required")
	}
	guard, err := AcquireOperationDirectory(ctx, configRoot, operationDirectory, create)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, guard.Close()) }()
	return action()
}

func validOperationDigestSegment(value string) bool {
	if len(value) != len(operationDigestPrefix)+64 || !strings.HasPrefix(value, operationDigestPrefix) {
		return false
	}
	for _, character := range value[len(operationDigestPrefix):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

// CurrentUserSID returns the invoking process token's canonical SID.
func CurrentUserSID(ctx context.Context) (*windows.SID, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, "", fmt.Errorf("resolve invoking Windows SID: %w", err)
	}
	if user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return nil, "", errors.New("invoking Windows SID is unavailable or invalid")
	}
	copySID, err := user.User.Sid.Copy()
	if err != nil {
		return nil, "", fmt.Errorf("copy invoking Windows SID: %w", err)
	}
	return copySID, copySID.String(), nil
}

// MachineGUID reads the 64-bit registry view of the local machine identity.
func MachineGUID(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		machineGUIDRegistryPath,
		registry.QUERY_VALUE|registry.WOW64_64KEY,
	)
	if err != nil {
		return "", fmt.Errorf("open Windows machine identity: %w", err)
	}
	defer func() { _ = key.Close() }()
	value, valueType, err := key.GetStringValue("MachineGuid")
	if err != nil {
		return "", fmt.Errorf("read Windows machine identity: %w", err)
	}
	if valueType != registry.SZ {
		return "", errors.New("windows machine identity registry type is invalid")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return value, nil
}

// ProtectUser encrypts and authenticates data with invoking-user DPAPI. The
// local-machine flag is deliberately absent because it would allow any local
// user to decrypt the record.
func ProtectUser(ctx context.Context, plaintext, entropy []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(plaintext) == 0 || len(plaintext) > maximumDPAPIBytes || len(entropy) == 0 {
		return nil, errors.New("DPAPI plaintext and entropy must be present and bounded")
	}
	input := dataBlob(plaintext)
	entropyBlob := dataBlob(entropy)
	description, err := windows.UTF16PtrFromString("AgentMemory bootstrap HMAC v1")
	if err != nil {
		return nil, err
	}
	var output windows.DataBlob
	err = windows.CryptProtectData(
		&input,
		description,
		&entropyBlob,
		0,
		nil,
		windows.CRYPTPROTECT_UI_FORBIDDEN,
		&output,
	)
	runtime.KeepAlive(plaintext)
	runtime.KeepAlive(entropy)
	if err != nil {
		return nil, fmt.Errorf("protect invoking-user DPAPI record: %w", err)
	}
	return copyAndFreeDPAPI(output)
}

// UnprotectUser decrypts a prompt-free invoking-user DPAPI record.
func UnprotectUser(ctx context.Context, ciphertext, entropy []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 || len(ciphertext) > maximumDPAPIBytes || len(entropy) == 0 {
		return nil, errors.New("DPAPI ciphertext and entropy must be present and bounded")
	}
	input := dataBlob(ciphertext)
	entropyBlob := dataBlob(entropy)
	var output windows.DataBlob
	err := windows.CryptUnprotectData(
		&input,
		nil,
		&entropyBlob,
		0,
		nil,
		windows.CRYPTPROTECT_UI_FORBIDDEN,
		&output,
	)
	runtime.KeepAlive(ciphertext)
	runtime.KeepAlive(entropy)
	if err != nil {
		return nil, fmt.Errorf("unprotect invoking-user DPAPI record: %w", err)
	}
	return copyAndFreeDPAPI(output)
}

func dataBlob(value []byte) windows.DataBlob {
	if len(value) == 0 {
		return windows.DataBlob{}
	}
	if uint64(len(value)) > uint64(^uint32(0)) {
		panic("DPAPI input exceeds the Windows DATA_BLOB size")
	}
	//nolint:gosec // G115: the explicit uint64 range proof above bounds this Windows DATA_BLOB conversion; owner=security expiry=2027-07-14.
	return windows.DataBlob{Size: uint32(len(value)), Data: &value[0]}
}

func copyAndFreeDPAPI(blob windows.DataBlob) ([]byte, error) {
	if blob.Data == nil || blob.Size == 0 || blob.Size > maximumDPAPIBytes {
		if blob.Data != nil {
			//nolint:gosec // G103: LocalFree requires the pointer returned by DPAPI; owner=security expiry=2027-07-14.
			_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(blob.Data)))
		}
		return nil, errors.New("DPAPI returned an invalid bounded record")
	}
	//nolint:gosec // G103: blob is DPAPI-owned memory whose size was bounded immediately above; owner=security expiry=2027-07-14.
	allocated := unsafe.Slice(blob.Data, int(blob.Size))
	result := append([]byte(nil), allocated...)
	clear(allocated)
	//nolint:gosec // G103: LocalFree requires the pointer returned by DPAPI; owner=security expiry=2027-07-14.
	if _, err := windows.LocalFree(windows.Handle(unsafe.Pointer(blob.Data))); err != nil {
		clear(result)
		return nil, fmt.Errorf("release DPAPI record: %w", err)
	}
	return result, nil
}

// ValidateLocalPath rejects UNC/device paths, mapped network drives, alternate
// data streams, and drive types without local writable-file semantics.
func ValidateLocalPath(path string) error {
	if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) || strings.IndexByte(path, 0) >= 0 {
		return errors.New("windows security path must be a non-empty absolute path")
	}
	cleanPath := filepath.Clean(path)
	volume := filepath.VolumeName(cleanPath)
	if len(volume) != 2 || volume[1] != ':' ||
		(volume[0] < 'A' || volume[0] > 'Z') && (volume[0] < 'a' || volume[0] > 'z') {
		return errors.New("windows security path must use a local drive-letter volume")
	}
	remainder := strings.TrimPrefix(cleanPath, volume)
	if strings.ContainsRune(remainder, ':') {
		return errors.New("windows alternate data stream syntax is forbidden")
	}
	root, err := windows.UTF16PtrFromString(volume + `\`)
	if err != nil {
		return errors.New("windows drive root is invalid")
	}
	if !windowsDriveTypeLocal(windows.GetDriveType(root)) {
		return errors.New("windows security path must use a local writable drive")
	}
	return nil
}

func windowsDriveTypeLocal(driveType uint32) bool {
	return driveType == windows.DRIVE_FIXED || driveType == windows.DRIVE_REMOVABLE ||
		driveType == windows.DRIVE_RAMDISK
}

// CreatePrivateDirectory creates one directory with an explicit protected
// DACL granting only the invoking SID full control.
func CreatePrivateDirectory(ctx context.Context, path string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidateLocalPath(path); err != nil {
		return err
	}
	attributes, descriptor, err := privateSecurityAttributes(ctx)
	if err != nil {
		return err
	}
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	err = windows.CreateDirectory(pathPointer, attributes)
	runtime.KeepAlive(descriptor)
	return err
}

// EnsurePrivateDirectoryTree creates or re-verifies target while retaining a
// no-delete handle for every traversed component. privateBoundary and every
// descendant must have the exact protected invoking-user DACL; system-owned
// ancestors above that boundary are identity-guarded but are not rewritten.
func EnsurePrivateDirectoryTree(
	ctx context.Context,
	privateBoundary string,
	target string,
) (FileIdentity, bool, error) {
	if err := ctx.Err(); err != nil {
		return FileIdentity{}, false, err
	}
	if err := ValidateLocalPath(privateBoundary); err != nil {
		return FileIdentity{}, false, err
	}
	if err := ValidateLocalPath(target); err != nil {
		return FileIdentity{}, false, err
	}
	privateBoundary = filepath.Clean(privateBoundary)
	target = filepath.Clean(target)
	if !windowsPathWithin(privateBoundary, target) ||
		!strings.EqualFold(filepath.VolumeName(privateBoundary), filepath.VolumeName(target)) {
		return FileIdentity{}, false, errors.New("private Windows directory target is outside its boundary")
	}
	volumeRoot := filepath.VolumeName(target) + `\`
	root, _, err := openAbsoluteDirectoryGuard(ctx, volumeRoot)
	if err != nil {
		return FileIdentity{}, false, err
	}
	handles := []*os.File{root}
	defer func() {
		for index := len(handles) - 1; index >= 0; index-- {
			_ = handles[index].Close()
		}
	}()
	relative, err := filepath.Rel(volumeRoot, target)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, `..\`) {
		return FileIdentity{}, false, errors.New("private Windows directory target is invalid")
	}
	currentPath := volumeRoot
	parent := root
	var finalIdentity FileIdentity
	finalCreated := false
	components := strings.Split(relative, `\`)
	for index, component := range components {
		if err := ctx.Err(); err != nil {
			return FileIdentity{}, false, err
		}
		if component == "" || component == "." || component == ".." || strings.ContainsAny(component, `/\:`) {
			return FileIdentity{}, false, errors.New("private Windows directory component is invalid")
		}
		opened, identity, openError := openRelativeDirectoryGuard(ctx, parent, component)
		created := false
		if openError != nil {
			opened, created, openError = openOrCreatePrivateDirectoryChild(ctx, parent, component)
			if openError == nil {
				identity, openError = VerifyOpened(ctx, opened, true, true)
			}
		}
		if openError != nil {
			return FileIdentity{}, false, openError
		}
		handles = append(handles, opened)
		parent = opened
		currentPath = filepath.Join(currentPath, component)
		if windowsPathWithin(privateBoundary, currentPath) {
			verified, verifyError := VerifyOpened(ctx, opened, true, true)
			if verifyError != nil {
				return FileIdentity{}, false, verifyError
			}
			identity = verified
		}
		if index == len(components)-1 {
			finalIdentity = identity
			finalCreated = created
		}
	}
	if finalIdentity == (FileIdentity{}) || !windowsPathWithin(privateBoundary, target) {
		return FileIdentity{}, false, errors.New("private Windows directory identity is absent")
	}
	return finalIdentity, finalCreated, nil
}

func openOrCreatePrivateDirectoryChild(
	ctx context.Context,
	parent *os.File,
	name string,
) (*os.File, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if parent == nil || filepath.Base(name) != name || name == "." || name == ".." ||
		strings.ContainsAny(name, `/\:`) {
		return nil, false, errors.New("private Windows directory child name is invalid")
	}
	if _, err := VerifyOpened(ctx, parent, true, false); err != nil {
		return nil, false, err
	}
	_, descriptor, err := privateSecurityAttributes(ctx)
	if err != nil {
		return nil, false, err
	}
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, false, err
	}
	attributes := &windows.OBJECT_ATTRIBUTES{
		Length:             uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory:      windows.Handle(parent.Fd()),
		ObjectName:         objectName,
		Attributes:         windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
		SecurityDescriptor: descriptor,
	}
	var status windows.IO_STATUS_BLOCK
	var handle windows.Handle
	err = windows.NtCreateFile(
		&handle,
		windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.DELETE|windows.READ_CONTROL|windows.WRITE_DAC,
		attributes,
		&status,
		nil,
		windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		windows.FILE_CREATE,
		windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|
			windows.FILE_WRITE_THROUGH|windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0,
	)
	created := err == nil
	if err != nil {
		attributes.SecurityDescriptor = nil
		err = windows.NtCreateFile(
			&handle,
			windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.DELETE|windows.READ_CONTROL|windows.WRITE_DAC,
			attributes,
			&status,
			nil,
			windows.FILE_ATTRIBUTE_NORMAL,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
			windows.FILE_OPEN,
			windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|
				windows.FILE_WRITE_THROUGH|windows.FILE_SYNCHRONOUS_IO_NONALERT,
			0,
			0,
		)
	}
	runtime.KeepAlive(objectName)
	runtime.KeepAlive(descriptor)
	if err != nil {
		return nil, false, err
	}
	file := os.NewFile(uintptr(handle), name)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, false, errors.New("private Windows directory handle is invalid")
	}
	if _, err := VerifyOpened(ctx, file, true, true); err != nil {
		_ = file.Close()
		return nil, false, err
	}
	return file, created, nil
}

func windowsPathWithin(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, `..\`)
}

// CreatePrivateFile exclusively creates an owner-only regular file with an
// explicit protected DACL and write-through handle.
func CreatePrivateFile(ctx context.Context, path string) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := ValidateLocalPath(path); err != nil {
		return nil, err
	}
	attributes, descriptor, err := privateSecurityAttributes(ctx)
	if err != nil {
		return nil, err
	}
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pathPointer,
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE|windows.READ_CONTROL|windows.WRITE_DAC,
		0,
		attributes,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_WRITE_THROUGH,
		0,
	)
	runtime.KeepAlive(descriptor)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), filepath.Base(path))
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("private Windows file descriptor is invalid")
	}
	if _, err := VerifyOpened(ctx, file, false, true); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

// OpenOrCreatePrivateChildSharedRead addresses one simple child name relative
// to an already verified directory handle. A retained handle permits readers
// but denies every concurrent writer and delete/rename request. No absolute
// pathname is resolved before sensitive bytes are written.
func OpenOrCreatePrivateChildSharedRead(
	ctx context.Context,
	directory *os.File,
	name string,
) (*os.File, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if directory == nil || filepath.Base(name) != name || name == "." || name == ".." ||
		strings.ContainsAny(name, `/\:`) {
		return nil, false, errors.New("private Windows child name is invalid")
	}
	if _, err := VerifyOpened(ctx, directory, true, true); err != nil {
		return nil, false, err
	}
	_, descriptor, err := privateSecurityAttributes(ctx)
	if err != nil {
		return nil, false, err
	}
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, false, err
	}
	attributes := &windows.OBJECT_ATTRIBUTES{
		Length:             uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory:      windows.Handle(directory.Fd()),
		ObjectName:         objectName,
		Attributes:         windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
		SecurityDescriptor: descriptor,
	}
	var status windows.IO_STATUS_BLOCK
	var handle windows.Handle
	err = windows.NtCreateFile(
		&handle,
		windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.READ_CONTROL|windows.WRITE_DAC,
		attributes,
		&status,
		nil,
		windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_SHARE_READ,
		windows.FILE_CREATE,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|
			windows.FILE_WRITE_THROUGH|windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0,
	)
	created := err == nil
	if err != nil {
		attributes.SecurityDescriptor = nil
		err = windows.NtCreateFile(
			&handle,
			windows.FILE_GENERIC_READ|windows.READ_CONTROL,
			attributes,
			&status,
			nil,
			windows.FILE_ATTRIBUTE_NORMAL,
			windows.FILE_SHARE_READ,
			windows.FILE_OPEN,
			windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|
				windows.FILE_SYNCHRONOUS_IO_NONALERT,
			0,
			0,
		)
	}
	runtime.KeepAlive(objectName)
	runtime.KeepAlive(descriptor)
	if err != nil {
		return nil, false, err
	}
	file := os.NewFile(uintptr(handle), name)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, false, errors.New("private shared-read Windows child descriptor is invalid")
	}
	if _, err := VerifyOpened(ctx, file, false, true); err != nil {
		_ = file.Close()
		return nil, false, err
	}
	return file, created, nil
}

func privateSecurityAttributes(ctx context.Context) (*windows.SecurityAttributes, *windows.SECURITY_DESCRIPTOR, error) {
	return privateSecurityAttributesWithRights(ctx, "FA")
}

func privateSecurityAttributesWithRights(
	ctx context.Context,
	rights string,
) (*windows.SecurityAttributes, *windows.SECURITY_DESCRIPTOR, error) {
	_, sid, err := CurrentUserSID(ctx)
	if err != nil {
		return nil, nil, err
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		"O:" + sid + "G:" + sid + "D:P(A;;" + rights + ";;;" + sid + ")",
	)
	if err != nil {
		return nil, nil, fmt.Errorf("construct owner-only Windows DACL: %w", err)
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
		InheritHandle:      0,
	}, descriptor, nil
}

// OpenVerified opens a final path without traversing a final reparse point and
// proves type, owner, protected DACL, link count, and stream invariants.
func OpenVerified(ctx context.Context, path string, wantDirectory, writable, strictDACL bool) (*os.File, FileIdentity, error) {
	if err := ctx.Err(); err != nil {
		return nil, FileIdentity{}, err
	}
	if err := ValidateLocalPath(path); err != nil {
		return nil, FileIdentity{}, err
	}
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, FileIdentity{}, err
	}
	access := uint32(windows.GENERIC_READ | windows.READ_CONTROL)
	if writable {
		access |= windows.GENERIC_WRITE | windows.WRITE_DAC
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if wantDirectory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(
		pathPointer,
		access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		flags,
		0,
	)
	if err != nil {
		return nil, FileIdentity{}, err
	}
	file := os.NewFile(uintptr(handle), filepath.Base(path))
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, FileIdentity{}, errors.New("verified Windows file descriptor is invalid")
	}
	identity, err := verifyHandle(ctx, handle, wantDirectory, strictDACL)
	if err != nil {
		_ = file.Close()
		return nil, FileIdentity{}, err
	}
	return file, identity, nil
}

// OpenVerifiedForDelete opens one regular owner-private file with DELETE
// authority while denying concurrent write/delete sharing. Callers can verify
// content through this same handle before marking that exact object for deletion.
func OpenVerifiedForDelete(ctx context.Context, path string) (*os.File, FileIdentity, error) {
	if err := ctx.Err(); err != nil {
		return nil, FileIdentity{}, err
	}
	if err := ValidateLocalPath(path); err != nil {
		return nil, FileIdentity{}, err
	}
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, FileIdentity{}, err
	}
	handle, err := windows.CreateFile(
		pathPointer,
		windows.GENERIC_READ|windows.READ_CONTROL|windows.DELETE,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, FileIdentity{}, err
	}
	file := os.NewFile(uintptr(handle), filepath.Base(path))
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, FileIdentity{}, errors.New("delete-authorized Windows file descriptor is invalid")
	}
	identity, err := verifyHandle(ctx, handle, false, true)
	if err != nil {
		_ = file.Close()
		return nil, FileIdentity{}, err
	}
	return file, identity, nil
}

// DeleteOpenedFile marks the exact retained handle for deletion on close.
// No pathname lookup occurs after the caller has authenticated its contents.
func DeleteOpenedFile(ctx context.Context, file *os.File) error {
	if ctx == nil || file == nil {
		return errors.New("Windows delete handle is invalid")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	deleteFile := byte(1)
	return windows.SetFileInformationByHandle(
		windows.Handle(file.Fd()), windows.FileDispositionInfo, &deleteFile, 1,
	)
}

// OpenVerifiedLockedRead opens an owner-only object while denying concurrent
// write and delete access. It is used when another process must consume a
// stable protected pathname while the launcher retains the identity handle.
func OpenVerifiedLockedRead(
	ctx context.Context,
	path string,
	wantDirectory bool,
) (*os.File, FileIdentity, error) {
	if err := ctx.Err(); err != nil {
		return nil, FileIdentity{}, err
	}
	if err := ValidateLocalPath(path); err != nil {
		return nil, FileIdentity{}, err
	}
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, FileIdentity{}, err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if wantDirectory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(
		pathPointer,
		windows.GENERIC_READ|windows.READ_CONTROL,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		flags,
		0,
	)
	if err != nil {
		return nil, FileIdentity{}, err
	}
	file := os.NewFile(uintptr(handle), filepath.Base(path))
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, FileIdentity{}, errors.New("locked Windows file descriptor is invalid")
	}
	identity, err := verifyHandle(ctx, handle, wantDirectory, true)
	if err != nil {
		_ = file.Close()
		return nil, FileIdentity{}, err
	}
	return file, identity, nil
}

// OpenVerifiedForOwnerSIDLockedRead opens a regular owner-private handoff
// file while denying concurrent write/delete and verifies it against an exact
// invoking-user SID even when the caller is an elevated helper running under
// a different token.
func OpenVerifiedForOwnerSIDLockedRead(
	ctx context.Context,
	path string,
	ownerSID string,
) (*os.File, FileIdentity, error) {
	if err := ctx.Err(); err != nil {
		return nil, FileIdentity{}, err
	}
	if err := ValidateLocalPath(path); err != nil {
		return nil, FileIdentity{}, err
	}
	expected, err := windows.StringToSid(ownerSID)
	if err != nil || expected == nil || !expected.IsValid() {
		return nil, FileIdentity{}, errors.New("expected Windows owner SID is invalid")
	}
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, FileIdentity{}, err
	}
	handle, err := windows.CreateFile(
		pathPointer,
		windows.GENERIC_READ|windows.READ_CONTROL,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, FileIdentity{}, err
	}
	file := os.NewFile(uintptr(handle), filepath.Base(path))
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, FileIdentity{}, errors.New("locked Windows owner file descriptor is invalid")
	}
	identity, err := verifyHandleForSID(ctx, handle, false, true, expected)
	if err != nil {
		_ = file.Close()
		return nil, FileIdentity{}, err
	}
	return file, identity, nil
}

// VerifyOpened proves an already-open os.File handle.
func VerifyOpened(ctx context.Context, file *os.File, wantDirectory, strictDACL bool) (FileIdentity, error) {
	if file == nil {
		return FileIdentity{}, errors.New("windows filesystem descriptor is absent")
	}
	return verifyHandle(ctx, windows.Handle(file.Fd()), wantDirectory, strictDACL)
}

func verifyHandle(ctx context.Context, handle windows.Handle, wantDirectory, strictDACL bool) (FileIdentity, error) {
	expectedSID, _, err := CurrentUserSID(ctx)
	if err != nil {
		return FileIdentity{}, err
	}
	return verifyHandleForSID(ctx, handle, wantDirectory, strictDACL, expectedSID)
}

func verifyHandleForSID(
	ctx context.Context,
	handle windows.Handle,
	wantDirectory bool,
	strictDACL bool,
	expectedSID *windows.SID,
) (FileIdentity, error) {
	if err := ctx.Err(); err != nil {
		return FileIdentity{}, err
	}
	if expectedSID == nil || !expectedSID.IsValid() {
		return FileIdentity{}, errors.New("windows filesystem owner SID is invalid")
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return FileIdentity{}, fmt.Errorf("inspect Windows file handle: %w", err)
	}
	isDirectory := information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if isDirectory != wantDirectory || information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		information.FileAttributes&windows.FILE_ATTRIBUTE_DEVICE != 0 {
		return FileIdentity{}, errUnsafeFilesystem
	}
	if !isDirectory {
		if information.NumberOfLinks != 1 {
			return FileIdentity{}, errors.New("windows protected file has multiple hard links")
		}
		if err := verifyNoAlternateStreams(handle); err != nil {
			return FileIdentity{}, err
		}
	}
	securityDescriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || securityDescriptor == nil {
		return FileIdentity{}, fmt.Errorf("read Windows security descriptor: %w", err)
	}
	if err := verifyOwnerDescriptor(securityDescriptor, expectedSID); err != nil {
		return FileIdentity{}, err
	}
	if strictDACL {
		if err := verifyPrivateDACL(securityDescriptor, expectedSID); err != nil {
			return FileIdentity{}, err
		}
	}
	return FileIdentity{
		VolumeSerial: information.VolumeSerialNumber,
		FileIndex:    uint64(information.FileIndexHigh)<<32 | uint64(information.FileIndexLow),
		Directory:    isDirectory,
	}, nil
}

func verifyPrivateDACL(descriptor *windows.SECURITY_DESCRIPTOR, expectedSID *windows.SID) error {
	return verifyPrivateDACLMask(descriptor, expectedSID, fileAllAccessMask)
}

func verifyOwnerDescriptor(descriptor *windows.SECURITY_DESCRIPTOR, expectedSID *windows.SID) error {
	if descriptor == nil || expectedSID == nil || !expectedSID.IsValid() {
		return errors.New("windows security owner proof is unavailable")
	}
	owner, defaulted, err := descriptor.Owner()
	if err != nil || owner == nil || defaulted || !owner.Equals(expectedSID) {
		return errors.New("windows filesystem owner is not the invoking SID")
	}
	return nil
}

func verifyPrivateDACLMask(
	descriptor *windows.SECURITY_DESCRIPTOR,
	expectedSID *windows.SID,
	expectedMask windows.ACCESS_MASK,
) error {
	if descriptor == nil || expectedSID == nil || !expectedSID.IsValid() {
		return errors.New("windows filesystem DACL proof is unavailable")
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 || control&windows.SE_DACL_PRESENT == 0 {
		return errors.New("windows filesystem DACL is absent, inherited, or unprotected")
	}
	dacl, defaulted, err := descriptor.DACL()
	if err != nil || dacl == nil || defaulted || dacl.AceCount != 1 {
		return errors.New("windows filesystem DACL is not the closed owner-only ACL")
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil || ace == nil {
		return errors.New("windows filesystem DACL ACE cannot be inspected")
	}
	//nolint:gosec // G103: GetAce returns an ACCESS_ALLOWED_ACE whose SidStart is the documented variable-length SID boundary; owner=security expiry=2027-07-14.
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 ||
		ace.Mask != expectedMask || !aceSID.IsValid() || !aceSID.Equals(expectedSID) {
		return errors.New("windows filesystem DACL grants a foreign, inherited, or incomplete ACE")
	}
	return nil
}

func verifyNoAlternateStreams(handle windows.Handle) error {
	buffer := make([]byte, maximumStreamInfoBytes)
	if err := windows.GetFileInformationByHandleEx(handle, fileStreamInfoClass, &buffer[0], maximumStreamInfoBytes); err != nil {
		return fmt.Errorf("enumerate Windows file streams: %w", err)
	}
	offset := uint32(0)
	entries := 0
	for {
		if int(offset)+24 > len(buffer) {
			return errors.New("windows file stream metadata is malformed")
		}
		next := binary.LittleEndian.Uint32(buffer[offset : offset+4])
		nameBytes := binary.LittleEndian.Uint32(buffer[offset+4 : offset+8])
		if nameBytes == 0 || nameBytes%2 != 0 || uint64(offset)+24+uint64(nameBytes) > uint64(len(buffer)) {
			return errors.New("windows file stream name is malformed")
		}
		nameUnits := make([]uint16, nameBytes/2)
		for index := range nameUnits {
			position := int(offset) + 24 + index*2
			nameUnits[index] = binary.LittleEndian.Uint16(buffer[position : position+2])
		}
		entries++
		if entries != 1 || syscall.UTF16ToString(nameUnits) != defaultDataStreamName {
			return errors.New("windows alternate data stream is forbidden")
		}
		if next == 0 {
			break
		}
		if next < 24+nameBytes || offset > ^uint32(0)-next {
			return errors.New("windows file stream chain is malformed")
		}
		offset += next
	}
	return nil
}

// VerifyPathIdentity reopens a path and compares its Windows file identity.
func VerifyPathIdentity(ctx context.Context, path string, expected FileIdentity, strictDACL bool) error {
	file, observed, err := OpenVerified(ctx, path, expected.Directory, false, strictDACL)
	if err != nil {
		return err
	}
	if closeError := file.Close(); closeError != nil {
		return closeError
	}
	if observed != expected {
		return errors.New("windows filesystem path was substituted")
	}
	return nil
}

// Flush forces an opened regular-file handle through FlushFileBuffers. Windows
// does not define FlushFileBuffers for an ordinary directory handle. Directory
// metadata durability is therefore established by the mutation primitive:
// FILE_FLAG_WRITE_THROUGH for native create/rename handles, or
// MOVEFILE_WRITE_THROUGH for path publication. Callers still pass retained
// directory handles here so their type and continued validity are proven at
// the durability boundary.
func Flush(file *os.File) error {
	if file == nil {
		return errors.New("windows durability descriptor is absent")
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &information); err != nil {
		return fmt.Errorf("inspect Windows durability descriptor: %w", err)
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		if information.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DEVICE) != 0 {
			return errors.New("windows durability directory is unsafe")
		}
		return nil
	}
	if err := windows.FlushFileBuffers(windows.Handle(file.Fd())); err != nil {
		return fmt.Errorf("flush Windows filesystem buffers: %w", err)
	}
	return nil
}

// AtomicReplace publishes replacement in the same protected directory. An
// existing target uses ReplaceFileW to preserve its verified DACL; a new target
// uses MoveFileExW with MOVEFILE_WRITE_THROUGH.
func AtomicReplace(ctx context.Context, replacementPath, targetPath string, targetExists bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidateLocalPath(replacementPath); err != nil {
		return err
	}
	if err := ValidateLocalPath(targetPath); err != nil {
		return err
	}
	if !strings.EqualFold(filepath.Dir(replacementPath), filepath.Dir(targetPath)) {
		return errors.New("windows atomic replacement must remain in one directory")
	}
	parentPath := filepath.Dir(targetPath)
	parent, parentIdentity, err := OpenVerified(ctx, parentPath, true, true, true)
	if err != nil {
		return err
	}
	defer func() { _ = parent.Close() }()
	if targetExists {
		target, _, verifyError := OpenVerified(ctx, targetPath, false, false, true)
		if verifyError != nil {
			return verifyError
		}
		if closeError := target.Close(); closeError != nil {
			return closeError
		}
	}
	replacement, replacementIdentity, err := OpenVerified(ctx, replacementPath, false, false, true)
	if err != nil {
		return err
	}
	if closeError := replacement.Close(); closeError != nil {
		return closeError
	}
	replacementPointer, _ := windows.UTF16PtrFromString(replacementPath)
	targetPointer, _ := windows.UTF16PtrFromString(targetPath)
	if targetExists {
		//nolint:gosec // G103: ReplaceFileW requires stable UTF-16 pointers for the duration of this synchronous native call; owner=security expiry=2027-07-14.
		result, _, callError := replaceFileW.Call(
			uintptr(unsafe.Pointer(targetPointer)),
			uintptr(unsafe.Pointer(replacementPointer)),
			0,
			replaceFileNoFlags,
			0,
			0,
		)
		if result == 0 {
			return fmt.Errorf("replace protected Windows file: %w", callError)
		}
	} else if err := windows.MoveFileEx(replacementPointer, targetPointer, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return fmt.Errorf("publish protected Windows file: %w", err)
	}
	runtime.KeepAlive(replacementPointer)
	runtime.KeepAlive(targetPointer)
	published, publishedIdentity, err := OpenVerified(ctx, targetPath, false, true, true)
	if err != nil {
		return err
	}
	if publishedIdentity != replacementIdentity {
		_ = published.Close()
		return errors.New("windows atomic replacement published a substituted file identity")
	}
	if err := Flush(published); err != nil {
		_ = published.Close()
		return err
	}
	if err := published.Close(); err != nil {
		return err
	}
	if err := Flush(parent); err != nil {
		return err
	}
	return VerifyPathIdentity(ctx, parentPath, parentIdentity, true)
}

// AtomicExchange replaces target with replacement while atomically preserving
// the displaced target at displacedPath. All three names must be distinct and
// reside in one verified owner-only directory. ReplaceFileW is followed by
// identity checks and FlushFileBuffers for both files and the parent handle.
func AtomicExchange(ctx context.Context, replacementPath, targetPath, displacedPath string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, path := range []string{replacementPath, targetPath, displacedPath} {
		if err := ValidateLocalPath(path); err != nil {
			return err
		}
	}
	parentPath := filepath.Dir(targetPath)
	if !strings.EqualFold(filepath.Dir(replacementPath), parentPath) ||
		!strings.EqualFold(filepath.Dir(displacedPath), parentPath) ||
		strings.EqualFold(replacementPath, targetPath) || strings.EqualFold(replacementPath, displacedPath) ||
		strings.EqualFold(targetPath, displacedPath) {
		return errors.New("windows atomic exchange requires distinct names in one directory")
	}
	if _, err := os.Lstat(displacedPath); err == nil {
		return errors.New("windows atomic exchange displaced path is occupied")
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("windows atomic exchange displaced path cannot be inspected")
	}
	parent, parentIdentity, err := OpenVerified(ctx, parentPath, true, true, true)
	if err != nil {
		return err
	}
	defer func() { _ = parent.Close() }()
	target, targetIdentity, err := OpenVerified(ctx, targetPath, false, false, true)
	if err != nil {
		return err
	}
	if err := target.Close(); err != nil {
		return err
	}
	replacement, replacementIdentity, err := OpenVerified(ctx, replacementPath, false, false, true)
	if err != nil {
		return err
	}
	if err := replacement.Close(); err != nil {
		return err
	}
	replacementPointer, _ := windows.UTF16PtrFromString(replacementPath)
	targetPointer, _ := windows.UTF16PtrFromString(targetPath)
	displacedPointer, _ := windows.UTF16PtrFromString(displacedPath)
	//nolint:gosec // G103: ReplaceFileW synchronously consumes stable UTF-16 path pointers; owner=security expiry=2027-07-14.
	result, _, callError := replaceFileW.Call(
		uintptr(unsafe.Pointer(targetPointer)),
		uintptr(unsafe.Pointer(replacementPointer)),
		uintptr(unsafe.Pointer(displacedPointer)),
		replaceFileNoFlags,
		0,
		0,
	)
	runtime.KeepAlive(replacementPointer)
	runtime.KeepAlive(targetPointer)
	runtime.KeepAlive(displacedPointer)
	if result == 0 {
		return fmt.Errorf("exchange protected Windows file: %w", callError)
	}
	published, publishedIdentity, err := OpenVerified(ctx, targetPath, false, true, true)
	if err != nil {
		return err
	}
	if publishedIdentity != replacementIdentity {
		_ = published.Close()
		return errors.New("windows atomic exchange published a substituted identity")
	}
	if err := Flush(published); err != nil {
		_ = published.Close()
		return err
	}
	if err := published.Close(); err != nil {
		return err
	}
	displaced, displacedIdentity, err := OpenVerified(ctx, displacedPath, false, true, true)
	if err != nil {
		return err
	}
	if displacedIdentity != targetIdentity {
		_ = displaced.Close()
		return errors.New("windows atomic exchange displaced a substituted identity")
	}
	if err := Flush(displaced); err != nil {
		_ = displaced.Close()
		return err
	}
	if err := displaced.Close(); err != nil {
		return err
	}
	if err := Flush(parent); err != nil {
		return err
	}
	return VerifyPathIdentity(ctx, parentPath, parentIdentity, true)
}

// AtomicPublishNoReplace publishes one protected file only when the final name
// does not already exist.
func AtomicPublishNoReplace(ctx context.Context, replacementPath, targetPath string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := ValidateLocalPath(replacementPath); err != nil {
		return false, err
	}
	if err := ValidateLocalPath(targetPath); err != nil {
		return false, err
	}
	if !strings.EqualFold(filepath.Dir(replacementPath), filepath.Dir(targetPath)) {
		return false, errors.New("windows atomic publication must remain in one directory")
	}
	parentPath := filepath.Dir(targetPath)
	parent, identity, err := OpenVerified(ctx, parentPath, true, true, true)
	if err != nil {
		return false, err
	}
	defer func() { _ = parent.Close() }()
	replacement, replacementIdentity, err := OpenVerified(ctx, replacementPath, false, false, true)
	if err != nil {
		return false, err
	}
	if err := replacement.Close(); err != nil {
		return false, err
	}
	replacementPointer, _ := windows.UTF16PtrFromString(replacementPath)
	targetPointer, _ := windows.UTF16PtrFromString(targetPath)
	err = windows.MoveFileEx(replacementPointer, targetPointer, windows.MOVEFILE_WRITE_THROUGH)
	runtime.KeepAlive(replacementPointer)
	runtime.KeepAlive(targetPointer)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_FILE_EXISTS) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	published, publishedIdentity, err := OpenVerified(ctx, targetPath, false, true, true)
	if err != nil {
		return false, err
	}
	if publishedIdentity != replacementIdentity {
		_ = published.Close()
		return false, errors.New("windows atomic publication published a substituted file identity")
	}
	if err := Flush(published); err != nil {
		_ = published.Close()
		return false, err
	}
	if err := published.Close(); err != nil {
		return false, err
	}
	if err := Flush(parent); err != nil {
		return false, err
	}
	if err := VerifyPathIdentity(ctx, parentPath, identity, true); err != nil {
		return false, err
	}
	return true, nil
}
