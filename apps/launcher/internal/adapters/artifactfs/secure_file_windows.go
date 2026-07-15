//go:build windows

package artifactfs

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"golang.org/x/sys/windows"
)

const storeIdentityLeaf = ".agentmemory-store-identity"

const forbiddenWindowsFileAttributes = windows.FILE_ATTRIBUTE_DIRECTORY |
	windows.FILE_ATTRIBUTE_DEVICE |
	windows.FILE_ATTRIBUTE_REPARSE_POINT |
	windows.FILE_ATTRIBUTE_SPARSE_FILE |
	windows.FILE_ATTRIBUTE_COMPRESSED |
	windows.FILE_ATTRIBUTE_OFFLINE |
	windows.FILE_ATTRIBUTE_ENCRYPTED |
	windows.FILE_ATTRIBUTE_INTEGRITY_STREAM |
	windows.FILE_ATTRIBUTE_VIRTUAL |
	windows.FILE_ATTRIBUTE_RECALL_ON_OPEN |
	windows.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS

var reopenFileW = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReOpenFile")

type secureFile struct {
	file         *os.File
	directory    *os.File
	leaf         string
	bundlePolicy bundleAccessPolicy
}

type windowsFileDispositionInfo struct {
	deleteFile byte
}

func (f *secureFile) close() {
	if f == nil {
		return
	}
	if f.file != nil {
		_ = f.file.Close()
		f.file = nil
	}
	if f.directory != nil {
		_ = f.directory.Close()
		f.directory = nil
	}
}

func windowsArtifactContext() context.Context { return context.Background() }

//nolint:contextcheck,nolintlint // A directory identity/DACL proof is atomic and deliberately cannot be interrupted by request cancellation.
func openSecureDirectory(path string) (*os.File, error) {
	ctx := windowsArtifactContext()
	if path == "" || filepath.Clean(path) != path || windowssecurity.ValidateLocalPath(path) != nil {
		return nil, artifactapp.ErrStoreIntegrity
	}
	guard, err := windowssecurity.AcquireDirectoryPathGuard(ctx, path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = guard.Close() }()
	opened, _, err := windowssecurity.OpenVerified(ctx, path, true, true, true)
	if err != nil {
		return nil, err
	}
	directory, err := relabelWindowsFile(opened, path)
	if err != nil {
		return nil, err
	}
	if err := guard.Verify(ctx); err != nil || !safeDirectoryDescriptor(directory) {
		_ = directory.Close()
		return nil, artifactapp.ErrStoreIntegrity
	}
	return directory, nil
}

func captureDirectoryIdentity(path string) (string, error) {
	directory, err := openSecureDirectory(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = directory.Close() }()
	identity, err := windowssecurity.VerifyOpened(windowsArtifactContext(), directory, true, true)
	if err != nil {
		return "", artifactapp.ErrStoreIntegrity
	}
	return windowsIdentityString(identity), nil
}

func openStoreIdentity(root *os.File) (*secureFile, [32]byte, error) {
	var identity [32]byte
	opened, _, err := openSecureLeafAt(root, storeIdentityLeaf, false)
	if err == nil {
		return readStoreIdentity(opened)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, identity, err
	}
	if _, err := rand.Read(identity[:]); err != nil {
		return nil, [32]byte{}, artifactapp.ErrStoreOperation
	}
	tempLeaf := fmt.Sprintf("%s.tmp-%x", storeIdentityLeaf, identity[:16])
	temporary, created, err := openSecureLeafAt(root, tempLeaf, true)
	if err != nil || !created {
		if temporary != nil {
			temporary.close()
		}
		return nil, [32]byte{}, artifactapp.ErrStoreOperation
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = removeOpenSecureFile(temporary)
		}
		temporary.close()
	}()
	written, writeError := temporary.file.WriteAt(identity[:], 0)
	if writeError != nil || written != len(identity) || durableSync(temporary.file) != nil ||
		temporary.verifyExactSize(uint64(len(identity))) != nil {
		return nil, [32]byte{}, artifactapp.ErrStoreOperation
	}
	if err := renameSecureNoReplace(temporary, root, storeIdentityLeaf); err != nil {
		if !windowsAlreadyExists(err) {
			return nil, [32]byte{}, artifactapp.ErrStoreOperation
		}
		if removeError := removeOpenSecureFile(temporary); removeError != nil {
			return nil, [32]byte{}, artifactapp.ErrStoreOperation
		}
		removeTemporary = false
		winner, _, openError := openSecureLeafAt(root, storeIdentityLeaf, false)
		if openError != nil {
			return nil, [32]byte{}, artifactapp.ErrStoreIntegrity
		}
		return readStoreIdentity(winner)
	}
	removeTemporary = false
	if durableSync(root) != nil {
		return nil, [32]byte{}, artifactapp.ErrStoreOperation
	}
	published, _, openError := openSecureLeafAt(root, storeIdentityLeaf, false)
	if openError != nil {
		return nil, [32]byte{}, artifactapp.ErrStoreIntegrity
	}
	return readStoreIdentity(published)
}

func readStoreIdentity(opened *secureFile) (*secureFile, [32]byte, error) {
	var identity [32]byte
	if opened == nil || opened.verifyExactSize(uint64(len(identity))) != nil {
		if opened != nil {
			opened.close()
		}
		return nil, [32]byte{}, artifactapp.ErrStoreIntegrity
	}
	read, readError := opened.file.ReadAt(identity[:], 0)
	if readError != nil || read != len(identity) || !validStoreIdentity(opened, identity) {
		opened.close()
		return nil, [32]byte{}, artifactapp.ErrStoreIntegrity
	}
	return opened, identity, nil
}

func validStoreIdentity(opened *secureFile, expected [32]byte) bool {
	if opened == nil || expected == [32]byte{} || opened.verifyExactSize(uint64(len(expected))) != nil {
		return false
	}
	var observed [32]byte
	read, err := opened.file.ReadAt(observed[:], 0)
	return err == nil && read == len(observed) && observed == expected
}

func boundFilesystemIdentity(filesystemID string, root *os.File, identity [32]byte) (string, error) {
	if filesystemID == "" || identity == [32]byte{} || !safeDirectoryDescriptor(root) {
		return "", artifactapp.ErrStoreIntegrity
	}
	rootIdentity, err := windowssecurity.VerifyOpened(windowsArtifactContext(), root, true, true)
	if err != nil {
		return "", artifactapp.ErrStoreIntegrity
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf(
		"agentmemory-artifact-root-v2\x00%s\x00%x", windowsIdentityString(rootIdentity), identity,
	)))
	return fmt.Sprintf("fs-%x", digest), nil
}

func directoryIdentityMatches(path, expected string) bool {
	if expected == "" {
		return false
	}
	identity, err := captureDirectoryIdentity(path)
	return err == nil && identity == expected
}

func openSecureLeaf(directoryPath, leaf string, create bool) (*secureFile, bool, error) {
	if !safeLeaf(leaf) {
		return nil, false, artifactapp.ErrStoreIntegrity
	}
	directory, err := openSecureDirectory(directoryPath)
	if err != nil {
		return nil, false, err
	}
	result, created, openError := openSecureLeafAt(directory, leaf, create)
	_ = directory.Close()
	return result, created, openError
}

func duplicateSecureDirectory(directory *os.File) (*os.File, error) {
	if !safeDirectoryDescriptor(directory) {
		return nil, artifactapp.ErrStoreIntegrity
	}
	var duplicate windows.Handle
	process := windows.CurrentProcess()
	if err := windows.DuplicateHandle(
		process, windows.Handle(directory.Fd()), process, &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS,
	); err != nil {
		return nil, err
	}
	result := os.NewFile(uintptr(duplicate), directory.Name())
	if result == nil {
		_ = windows.CloseHandle(duplicate)
		return nil, artifactapp.ErrStoreIntegrity
	}
	if !safeDirectoryDescriptor(result) {
		_ = result.Close()
		return nil, artifactapp.ErrStoreIntegrity
	}
	return result, nil
}

//nolint:contextcheck,nolintlint // Integrity proofs deliberately use a non-cancelable local context so cancellation cannot leave a partial DACL/path proof.
func safeDirectoryDescriptor(directory *os.File) bool {
	if directory == nil || directory.Name() == "" || filepath.Clean(directory.Name()) != directory.Name() {
		return false
	}
	ctx := windowsArtifactContext()
	identity, err := windowssecurity.VerifyOpened(ctx, directory, true, true)
	if err != nil {
		return false
	}
	guard, err := windowssecurity.AcquireDirectoryPathGuard(ctx, directory.Name())
	if err != nil {
		return false
	}
	defer func() { _ = guard.Close() }()
	pathFile, pathIdentity, err := windowssecurity.OpenVerified(ctx, directory.Name(), true, false, true)
	if err != nil {
		return false
	}
	closeError := pathFile.Close()
	return closeError == nil && pathIdentity == identity && guard.Verify(ctx) == nil
}

func openSecureLeafAt(directory *os.File, leaf string, create bool) (*secureFile, bool, error) {
	return openWindowsSecureLeafAt(directory, leaf, create, true)
}

func openSecureReadLeafAt(directory *os.File, leaf string) (*secureFile, error) {
	opened, _, err := openWindowsSecureLeafAt(directory, leaf, false, false)
	return opened, err
}

//nolint:contextcheck,nolintlint // Opening and proving a protected leaf is one non-cancelable local integrity transaction.
func openWindowsSecureLeafAt(
	directory *os.File,
	leaf string,
	create bool,
	writable bool,
) (*secureFile, bool, error) {
	if !safeLeaf(leaf) || !safeDirectoryDescriptor(directory) {
		return nil, false, artifactapp.ErrStoreIntegrity
	}
	ownedDirectory, err := duplicateSecureDirectory(directory)
	if err != nil {
		return nil, false, err
	}
	ctx := windowsArtifactContext()
	guard, err := windowssecurity.AcquireDirectoryPathGuard(ctx, directory.Name())
	if err != nil {
		_ = ownedDirectory.Close()
		return nil, false, err
	}
	defer func() { _ = guard.Close() }()
	targetPath := filepath.Join(directory.Name(), leaf)
	var file *os.File
	created := false
	if create {
		file, err = windowssecurity.CreatePrivateFile(ctx, targetPath)
		created = err == nil
		if created {
			createdIdentity, verifyError := windowssecurity.VerifyOpened(ctx, file, false, true)
			closeError := file.Close()
			if verifyError != nil || closeError != nil {
				_ = os.Remove(targetPath)
				_ = ownedDirectory.Close()
				return nil, false, artifactapp.ErrStoreIntegrity
			}
			file, err = openWindowsPrivateFile(ctx, targetPath, writable)
			if err == nil {
				reopenedIdentity, identityError := windowssecurity.VerifyOpened(ctx, file, false, true)
				if identityError != nil || reopenedIdentity != createdIdentity {
					_ = file.Close()
					file = nil
					err = artifactapp.ErrStoreIntegrity
				}
			}
		}
		if err != nil && windowsAlreadyExists(err) {
			file, err = openWindowsPrivateFile(ctx, targetPath, writable)
		}
	} else {
		file, err = openWindowsPrivateFile(ctx, targetPath, writable)
	}
	if err != nil {
		if created {
			_ = os.Remove(targetPath)
			_ = durableSync(ownedDirectory)
		}
		_ = ownedDirectory.Close()
		return nil, false, err
	}
	result := &secureFile{file: file, directory: ownedDirectory, leaf: leaf}
	if err := guard.Verify(ctx); err != nil || result.verifyPathIdentity() != nil {
		if created {
			if mutation, mutationError := reopenWindowsMutationFile(file); mutationError == nil {
				_ = deleteWindowsOpenFile(mutation)
				_ = mutation.Close()
			}
		}
		result.close()
		return nil, false, artifactapp.ErrStoreIntegrity
	}
	return result, created, nil
}

//nolint:contextcheck,nolintlint // Directory creation plus path/handle/DACL proof must not stop at a cancellation boundary.
func openSecureChildDirectoryAt(parent *os.File, leaf string, create bool) (*os.File, error) {
	if !safeLeaf(leaf) || !safeDirectoryDescriptor(parent) {
		return nil, artifactapp.ErrStoreIntegrity
	}
	ctx := windowsArtifactContext()
	guard, err := windowssecurity.AcquireDirectoryPathGuard(ctx, parent.Name())
	if err != nil {
		return nil, err
	}
	defer func() { _ = guard.Close() }()
	childPath := filepath.Join(parent.Name(), leaf)
	if create {
		if _, _, err := windowssecurity.EnsurePrivateDirectoryTree(ctx, parent.Name(), childPath); err != nil {
			return nil, err
		}
	}
	opened, _, err := windowssecurity.OpenVerified(ctx, childPath, true, true, true)
	if err != nil {
		return nil, err
	}
	child, err := relabelWindowsFile(opened, childPath)
	if err != nil {
		return nil, err
	}
	if err := guard.Verify(ctx); err != nil || !secureChildDirectoryIdentity(parent, leaf, child) {
		_ = child.Close()
		return nil, artifactapp.ErrStoreIntegrity
	}
	return child, nil
}

//nolint:contextcheck,nolintlint // Parent/child identity comparison must finish as one non-cancelable local security proof.
func secureChildDirectoryIdentity(parent *os.File, leaf string, child *os.File) bool {
	if !safeLeaf(leaf) || !safeDirectoryDescriptor(parent) || !safeDirectoryDescriptor(child) ||
		!strings.EqualFold(filepath.Join(parent.Name(), leaf), child.Name()) {
		return false
	}
	ctx := windowsArtifactContext()
	parentIdentity, parentError := windowssecurity.VerifyOpened(ctx, parent, true, true)
	childIdentity, childError := windowssecurity.VerifyOpened(ctx, child, true, true)
	if parentError != nil || childError != nil || parentIdentity.VolumeSerial != childIdentity.VolumeSerial {
		return false
	}
	pathFile, pathIdentity, err := windowssecurity.OpenVerified(ctx, filepath.Join(parent.Name(), leaf), true, false, true)
	if err != nil {
		return false
	}
	closeError := pathFile.Close()
	return closeError == nil && pathIdentity == childIdentity
}

//nolint:contextcheck,nolintlint // Path/handle identity and DACL verification must complete atomically even when a request is canceled.
func (f *secureFile) verifyPathIdentity() error {
	if f == nil || f.file == nil || f.directory == nil || !safeLeaf(f.leaf) ||
		!safeBundleDirectoryDescriptor(f.directory, f.bundlePolicy) {
		return artifactapp.ErrStoreIntegrity
	}
	ctx := windowsArtifactContext()
	var descriptorIdentity windowssecurity.FileIdentity
	var err error
	if f.bundlePolicy == bundleAccessInstalledReadOnly {
		descriptorIdentity, err = windowssecurity.VerifyInstalledReadOnlyOpened(ctx, f.file, false)
	} else {
		descriptorIdentity, err = windowssecurity.VerifyOpened(ctx, f.file, false, true)
	}
	if err != nil || !windowsSafeRegularFile(f.file) {
		return artifactapp.ErrStoreIntegrity
	}
	targetPath := filepath.Join(f.directory.Name(), f.leaf)
	guard, err := windowssecurity.AcquireDirectoryPathGuard(ctx, f.directory.Name())
	if err != nil {
		return artifactapp.ErrStoreIntegrity
	}
	defer func() { _ = guard.Close() }()
	var pathFile *os.File
	var pathIdentity windowssecurity.FileIdentity
	if f.bundlePolicy == bundleAccessInstalledReadOnly {
		pathFile, pathIdentity, err = windowssecurity.OpenInstalledReadOnly(ctx, targetPath, false)
	} else {
		pathFile, pathIdentity, err = windowssecurity.OpenVerified(ctx, targetPath, false, false, true)
	}
	if err != nil {
		return err
	}
	pathSafe := windowsSafeRegularFile(pathFile)
	closeError := pathFile.Close()
	if closeError != nil || !pathSafe || pathIdentity != descriptorIdentity || guard.Verify(ctx) != nil {
		return artifactapp.ErrStoreIntegrity
	}
	return nil
}

func (f *secureFile) verifyExactSize(size uint64) error {
	if err := f.verifyPathIdentity(); err != nil {
		return err
	}
	info, err := f.file.Stat()
	if err != nil || !safeFileInfo(info, size) {
		return artifactapp.ErrStoreIntegrity
	}
	return nil
}

func (f *secureFile) syncDirectory() error {
	if f == nil || f.directory == nil || !safeDirectoryDescriptor(f.directory) {
		return artifactapp.ErrStoreOperation
	}
	return durableSync(f.directory)
}

func removeSecureLeaf(directoryPath, leaf string, expectedSize uint64) error {
	opened, _, err := openSecureLeaf(directoryPath, leaf, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return artifactapp.ErrStoreIntegrity
	}
	defer opened.close()
	if err := opened.verifyExactSize(expectedSize); err != nil {
		return err
	}
	return removeOpenSecureFile(opened)
}

func removeSecureLeafAt(directory *os.File, leaf string, expectedSize uint64) error {
	opened, _, err := openSecureLeafAt(directory, leaf, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return artifactapp.ErrStoreIntegrity
	}
	defer opened.close()
	if err := opened.verifyExactSize(expectedSize); err != nil {
		return err
	}
	return removeOpenSecureFile(opened)
}

func removeSecureLeafAtMost(directoryPath, leaf string, maximumSize uint64) error {
	opened, _, err := openSecureLeaf(directoryPath, leaf, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return artifactapp.ErrStoreIntegrity
	}
	defer opened.close()
	info, statError := opened.file.Stat()
	observed, valid := nonNegativeInt64(infoSize(info, statError))
	if statError != nil || !valid || observed > maximumSize || opened.verifyExactSize(observed) != nil {
		return artifactapp.ErrStoreIntegrity
	}
	return removeOpenSecureFile(opened)
}

func removeSecureLeafAtMostAt(directory *os.File, leaf string, maximumSize uint64) error {
	opened, _, err := openSecureLeafAt(directory, leaf, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return artifactapp.ErrStoreIntegrity
	}
	defer opened.close()
	info, statError := opened.file.Stat()
	observed, valid := nonNegativeInt64(infoSize(info, statError))
	if statError != nil || !valid || observed > maximumSize || opened.verifyExactSize(observed) != nil {
		return artifactapp.ErrStoreIntegrity
	}
	return removeOpenSecureFile(opened)
}

func removeOpenSecureFile(opened *secureFile) error {
	if opened == nil || opened.file == nil || opened.verifyPathIdentity() != nil {
		return artifactapp.ErrStoreIntegrity
	}
	path := filepath.Join(opened.directory.Name(), opened.leaf)
	mutation, err := reopenWindowsMutationFile(opened.file)
	if err != nil {
		return artifactapp.ErrStoreOperation
	}
	if err := deleteWindowsOpenFile(mutation); err != nil {
		_ = mutation.Close()
		return artifactapp.ErrStoreOperation
	}
	if err := mutation.Close(); err != nil {
		return artifactapp.ErrStoreOperation
	}
	if err := opened.file.Close(); err != nil {
		return artifactapp.ErrStoreOperation
	}
	opened.file = nil
	if err := opened.syncDirectory(); err != nil {
		return artifactapp.ErrStoreOperation
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return artifactapp.ErrStoreOperation
	}
	return nil
}

func deleteWindowsOpenFile(file *os.File) error {
	if file == nil {
		return os.ErrInvalid
	}
	information := windowsFileDispositionInfo{deleteFile: 1}
	return windows.SetFileInformationByHandle(
		windows.Handle(file.Fd()), windows.FileDispositionInfo,
		//nolint:gosec // G103: SetFileInformationByHandle synchronously reads the reviewed fixed-size FILE_DISPOSITION_INFO layout; owner=security expiry=2027-07-14.
		(*byte)(unsafe.Pointer(&information)), uint32(unsafe.Sizeof(information)),
	)
}

func openWindowsPrivateFile(ctx context.Context, path string, writable bool) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if windowssecurity.ValidateLocalPath(path) != nil || filepath.Clean(path) != path {
		return nil, artifactapp.ErrStoreIntegrity
	}
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	access := uint32(windows.GENERIC_READ | windows.READ_CONTROL | windows.SYNCHRONIZE)
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if writable {
		access |= windows.GENERIC_WRITE | windows.WRITE_DAC
		flags |= windows.FILE_FLAG_WRITE_THROUGH
	}
	handle, err := windows.CreateFile(
		pointer, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, flags, 0,
	)
	runtime.KeepAlive(pointer)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), filepath.Base(path))
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, artifactapp.ErrStoreIntegrity
	}
	if _, err := windowssecurity.VerifyOpened(ctx, file, false, true); err != nil || !windowsSafeRegularFile(file) {
		_ = file.Close()
		return nil, artifactapp.ErrStoreIntegrity
	}
	return file, nil
}

//nolint:contextcheck,nolintlint // Cleanup and publication mutation handles must finish identity proof even after request cancellation.
func reopenWindowsMutationFile(file *os.File) (*os.File, error) {
	if file == nil {
		return nil, os.ErrInvalid
	}
	originalIdentity, err := windowssecurity.VerifyOpened(windowsArtifactContext(), file, false, true)
	if err != nil {
		return nil, artifactapp.ErrStoreIntegrity
	}
	handleValue, _, callError := reopenFileW.Call(
		file.Fd(),
		uintptr(windows.DELETE|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE),
		uintptr(windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE),
		uintptr(windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_WRITE_THROUGH),
	)
	if windows.Handle(handleValue) == windows.InvalidHandle {
		return nil, callError
	}
	mutation := os.NewFile(handleValue, file.Name()+".mutation")
	if mutation == nil {
		_ = windows.CloseHandle(windows.Handle(handleValue))
		return nil, artifactapp.ErrStoreIntegrity
	}
	mutationIdentity, err := windowssecurity.VerifyOpened(windowsArtifactContext(), mutation, false, true)
	if err != nil || mutationIdentity != originalIdentity || !windowsSafeRegularFile(mutation) {
		_ = mutation.Close()
		return nil, artifactapp.ErrStoreIntegrity
	}
	return mutation, nil
}

func windowsSafeRegularFile(file *os.File) bool {
	if file == nil {
		return false
	}
	var information windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &information) != nil {
		return false
	}
	return information.FileAttributes&forbiddenWindowsFileAttributes == 0 && information.NumberOfLinks == 1
}

func relabelWindowsFile(file *os.File, name string) (*os.File, error) {
	if file == nil {
		return nil, os.ErrInvalid
	}
	var duplicate windows.Handle
	process := windows.CurrentProcess()
	if err := windows.DuplicateHandle(
		process, windows.Handle(file.Fd()), process, &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS,
	); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		_ = windows.CloseHandle(duplicate)
		return nil, err
	}
	result := os.NewFile(uintptr(duplicate), name)
	if result == nil {
		_ = windows.CloseHandle(duplicate)
		return nil, artifactapp.ErrStoreIntegrity
	}
	return result, nil
}

func windowsIdentityString(identity windowssecurity.FileIdentity) string {
	return fmt.Sprintf("%08x:%016x", identity.VolumeSerial, identity.FileIndex)
}

func windowsAlreadyExists(err error) bool {
	return errors.Is(err, os.ErrExist) || errors.Is(err, windows.ERROR_FILE_EXISTS) ||
		errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) ||
		errors.Is(err, windows.STATUS_OBJECT_NAME_EXISTS)
}

func safeLeaf(value string) bool {
	if value == "" || value == "." || value == ".." || filepath.Base(value) != value ||
		strings.ContainsAny(value, `<>:"/\|?*`) || strings.HasSuffix(value, ".") || strings.HasSuffix(value, " ") {
		return false
	}
	units, err := syscall.UTF16FromString(value)
	if err != nil || len(units) <= 1 || len(units)-1 > 255 {
		return false
	}
	for _, character := range value {
		if character < 32 {
			return false
		}
	}
	stem := strings.ToUpper(strings.SplitN(value, ".", 2)[0])
	if stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" ||
		len(stem) == 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) &&
			stem[3] >= '1' && stem[3] <= '9' {
		return false
	}
	return true
}

func safeDirectoryInfo(info os.FileInfo) bool {
	return info != nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
}

func isNotDirectoryError(err error) bool {
	return errors.Is(err, windows.ERROR_DIRECTORY)
}
