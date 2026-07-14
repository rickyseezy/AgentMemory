//go:build windows

package process

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"golang.org/x/sys/windows"
)

const maximumExecutableBytes = int64(512 * 1024 * 1024)

type windowsExecutableAncestor struct {
	path     string
	file     *os.File
	identity string
}

type executableLease struct {
	file         *os.File
	path         string
	identityText string
	owner        string
	digest       [sha256.Size]byte
	ancestors    []windowsExecutableAncestor
	allowMutable bool
}

func acquireExecutableLease(
	ctx context.Context,
	authority argvprocess.ExecutableAuthority,
	allowMutable bool,
) (*executableLease, error) {
	if ctx == nil || ctx.Err() != nil || !authority.Valid() || authority.Platform() != runtime.GOOS ||
		authority.Architecture() != runtime.GOARCH ||
		!strings.HasPrefix(authority.OwnerIdentity(), "sid:") {
		return nil, argvprocess.ErrInvalidInvocation
	}
	expectedSID, err := windows.StringToSid(strings.TrimPrefix(authority.OwnerIdentity(), "sid:"))
	if err != nil || expectedSID == nil || !expectedSID.IsValid() {
		return nil, argvprocess.ErrInvalidInvocation
	}
	lease := &executableLease{
		path: authority.CanonicalPath(), owner: authority.OwnerIdentity(), allowMutable: allowMutable,
	}
	failed := true
	defer func() {
		if failed {
			lease.close()
		}
	}()
	volume := filepath.VolumeName(authority.CanonicalPath())
	rootPath := volume + `\`
	root, identity, err := openWindowsExecutableDirectoryAbsolute(ctx, rootPath)
	if err != nil {
		return nil, err
	}
	lease.ancestors = append(lease.ancestors, windowsExecutableAncestor{
		path: rootPath, file: root, identity: identity,
	})
	relative, err := filepath.Rel(rootPath, authority.CanonicalPath())
	if err != nil {
		return nil, err
	}
	components := strings.Split(relative, `\`)
	if len(components) < 2 {
		return nil, argvprocess.ErrInvalidInvocation
	}
	parent := root
	currentPath := rootPath
	for _, component := range components[:len(components)-1] {
		opened, observed, openError := openWindowsExecutableDirectoryRelative(ctx, parent, component)
		if openError != nil {
			return nil, openError
		}
		currentPath = filepath.Join(currentPath, component)
		lease.ancestors = append(lease.ancestors, windowsExecutableAncestor{
			path: currentPath, file: opened, identity: observed,
		})
		parent = opened
	}
	lease.file, lease.identityText, err = openWindowsExecutableRelative(
		ctx, parent, components[len(components)-1], expectedSID, allowMutable,
	)
	if err != nil {
		return nil, err
	}
	pathInfo, err := os.Lstat(authority.CanonicalPath())
	openedInfo, statError := lease.file.Stat()
	if err != nil || statError != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(pathInfo, openedInfo) {
		return nil, argvprocess.ErrInvalidInvocation
	}
	lease.digest, err = digestWindowsExecutable(lease.file)
	if err != nil || lease.digest != authority.SHA256() {
		return nil, argvprocess.ErrInvalidInvocation
	}
	if err := lease.verify(ctx, authority); err != nil {
		return nil, err
	}
	failed = false
	return lease, nil
}

func openWindowsExecutableDirectoryAbsolute(ctx context.Context, path string) (*os.File, string, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, "", err
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
		return nil, "", err
	}
	return windowsExecutableDirectoryFile(ctx, handle, filepath.Base(path))
}

func openWindowsExecutableDirectoryRelative(
	ctx context.Context,
	parent *os.File,
	name string,
) (*os.File, string, error) {
	if parent == nil || filepath.Base(name) != name || name == "." || name == ".." || strings.ContainsAny(name, `/\:`) {
		return nil, "", argvprocess.ErrInvalidInvocation
	}
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, "", err
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
		windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
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
		return nil, "", err
	}
	return windowsExecutableDirectoryFile(ctx, handle, name)
}

func windowsExecutableDirectoryFile(
	ctx context.Context,
	handle windows.Handle,
	name string,
) (*os.File, string, error) {
	identity, err := windowsExecutableIdentity(handle, true)
	if err != nil || ctx.Err() != nil {
		_ = windows.CloseHandle(handle)
		return nil, "", errors.Join(err, ctx.Err())
	}
	file := os.NewFile(uintptr(handle), name)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, "", os.ErrInvalid
	}
	return file, identity, nil
}

func openWindowsExecutableRelative(
	ctx context.Context,
	parent *os.File,
	name string,
	expectedSID *windows.SID,
	allowMutable bool,
) (*os.File, string, error) {
	if parent == nil || filepath.Base(name) != name || name == "." || name == ".." || strings.ContainsAny(name, `/\:`) {
		return nil, "", argvprocess.ErrInvalidInvocation
	}
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, "", err
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
		windows.FILE_GENERIC_READ|windows.READ_CONTROL,
		attributes,
		&status,
		nil,
		0,
		windows.FILE_SHARE_READ,
		windows.FILE_OPEN,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0,
	)
	runtime.KeepAlive(objectName)
	if err != nil {
		return nil, "", err
	}
	identity, err := windowsExecutableIdentity(handle, false)
	if err != nil || verifyWindowsExecutableSecurity(handle, expectedSID, allowMutable) != nil || ctx.Err() != nil {
		_ = windows.CloseHandle(handle)
		return nil, "", argvprocess.ErrInvalidInvocation
	}
	file := os.NewFile(uintptr(handle), name)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, "", os.ErrInvalid
	}
	return file, identity, nil
}

func windowsExecutableIdentity(handle windows.Handle, wantDirectory bool) (string, error) {
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return "", err
	}
	directory := information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if directory != wantDirectory || information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		information.FileAttributes&windows.FILE_ATTRIBUTE_DEVICE != 0 || !directory && information.NumberOfLinks != 1 {
		return "", argvprocess.ErrInvalidInvocation
	}
	fileIndex := uint64(information.FileIndexHigh)<<32 | uint64(information.FileIndexLow)
	if directory {
		// A retained directory object's security identity is its volume and file
		// index. Directory size and last-write time are mutable bookkeeping: a
		// sibling process creating an unrelated child legitimately changes them.
		// Including either would turn safe parallel activity into a false
		// executable-substitution finding. The retained no-delete-share handle and
		// the path SameFile check below protect name ownership independently.
		return fmt.Sprintf("windows-dir:%d:%d", information.VolumeSerialNumber, fileIndex), nil
	}
	return fmt.Sprintf(
		"windows-file:%d:%d:%d:%d",
		information.VolumeSerialNumber,
		fileIndex,
		uint64(information.FileSizeHigh)<<32|uint64(information.FileSizeLow),
		uint64(information.LastWriteTime.HighDateTime)<<32|uint64(information.LastWriteTime.LowDateTime),
	), nil
}

func verifyWindowsExecutableSecurity(handle windows.Handle, expectedSID *windows.SID, allowMutable bool) error {
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil {
		return argvprocess.ErrInvalidInvocation
	}
	owner, defaulted, err := descriptor.Owner()
	if err != nil || owner == nil || defaulted || !owner.Equals(expectedSID) {
		return argvprocess.ErrInvalidInvocation
	}
	if allowMutable {
		return nil
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return argvprocess.ErrInvalidInvocation
	}
	dangerous := windows.ACCESS_MASK(
		windows.GENERIC_WRITE | windows.GENERIC_ALL | windows.WRITE_DAC | windows.WRITE_OWNER |
			windows.DELETE | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA |
			windows.FILE_WRITE_ATTRIBUTES | windows.FILE_WRITE_EA,
	)
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil {
			return argvprocess.ErrInvalidInvocation
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		// Object/callback/conditional allow ACEs have different layouts and may
		// grant write authority through fields this parser cannot safely prove.
		// Reject every non-basic allow form instead of silently skipping it.
		if !supportedWindowsExecutableDACLType(ace.Header.AceType) {
			return argvprocess.ErrInvalidInvocation
		}
		if ace.Mask&dangerous == 0 {
			continue
		}
		//nolint:gosec // G103: GetAce exposes the documented variable-length SID boundary.
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || !trustedWindowsExecutableWriter(sid, expectedSID) {
			return argvprocess.ErrInvalidInvocation
		}
	}
	return nil
}

func supportedWindowsExecutableDACLType(aceType uint8) bool {
	return aceType == windows.ACCESS_ALLOWED_ACE_TYPE || aceType == windows.ACCESS_DENIED_ACE_TYPE
}

func trustedWindowsExecutableWriter(candidate, owner *windows.SID) bool {
	if candidate.Equals(owner) {
		return true
	}
	for _, value := range []string{"S-1-5-18", "S-1-5-32-544"} {
		trusted, err := windows.StringToSid(value)
		if err == nil && candidate.Equals(trusted) {
			return true
		}
	}
	return false
}

func digestWindowsExecutable(file *os.File) ([sha256.Size]byte, error) {
	if file == nil {
		return [sha256.Size]byte{}, os.ErrInvalid
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return [sha256.Size]byte{}, err
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, maximumExecutableBytes+1))
	if err != nil || written <= 0 || written > maximumExecutableBytes {
		return [sha256.Size]byte{}, argvprocess.ErrInvalidInvocation
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return [sha256.Size]byte{}, err
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

func (l *executableLease) verify(ctx context.Context, authority argvprocess.ExecutableAuthority) error {
	if l == nil || l.file == nil || ctx == nil || ctx.Err() != nil || l.path != authority.CanonicalPath() ||
		l.owner != authority.OwnerIdentity() || l.digest != authority.SHA256() {
		return argvprocess.ErrInvalidInvocation
	}
	for _, ancestor := range l.ancestors {
		if ancestor.file == nil {
			return argvprocess.ErrInvalidInvocation
		}
		identity, err := windowsExecutableIdentity(windows.Handle(ancestor.file.Fd()), true)
		pathInfo, pathError := os.Lstat(ancestor.path)
		openedInfo, statError := ancestor.file.Stat()
		if err != nil || pathError != nil || statError != nil || identity != ancestor.identity ||
			pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(pathInfo, openedInfo) {
			return argvprocess.ErrInvalidInvocation
		}
	}
	expectedSID, err := windows.StringToSid(strings.TrimPrefix(authority.OwnerIdentity(), "sid:"))
	if err != nil || verifyWindowsExecutableSecurity(windows.Handle(l.file.Fd()), expectedSID, l.allowMutable) != nil {
		return argvprocess.ErrInvalidInvocation
	}
	identity, err := windowsExecutableIdentity(windows.Handle(l.file.Fd()), false)
	pathInfo, pathError := os.Lstat(l.path)
	openedInfo, statError := l.file.Stat()
	if err != nil || pathError != nil || statError != nil || identity != l.identityText ||
		pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(pathInfo, openedInfo) {
		return argvprocess.ErrInvalidInvocation
	}
	digest, err := digestWindowsExecutable(l.file)
	if err != nil || digest != l.digest {
		return argvprocess.ErrInvalidInvocation
	}
	return nil
}

func (l *executableLease) evidence(authority argvprocess.ExecutableAuthority) ExecutableEvidence {
	return ExecutableEvidence{
		CanonicalID: authority.CanonicalID(), FileIdentity: l.identityText, Digest: l.digest, OwnerIdentity: l.owner,
		ReleaseManifestDigest: authority.ReleaseManifestDigest(),
		RuntimePlanDigest:     authority.RuntimePlanDigest(), Role: authority.Role(),
		retainedHandle: l.file.Fd(),
	}
}

func (l *executableLease) command(ctx context.Context, arguments []string) (*exec.Cmd, error) {
	if l == nil || l.file == nil {
		return nil, os.ErrInvalid
	}
	return exec.CommandContext(ctx, l.path, arguments...), nil // #nosec G204 -- path is locked against write/delete and identity-bound.
}

func (l *executableLease) trustedWorkingDirectory() string {
	return filepath.VolumeName(l.path) + `\`
}

func (l *executableLease) close() {
	if l == nil {
		return
	}
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
	for index := len(l.ancestors) - 1; index >= 0; index-- {
		if l.ancestors[index].file != nil {
			_ = l.ancestors[index].file.Close()
			l.ancestors[index].file = nil
		}
	}
}
