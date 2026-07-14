//go:build windows

package runtimeprovision

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"golang.org/x/sys/windows"
)

const (
	windowsSEEMaskNoCloseProcess = uint32(0x00000040)
	windowsSEEMaskNoAsync        = uint32(0x00000100)
	windowsSWNormal              = int32(1)
	errWindowsUACCancelled       = windows.Errno(1223)
)

var (
	desktopShell32         = windows.NewLazySystemDLL("shell32.dll")
	desktopShellExecuteExW = desktopShell32.NewProc("ShellExecuteExW")
)

type desktopShellExecuteInfo struct {
	Size       uint32
	Mask       uint32
	Window     windows.HWND
	Verb       *uint16
	File       *uint16
	Parameters *uint16
	Directory  *uint16
	Show       int32
	Instance   windows.Handle
	IDList     unsafe.Pointer
	Class      *uint16
	ClassKey   windows.Handle
	HotKey     uint32
	Icon       windows.Handle
	Process    windows.Handle
}

func createNativeDesktopMutationExchange(
	ctx context.Context,
	helper runtimeport.DesktopHelperAuthority,
	request runtimeport.DesktopMutationRequest,
) (nativeDesktopMutationExchange, error) {
	if ctx == nil || ctx.Err() != nil || helper.Platform() != runtimeinstall.PlatformWindows {
		return nativeDesktopMutationExchange{}, runtimeport.ErrDesktopMutationIntegrity
	}
	directory, _, err := windowssecurity.OpenVerified(ctx, helper.ExchangeDirectory(), true, false, true)
	if err != nil {
		return nativeDesktopMutationExchange{}, runtimeport.ErrDesktopMutationIntegrity
	}
	_ = directory.Close()
	base := "request-" + request.Digest().String()
	requestPath := filepath.Join(helper.ExchangeDirectory(), base+".json")
	receiptPath := filepath.Join(helper.ExchangeDirectory(), base+".receipt.json")
	_ = os.Remove(requestPath)
	_ = os.Remove(receiptPath)
	file, err := windowssecurity.CreatePrivateFile(ctx, requestPath)
	if err != nil {
		return nativeDesktopMutationExchange{}, err
	}
	contents := request.CanonicalBytes()
	written, writeError := file.Write(contents)
	syncError := file.Sync()
	closeError := file.Close()
	if writeError != nil || written != len(contents) || syncError != nil || closeError != nil {
		_ = os.Remove(requestPath)
		return nativeDesktopMutationExchange{}, runtimeport.ErrDesktopMutationIntegrity
	}
	return nativeDesktopMutationExchange{
		requestPath: requestPath, receiptPath: receiptPath, read: readWindowsMutationReceipt,
		remove: func(path string) error {
			if !strings.EqualFold(filepath.Dir(path), helper.ExchangeDirectory()) {
				return runtimeport.ErrDesktopMutationIntegrity
			}
			return os.Remove(path)
		},
	}, nil
}

func readWindowsMutationReceipt(ctx context.Context, path string) ([]byte, error) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		file, _, err := windowssecurity.OpenVerifiedLockedRead(ctx, path, false)
		if err == nil {
			info, statError := file.Stat()
			if statError != nil || info.Size() <= 0 || info.Size() > 64*1024 {
				_ = file.Close()
				return nil, runtimeport.ErrDesktopMutationIntegrity
			}
			contents, readError := io.ReadAll(io.LimitReader(file, 64*1024+1))
			closeError := file.Close()
			if readError != nil || closeError != nil || len(contents) == 0 || len(contents) > 64*1024 {
				return nil, runtimeport.ErrDesktopMutationIntegrity
			}
			return contents, nil
		}
		if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func executeNativeDesktopHelper(
	ctx context.Context,
	helper runtimeport.DesktopHelperAuthority,
	requestPath string,
) error {
	if ctx == nil || ctx.Err() != nil || helper.Platform() != runtimeinstall.PlatformWindows ||
		!strings.EqualFold(filepath.Dir(requestPath), helper.ExchangeDirectory()) {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	retained, err := retainWindowsMutationHelper(ctx, helper)
	if err != nil {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	defer func() { _ = retained.Close() }()
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(helper.CanonicalPath())
	parameters, _ := windows.UTF16PtrFromString(
		"--execute-desktop-mutation " + windows.EscapeArg(requestPath),
	)
	directory, _ := windows.UTF16PtrFromString(filepath.Dir(helper.CanonicalPath()))
	if verb == nil || file == nil || parameters == nil || directory == nil {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	information := desktopShellExecuteInfo{
		Size: uint32(unsafe.Sizeof(desktopShellExecuteInfo{})),
		Mask: windowsSEEMaskNoCloseProcess | windowsSEEMaskNoAsync,
		Verb: verb, File: file, Parameters: parameters, Directory: directory, Show: windowsSWNormal,
	}
	result, _, callError := desktopShellExecuteExW.Call(uintptr(unsafe.Pointer(&information))) // #nosec G103 -- exact ShellExecuteExW ABI structure.
	runtimeKeepAliveDesktopShell(&information, verb, file, parameters, directory)
	if result == 0 {
		if errors.Is(callError, errWindowsUACCancelled) {
			return runtimeport.ErrDesktopMutationDenied
		}
		return runtimeport.ErrDesktopMutationPolicy
	}
	if information.Process == 0 {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	defer func() { _ = windows.CloseHandle(information.Process) }()
	for {
		wait, err := windows.WaitForSingleObject(information.Process, 100)
		if err != nil {
			return runtimeport.ErrDesktopMutationIntegrity
		}
		switch wait {
		case windows.WAIT_OBJECT_0:
			var exitCode uint32
			if windows.GetExitCodeProcess(information.Process, &exitCode) != nil || exitCode != 0 {
				return runtimeport.ErrDesktopMutationIntegrity
			}
			return nil
		case uint32(windows.WAIT_TIMEOUT):
			if err := ctx.Err(); err != nil {
				return err
			}
		default:
			return runtimeport.ErrDesktopMutationIntegrity
		}
	}
}

func retainWindowsMutationHelper(
	ctx context.Context,
	helper runtimeport.DesktopHelperAuthority,
) (*os.File, error) {
	pointer, err := windows.UTF16PtrFromString(helper.CanonicalPath())
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pointer, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), filepath.Base(helper.CanonicalPath()))
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, runtimeport.ErrDesktopMutationIntegrity
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 128*1024*1024 {
		_ = file.Close()
		return nil, runtimeport.ErrDesktopMutationIntegrity
	}
	expectedBytes := uint64(info.Size()) // #nosec G115 -- size was proven positive and <= 128 MiB above.
	digest, read, err := digestWindowsDesktopArtifact(ctx, file, expectedBytes)
	if err != nil || read != expectedBytes || digest != helper.SHA256() || !verifyWindowsAuthenticode(helper.CanonicalPath()) {
		_ = file.Close()
		return nil, runtimeport.ErrDesktopMutationIntegrity
	}
	return file, nil
}

func runtimeKeepAliveDesktopShell(values ...any) {
	for _, value := range values {
		runtime.KeepAlive(value)
	}
}
