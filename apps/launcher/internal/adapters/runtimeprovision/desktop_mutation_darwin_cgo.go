//go:build darwin && cgo

package runtimeprovision

/*
#cgo LDFLAGS: -framework Security
#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>
#include <stdio.h>
#include <stdlib.h>

static OSStatus am_authorized_desktop_helper(
	const char *helper,
	const char *operation,
	const char *request_path
) {
	AuthorizationRef authorization = NULL;
	OSStatus status = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &authorization);
	if (status != errAuthorizationSuccess || authorization == NULL) return status;
	AuthorizationItem item = {kAuthorizationRightExecute, 0, NULL, 0};
	AuthorizationRights rights = {1, &item};
	AuthorizationFlags flags = kAuthorizationFlagInteractionAllowed | kAuthorizationFlagExtendRights |
		kAuthorizationFlagPreAuthorize;
	status = AuthorizationCopyRights(authorization, &rights, kAuthorizationEmptyEnvironment, flags, NULL);
	if (status == errAuthorizationSuccess) {
		char *arguments[] = {(char *)operation, (char *)request_path, NULL};
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
		FILE *communications_pipe = NULL;
		status = AuthorizationExecuteWithPrivileges(
			authorization, helper, kAuthorizationFlagDefaults, arguments, &communications_pipe);
#pragma clang diagnostic pop
		if (communications_pipe != NULL) fclose(communications_pipe);
	}
	AuthorizationFree(authorization, kAuthorizationFlagDestroyRights);
	return status;
}
*/
import "C"

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"golang.org/x/sys/unix"
)

const (
	darwinAuthorizationCanceled              = -60006
	darwinAuthorizationInteractionNotAllowed = -60007
)

func createNativeDesktopMutationExchange(
	ctx context.Context,
	helper runtimeport.DesktopHelperAuthority,
	request runtimeport.DesktopMutationRequest,
) (nativeDesktopMutationExchange, error) {
	if helper.Platform() != runtimeinstall.PlatformDarwin || ctx.Err() != nil {
		return nativeDesktopMutationExchange{}, runtimeport.ErrDesktopMutationIntegrity
	}
	directory, err := openDarwinMutationDirectory(helper.ExchangeDirectory())
	if err != nil {
		return nativeDesktopMutationExchange{}, err
	}
	defer func() { _ = directory.Close() }()
	base := "request-" + request.Digest().String()
	requestName := base + ".json"
	receiptName := base + ".receipt.json"
	requestPath := filepath.Join(helper.ExchangeDirectory(), requestName)
	receiptPath := filepath.Join(helper.ExchangeDirectory(), receiptName)
	_ = os.Remove(requestPath)
	_ = os.Remove(receiptPath)
	descriptor, err := unix.Openat(
		int(directory.Fd()), requestName,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		return nativeDesktopMutationExchange{}, err
	}
	file := os.NewFile(uintptr(descriptor), requestName)
	if file == nil {
		_ = unix.Close(descriptor)
		return nativeDesktopMutationExchange{}, runtimeport.ErrDesktopMutationIntegrity
	}
	contents := request.CanonicalBytes()
	written, writeError := file.Write(contents)
	syncError := file.Sync()
	closeError := file.Close()
	directorySync := unix.Fsync(int(directory.Fd()))
	if writeError != nil || written != len(contents) || syncError != nil || closeError != nil || directorySync != nil {
		_ = os.Remove(requestPath)
		return nativeDesktopMutationExchange{}, runtimeport.ErrDesktopMutationIntegrity
	}
	return nativeDesktopMutationExchange{
		requestPath: requestPath, receiptPath: receiptPath,
		read: readDarwinMutationReceipt,
		remove: func(path string) error {
			if filepath.Dir(path) != helper.ExchangeDirectory() {
				return runtimeport.ErrDesktopMutationIntegrity
			}
			return os.Remove(path)
		},
	}, nil
}

func openDarwinMutationDirectory(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return nil, runtimeport.ErrDesktopMutationIntegrity
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	uid := os.Geteuid()
	if !ok || uid <= 0 || status.Uid != uint32(uid) { // #nosec G115 -- positive Darwin UID.
		return nil, runtimeport.ErrDesktopMutationIntegrity
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), "native-mutation")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, runtimeport.ErrDesktopMutationIntegrity
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, runtimeport.ErrDesktopMutationIntegrity
	}
	return file, nil
}

func readDarwinMutationReceipt(ctx context.Context, path string) ([]byte, error) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		contents, err := readDarwinMutationReceiptOnce(path)
		if err == nil {
			return contents, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func readDarwinMutationReceiptOnce(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	uid := os.Geteuid()
	if !ok || uid <= 0 || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > 64*1024 || status.Uid != uint32(uid) || status.Nlink != 1 { // #nosec G115 -- positive Darwin UID.
		return nil, runtimeport.ErrDesktopMutationIntegrity
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), "native-mutation-receipt")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, runtimeport.ErrDesktopMutationIntegrity
	}
	defer func() { _ = file.Close() }()
	contents, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	opened, statError := file.Stat()
	if err != nil || statError != nil || len(contents) == 0 || len(contents) > 64*1024 || !os.SameFile(info, opened) {
		return nil, runtimeport.ErrDesktopMutationIntegrity
	}
	return contents, nil
}

func executeNativeDesktopHelper(
	ctx context.Context,
	helper runtimeport.DesktopHelperAuthority,
	requestPath string,
) error {
	if ctx == nil || ctx.Err() != nil || helper.Platform() != runtimeinstall.PlatformDarwin ||
		filepath.Dir(requestPath) != helper.ExchangeDirectory() || !verifyDarwinMutationHelper(ctx, helper) {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	helperCString := C.CString(helper.CanonicalPath())
	operationCString := C.CString("--execute-desktop-mutation")
	requestCString := C.CString(requestPath)
	if helperCString == nil || operationCString == nil || requestCString == nil {
		if helperCString != nil {
			C.free(unsafe.Pointer(helperCString))
		}
		if operationCString != nil {
			C.free(unsafe.Pointer(operationCString))
		}
		if requestCString != nil {
			C.free(unsafe.Pointer(requestCString))
		}
		return runtimeport.ErrDesktopMutationIntegrity
	}
	defer C.free(unsafe.Pointer(helperCString))
	defer C.free(unsafe.Pointer(operationCString))
	defer C.free(unsafe.Pointer(requestCString))
	status := int32(C.am_authorized_desktop_helper(helperCString, operationCString, requestCString))
	switch status {
	case 0:
		return nil
	case darwinAuthorizationCanceled:
		return runtimeport.ErrDesktopMutationDenied
	case darwinAuthorizationInteractionNotAllowed:
		return runtimeport.ErrDesktopMutationUnavailable
	default:
		return runtimeport.ErrDesktopMutationPolicy
	}
}

func verifyDarwinMutationHelper(ctx context.Context, helper runtimeport.DesktopHelperAuthority) bool {
	info, err := os.Lstat(helper.CanonicalPath())
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 ||
		info.Size() <= 0 || info.Size() > 128*1024*1024 {
		return false
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || status.Uid != 0 || status.Gid != 0 || status.Nlink != 1 {
		return false
	}
	file, err := os.Open(helper.CanonicalPath())
	if err != nil {
		return false
	}
	defer func() { _ = file.Close() }()
	digest, read, err := digestBoundedDesktopArtifact(ctx, file, uint64(info.Size())) // #nosec G115 -- positive bounded size.
	return err == nil && read == uint64(info.Size()) && digest == helper.SHA256() && !digest.IsZero()
}
