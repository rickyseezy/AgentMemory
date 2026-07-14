//go:build windows

package windowssecurity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	credentialTypeGeneric        = uint32(1)
	credentialPersistLocal       = uint32(2)
	maximumCredentialBlobBytes   = 5 * 512
	maximumCredentialTargetUTF16 = 32767
	maximumCredentialUserUTF16   = 513
	maximumOwnerMutexIdentity    = 4 << 10
	ownerMutexPollMilliseconds   = uint32(50)
	ownerMutexAccessMask         = windows.ACCESS_MASK(windows.MUTEX_ALL_ACCESS)
	ownerMutexNamePrefix         = `Global\AgentMemory-PF001-`
)

// ErrOwnerMutexSecurity identifies a named kernel object whose owner and
// complete protected DACL could not be proved. Callers must fail closed and
// must never wait on or release a mutex carrying this error.
var ErrOwnerMutexSecurity = errors.New("windows owner mutex security proof failed")

// OwnerMutex is a verified, owner-only Windows kernel mutex held by a
// dedicated goroutine pinned to one operating-system thread. Windows mutex
// ownership is thread-affine, so the handle-owning goroutine remains alive
// from the successful wait through Release.
type OwnerMutex struct {
	mu           sync.Mutex
	release      chan chan error
	released     bool
	releaseError error
}

var (
	advapi32    = windows.NewLazySystemDLL("advapi32.dll")
	credWriteW  = advapi32.NewProc("CredWriteW")
	credReadW   = advapi32.NewProc("CredReadW")
	credDeleteW = advapi32.NewProc("CredDeleteW")
	credFree    = advapi32.NewProc("CredFree")
)

// nativeCredential matches CREDENTIALW from wincred.h. Pointer-bearing fields
// deliberately use their native pointer types so Go applies the correct
// Windows amd64/arm64 alignment.
type nativeCredential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

// WriteGenericCredential stores an opaque bounded record in the invoking
// user's non-roaming Windows Credential Manager set. Callers still DPAPI-wrap
// key material before invoking this boundary.
func WriteGenericCredential(ctx context.Context, target, user string, secret []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	targetPointer, err := checkedUTF16Pointer(target, maximumCredentialTargetUTF16, "credential target")
	if err != nil {
		return err
	}
	userPointer, err := checkedUTF16Pointer(user, maximumCredentialUserUTF16, "credential user")
	if err != nil {
		return err
	}
	if len(secret) == 0 || len(secret) > maximumCredentialBlobBytes {
		return errors.New("credential secret is empty or oversized")
	}
	credential := nativeCredential{
		Type:               credentialTypeGeneric,
		TargetName:         targetPointer,
		CredentialBlobSize: uint32(len(secret)), //nolint:gosec // G115: maximumCredentialBlobBytes is far below uint32; owner=security expiry=2027-07-14.
		CredentialBlob:     &secret[0],
		Persist:            credentialPersistLocal,
		UserName:           userPointer,
	}
	//nolint:gosec // G103: CredWriteW synchronously consumes the reviewed CREDENTIALW layout above; owner=security expiry=2027-07-14.
	result, _, callError := credWriteW.Call(uintptr(unsafe.Pointer(&credential)), 0)
	runtime.KeepAlive(targetPointer)
	runtime.KeepAlive(userPointer)
	runtime.KeepAlive(secret)
	if result == 0 {
		return nativeCallError("write Windows generic credential", callError)
	}
	return ctx.Err()
}

// ReadGenericCredential returns a copy of one invoking-user generic credential.
// The OS buffer is cleared before CredFree.
func ReadGenericCredential(ctx context.Context, target string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	targetPointer, err := checkedUTF16Pointer(target, maximumCredentialTargetUTF16, "credential target")
	if err != nil {
		return nil, err
	}
	var credential *nativeCredential
	//nolint:gosec // G103: CredReadW writes one documented PCREDENTIALW pointer to credential; owner=security expiry=2027-07-14.
	result, _, callError := credReadW.Call(
		uintptr(unsafe.Pointer(targetPointer)),
		uintptr(credentialTypeGeneric),
		0,
		uintptr(unsafe.Pointer(&credential)),
	)
	runtime.KeepAlive(targetPointer)
	if result == 0 {
		if errors.Is(callError, windows.ERROR_NOT_FOUND) {
			return nil, os.ErrNotExist
		}
		return nil, nativeCallError("read Windows generic credential", callError)
	}
	if credential == nil {
		return nil, errors.New("credential manager returned an absent record")
	}
	defer func() {
		//nolint:gosec // G103: CredFree requires the exact pointer allocated by CredReadW; owner=security expiry=2027-07-14.
		_, _, _ = credFree.Call(uintptr(unsafe.Pointer(credential)))
	}()
	if credential.Type != credentialTypeGeneric || credential.Persist != credentialPersistLocal ||
		credential.CredentialBlob == nil || credential.CredentialBlobSize == 0 ||
		credential.CredentialBlobSize > maximumCredentialBlobBytes {
		return nil, errors.New("credential manager returned an invalid bounded record")
	}
	//nolint:gosec // G103: CredReadW supplies a writable blob bounded by CredentialBlobSize immediately above; owner=security expiry=2027-07-14.
	allocated := unsafe.Slice(credential.CredentialBlob, int(credential.CredentialBlobSize))
	resultBytes := append([]byte(nil), allocated...)
	clear(allocated)
	if err := ctx.Err(); err != nil {
		clear(resultBytes)
		return nil, err
	}
	return resultBytes, nil
}

// DeleteGenericCredential removes one invoking-user generic credential.
func DeleteGenericCredential(ctx context.Context, target string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	targetPointer, err := checkedUTF16Pointer(target, maximumCredentialTargetUTF16, "credential target")
	if err != nil {
		return err
	}
	//nolint:gosec // G103: CredDeleteW synchronously consumes the bounded UTF-16 target pointer; owner=security expiry=2027-07-14.
	result, _, callError := credDeleteW.Call(
		uintptr(unsafe.Pointer(targetPointer)),
		uintptr(credentialTypeGeneric),
		0,
	)
	runtime.KeepAlive(targetPointer)
	if result == 0 {
		if errors.Is(callError, windows.ERROR_NOT_FOUND) {
			return os.ErrNotExist
		}
		return nativeCallError("delete Windows generic credential", callError)
	}
	return ctx.Err()
}

// OwnerMutexName derives the only accepted named-mutex shape from a bounded,
// caller-canonicalized identity. The digest keeps platform identity data out
// of the global kernel-object namespace.
func OwnerMutexName(canonicalIdentity string) (string, error) {
	if canonicalIdentity == "" || len(canonicalIdentity) > maximumOwnerMutexIdentity ||
		strings.IndexByte(canonicalIdentity, 0) >= 0 {
		return "", errors.New("owner mutex identity must be present, bounded, and NUL-free")
	}
	digest := sha256.Sum256([]byte(canonicalIdentity))
	return ownerMutexNamePrefix + hex.EncodeToString(digest[:]), nil
}

// AcquireOwnerMutex creates or opens a cross-process, cross-session kernel
// mutex with explicit owner-only SECURITY_ATTRIBUTES, then proves the owner
// and exact protected DACL on the returned handle. Verification also applies
// when an attacker created the named object first. WAIT_ABANDONED is accepted
// because callers authenticate and reconcile persistent state before mutation.
func AcquireOwnerMutex(ctx context.Context, name string) (*OwnerMutex, error) {
	if ctx == nil {
		return nil, errors.New("owner mutex context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validOwnerMutexName(name) {
		return nil, errors.New("owner mutex requires a fixed digest name")
	}

	acquired := make(chan ownerMutexAcquisition, 1)
	go ownOwnerMutex(ctx, name, acquired)
	result := <-acquired
	return result.mutex, result.err
}

type ownerMutexAcquisition struct {
	mutex *OwnerMutex
	err   error
}

func ownOwnerMutex(ctx context.Context, name string, acquired chan<- ownerMutexAcquisition) {
	// Windows mutex ownership is thread-affine. Keep all wait and release calls
	// on this dedicated OS thread even if the application transfers the guard
	// between goroutines before releasing it.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	namePointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		acquired <- ownerMutexAcquisition{err: err}
		return
	}
	attributes, descriptor, err := privateSecurityAttributesWithRights(ctx, "0x001F0001")
	if err != nil {
		acquired <- ownerMutexAcquisition{err: err}
		return
	}
	handle, err := windows.CreateMutex(attributes, false, namePointer)
	runtime.KeepAlive(descriptor)
	runtime.KeepAlive(namePointer)
	// x/sys reports ERROR_ALREADY_EXISTS alongside the valid opened handle.
	// That status is expected for contention; it must not bypass the descriptor
	// verification immediately below.
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		acquired <- ownerMutexAcquisition{err: fmt.Errorf("create protected Windows owner mutex: %w", err)}
		return
	}
	if handle == 0 {
		acquired <- ownerMutexAcquisition{err: errors.New("create protected Windows owner mutex returned an invalid handle")}
		return
	}
	fail := func(cause error) {
		acquired <- ownerMutexAcquisition{err: errors.Join(cause, windows.CloseHandle(handle))}
	}
	securityDescriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_KERNEL_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || securityDescriptor == nil {
		if err != nil {
			fail(fmt.Errorf("%w: read descriptor: %w", ErrOwnerMutexSecurity, err))
		} else {
			fail(ErrOwnerMutexSecurity)
		}
		return
	}
	expectedSID, _, err := CurrentUserSID(ctx)
	if err != nil {
		fail(err)
		return
	}
	if err := verifyOwnerDescriptor(securityDescriptor, expectedSID); err != nil {
		fail(fmt.Errorf("%w: %w", ErrOwnerMutexSecurity, err))
		return
	}
	if err := verifyPrivateDACLMask(securityDescriptor, expectedSID, ownerMutexAccessMask); err != nil {
		fail(fmt.Errorf("%w: %w", ErrOwnerMutexSecurity, err))
		return
	}
	for {
		waitResult, waitError := windows.WaitForSingleObject(handle, ownerMutexPollMilliseconds)
		switch waitResult {
		case windows.WAIT_OBJECT_0, windows.WAIT_ABANDONED:
			if err := ctx.Err(); err != nil {
				fail(errors.Join(err, windows.ReleaseMutex(handle)))
				return
			}
			release := make(chan chan error)
			acquired <- ownerMutexAcquisition{mutex: &OwnerMutex{release: release}}
			reply := <-release
			reply <- errors.Join(windows.ReleaseMutex(handle), windows.CloseHandle(handle))
			return
		case uint32(windows.WAIT_TIMEOUT):
			if err := ctx.Err(); err != nil {
				fail(err)
				return
			}
		default:
			fail(fmt.Errorf("wait for Windows owner mutex: result=%d: %w", waitResult, waitError))
			return
		}
	}
}

// Release relinquishes and closes the verified kernel handle. It is safe to
// call repeatedly and from a goroutine other than the acquiring goroutine.
func (m *OwnerMutex) Release() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.released {
		return m.releaseError
	}
	reply := make(chan error, 1)
	m.release <- reply
	m.releaseError = <-reply
	m.released = true
	return m.releaseError
}

// WithOwnerMutex serializes a bounded operation across processes and logon
// sessions using the same acquired-guard capability as longer-lived callers.
func WithOwnerMutex(ctx context.Context, name string, action func() error) (result error) {
	if action == nil {
		return errors.New("owner mutex action is required")
	}
	mutex, err := AcquireOwnerMutex(ctx, name)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, mutex.Release()) }()
	return action()
}

func checkedUTF16Pointer(value string, maximumUnits int, field string) (*uint16, error) {
	if strings.TrimSpace(value) == "" || strings.IndexByte(value, 0) >= 0 {
		return nil, fmt.Errorf("%s is empty or contains NUL", field)
	}
	encoded, err := windows.UTF16FromString(value)
	if err != nil || len(encoded)-1 > maximumUnits {
		return nil, fmt.Errorf("%s exceeds its Windows UTF-16 limit", field)
	}
	return &encoded[0], nil
}

func validOwnerMutexName(name string) bool {
	if !strings.HasPrefix(name, ownerMutexNamePrefix) || len(name) != len(ownerMutexNamePrefix)+64 {
		return false
	}
	for _, character := range name[len(ownerMutexNamePrefix):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func nativeCallError(operation string, callError error) error {
	if callError == nil || errors.Is(callError, syscall.Errno(0)) {
		return fmt.Errorf("%s failed without an OS status", operation)
	}
	return fmt.Errorf("%s: %w", operation, callError)
}
