//go:build windows

package runtimeprovision

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"golang.org/x/sys/windows"
)

const (
	windowsDesktopMutationKeyRoot        = `C:\ProgramData\AgentMemory\runtime-helper`
	windowsDesktopMutationPrivateKeyPath = windowsDesktopMutationKeyRoot + `\receipt.key`
	windowsDesktopMutationPublicKeyPath  = windowsDesktopMutationKeyRoot + `\receipt.pub`
	windowsDesktopMutationKeyLockPath    = windowsDesktopMutationKeyRoot + `\receipt.lock`
)

type protectedDesktopMutationPublicKeySource struct{ helperPath string }

// NewProtectedDesktopMutationReceiptPublicKeySource constructs the Windows
// protected public-key loader bound to the installed helper path.
func NewProtectedDesktopMutationReceiptPublicKeySource(
	helperPath string,
) (DesktopMutationReceiptPublicKeySource, error) {
	if helperPath == "" || !filepath.IsAbs(helperPath) || filepath.Clean(helperPath) != helperPath ||
		strings.ContainsAny(helperPath, "\x00\r\n") || windowssecurity.ValidateLocalPath(helperPath) != nil {
		return nil, ErrProvisionIntegrity
	}
	return protectedDesktopMutationPublicKeySource{helperPath: helperPath}, nil
}

func (s protectedDesktopMutationPublicKeySource) LoadDesktopMutationPublicKey(
	ctx context.Context,
	expectedHelper runtimeinstall.Hash,
) (ed25519.PublicKey, error) {
	if ctx == nil || expectedHelper.IsZero() ||
		!windowsDesktopMutationHelperDigestMatches(ctx, s.helperPath, expectedHelper) {
		return nil, ErrProvisionIntegrity
	}
	value, err := readExactWindowsDesktopMutationKey(
		ctx, windowsDesktopMutationPublicKeyPath, ed25519.PublicKeySize,
	)
	if err != nil {
		return nil, ErrProvisionIntegrity
	}
	return ed25519.PublicKey(value), nil
}

type protectedDesktopMutationSigningKeySource struct{}

// NewNativeDesktopMutationReceiptSigner constructs the helper-only Windows
// signer backed by an elevated-user protected, per-machine Ed25519 identity.
func NewNativeDesktopMutationReceiptSigner() (DesktopMutationReceiptSigner, error) {
	return NewProtectedDesktopMutationReceiptSigner(protectedDesktopMutationSigningKeySource{})
}

func (protectedDesktopMutationSigningKeySource) LoadDesktopMutationSigningKey(
	ctx context.Context,
) (ed25519.PrivateKey, error) {
	if ctx == nil || !windows.GetCurrentProcessToken().IsElevated() {
		return nil, ErrProvisionIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, _, err := windowssecurity.EnsurePrivateDirectoryTree(
		ctx, windowsDesktopMutationKeyRoot, windowsDesktopMutationKeyRoot,
	); err != nil {
		return nil, ErrProvisionIntegrity
	}
	lock, err := openWindowsDesktopMutationKeyLock(ctx)
	if err != nil {
		return nil, ErrProvisionIntegrity
	}
	defer func() {
		var overlapped windows.Overlapped
		_ = windows.UnlockFileEx(windows.Handle(lock.Fd()), 0, 1, 0, &overlapped)
		_ = lock.Close()
	}()
	private, err := loadOrCreateWindowsDesktopMutationPrivateKey(ctx)
	if err != nil {
		clear(private)
		return nil, ErrProvisionIntegrity
	}
	public := append(ed25519.PublicKey(nil), private[ed25519.SeedSize:]...)
	if err := ensureWindowsDesktopMutationPublicKey(ctx, public); err != nil {
		clear(private)
		return nil, ErrProvisionIntegrity
	}
	if err := ctx.Err(); err != nil {
		clear(private)
		return nil, err
	}
	return private, nil
}

func openWindowsDesktopMutationKeyLock(ctx context.Context) (*os.File, error) {
	root, _, err := windowssecurity.OpenVerified(ctx, windowsDesktopMutationKeyRoot, true, true, true)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	lock, _, err := windowssecurity.OpenOrCreatePrivateChildSharedRead(ctx, root, filepath.Base(windowsDesktopMutationKeyLockPath))
	if err != nil {
		return nil, err
	}
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(
		windows.Handle(lock.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlapped,
	); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return lock, nil
}

func loadOrCreateWindowsDesktopMutationPrivateKey(ctx context.Context) (ed25519.PrivateKey, error) {
	private, err := readExactWindowsDesktopMutationKey(
		ctx, windowsDesktopMutationPrivateKeyPath, ed25519.PrivateKeySize,
	)
	if err == nil {
		rebuilt := ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])
		if !bytes.Equal(rebuilt, private) {
			clear(private)
			clear(rebuilt)
			return nil, ErrProvisionIntegrity
		}
		clear(rebuilt)
		return ed25519.PrivateKey(private), nil
	}
	if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil, err
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := writeExactWindowsDesktopMutationKey(ctx, windowsDesktopMutationPrivateKeyPath, privateKey); err != nil {
		clear(privateKey)
		return nil, err
	}
	return privateKey, nil
}

func ensureWindowsDesktopMutationPublicKey(ctx context.Context, expected ed25519.PublicKey) error {
	actual, err := readExactWindowsDesktopMutationKey(
		ctx, windowsDesktopMutationPublicKeyPath, ed25519.PublicKeySize,
	)
	if err == nil {
		if !bytes.Equal(actual, expected) {
			return ErrProvisionIntegrity
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return err
	}
	return writeExactWindowsDesktopMutationKey(ctx, windowsDesktopMutationPublicKeyPath, expected)
}

func readExactWindowsDesktopMutationKey(ctx context.Context, path string, size int) ([]byte, error) {
	file, _, err := windowssecurity.OpenVerifiedLockedRead(ctx, path, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || info.Size() != int64(size) {
		return nil, ErrProvisionIntegrity
	}
	value := make([]byte, size)
	if _, err := io.ReadFull(file, value); err != nil {
		return nil, ErrProvisionIntegrity
	}
	var extra [1]byte
	if count, readError := file.Read(extra[:]); count != 0 || !errors.Is(readError, io.EOF) {
		return nil, ErrProvisionIntegrity
	}
	return value, nil
}

func writeExactWindowsDesktopMutationKey(ctx context.Context, path string, value []byte) error {
	file, err := windowssecurity.CreatePrivateFile(ctx, path)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(path)
		}
	}()
	if written, err := file.Write(value); err != nil || written != len(value) ||
		windowssecurity.Flush(file) != nil || file.Close() != nil {
		return ErrProvisionIntegrity
	}
	committed = true
	return nil
}

func windowsDesktopMutationHelperDigestMatches(
	ctx context.Context,
	path string,
	expected runtimeinstall.Hash,
) bool {
	if ctx == nil || expected.IsZero() || windowssecurity.ValidateLocalPath(path) != nil {
		return false
	}
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	handle, err := windows.CreateFile(
		pointer, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0,
	)
	if err != nil {
		return false
	}
	file := os.NewFile(uintptr(handle), filepath.Base(path))
	if file == nil {
		_ = windows.CloseHandle(handle)
		return false
	}
	defer func() { _ = file.Close() }()
	var information windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(handle, &information) != nil ||
		information.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DEVICE) != 0 ||
		information.NumberOfLinks != 1 {
		return false
	}
	info, err := file.Stat()
	if err != nil || info.Size() <= 0 || info.Size() > 128*1024*1024 {
		return false
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, info.Size()+1))
	var actual runtimeinstall.Hash
	copy(actual[:], hasher.Sum(nil))
	return err == nil && written == info.Size() && actual == expected && ctx.Err() == nil
}

var (
	_ DesktopMutationReceiptPublicKeySource  = protectedDesktopMutationPublicKeySource{}
	_ DesktopMutationReceiptSigningKeySource = protectedDesktopMutationSigningKeySource{}
)
