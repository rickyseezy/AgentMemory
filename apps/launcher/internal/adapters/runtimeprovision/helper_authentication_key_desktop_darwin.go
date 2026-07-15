//go:build darwin

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

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"golang.org/x/sys/unix"
)

const (
	darwinDesktopMutationKeyRoot        = "/Library/Application Support/AgentMemory/runtime-helper"
	darwinDesktopMutationPrivateKeyPath = darwinDesktopMutationKeyRoot + "/receipt.key"
	darwinDesktopMutationPublicKeyPath  = darwinDesktopMutationKeyRoot + "/receipt.pub"
	darwinDesktopMutationKeyLockPath    = darwinDesktopMutationKeyRoot + "/receipt.lock"
)

type protectedDesktopMutationPublicKeySource struct{ helperPath string }

// NewProtectedDesktopMutationReceiptPublicKeySource constructs the macOS
// descriptor-based public-key loader bound to the installed helper path.
func NewProtectedDesktopMutationReceiptPublicKeySource(
	helperPath string,
) (DesktopMutationReceiptPublicKeySource, error) {
	if helperPath == "" || !filepath.IsAbs(helperPath) || filepath.Clean(helperPath) != helperPath ||
		strings.ContainsAny(helperPath, "\x00\r\n") {
		return nil, ErrProvisionIntegrity
	}
	return protectedDesktopMutationPublicKeySource{helperPath: helperPath}, nil
}

func (s protectedDesktopMutationPublicKeySource) LoadDesktopMutationPublicKey(
	ctx context.Context,
	expectedHelper runtimeinstall.Hash,
) (ed25519.PublicKey, error) {
	if ctx == nil || expectedHelper.IsZero() ||
		!darwinDesktopMutationHelperDigestMatches(ctx, s.helperPath, expectedHelper) {
		return nil, ErrProvisionIntegrity
	}
	value, err := readExactDarwinDesktopMutationKey(
		darwinDesktopMutationPublicKeyPath, ed25519.PublicKeySize, 0o444, 0, 0,
	)
	if err != nil {
		return nil, ErrProvisionIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return ed25519.PublicKey(value), nil
}

type protectedDesktopMutationSigningKeySource struct{}

// NewNativeDesktopMutationReceiptSigner constructs the helper-only macOS
// signer backed by a root-owned, per-machine Ed25519 identity.
func NewNativeDesktopMutationReceiptSigner() (DesktopMutationReceiptSigner, error) {
	return NewProtectedDesktopMutationReceiptSigner(protectedDesktopMutationSigningKeySource{})
}

func (protectedDesktopMutationSigningKeySource) LoadDesktopMutationSigningKey(
	ctx context.Context,
) (ed25519.PrivateKey, error) {
	if ctx == nil || os.Geteuid() != 0 {
		return nil, ErrProvisionIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, directory := range []struct {
		path string
		mode os.FileMode
	}{
		{path: "/Library/Application Support/AgentMemory", mode: 0o755},
		{path: darwinDesktopMutationKeyRoot, mode: 0o755},
	} {
		if err := ensureDarwinDesktopMutationDirectory(directory.path, directory.mode); err != nil {
			return nil, ErrProvisionIntegrity
		}
	}
	lock, err := openDarwinDesktopMutationKeyLock()
	if err != nil {
		return nil, ErrProvisionIntegrity
	}
	defer func() {
		_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
		_ = lock.Close()
	}()
	private, err := loadOrCreateDarwinDesktopMutationPrivateKey()
	if err != nil {
		clear(private)
		return nil, ErrProvisionIntegrity
	}
	public := append(ed25519.PublicKey(nil), private[ed25519.SeedSize:]...)
	if err := ensureDarwinDesktopMutationPublicKey(public); err != nil {
		clear(private)
		return nil, ErrProvisionIntegrity
	}
	if err := ctx.Err(); err != nil {
		clear(private)
		return nil, err
	}
	return private, nil
}

func openDarwinDesktopMutationKeyLock() (*os.File, error) {
	return openDarwinDesktopMutationKeyLockAt(darwinDesktopMutationKeyLockPath, 0, 0)
}

func openDarwinDesktopMutationKeyLockAt(path string, uid uint32, gid uint32) (*os.File, error) {
	descriptor, err := unix.Open(
		path,
		unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), "desktop-mutation-key-lock")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, ErrProvisionIntegrity
	}
	if !darwinDesktopMutationKeyDescriptorMatches(descriptor, uid, gid, 0, 0o600) ||
		unix.Flock(descriptor, unix.LOCK_EX) != nil {
		_ = file.Close()
		return nil, ErrProvisionIntegrity
	}
	return file, nil
}

func loadOrCreateDarwinDesktopMutationPrivateKey() (ed25519.PrivateKey, error) {
	return loadOrCreateDarwinDesktopMutationPrivateKeyAt(
		darwinDesktopMutationPrivateKeyPath, darwinDesktopMutationKeyRoot, 0, 0,
	)
}

func loadOrCreateDarwinDesktopMutationPrivateKeyAt(
	path string,
	directory string,
	uid uint32,
	gid uint32,
) (ed25519.PrivateKey, error) {
	private, err := readExactDarwinDesktopMutationKey(
		path, ed25519.PrivateKeySize, 0o600, uid, gid,
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
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := writeExactDarwinDesktopMutationKey(
		path, directory, privateKey, 0o600,
	); err != nil {
		clear(privateKey)
		return nil, err
	}
	return privateKey, nil
}

func ensureDarwinDesktopMutationPublicKey(expected ed25519.PublicKey) error {
	return ensureDarwinDesktopMutationPublicKeyAt(
		darwinDesktopMutationPublicKeyPath, darwinDesktopMutationKeyRoot, expected, 0, 0,
	)
}

func ensureDarwinDesktopMutationPublicKeyAt(
	path string,
	directory string,
	expected ed25519.PublicKey,
	uid uint32,
	gid uint32,
) error {
	actual, err := readExactDarwinDesktopMutationKey(
		path, ed25519.PublicKeySize, 0o444, uid, gid,
	)
	if err == nil {
		if !bytes.Equal(actual, expected) {
			return ErrProvisionIntegrity
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeExactDarwinDesktopMutationKey(path, directory, expected, 0o444)
}

func readExactDarwinDesktopMutationKey(
	path string,
	size int,
	mode uint32,
	uid uint32,
	gid uint32,
) ([]byte, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), "desktop-mutation-key")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, ErrProvisionIntegrity
	}
	defer func() { _ = file.Close() }()
	if !darwinDesktopMutationKeyDescriptorMatches(descriptor, uid, gid, uint64(size), mode) {
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

func writeExactDarwinDesktopMutationKey(
	path string,
	directory string,
	value []byte,
	mode uint32,
) error {
	if directory == "" || filepath.Dir(path) != directory {
		return ErrProvisionIntegrity
	}
	descriptor, err := unix.Open(
		path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, mode,
	)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(descriptor), "desktop-mutation-key-create")
	if file == nil {
		_ = unix.Close(descriptor)
		_ = os.Remove(path)
		return ErrProvisionIntegrity
	}
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(path)
		}
	}()
	if written, err := file.Write(value); err != nil || written != len(value) || file.Sync() != nil ||
		file.Chmod(os.FileMode(mode)) != nil || file.Close() != nil {
		return ErrProvisionIntegrity
	}
	committed = true
	return syncPrivilegeProtectedDirectory(directory)
}

func darwinDesktopMutationKeyDescriptorMatches(
	descriptor int,
	uid uint32,
	gid uint32,
	size uint64,
	mode uint32,
) bool {
	var status unix.Stat_t
	return unix.Fstat(descriptor, &status) == nil && status.Mode&unix.S_IFMT == unix.S_IFREG &&
		status.Uid == uid && status.Gid == gid && status.Nlink == 1 &&
		uint32(status.Mode)&0o7777 == mode && status.Size >= 0 && uint64(status.Size) == size
}

func darwinDesktopMutationHelperDigestMatches(
	ctx context.Context,
	path string,
	expected runtimeinstall.Hash,
) bool {
	if ctx == nil || expected.IsZero() || path == "" {
		return false
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	file := os.NewFile(uintptr(descriptor), "desktop-mutation-helper")
	if file == nil {
		_ = unix.Close(descriptor)
		return false
	}
	defer func() { _ = file.Close() }()
	var status unix.Stat_t
	if unix.Fstat(descriptor, &status) != nil || status.Mode&unix.S_IFMT != unix.S_IFREG ||
		status.Uid != 0 || status.Gid != 0 || status.Nlink != 1 || status.Mode&0o022 != 0 ||
		status.Mode&0o100 == 0 || status.Size <= 0 || status.Size > 128*1024*1024 {
		return false
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, status.Size+1))
	var actual runtimeinstall.Hash
	copy(actual[:], hasher.Sum(nil))
	return err == nil && written == status.Size && actual == expected && ctx.Err() == nil
}

var (
	_ DesktopMutationReceiptPublicKeySource  = protectedDesktopMutationPublicKeySource{}
	_ DesktopMutationReceiptSigningKeySource = protectedDesktopMutationSigningKeySource{}
)
