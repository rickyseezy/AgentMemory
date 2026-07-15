//go:build linux

package runtimeprovision

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const rootPrivilegeReceiptPublicKeyPath = "/var/lib/agentmemory/runtime-helper/receipt.pub"

const (
	rootPrivilegeReceiptPrivateKeyPath = "/var/lib/agentmemory/runtime-helper/receipt.key"
	rootPrivilegeReceiptKeyLockPath    = "/var/lib/agentmemory/runtime-helper/receipt.lock"
)

type rootPrivilegeReceiptPublicKeySource struct{}

// NewRootPrivilegeReceiptPublicKeySource constructs the descriptor-based
// root-owned local public-key loader.
func NewRootPrivilegeReceiptPublicKeySource() PrivilegeReceiptPublicKeySource {
	return rootPrivilegeReceiptPublicKeySource{}
}

func (rootPrivilegeReceiptPublicKeySource) LoadPrivilegeReceiptPublicKey(
	ctx context.Context,
) (ed25519.PublicKey, error) {
	if ctx == nil {
		return nil, ErrProvisionIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	descriptor, err := unix.Open(
		rootPrivilegeReceiptPublicKeyPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0,
	)
	if err != nil {
		return nil, ErrProvisionIntegrity
	}
	file := os.NewFile(uintptr(descriptor), "privilege-receipt-public-key")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, ErrProvisionIntegrity
	}
	defer func() { _ = file.Close() }()
	var stat unix.Stat_t
	if unix.Fstat(descriptor, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o333 != 0 || stat.Nlink != 1 ||
		stat.Size != ed25519.PublicKeySize {
		return nil, ErrProvisionIntegrity
	}
	key := make(ed25519.PublicKey, ed25519.PublicKeySize)
	if _, err := io.ReadFull(file, key); err != nil {
		return nil, ErrProvisionIntegrity
	}
	var extra [1]byte
	if count, readError := file.Read(extra[:]); count != 0 || !errors.Is(readError, io.EOF) {
		return nil, ErrProvisionIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return key, nil
}

type rootPrivilegeReceiptSigningKeySource struct{}

// NewRootPrivilegeReceiptSigner constructs the helper-only protected signer.
func NewRootPrivilegeReceiptSigner() (PrivilegeReceiptSigner, error) {
	return newProtectedPrivilegeReceiptSigner(rootPrivilegeReceiptSigningKeySource{})
}

func (rootPrivilegeReceiptSigningKeySource) LoadPrivilegeReceiptSigningKey(
	ctx context.Context,
) (ed25519.PrivateKey, error) {
	if ctx == nil || os.Geteuid() != 0 {
		return nil, ErrProvisionIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ensureRootPrivilegeDirectory("/var/lib/agentmemory", 0o755) != nil ||
		ensureRootPrivilegeDirectory("/var/lib/agentmemory/runtime-helper", 0o755) != nil {
		return nil, ErrProvisionIntegrity
	}
	lock, err := openRootPrivilegeKeyLock()
	if err != nil {
		return nil, ErrProvisionIntegrity
	}
	defer func() {
		_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
		_ = lock.Close()
	}()
	private, err := loadOrCreateRootPrivilegePrivateKey()
	if err != nil {
		clear(private)
		return nil, ErrProvisionIntegrity
	}
	public := append(ed25519.PublicKey(nil), private[ed25519.SeedSize:]...)
	if err := ensureRootPrivilegePublicKey(public); err != nil {
		clear(private)
		return nil, ErrProvisionIntegrity
	}
	if err := ctx.Err(); err != nil {
		clear(private)
		return nil, err
	}
	return ed25519.PrivateKey(private), nil
}

func openRootPrivilegeKeyLock() (*os.File, error) {
	descriptor, err := unix.Open(
		rootPrivilegeReceiptKeyLockPath,
		unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), "privilege-receipt-key-lock")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, ErrProvisionIntegrity
	}
	var stat unix.Stat_t
	if unix.Fstat(descriptor, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o777 != 0o600 || stat.Nlink != 1 ||
		unix.Flock(descriptor, unix.LOCK_EX) != nil {
		_ = file.Close()
		return nil, ErrProvisionIntegrity
	}
	return file, nil
}

func loadOrCreateRootPrivilegePrivateKey() (ed25519.PrivateKey, error) {
	private, err := readExactRootPrivilegeKey(
		rootPrivilegeReceiptPrivateKeyPath, ed25519.PrivateKeySize, 0o600,
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
	_, private, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := writeExactRootPrivilegeKey(rootPrivilegeReceiptPrivateKeyPath, private, 0o600); err != nil {
		clear(private)
		return nil, err
	}
	return private, nil
}

func ensureRootPrivilegePublicKey(expected ed25519.PublicKey) error {
	actual, err := readExactRootPrivilegeKey(
		rootPrivilegeReceiptPublicKeyPath, ed25519.PublicKeySize, 0o444,
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
	return writeExactRootPrivilegeKey(rootPrivilegeReceiptPublicKeyPath, expected, 0o444)
}

func readExactRootPrivilegeKey(path string, size int, mode uint32) ([]byte, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), "privilege-receipt-key")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, ErrProvisionIntegrity
	}
	defer func() { _ = file.Close() }()
	var stat unix.Stat_t
	if unix.Fstat(descriptor, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o777 != mode || stat.Nlink != 1 ||
		stat.Size != int64(size) {
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

func writeExactRootPrivilegeKey(path string, value []byte, mode uint32) error {
	descriptor, err := unix.Open(
		path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, mode,
	)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(descriptor), "privilege-receipt-key-create")
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
	return syncPrivilegeDirectory("/var/lib/agentmemory/runtime-helper")
}

var _ PrivilegeReceiptPublicKeySource = rootPrivilegeReceiptPublicKeySource{}

var _ privilegeReceiptSigningKeySource = rootPrivilegeReceiptSigningKeySource{}
