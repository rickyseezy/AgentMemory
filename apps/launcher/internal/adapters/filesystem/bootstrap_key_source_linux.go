//go:build linux

package filesystem

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const (
	linuxKeyRecordSize = 16 + sha256.Size*5
	linuxKeyBytes      = sha256.Size
)

var linuxKeyRecordMagic = [16]byte{'A', 'M', 'B', 'O', 'O', 'T', 'K', 'E', 'Y', 'v', '1'}

// LinuxFileOperationKeySource persists operation HMAC keys in owner-only
// regular files bound to the current Linux machine and effective UID.
type LinuxFileOperationKeySource struct {
	locator *bootstrapadapter.OperationLocator
	owners  bootstrapport.OwnerBindingSource
	entropy io.Reader
	mu      sync.Mutex
}

var _ bootstrapport.OperationKeySource = (*LinuxFileOperationKeySource)(nil)

// NewLinuxFileOperationKeySource creates the Linux owner-file fallback. A
// composition policy may prefer a separately certified OS credential store.
func NewLinuxFileOperationKeySource(
	locator *bootstrapadapter.OperationLocator,
	owners bootstrapport.OwnerBindingSource,
) (*LinuxFileOperationKeySource, error) {
	return newLinuxFileOperationKeySource(locator, owners, rand.Reader)
}

func newLinuxFileOperationKeySource(
	locator *bootstrapadapter.OperationLocator,
	owners bootstrapport.OwnerBindingSource,
	entropy io.Reader,
) (*LinuxFileOperationKeySource, error) {
	if locator == nil || nilInterface(owners) || nilInterface(entropy) {
		return nil, errors.New("linux operation key source requires locator, owner source, and entropy")
	}
	return &LinuxFileOperationKeySource{locator: locator, owners: owners, entropy: entropy}, nil
}

// Ensure creates exactly one protected owner-bound key, even across concurrent
// source values, by publishing a fully synced temporary file with link(2).
func (s *LinuxFileOperationKeySource) Ensure(
	ctx context.Context,
	operationID install.OperationID,
	owner install.OwnerBinding,
) (install.BootstrapKeyRef, error) {
	if err := s.verifyCurrentOwner(ctx, owner); err != nil {
		return install.BootstrapKeyRef{}, err
	}
	keyPath, err := s.locator.KeyPath(operationID)
	if err != nil {
		return install.BootstrapKeyRef{}, fmt.Errorf("%w: invalid operation key location", bootstrapport.ErrIntegrity)
	}
	if err := ensureLinuxOperationDirectory(ctx, filepath.Dir(keyPath)); err != nil {
		return install.BootstrapKeyRef{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := readLinuxKeyRecord(keyPath, operationID, owner)
	if err == nil {
		clear(record.key[:])
		return record.ref, nil
	}
	if !errors.Is(err, bootstrapport.ErrNotFound) {
		return install.BootstrapKeyRef{}, err
	}

	var key [linuxKeyBytes]byte
	if _, err := io.ReadFull(s.entropy, key[:]); err != nil {
		return install.BootstrapKeyRef{}, errors.New("generate Linux operation key")
	}
	defer clear(key[:])
	ref, err := linuxFileKeyReference(operationID, owner, key[:])
	if err != nil {
		return install.BootstrapKeyRef{}, err
	}
	contents, err := encodeLinuxKeyRecord(operationID, owner, ref, key)
	if err != nil {
		return install.BootstrapKeyRef{}, err
	}
	published, err := publishProtectedFile(ctx, keyPath, contents)
	clear(contents)
	if err != nil {
		return install.BootstrapKeyRef{}, err
	}
	if published {
		return ref, nil
	}
	winner, err := readLinuxKeyRecord(keyPath, operationID, owner)
	if err != nil {
		return install.BootstrapKeyRef{}, err
	}
	defer clear(winner.key[:])
	return winner.ref, nil
}

// UseHMACKey opens the protected file without following symlinks, verifies all
// bindings, and clears the callback copy on return.
func (s *LinuxFileOperationKeySource) UseHMACKey(
	ctx context.Context,
	keyRef install.BootstrapKeyRef,
	operationID install.OperationID,
	owner install.OwnerBinding,
	consumer bootstrapport.OperationKeyConsumer,
) error {
	if consumer == nil || keyRef.IsZero() {
		return fmt.Errorf("%w: complete key access binding is required", bootstrapport.ErrIntegrity)
	}
	if err := s.verifyCurrentOwner(ctx, owner); err != nil {
		return err
	}
	keyPath, err := s.locator.KeyPath(operationID)
	if err != nil {
		return fmt.Errorf("%w: invalid operation key location", bootstrapport.ErrIntegrity)
	}
	s.mu.Lock()
	record, err := readLinuxKeyRecord(keyPath, operationID, owner)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	defer clear(record.key[:])
	if !record.ref.Equal(keyRef) {
		return fmt.Errorf("%w: operation key reference changed", bootstrapport.ErrIntegrity)
	}
	temporary := append([]byte(nil), record.key[:]...)
	defer clear(temporary)
	return consumer(temporary)
}

func (s *LinuxFileOperationKeySource) verifyCurrentOwner(ctx context.Context, expected install.OwnerBinding) error {
	if expected.IsZero() {
		return fmt.Errorf("%w: owner binding is absent", bootstrapport.ErrIntegrity)
	}
	current, err := s.owners.Current(ctx)
	if err != nil {
		return err
	}
	if !current.Equal(expected) {
		return fmt.Errorf("%w: machine or OS principal changed", bootstrapport.ErrIntegrity)
	}
	return nil
}

type linuxKeyRecord struct {
	ref install.BootstrapKeyRef
	key [linuxKeyBytes]byte
}

func encodeLinuxKeyRecord(
	operationID install.OperationID,
	owner install.OwnerBinding,
	ref install.BootstrapKeyRef,
	key [linuxKeyBytes]byte,
) ([]byte, error) {
	result := make([]byte, 0, linuxKeyRecordSize)
	result = append(result, linuxKeyRecordMagic[:]...)
	operationDigest := operationIdentityDigest(operationID)
	result = append(result, operationDigest[:]...)
	machine, err := hex.DecodeString(owner.MachineDigest().String())
	if err != nil {
		return nil, err
	}
	principal, err := hex.DecodeString(owner.PrincipalDigest().String())
	if err != nil {
		return nil, err
	}
	refDigest, err := keyRefDigest(ref)
	if err != nil {
		return nil, err
	}
	result = append(result, machine...)
	result = append(result, principal...)
	result = append(result, refDigest...)
	result = append(result, key[:]...)
	return result, nil
}

func readLinuxKeyRecord(
	path string,
	operationID install.OperationID,
	owner install.OwnerBinding,
) (linuxKeyRecord, error) {
	contents, err := readProtectedFile(path, linuxKeyRecordSize)
	if err != nil {
		return linuxKeyRecord{}, err
	}
	defer clear(contents)
	if len(contents) != linuxKeyRecordSize || !bytes.Equal(contents[:16], linuxKeyRecordMagic[:]) {
		return linuxKeyRecord{}, fmt.Errorf("%w: operation key record format is invalid", bootstrapport.ErrIntegrity)
	}
	offset := 16
	expectedOperation := operationIdentityDigest(operationID)
	if !hmac.Equal(contents[offset:offset+sha256.Size], expectedOperation[:]) {
		return linuxKeyRecord{}, fmt.Errorf("%w: operation key identity changed", bootstrapport.ErrIntegrity)
	}
	offset += sha256.Size
	expectedMachine, _ := hex.DecodeString(owner.MachineDigest().String())
	if !hmac.Equal(contents[offset:offset+sha256.Size], expectedMachine) {
		return linuxKeyRecord{}, fmt.Errorf("%w: operation key machine changed", bootstrapport.ErrIntegrity)
	}
	offset += sha256.Size
	expectedPrincipal, _ := hex.DecodeString(owner.PrincipalDigest().String())
	if !hmac.Equal(contents[offset:offset+sha256.Size], expectedPrincipal) {
		return linuxKeyRecord{}, fmt.Errorf("%w: operation key principal changed", bootstrapport.ErrIntegrity)
	}
	offset += sha256.Size
	persistedRefDigest := append([]byte(nil), contents[offset:offset+sha256.Size]...)
	offset += sha256.Size
	var key [linuxKeyBytes]byte
	copy(key[:], contents[offset:offset+linuxKeyBytes])
	ref, err := linuxFileKeyReference(operationID, owner, key[:])
	if err != nil {
		clear(key[:])
		return linuxKeyRecord{}, err
	}
	computedRefDigest, _ := keyRefDigest(ref)
	if !hmac.Equal(persistedRefDigest, computedRefDigest) {
		clear(key[:])
		return linuxKeyRecord{}, fmt.Errorf("%w: operation key record was modified", bootstrapport.ErrIntegrity)
	}
	return linuxKeyRecord{ref: ref, key: key}, nil
}

func linuxFileKeyReference(
	operationID install.OperationID,
	owner install.OwnerBinding,
	key []byte,
) (install.BootstrapKeyRef, error) {
	canonical := append([]byte("agentmemory:linux-file-key-ref:v1\x00"), operationID.String()...)
	canonical = append(canonical, 0)
	canonical = append(canonical, owner.Fingerprint().String()...)
	canonical = append(canonical, 0)
	canonical = append(canonical, key...)
	return install.BootstrapKeyRefFromDigest(install.DigestBytes(canonical))
}

func operationIdentityDigest(operationID install.OperationID) [sha256.Size]byte {
	return sha256.Sum256(append([]byte("agentmemory:operation-id:v1\x00"), operationID.String()...))
}

func keyRefDigest(ref install.BootstrapKeyRef) ([]byte, error) {
	value := ref.String()
	separator := strings.LastIndexByte(value, ':')
	if separator < 0 {
		return nil, fmt.Errorf("%w: operation key reference is invalid", bootstrapport.ErrIntegrity)
	}
	decoded, err := hex.DecodeString(value[separator+1:])
	if err != nil || len(decoded) != sha256.Size {
		return nil, fmt.Errorf("%w: operation key reference is invalid", bootstrapport.ErrIntegrity)
	}
	return decoded, nil
}

func ensureLinuxOperationDirectory(ctx context.Context, directory string) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if err := verifyPrivateDirectory(ctx, directory); err != nil {
		return fmt.Errorf("%w: operation directory is unsafe: %w", bootstrapport.ErrIntegrity, err)
	}
	return nil
}

func readProtectedFile(path string, exactSize int) ([]byte, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, bootstrapport.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: protected bootstrap file is unsafe", bootstrapport.ErrIntegrity)
	}
	if err := verifyCurrentOwner(info, "inspect_bootstrap_file"); err != nil {
		return nil, fmt.Errorf("%w: protected bootstrap file owner is unsafe", bootstrapport.ErrIntegrity)
	}
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: protected bootstrap file cannot be opened", bootstrapport.ErrIntegrity)
	}
	file := os.NewFile(uintptr(descriptor), filepath.Base(path))
	if file == nil {
		_ = syscall.Close(descriptor)
		return nil, fmt.Errorf("%w: protected bootstrap descriptor is invalid", bootstrapport.ErrIntegrity)
	}
	defer func() { _ = file.Close() }()
	contents, err := io.ReadAll(io.LimitReader(file, int64(exactSize+1)))
	if err != nil || len(contents) != exactSize {
		clear(contents)
		return nil, fmt.Errorf("%w: protected bootstrap file size is invalid", bootstrapport.ErrIntegrity)
	}
	return contents, nil
}

func publishProtectedFile(ctx context.Context, path string, contents []byte) (bool, error) {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".bootstrap-key-*.tmp")
	if err != nil {
		return false, err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return false, err
	}
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return false, err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return false, err
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	if err := os.Link(temporaryPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, err
	}
	if err := syncDirectory(ctx, directory); err != nil {
		return false, err
	}
	return true, nil
}
