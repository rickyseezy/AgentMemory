//go:build linux

package filesystem

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const linuxAnchorRecordSize = 16 + sha256.Size*5 + 8

var linuxAnchorRecordMagic = [16]byte{'A', 'M', 'R', 'O', 'L', 'L', 'B', 'A', 'C', 'K', 'v', '1'}

// LinuxFileRollbackAnchorStore is the owner-only, HMAC-protected Linux file
// implementation of the monotonic rollback-anchor port. A cross-process
// installation lock is still mandatory around Advance.
type LinuxFileRollbackAnchorStore struct {
	locator *bootstrapadapter.OperationLocator
	keys    bootstrapport.OperationKeySource
	owners  bootstrapport.OwnerBindingSource
	mu      sync.Mutex
}

var _ bootstrapport.RollbackAnchorStore = (*LinuxFileRollbackAnchorStore)(nil)

// NewLinuxFileRollbackAnchorStore creates the Linux anchor adapter.
func NewLinuxFileRollbackAnchorStore(
	locator *bootstrapadapter.OperationLocator,
	keys bootstrapport.OperationKeySource,
	owners bootstrapport.OwnerBindingSource,
) (*LinuxFileRollbackAnchorStore, error) {
	if locator == nil || nilInterface(keys) || nilInterface(owners) {
		return nil, errors.New("linux rollback anchor requires locator, key source, and owner source")
	}
	return &LinuxFileRollbackAnchorStore{locator: locator, keys: keys, owners: owners}, nil
}

// Load verifies filesystem protection, owner/machine binding, key binding, and
// the anchor HMAC before returning state.
func (s *LinuxFileRollbackAnchorStore) Load(
	ctx context.Context,
	keyRef install.BootstrapKeyRef,
	operationID install.OperationID,
	owner install.OwnerBinding,
) (install.RollbackAnchor, error) {
	if err := s.verifyOwner(ctx, owner); err != nil {
		return install.RollbackAnchor{}, err
	}
	path, err := s.locator.RollbackAnchorPath(operationID)
	if err != nil {
		return install.RollbackAnchor{}, fmt.Errorf("%w: invalid rollback anchor location", bootstrapport.ErrIntegrity)
	}
	var result install.RollbackAnchor
	err = s.keys.UseHMACKey(ctx, keyRef, operationID, owner, func(key []byte) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		anchor, readError := readLinuxAnchorRecord(path, operationID, owner, key)
		result = anchor
		return readError
	})
	return result, err
}

// Advance atomically replaces the exact expected sequence with its successor.
func (s *LinuxFileRollbackAnchorStore) Advance(
	ctx context.Context,
	keyRef install.BootstrapKeyRef,
	expectedSequence uint64,
	next install.RollbackAnchor,
) error {
	if expectedSequence == math.MaxUint64 || next.Sequence() != expectedSequence+1 {
		return fmt.Errorf("%w: rollback anchor is not the next sequence", bootstrapport.ErrConflict)
	}
	if err := s.verifyOwner(ctx, next.Owner()); err != nil {
		return err
	}
	path, err := s.locator.RollbackAnchorPath(next.OperationID())
	if err != nil {
		return fmt.Errorf("%w: invalid rollback anchor location", bootstrapport.ErrIntegrity)
	}
	if err := ensureLinuxOperationDirectory(ctx, filepath.Dir(path)); err != nil {
		return err
	}
	return s.keys.UseHMACKey(ctx, keyRef, next.OperationID(), next.Owner(), func(key []byte) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		existing, readError := readLinuxAnchorRecord(path, next.OperationID(), next.Owner(), key)
		switch {
		case errors.Is(readError, bootstrapport.ErrNotFound) && expectedSequence != 0:
			return bootstrapport.ErrConflict
		case readError != nil && !errors.Is(readError, bootstrapport.ErrNotFound):
			return readError
		case readError == nil && existing.Sequence() != expectedSequence:
			return bootstrapport.ErrConflict
		}
		contents, encodeError := encodeLinuxAnchorRecord(next, key)
		if encodeError != nil {
			return encodeError
		}
		defer clear(contents)
		return replaceProtectedFile(ctx, path, contents)
	})
}

// ConfirmDurable re-authenticates the exact anchor, synchronizes its opened
// descriptor, and then synchronizes the containing directory. This resolves a
// prior ambiguous post-rename error without treating a different sequence as
// an idempotent success.
func (s *LinuxFileRollbackAnchorStore) ConfirmDurable(
	ctx context.Context,
	keyRef install.BootstrapKeyRef,
	expected install.RollbackAnchor,
) error {
	if err := s.verifyOwner(ctx, expected.Owner()); err != nil {
		return err
	}
	path, err := s.locator.RollbackAnchorPath(expected.OperationID())
	if err != nil {
		return fmt.Errorf("%w: invalid rollback anchor location", bootstrapport.ErrIntegrity)
	}
	return s.keys.UseHMACKey(ctx, keyRef, expected.OperationID(), expected.Owner(), func(key []byte) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		observed, readError := readLinuxAnchorRecord(path, expected.OperationID(), expected.Owner(), key)
		if readError != nil {
			return readError
		}
		if !sameLinuxRollbackAnchor(observed, expected) {
			return fmt.Errorf("%w: rollback anchor changed before durability confirmation", bootstrapport.ErrIntegrity)
		}
		return syncProtectedAnchor(ctx, path)
	})
}

func (s *LinuxFileRollbackAnchorStore) verifyOwner(ctx context.Context, expected install.OwnerBinding) error {
	if expected.IsZero() {
		return fmt.Errorf("%w: rollback anchor owner is absent", bootstrapport.ErrIntegrity)
	}
	current, err := s.owners.Current(ctx)
	if err != nil {
		return err
	}
	if !current.Equal(expected) {
		return fmt.Errorf("%w: rollback anchor machine or principal changed", bootstrapport.ErrIntegrity)
	}
	return nil
}

func encodeLinuxAnchorRecord(anchor install.RollbackAnchor, key []byte) ([]byte, error) {
	result := make([]byte, 0, linuxAnchorRecordSize)
	result = append(result, linuxAnchorRecordMagic[:]...)
	operationDigest := operationIdentityDigest(anchor.OperationID())
	result = append(result, operationDigest[:]...)
	machine, err := hex.DecodeString(anchor.Owner().MachineDigest().String())
	if err != nil {
		return nil, err
	}
	principal, err := hex.DecodeString(anchor.Owner().PrincipalDigest().String())
	if err != nil {
		return nil, err
	}
	state, err := hex.DecodeString(anchor.StateDigest().String())
	if err != nil {
		return nil, err
	}
	result = append(result, machine...)
	result = append(result, principal...)
	sequence := make([]byte, 8)
	binary.BigEndian.PutUint64(sequence, anchor.Sequence())
	result = append(result, sequence...)
	result = append(result, state...)
	authenticator := hmac.New(sha256.New, key)
	_, _ = authenticator.Write(anchor.CanonicalBytes())
	result = append(result, authenticator.Sum(nil)...)
	return result, nil
}

func readLinuxAnchorRecord(
	path string,
	operationID install.OperationID,
	owner install.OwnerBinding,
	key []byte,
) (install.RollbackAnchor, error) {
	contents, err := readProtectedFile(path, linuxAnchorRecordSize)
	if err != nil {
		return install.RollbackAnchor{}, err
	}
	defer clear(contents)
	if !bytes.Equal(contents[:16], linuxAnchorRecordMagic[:]) {
		return install.RollbackAnchor{}, fmt.Errorf("%w: rollback anchor format is invalid", bootstrapport.ErrIntegrity)
	}
	offset := 16
	expectedOperation := operationIdentityDigest(operationID)
	if !hmac.Equal(contents[offset:offset+sha256.Size], expectedOperation[:]) {
		return install.RollbackAnchor{}, fmt.Errorf("%w: rollback anchor operation changed", bootstrapport.ErrIntegrity)
	}
	offset += sha256.Size
	machine := hex.EncodeToString(contents[offset : offset+sha256.Size])
	offset += sha256.Size
	principal := hex.EncodeToString(contents[offset : offset+sha256.Size])
	offset += sha256.Size
	persistedOwner, err := install.RestoreOwnerBinding(machine, principal)
	if err != nil || !persistedOwner.Equal(owner) {
		return install.RollbackAnchor{}, fmt.Errorf("%w: rollback anchor owner changed", bootstrapport.ErrIntegrity)
	}
	sequence := binary.BigEndian.Uint64(contents[offset : offset+8])
	offset += 8
	stateDigest, err := install.ParseDigest(hex.EncodeToString(contents[offset : offset+sha256.Size]))
	if err != nil {
		return install.RollbackAnchor{}, fmt.Errorf("%w: rollback anchor state digest is invalid", bootstrapport.ErrIntegrity)
	}
	offset += sha256.Size
	anchor, err := install.NewRollbackAnchor(operationID, owner, sequence, stateDigest)
	if err != nil {
		return install.RollbackAnchor{}, fmt.Errorf("%w: rollback anchor violates invariants", bootstrapport.ErrIntegrity)
	}
	authenticator := hmac.New(sha256.New, key)
	_, _ = authenticator.Write(anchor.CanonicalBytes())
	if !hmac.Equal(contents[offset:offset+sha256.Size], authenticator.Sum(nil)) {
		return install.RollbackAnchor{}, fmt.Errorf("%w: rollback anchor authentication failed", bootstrapport.ErrIntegrity)
	}
	return anchor, nil
}

func sameLinuxRollbackAnchor(first, second install.RollbackAnchor) bool {
	return first.OperationID() == second.OperationID() && first.Owner().Equal(second.Owner()) &&
		first.Sequence() == second.Sequence() && first.StateDigest().Equal(second.StateDigest())
}

func syncProtectedAnchor(ctx context.Context, path string) error {
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(descriptor), filepath.Base(path))
	if file == nil {
		_ = syscall.Close(descriptor)
		return fmt.Errorf("%w: rollback anchor descriptor is invalid", bootstrapport.ErrIntegrity)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: rollback anchor is unsafe", bootstrapport.ErrIntegrity)
	}
	if err := verifyCurrentOwner(info, "confirm_rollback_anchor"); err != nil {
		return fmt.Errorf("%w: rollback anchor owner is unsafe", bootstrapport.ErrIntegrity)
	}
	if err := file.Sync(); err != nil {
		return err
	}
	return syncDirectory(ctx, filepath.Dir(path))
}

func replaceProtectedFile(ctx context.Context, path string, contents []byte) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("%w: rollback anchor target is unsafe", bootstrapport.ErrIntegrity)
		}
		if err := verifyCurrentOwner(info, "inspect_rollback_anchor"); err != nil {
			return fmt.Errorf("%w: rollback anchor owner is unsafe", bootstrapport.ErrIntegrity)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".rollback-anchor-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncDirectory(ctx, directory)
}
