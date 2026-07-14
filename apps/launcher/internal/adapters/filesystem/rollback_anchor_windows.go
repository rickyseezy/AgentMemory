//go:build windows

package filesystem

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const windowsAnchorRecordSize = 16 + sha256.Size*5 + 8

var windowsAnchorRecordMagic = [16]byte{'A', 'M', 'R', 'O', 'L', 'L', 'B', 'A', 'C', 'K', 'v', '1'}

// WindowsFileRollbackAnchorStore is the protected-DACL, HMAC-authenticated
// monotonic anchor implementation. Callers still hold the machine-global lock
// around Advance.
type WindowsFileRollbackAnchorStore struct {
	locator *bootstrapadapter.OperationLocator
	keys    bootstrapport.OperationKeySource
	owners  bootstrapport.OwnerBindingSource
	mu      sync.Mutex
}

var _ bootstrapport.RollbackAnchorStore = (*WindowsFileRollbackAnchorStore)(nil)

// NewWindowsFileRollbackAnchorStore creates the Windows rollback adapter.
func NewWindowsFileRollbackAnchorStore(
	locator *bootstrapadapter.OperationLocator,
	keys bootstrapport.OperationKeySource,
	owners bootstrapport.OwnerBindingSource,
) (*WindowsFileRollbackAnchorStore, error) {
	if locator == nil || nilInterface(keys) || nilInterface(owners) {
		return nil, errors.New("windows rollback anchor requires locator, key source, and owner source")
	}
	return &WindowsFileRollbackAnchorStore{locator: locator, keys: keys, owners: owners}, nil
}

// Load authenticates and returns the current owner-bound monotonic anchor.
func (s *WindowsFileRollbackAnchorStore) Load(
	ctx context.Context,
	keyRef install.BootstrapKeyRef,
	operationID install.OperationID,
	owner install.OwnerBinding,
) (install.RollbackAnchor, error) {
	if err := s.verifyOwner(ctx, owner); err != nil {
		return install.RollbackAnchor{}, err
	}
	path, directory, err := s.location(operationID)
	if err != nil {
		return install.RollbackAnchor{}, err
	}
	var result install.RollbackAnchor
	err = windowssecurity.WithOperationDirectory(ctx, s.locator.Root(), directory, false, func() error {
		return s.keys.UseHMACKey(ctx, keyRef, operationID, owner, func(key []byte) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			anchor, readError := readWindowsAnchorRecord(ctx, path, operationID, owner, key)
			result = anchor
			return readError
		})
	})
	if errors.Is(err, os.ErrNotExist) {
		return install.RollbackAnchor{}, bootstrapport.ErrNotFound
	}
	return result, err
}

// Advance performs a compare-and-swap transition to the next anchor sequence.
func (s *WindowsFileRollbackAnchorStore) Advance(
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
	path, directory, err := s.location(next.OperationID())
	if err != nil {
		return err
	}
	return windowssecurity.WithOperationDirectory(ctx, s.locator.Root(), directory, true, func() error {
		return s.keys.UseHMACKey(ctx, keyRef, next.OperationID(), next.Owner(), func(key []byte) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			existing, readError := readWindowsAnchorRecord(ctx, path, next.OperationID(), next.Owner(), key)
			switch {
			case errors.Is(readError, bootstrapport.ErrNotFound) && expectedSequence != 0:
				return bootstrapport.ErrConflict
			case readError != nil && !errors.Is(readError, bootstrapport.ErrNotFound):
				return readError
			case readError == nil && existing.Sequence() != expectedSequence:
				return bootstrapport.ErrConflict
			}
			contents, encodeError := encodeWindowsAnchorRecord(next, key)
			if encodeError != nil {
				return encodeError
			}
			defer clear(contents)
			return replaceWindowsProtectedAnchor(ctx, path, contents)
		})
	})
}

// ConfirmDurable re-authenticates and flushes the anchor and parent directory.
func (s *WindowsFileRollbackAnchorStore) ConfirmDurable(
	ctx context.Context,
	keyRef install.BootstrapKeyRef,
	expected install.RollbackAnchor,
) error {
	if err := s.verifyOwner(ctx, expected.Owner()); err != nil {
		return err
	}
	path, directory, err := s.location(expected.OperationID())
	if err != nil {
		return err
	}
	return windowssecurity.WithOperationDirectory(ctx, s.locator.Root(), directory, false, func() error {
		return s.keys.UseHMACKey(ctx, keyRef, expected.OperationID(), expected.Owner(), func(key []byte) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			observed, readError := readWindowsAnchorRecord(ctx, path, expected.OperationID(), expected.Owner(), key)
			if readError != nil {
				return readError
			}
			if !sameWindowsRollbackAnchor(observed, expected) {
				return fmt.Errorf("%w: rollback anchor changed before durability confirmation", bootstrapport.ErrIntegrity)
			}
			file, identity, openError := windowssecurity.OpenVerified(ctx, path, false, true, true)
			if openError != nil {
				return windowsAnchorIntegrity("durability handle proof failed", openError)
			}
			if syncError := windowssecurity.Flush(file); syncError != nil {
				_ = file.Close()
				return syncError
			}
			if pathError := windowssecurity.VerifyPathIdentity(ctx, path, identity, true); pathError != nil {
				_ = file.Close()
				return windowsAnchorIntegrity("anchor path changed during durability confirmation", pathError)
			}
			if closeError := file.Close(); closeError != nil {
				return closeError
			}
			parent, parentIdentity, parentError := windowssecurity.OpenVerified(ctx, filepath.Dir(path), true, true, true)
			if parentError != nil {
				return parentError
			}
			if syncError := windowssecurity.Flush(parent); syncError != nil {
				_ = parent.Close()
				return syncError
			}
			if closeError := parent.Close(); closeError != nil {
				return closeError
			}
			return windowssecurity.VerifyPathIdentity(ctx, filepath.Dir(path), parentIdentity, true)
		})
	})
}

func (s *WindowsFileRollbackAnchorStore) location(operationID install.OperationID) (string, string, error) {
	path, err := s.locator.RollbackAnchorPath(operationID)
	if err != nil {
		return "", "", fmt.Errorf("%w: invalid Windows rollback anchor location", bootstrapport.ErrIntegrity)
	}
	directory, err := s.locator.OperationDirectory(operationID)
	if err != nil || filepath.Dir(path) != directory {
		return "", "", fmt.Errorf("%w: Windows rollback anchor escaped its operation directory", bootstrapport.ErrIntegrity)
	}
	return path, directory, nil
}

func (s *WindowsFileRollbackAnchorStore) verifyOwner(ctx context.Context, owner install.OwnerBinding) error {
	if owner.IsZero() {
		return fmt.Errorf("%w: Windows rollback anchor owner is absent", bootstrapport.ErrIntegrity)
	}
	current, err := s.owners.Current(ctx)
	if err != nil {
		return err
	}
	if !current.Equal(owner) {
		return fmt.Errorf("%w: Windows rollback anchor machine or SID changed", bootstrapport.ErrIntegrity)
	}
	return nil
}

func encodeWindowsAnchorRecord(anchor install.RollbackAnchor, key []byte) ([]byte, error) {
	result := make([]byte, 0, windowsAnchorRecordSize)
	result = append(result, windowsAnchorRecordMagic[:]...)
	operationDigest := windowsAnchorOperationDigest(anchor.OperationID())
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
	var sequence [8]byte
	binary.BigEndian.PutUint64(sequence[:], anchor.Sequence())
	result = append(result, sequence[:]...)
	result = append(result, state...)
	authenticator := hmac.New(sha256.New, key)
	_, _ = authenticator.Write(anchor.CanonicalBytes())
	return append(result, authenticator.Sum(nil)...), nil
}

func readWindowsAnchorRecord(
	ctx context.Context,
	path string,
	operationID install.OperationID,
	owner install.OwnerBinding,
	key []byte,
) (install.RollbackAnchor, error) {
	contents, err := readWindowsProtectedFile(ctx, path, windowsAnchorRecordSize)
	if err != nil {
		return install.RollbackAnchor{}, err
	}
	defer clear(contents)
	if !bytes.Equal(contents[:16], windowsAnchorRecordMagic[:]) {
		return install.RollbackAnchor{}, windowsAnchorIntegrity("record format is invalid", nil)
	}
	offset := 16
	expectedOperation := windowsAnchorOperationDigest(operationID)
	if !hmac.Equal(contents[offset:offset+sha256.Size], expectedOperation[:]) {
		return install.RollbackAnchor{}, windowsAnchorIntegrity("operation binding changed", nil)
	}
	offset += sha256.Size
	machine := hex.EncodeToString(contents[offset : offset+sha256.Size])
	offset += sha256.Size
	principal := hex.EncodeToString(contents[offset : offset+sha256.Size])
	offset += sha256.Size
	persistedOwner, err := install.RestoreOwnerBinding(machine, principal)
	if err != nil || !persistedOwner.Equal(owner) {
		return install.RollbackAnchor{}, windowsAnchorIntegrity("owner binding changed", err)
	}
	sequence := binary.BigEndian.Uint64(contents[offset : offset+8])
	offset += 8
	stateDigest, err := install.ParseDigest(hex.EncodeToString(contents[offset : offset+sha256.Size]))
	if err != nil {
		return install.RollbackAnchor{}, windowsAnchorIntegrity("state digest is invalid", err)
	}
	offset += sha256.Size
	anchor, err := install.NewRollbackAnchor(operationID, owner, sequence, stateDigest)
	if err != nil {
		return install.RollbackAnchor{}, windowsAnchorIntegrity("record violates anchor invariants", err)
	}
	authenticator := hmac.New(sha256.New, key)
	_, _ = authenticator.Write(anchor.CanonicalBytes())
	if !hmac.Equal(contents[offset:offset+sha256.Size], authenticator.Sum(nil)) {
		return install.RollbackAnchor{}, windowsAnchorIntegrity("record authentication failed", nil)
	}
	return anchor, nil
}

func readWindowsProtectedFile(ctx context.Context, path string, exactSize int) ([]byte, error) {
	file, identity, err := windowssecurity.OpenVerified(ctx, path, false, false, true)
	if errors.Is(err, os.ErrNotExist) {
		return nil, bootstrapport.ErrNotFound
	}
	if err != nil {
		return nil, windowsAnchorIntegrity("protected file proof failed", err)
	}
	contents, readError := io.ReadAll(io.LimitReader(file, int64(exactSize+1)))
	if readError != nil || len(contents) != exactSize {
		clear(contents)
		_ = file.Close()
		return nil, windowsAnchorIntegrity("protected file size is invalid", readError)
	}
	if err := windowssecurity.VerifyPathIdentity(ctx, path, identity, true); err != nil {
		clear(contents)
		_ = file.Close()
		return nil, windowsAnchorIntegrity("protected file path changed", err)
	}
	if closeError := file.Close(); closeError != nil {
		clear(contents)
		return nil, closeError
	}
	return contents, nil
}

func replaceWindowsProtectedAnchor(ctx context.Context, path string, contents []byte) error {
	targetExists := false
	if _, err := os.Lstat(path); err == nil {
		target, _, openError := windowssecurity.OpenVerified(ctx, path, false, false, true)
		if openError != nil {
			return windowsAnchorIntegrity("existing anchor proof failed", openError)
		}
		if closeError := target.Close(); closeError != nil {
			return closeError
		}
		targetExists = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var randomBytes [12]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		return err
	}
	temporaryPath := filepath.Join(filepath.Dir(path), ".rollback-anchor-"+hex.EncodeToString(randomBytes[:])+".tmp")
	temporary, err := windowssecurity.CreatePrivateFile(ctx, temporaryPath)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(temporaryPath) }()
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := windowssecurity.Flush(temporary); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := windowssecurity.AtomicReplace(ctx, temporaryPath, path, targetExists); err != nil {
		return err
	}
	observed, err := readWindowsProtectedFile(ctx, path, len(contents))
	if err != nil {
		return err
	}
	defer clear(observed)
	if !hmac.Equal(observed, contents) {
		return windowsAnchorIntegrity("replacement contents changed", nil)
	}
	return nil
}

func windowsAnchorOperationDigest(operationID install.OperationID) [sha256.Size]byte {
	return sha256.Sum256(append([]byte("agentmemory:operation-id:v1\x00"), operationID.String()...))
}

func sameWindowsRollbackAnchor(first, second install.RollbackAnchor) bool {
	return first.OperationID() == second.OperationID() && first.Owner().Equal(second.Owner()) &&
		first.Sequence() == second.Sequence() && first.StateDigest().Equal(second.StateDigest())
}

func windowsAnchorIntegrity(message string, cause error) error {
	if cause == nil {
		return fmt.Errorf("%w: Windows rollback anchor %s", bootstrapport.ErrIntegrity, message)
	}
	return fmt.Errorf("%w: Windows rollback anchor %s: %w", bootstrapport.ErrIntegrity, message, cause)
}
