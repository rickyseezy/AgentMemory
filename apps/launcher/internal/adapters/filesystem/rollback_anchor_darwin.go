//go:build darwin

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
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const darwinAnchorRecordSize = 16 + sha256.Size*5 + 8

var darwinAnchorRecordMagic = [16]byte{'A', 'M', 'R', 'O', 'L', 'L', 'B', 'A', 'C', 'K', 'v', '1'}

// DarwinFileRollbackAnchorStore is the owner-only, ACL-free, HMAC-protected
// macOS implementation of the monotonic rollback-anchor port. The caller must
// still hold the installation's cross-process lock around Advance.
type DarwinFileRollbackAnchorStore struct {
	locator *bootstrapadapter.OperationLocator
	keys    bootstrapport.OperationKeySource
	owners  bootstrapport.OwnerBindingSource
	mu      sync.Mutex
}

var _ bootstrapport.RollbackAnchorStore = (*DarwinFileRollbackAnchorStore)(nil)

// NewDarwinFileRollbackAnchorStore creates the native macOS rollback store.
func NewDarwinFileRollbackAnchorStore(
	locator *bootstrapadapter.OperationLocator,
	keys bootstrapport.OperationKeySource,
	owners bootstrapport.OwnerBindingSource,
) (*DarwinFileRollbackAnchorStore, error) {
	if locator == nil || nilInterface(keys) || nilInterface(owners) {
		return nil, errors.New("macOS rollback anchor requires locator, key source, and owner source")
	}
	return &DarwinFileRollbackAnchorStore{locator: locator, keys: keys, owners: owners}, nil
}

// Load verifies the controlled directory chain, file ownership and ACL, owner
// binding, key reference, and HMAC before returning an anchor.
func (s *DarwinFileRollbackAnchorStore) Load(
	ctx context.Context,
	keyRef install.BootstrapKeyRef,
	operationID install.OperationID,
	owner install.OwnerBinding,
) (install.RollbackAnchor, error) {
	if err := s.verifyOwner(ctx, owner); err != nil {
		return install.RollbackAnchor{}, err
	}
	path, directory, err := s.anchorLocation(operationID)
	if err != nil {
		return install.RollbackAnchor{}, err
	}
	if err := verifyDarwinOperationDirectory(ctx, s.locator.Root(), directory); err != nil {
		return install.RollbackAnchor{}, err
	}
	var result install.RollbackAnchor
	err = s.keys.UseHMACKey(ctx, keyRef, operationID, owner, func(key []byte) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		anchor, readError := readDarwinAnchorRecord(ctx, path, operationID, owner, key)
		result = anchor
		return readError
	})
	return result, err
}

// Advance atomically and durably replaces the exact expected sequence with
// its immediate successor.
func (s *DarwinFileRollbackAnchorStore) Advance(
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
	path, directory, err := s.anchorLocation(next.OperationID())
	if err != nil {
		return err
	}
	if err := ensureDarwinOperationDirectory(ctx, s.locator.Root(), directory); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.keys.UseHMACKey(ctx, keyRef, next.OperationID(), next.Owner(), func(key []byte) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		existing, readError := readDarwinAnchorRecord(ctx, path, next.OperationID(), next.Owner(), key)
		switch {
		case errors.Is(readError, bootstrapport.ErrNotFound) && expectedSequence != 0:
			return bootstrapport.ErrConflict
		case readError != nil && !errors.Is(readError, bootstrapport.ErrNotFound):
			return readError
		case readError == nil && existing.Sequence() != expectedSequence:
			return bootstrapport.ErrConflict
		}
		contents, encodeError := encodeDarwinAnchorRecord(next, key)
		if encodeError != nil {
			return encodeError
		}
		defer clear(contents)
		return replaceDarwinProtectedFile(ctx, path, contents)
	})
}

// ConfirmDurable re-authenticates the exact expected anchor and issues
// F_FULLFSYNC for both the opened file and its descriptor-anchored directory.
func (s *DarwinFileRollbackAnchorStore) ConfirmDurable(
	ctx context.Context,
	keyRef install.BootstrapKeyRef,
	expected install.RollbackAnchor,
) error {
	if err := s.verifyOwner(ctx, expected.Owner()); err != nil {
		return err
	}
	path, directory, err := s.anchorLocation(expected.OperationID())
	if err != nil {
		return err
	}
	if err := verifyDarwinOperationDirectory(ctx, s.locator.Root(), directory); err != nil {
		return err
	}
	return s.keys.UseHMACKey(ctx, keyRef, expected.OperationID(), expected.Owner(), func(key []byte) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		observed, readError := readDarwinAnchorRecord(ctx, path, expected.OperationID(), expected.Owner(), key)
		if readError != nil {
			return readError
		}
		if !sameDarwinRollbackAnchor(observed, expected) {
			return fmt.Errorf("%w: rollback anchor changed before durability confirmation", bootstrapport.ErrIntegrity)
		}
		return syncDarwinProtectedFile(ctx, path)
	})
}

func (s *DarwinFileRollbackAnchorStore) anchorLocation(operationID install.OperationID) (string, string, error) {
	path, err := s.locator.RollbackAnchorPath(operationID)
	if err != nil {
		return "", "", fmt.Errorf("%w: invalid rollback anchor location", bootstrapport.ErrIntegrity)
	}
	directory, err := s.locator.OperationDirectory(operationID)
	if err != nil || filepath.Dir(path) != directory {
		return "", "", fmt.Errorf("%w: rollback anchor escaped its operation directory", bootstrapport.ErrIntegrity)
	}
	return path, directory, nil
}

func (s *DarwinFileRollbackAnchorStore) verifyOwner(ctx context.Context, expected install.OwnerBinding) error {
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

func encodeDarwinAnchorRecord(anchor install.RollbackAnchor, key []byte) ([]byte, error) {
	result := make([]byte, 0, darwinAnchorRecordSize)
	result = append(result, darwinAnchorRecordMagic[:]...)
	operationDigest := darwinAnchorOperationDigest(anchor.OperationID())
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
	result = append(result, authenticator.Sum(nil)...)
	return result, nil
}

func readDarwinAnchorRecord(
	ctx context.Context,
	path string,
	operationID install.OperationID,
	owner install.OwnerBinding,
	key []byte,
) (install.RollbackAnchor, error) {
	contents, err := readDarwinProtectedFile(ctx, path, darwinAnchorRecordSize)
	if err != nil {
		return install.RollbackAnchor{}, err
	}
	defer clear(contents)
	if !bytes.Equal(contents[:16], darwinAnchorRecordMagic[:]) {
		return install.RollbackAnchor{}, fmt.Errorf("%w: rollback anchor format is invalid", bootstrapport.ErrIntegrity)
	}
	offset := 16
	expectedOperation := darwinAnchorOperationDigest(operationID)
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

func darwinAnchorOperationDigest(operationID install.OperationID) [sha256.Size]byte {
	return sha256.Sum256(append([]byte("agentmemory:operation-id:v1\x00"), operationID.String()...))
}

func sameDarwinRollbackAnchor(first, second install.RollbackAnchor) bool {
	return first.OperationID() == second.OperationID() && first.Owner().Equal(second.Owner()) &&
		first.Sequence() == second.Sequence() && first.StateDigest().Equal(second.StateDigest())
}

func readDarwinProtectedFile(ctx context.Context, path string, exactSize int) ([]byte, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, bootstrapport.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 ||
		info.Size() != int64(exactSize) {
		return nil, fmt.Errorf("%w: protected macOS bootstrap file is unsafe", bootstrapport.ErrIntegrity)
	}
	file, err := openVerifiedProtectedObject(ctx, path, info, "open_darwin_bootstrap_file")
	if err != nil {
		return nil, fmt.Errorf("%w: protected macOS bootstrap file proof failed: %w", bootstrapport.ErrIntegrity, err)
	}
	defer func() { _ = file.Close() }()
	contents, err := io.ReadAll(io.LimitReader(file, int64(exactSize+1)))
	if err != nil || len(contents) != exactSize {
		clear(contents)
		return nil, fmt.Errorf("%w: protected macOS bootstrap file size is invalid", bootstrapport.ErrIntegrity)
	}
	openedInfo, statError := file.Stat()
	currentInfo, pathError := os.Lstat(path)
	if statError != nil || pathError != nil || !os.SameFile(openedInfo, currentInfo) {
		clear(contents)
		return nil, fmt.Errorf("%w: protected macOS bootstrap path was substituted", bootstrapport.ErrIntegrity)
	}
	return contents, nil
}

func replaceDarwinProtectedFile(ctx context.Context, path string, contents []byte) error {
	directory := filepath.Dir(path)
	directoryInfo, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if existing, inspectError := os.Lstat(path); inspectError == nil {
		if !existing.Mode().IsRegular() || existing.Mode()&os.ModeSymlink != 0 || existing.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("%w: rollback anchor target is unsafe", bootstrapport.ErrIntegrity)
		}
		opened, openError := openVerifiedProtectedObject(ctx, path, existing, "inspect_darwin_rollback_anchor")
		if openError != nil {
			return fmt.Errorf("%w: rollback anchor target proof failed: %w", bootstrapport.ErrIntegrity, openError)
		}
		if closeError := opened.Close(); closeError != nil {
			return closeError
		}
	} else if !errors.Is(inspectError, os.ErrNotExist) {
		return inspectError
	}

	root, err := os.OpenRoot(directory)
	if err != nil {
		return darwinDirectoryIntegrity("rollback anchor directory cannot be anchored", err)
	}
	defer func() { _ = root.Close() }()
	rootInfo, err := root.Stat(".")
	if err != nil || !os.SameFile(directoryInfo, rootInfo) {
		return darwinDirectoryIntegrity("rollback anchor directory changed while opening", err)
	}
	directoryDescriptor, err := root.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = directoryDescriptor.Close() }()
	if err := verifyOpenedProtectedObject(ctx, directoryDescriptor, directoryInfo, "open_darwin_rollback_directory"); err != nil {
		return darwinDirectoryIntegrity("rollback anchor directory proof failed", err)
	}
	temporary, temporaryName, err := createProtectedRootTemporary(ctx, root, ".rollback-anchor-")
	if err != nil {
		return err
	}
	temporaryOpen := true
	defer func() {
		if temporaryOpen {
			_ = temporary.Close()
		}
		_ = root.Remove(temporaryName)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if err := verifyOpenedProtectedObject(ctx, temporary, nil, "protect_darwin_rollback_temporary"); err != nil {
		return darwinDirectoryIntegrity("rollback anchor temporary proof failed", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		return err
	}
	if err := platformDurableSync(temporary); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	temporaryOpen = false
	if err := root.Rename(temporaryName, filepath.Base(path)); err != nil {
		return err
	}
	if err := platformDurableSync(directoryDescriptor); err != nil {
		return err
	}
	currentDirectoryInfo, err := os.Lstat(directory)
	if err != nil || !os.SameFile(directoryInfo, currentDirectoryInfo) {
		return darwinDirectoryIntegrity("rollback anchor directory path was substituted", err)
	}
	return verifyDarwinProtectedPath(ctx, path, contents)
}

func verifyDarwinProtectedPath(ctx context.Context, path string, expectedContents []byte) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	file, err := openVerifiedProtectedObject(ctx, path, info, "verify_darwin_protected_path")
	if err != nil {
		return darwinDirectoryIntegrity("protected replacement proof failed", err)
	}
	defer func() { _ = file.Close() }()
	observed, err := io.ReadAll(io.LimitReader(file, int64(len(expectedContents)+1)))
	if err != nil {
		clear(observed)
		return err
	}
	defer clear(observed)
	if !hmac.Equal(observed, expectedContents) {
		return fmt.Errorf("%w: protected replacement contents changed", bootstrapport.ErrIntegrity)
	}
	return nil
}

func syncDarwinProtectedFile(ctx context.Context, path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	file, err := openVerifiedProtectedObject(ctx, path, info, "confirm_darwin_rollback_anchor")
	if err != nil {
		return fmt.Errorf("%w: rollback anchor durability proof failed: %w", bootstrapport.ErrIntegrity, err)
	}
	if err := platformDurableSync(file); err != nil {
		_ = file.Close()
		return err
	}
	openedInfo, statError := file.Stat()
	if closeError := file.Close(); closeError != nil {
		return closeError
	}
	currentInfo, pathError := os.Lstat(path)
	if statError != nil || pathError != nil || !os.SameFile(openedInfo, currentInfo) {
		return fmt.Errorf("%w: rollback anchor path was substituted during durability confirmation", bootstrapport.ErrIntegrity)
	}
	return syncDirectory(ctx, filepath.Dir(path))
}
