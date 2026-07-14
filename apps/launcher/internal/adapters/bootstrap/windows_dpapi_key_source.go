//go:build windows

package bootstrap

import (
	"bytes"
	"context"
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

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const (
	windowsPlainKeyRecordSize    = 16 + sha256.Size*5
	maximumWindowsProtectedBytes = 5 * 512
)

var windowsPlainKeyRecordMagic = [16]byte{'A', 'M', 'D', 'P', 'A', 'P', 'I', 'K', 'E', 'Y', 'v', '1'}

type windowsDPAPICapability interface {
	Protect(context.Context, []byte, []byte) ([]byte, error)
	Unprotect(context.Context, []byte, []byte) ([]byte, error)
}

type windowsKeyRecordStore interface {
	Load(context.Context, install.OperationID) ([]byte, error)
	Publish(context.Context, install.OperationID, []byte) (bool, error)
}

type windowsOperationLock interface {
	WithExclusive(
		context.Context,
		install.OperationID,
		install.OwnerBinding,
		func() error,
	) error
}

// WindowsDPAPIOperationKeySource persists only user-scoped DPAPI ciphertext in
// the invoking user's non-roaming Windows Credential Manager set. Plaintext
// key bytes exist only in bounded callback copies and are cleared on return.
type WindowsDPAPIOperationKeySource struct {
	owners  bootstrapport.OwnerBindingSource
	dpapi   windowsDPAPICapability
	store   windowsKeyRecordStore
	entropy io.Reader
	locks   windowsOperationLock
	mu      sync.Mutex
}

var _ bootstrapport.OperationKeySource = (*WindowsDPAPIOperationKeySource)(nil)

// NewWindowsDPAPIOperationKeySource creates the native Windows key source.
func NewWindowsDPAPIOperationKeySource(
	locator *OperationLocator,
	owners bootstrapport.OwnerBindingSource,
) (*WindowsDPAPIOperationKeySource, error) {
	if locator == nil {
		return nil, errors.New("windows DPAPI key source requires an operation locator")
	}
	return newWindowsDPAPIOperationKeySource(
		owners,
		windowsNativeDPAPI{},
		&windowsCredentialKeyRecordStore{locator: locator},
		rand.Reader,
		windowsNativeOperationLock{},
	)
}

func newWindowsDPAPIOperationKeySource(
	owners bootstrapport.OwnerBindingSource,
	dpapi windowsDPAPICapability,
	store windowsKeyRecordStore,
	entropy io.Reader,
	locks windowsOperationLock,
) (*WindowsDPAPIOperationKeySource, error) {
	if nilDependency(owners) || nilDependency(dpapi) || nilDependency(store) ||
		nilDependency(entropy) || nilDependency(locks) {
		return nil, errors.New("windows DPAPI key source requires owner, DPAPI, credential store, entropy, and lock capabilities")
	}
	return &WindowsDPAPIOperationKeySource{
		owners:  owners,
		dpapi:   dpapi,
		store:   store,
		entropy: entropy,
		locks:   locks,
	}, nil
}

// Ensure creates exactly one protected operation key and converges on the
// atomically published winner across concurrent launcher processes.
func (s *WindowsDPAPIOperationKeySource) Ensure(
	ctx context.Context,
	operationID install.OperationID,
	owner install.OwnerBinding,
) (install.BootstrapKeyRef, error) {
	if err := s.verifyOwner(ctx, owner); err != nil {
		return install.BootstrapKeyRef{}, err
	}
	if operationID.IsZero() {
		return install.BootstrapKeyRef{}, fmt.Errorf("%w: operation identity is absent", bootstrapport.ErrIntegrity)
	}
	var result install.BootstrapKeyRef
	err := s.locks.WithExclusive(ctx, operationID, owner, func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		resolved, ensureError := s.ensureExclusive(ctx, operationID, owner)
		result = resolved
		return ensureError
	})
	return result, err
}

func (s *WindowsDPAPIOperationKeySource) ensureExclusive(
	ctx context.Context,
	operationID install.OperationID,
	owner install.OwnerBinding,
) (install.BootstrapKeyRef, error) {
	if existing, err := s.loadRecord(ctx, operationID, owner); err == nil {
		defer clear(existing.key[:])
		return existing.ref, nil
	} else if !errors.Is(err, bootstrapport.ErrNotFound) {
		return install.BootstrapKeyRef{}, err
	}

	var key [sha256.Size]byte
	if _, err := io.ReadFull(s.entropy, key[:]); err != nil {
		return install.BootstrapKeyRef{}, errors.New("generate Windows operation HMAC key")
	}
	defer clear(key[:])
	ref, err := keyReference(operationID, owner, key[:])
	if err != nil {
		return install.BootstrapKeyRef{}, err
	}
	plaintext, err := encodeWindowsPlainKeyRecord(operationID, owner, ref, key)
	if err != nil {
		return install.BootstrapKeyRef{}, err
	}
	defer clear(plaintext)
	entropy := windowsDPAPIEntropy(operationID, owner)
	protected, err := s.dpapi.Protect(ctx, plaintext, entropy[:])
	if err != nil {
		return install.BootstrapKeyRef{}, err
	}
	defer clear(protected)
	published, err := s.store.Publish(ctx, operationID, protected)
	if err != nil {
		return install.BootstrapKeyRef{}, err
	}
	if published {
		return ref, nil
	}
	winner, err := s.loadRecord(ctx, operationID, owner)
	if err != nil {
		return install.BootstrapKeyRef{}, err
	}
	defer clear(winner.key[:])
	return winner.ref, nil
}

// UseHMACKey decrypts, authenticates, binds, and clears one callback copy.
func (s *WindowsDPAPIOperationKeySource) UseHMACKey(
	ctx context.Context,
	keyRef install.BootstrapKeyRef,
	operationID install.OperationID,
	owner install.OwnerBinding,
	consumer bootstrapport.OperationKeyConsumer,
) error {
	if keyRef.IsZero() || operationID.IsZero() || owner.IsZero() || consumer == nil {
		return fmt.Errorf("%w: complete Windows key binding is required", bootstrapport.ErrIntegrity)
	}
	if err := s.verifyOwner(ctx, owner); err != nil {
		return err
	}
	s.mu.Lock()
	record, err := s.loadRecord(ctx, operationID, owner)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	defer clear(record.key[:])
	if !record.ref.Equal(keyRef) {
		return fmt.Errorf("%w: Windows DPAPI key reference changed", bootstrapport.ErrIntegrity)
	}
	key := append([]byte(nil), record.key[:]...)
	defer clear(key)
	return consumer(key)
}

func (s *WindowsDPAPIOperationKeySource) loadRecord(
	ctx context.Context,
	operationID install.OperationID,
	owner install.OwnerBinding,
) (windowsPlainKeyRecord, error) {
	protected, err := s.store.Load(ctx, operationID)
	if err != nil {
		return windowsPlainKeyRecord{}, err
	}
	defer clear(protected)
	entropy := windowsDPAPIEntropy(operationID, owner)
	plaintext, err := s.dpapi.Unprotect(ctx, protected, entropy[:])
	if err != nil {
		return windowsPlainKeyRecord{}, fmt.Errorf("%w: Windows DPAPI record cannot be authenticated: %w", bootstrapport.ErrIntegrity, err)
	}
	defer clear(plaintext)
	return decodeWindowsPlainKeyRecord(plaintext, operationID, owner)
}

func (s *WindowsDPAPIOperationKeySource) verifyOwner(ctx context.Context, owner install.OwnerBinding) error {
	if owner.IsZero() {
		return fmt.Errorf("%w: Windows key owner is absent", bootstrapport.ErrIntegrity)
	}
	current, err := s.owners.Current(ctx)
	if err != nil {
		return err
	}
	if !current.Equal(owner) {
		return fmt.Errorf("%w: Windows machine or invoking SID changed", bootstrapport.ErrIntegrity)
	}
	return nil
}

type windowsPlainKeyRecord struct {
	ref install.BootstrapKeyRef
	key [sha256.Size]byte
}

func encodeWindowsPlainKeyRecord(
	operationID install.OperationID,
	owner install.OwnerBinding,
	ref install.BootstrapKeyRef,
	key [sha256.Size]byte,
) ([]byte, error) {
	result := make([]byte, 0, windowsPlainKeyRecordSize)
	result = append(result, windowsPlainKeyRecordMagic[:]...)
	operationDigest := windowsOperationIdentityDigest(operationID)
	result = append(result, operationDigest[:]...)
	machine, _ := hex.DecodeString(owner.MachineDigest().String())
	principal, _ := hex.DecodeString(owner.PrincipalDigest().String())
	refDigest, err := windowsKeyRefDigest(ref)
	if err != nil {
		return nil, err
	}
	result = append(result, machine...)
	result = append(result, principal...)
	result = append(result, refDigest...)
	result = append(result, key[:]...)
	return result, nil
}

func decodeWindowsPlainKeyRecord(
	contents []byte,
	operationID install.OperationID,
	owner install.OwnerBinding,
) (windowsPlainKeyRecord, error) {
	if len(contents) != windowsPlainKeyRecordSize || !bytes.Equal(contents[:16], windowsPlainKeyRecordMagic[:]) {
		return windowsPlainKeyRecord{}, fmt.Errorf("%w: Windows DPAPI record format is invalid", bootstrapport.ErrIntegrity)
	}
	offset := 16
	operationDigest := windowsOperationIdentityDigest(operationID)
	if !bytes.Equal(contents[offset:offset+sha256.Size], operationDigest[:]) {
		return windowsPlainKeyRecord{}, fmt.Errorf("%w: Windows DPAPI operation changed", bootstrapport.ErrIntegrity)
	}
	offset += sha256.Size
	machine, _ := hex.DecodeString(owner.MachineDigest().String())
	if !bytes.Equal(contents[offset:offset+sha256.Size], machine) {
		return windowsPlainKeyRecord{}, fmt.Errorf("%w: Windows DPAPI machine changed", bootstrapport.ErrIntegrity)
	}
	offset += sha256.Size
	principal, _ := hex.DecodeString(owner.PrincipalDigest().String())
	if !bytes.Equal(contents[offset:offset+sha256.Size], principal) {
		return windowsPlainKeyRecord{}, fmt.Errorf("%w: Windows DPAPI principal changed", bootstrapport.ErrIntegrity)
	}
	offset += sha256.Size
	persistedRefDigest := contents[offset : offset+sha256.Size]
	offset += sha256.Size
	var key [sha256.Size]byte
	copy(key[:], contents[offset:offset+sha256.Size])
	ref, err := keyReference(operationID, owner, key[:])
	if err != nil {
		clear(key[:])
		return windowsPlainKeyRecord{}, err
	}
	computedRefDigest, _ := windowsKeyRefDigest(ref)
	if !bytes.Equal(persistedRefDigest, computedRefDigest) {
		clear(key[:])
		return windowsPlainKeyRecord{}, fmt.Errorf("%w: Windows DPAPI record was modified", bootstrapport.ErrIntegrity)
	}
	return windowsPlainKeyRecord{ref: ref, key: key}, nil
}

func windowsDPAPIEntropy(operationID install.OperationID, owner install.OwnerBinding) [sha256.Size]byte {
	value := append([]byte("agentmemory:windows-dpapi-entropy:v1\x00"), operationID.String()...)
	value = append(value, 0)
	value = append(value, owner.Fingerprint().String()...)
	return sha256.Sum256(value)
}

func windowsOperationIdentityDigest(operationID install.OperationID) [sha256.Size]byte {
	return sha256.Sum256(append([]byte("agentmemory:windows-dpapi-operation:v1\x00"), operationID.String()...))
}

func windowsKeyRefDigest(ref install.BootstrapKeyRef) ([]byte, error) {
	value := ref.String()
	separator := strings.LastIndexByte(value, ':')
	if separator < 0 {
		return nil, fmt.Errorf("%w: Windows key reference is invalid", bootstrapport.ErrIntegrity)
	}
	decoded, err := hex.DecodeString(value[separator+1:])
	if err != nil || len(decoded) != sha256.Size {
		return nil, fmt.Errorf("%w: Windows key reference is invalid", bootstrapport.ErrIntegrity)
	}
	return decoded, nil
}

type windowsNativeDPAPI struct{}

func (windowsNativeDPAPI) Protect(ctx context.Context, plaintext, entropy []byte) ([]byte, error) {
	return windowssecurity.ProtectUser(ctx, plaintext, entropy)
}

func (windowsNativeDPAPI) Unprotect(ctx context.Context, ciphertext, entropy []byte) ([]byte, error) {
	return windowssecurity.UnprotectUser(ctx, ciphertext, entropy)
}

type windowsNativeOperationLock struct{}

func (windowsNativeOperationLock) WithExclusive(
	ctx context.Context,
	operationID install.OperationID,
	owner install.OwnerBinding,
	action func() error,
) error {
	canonical := append([]byte("agentmemory:windows-bootstrap-owner-mutex:v1\x00"), operationID.String()...)
	canonical = append(canonical, 0)
	canonical = append(canonical, owner.Fingerprint().String()...)
	digest := sha256.Sum256(canonical)
	return windowssecurity.WithOwnerMutex(ctx, `Global\AgentMemory-PF001-`+hex.EncodeToString(digest[:]), action)
}

type windowsCredentialKeyRecordStore struct{ locator *OperationLocator }

func (s *windowsCredentialKeyRecordStore) Load(
	ctx context.Context,
	operationID install.OperationID,
) ([]byte, error) {
	target, err := s.target(operationID)
	if err != nil {
		return nil, err
	}
	record, err := windowssecurity.ReadGenericCredential(ctx, target)
	if errors.Is(err, os.ErrNotExist) {
		return nil, bootstrapport.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(record) == 0 || len(record) > maximumWindowsProtectedBytes {
		clear(record)
		return nil, fmt.Errorf("%w: Windows credential record is invalid", bootstrapport.ErrIntegrity)
	}
	return record, nil
}

func (s *windowsCredentialKeyRecordStore) Publish(
	ctx context.Context,
	operationID install.OperationID,
	record []byte,
) (bool, error) {
	if len(record) == 0 || len(record) > maximumWindowsProtectedBytes {
		return false, errors.New("windows protected key record is empty or oversized")
	}
	target, err := s.target(operationID)
	if err != nil {
		return false, err
	}
	_, sid, err := windowssecurity.CurrentUserSID(ctx)
	if err != nil {
		return false, err
	}
	if err := windowssecurity.WriteGenericCredential(ctx, target, sid, record); err != nil {
		return false, err
	}
	return true, nil
}

func (s *windowsCredentialKeyRecordStore) target(operationID install.OperationID) (string, error) {
	if s == nil || s.locator == nil {
		return "", fmt.Errorf("%w: Windows credential locator is absent", bootstrapport.ErrIntegrity)
	}
	directory, err := s.locator.OperationDirectory(operationID)
	if err != nil {
		return "", fmt.Errorf("%w: invalid Windows credential operation", bootstrapport.ErrIntegrity)
	}
	target, err := windowsCredentialTarget(operationID)
	if err != nil || filepath.Base(directory) != strings.TrimPrefix(target, "AgentMemory/bootstrap-hmac/v1/") {
		return "", fmt.Errorf("%w: Windows credential target diverged from its digest directory", bootstrapport.ErrIntegrity)
	}
	return target, nil
}

func windowsCredentialTarget(operationID install.OperationID) (string, error) {
	if operationID.IsZero() {
		return "", fmt.Errorf("%w: Windows credential operation is absent", bootstrapport.ErrIntegrity)
	}
	canonical := append([]byte("agentmemory:bootstrap-operation-path:v1\x00"), operationID.String()...)
	digest := sha256.Sum256(canonical)
	return "AgentMemory/bootstrap-hmac/v1/sha256-" + hex.EncodeToString(digest[:]), nil
}
