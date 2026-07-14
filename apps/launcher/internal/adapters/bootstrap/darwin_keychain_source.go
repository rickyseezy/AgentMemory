//go:build darwin

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
	"strings"
	"sync"

	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const (
	darwinBootstrapKeychainService = "io.agentmemory.bootstrap-hmac.v1"
	darwinKeyRecordSize            = 16 + sha256.Size*5
)

var (
	errDarwinKeychainDuplicate = errors.New("macOS Keychain item already exists")
	errDarwinKeychainNotFound  = errors.New("macOS Keychain item not found")
	darwinKeyRecordMagic       = [16]byte{'A', 'M', 'K', 'E', 'Y', 'C', 'H', 'A', 'I', 'N', 'v', '1'}
)

type darwinKeychainCapability interface {
	Add(context.Context, string, []byte) error
	Get(context.Context, string) ([]byte, error)
}

// DarwinKeychainOperationKeySource stores each 256-bit bootstrap key only in
// the invoking user's device-only Data Protection Keychain.
type DarwinKeychainOperationKeySource struct {
	owners   bootstrapport.OwnerBindingSource
	keychain darwinKeychainCapability
	entropy  io.Reader
	mu       sync.Mutex
}

var _ bootstrapport.OperationKeySource = (*DarwinKeychainOperationKeySource)(nil)

// NewDarwinKeychainOperationKeySource creates the native Keychain source. A
// missing entitlement, locked Keychain, or required UI fails during access;
// this adapter never invokes authentication UI or substitutes a local file.
func NewDarwinKeychainOperationKeySource(
	owners bootstrapport.OwnerBindingSource,
) (*DarwinKeychainOperationKeySource, error) {
	keychain, err := newDarwinKeychainCapability(darwinBootstrapKeychainService)
	if err != nil {
		return nil, err
	}
	return newDarwinKeychainOperationKeySource(owners, keychain, rand.Reader)
}

func newDarwinKeychainOperationKeySource(
	owners bootstrapport.OwnerBindingSource,
	keychain darwinKeychainCapability,
	entropy io.Reader,
) (*DarwinKeychainOperationKeySource, error) {
	if nilDependency(owners) || nilDependency(keychain) || nilDependency(entropy) {
		return nil, errors.New("macOS key source requires owner, Keychain, and entropy capabilities")
	}
	return &DarwinKeychainOperationKeySource{owners: owners, keychain: keychain, entropy: entropy}, nil
}

// Ensure publishes exactly one owner-bound Keychain record. SecItemAdd is the
// cross-process exclusive create boundary; a duplicate is read and verified.
func (s *DarwinKeychainOperationKeySource) Ensure(
	ctx context.Context,
	operationID install.OperationID,
	owner install.OwnerBinding,
) (install.BootstrapKeyRef, error) {
	if err := s.verifyCurrentOwner(ctx, owner); err != nil {
		return install.BootstrapKeyRef{}, err
	}
	if operationID.IsZero() {
		return install.BootstrapKeyRef{}, fmt.Errorf("%w: operation identity is absent", bootstrapport.ErrIntegrity)
	}
	account := darwinKeychainAccount(operationID)
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.keychain.Get(ctx, account)
	if err == nil {
		decoded, decodeError := decodeDarwinKeyRecord(record, operationID, owner)
		clear(record)
		if decodeError != nil {
			return install.BootstrapKeyRef{}, decodeError
		}
		clear(decoded.key[:])
		return decoded.ref, nil
	}
	if !errors.Is(err, errDarwinKeychainNotFound) {
		return install.BootstrapKeyRef{}, err
	}

	var key [sha256.Size]byte
	if _, err := io.ReadFull(s.entropy, key[:]); err != nil {
		return install.BootstrapKeyRef{}, errors.New("generate Darwin bootstrap HMAC key")
	}
	defer clear(key[:])
	ref, err := keyReference(operationID, owner, key[:])
	if err != nil {
		return install.BootstrapKeyRef{}, err
	}
	encoded, err := encodeDarwinKeyRecord(operationID, owner, ref, key)
	if err != nil {
		return install.BootstrapKeyRef{}, err
	}
	defer clear(encoded)
	err = s.keychain.Add(ctx, account, encoded)
	switch {
	case err == nil:
		return ref, nil
	case errors.Is(err, errDarwinKeychainDuplicate):
		winner, getError := s.keychain.Get(ctx, account)
		if getError != nil {
			return install.BootstrapKeyRef{}, getError
		}
		decoded, decodeError := decodeDarwinKeyRecord(winner, operationID, owner)
		clear(winner)
		if decodeError != nil {
			return install.BootstrapKeyRef{}, decodeError
		}
		defer clear(decoded.key[:])
		return decoded.ref, nil
	default:
		return install.BootstrapKeyRef{}, err
	}
}

// UseHMACKey resolves one temporary copy and clears it after the bounded
// callback. Keychain access is configured to fail rather than display UI.
func (s *DarwinKeychainOperationKeySource) UseHMACKey(
	ctx context.Context,
	keyRef install.BootstrapKeyRef,
	operationID install.OperationID,
	owner install.OwnerBinding,
	consumer bootstrapport.OperationKeyConsumer,
) error {
	if keyRef.IsZero() || operationID.IsZero() || owner.IsZero() || consumer == nil {
		return fmt.Errorf("%w: complete Darwin key binding is required", bootstrapport.ErrIntegrity)
	}
	if err := s.verifyCurrentOwner(ctx, owner); err != nil {
		return err
	}
	s.mu.Lock()
	record, err := s.keychain.Get(ctx, darwinKeychainAccount(operationID))
	s.mu.Unlock()
	if errors.Is(err, errDarwinKeychainNotFound) {
		return bootstrapport.ErrNotFound
	}
	if err != nil {
		return err
	}
	decoded, err := decodeDarwinKeyRecord(record, operationID, owner)
	clear(record)
	if err != nil {
		return err
	}
	defer clear(decoded.key[:])
	if !decoded.ref.Equal(keyRef) {
		return fmt.Errorf("%w: Darwin Keychain reference changed", bootstrapport.ErrIntegrity)
	}
	temporary := append([]byte(nil), decoded.key[:]...)
	defer clear(temporary)
	return consumer(temporary)
}

func (s *DarwinKeychainOperationKeySource) verifyCurrentOwner(
	ctx context.Context,
	expected install.OwnerBinding,
) error {
	if expected.IsZero() {
		return fmt.Errorf("%w: Darwin key owner is absent", bootstrapport.ErrIntegrity)
	}
	current, err := s.owners.Current(ctx)
	if err != nil {
		return err
	}
	if !current.Equal(expected) {
		return fmt.Errorf("%w: Darwin machine or OS principal changed", bootstrapport.ErrIntegrity)
	}
	return nil
}

type darwinKeyRecord struct {
	ref install.BootstrapKeyRef
	key [sha256.Size]byte
}

func encodeDarwinKeyRecord(
	operationID install.OperationID,
	owner install.OwnerBinding,
	ref install.BootstrapKeyRef,
	key [sha256.Size]byte,
) ([]byte, error) {
	result := make([]byte, 0, darwinKeyRecordSize)
	result = append(result, darwinKeyRecordMagic[:]...)
	operationDigest := darwinOperationIdentityDigest(operationID)
	result = append(result, operationDigest[:]...)
	machine, _ := hex.DecodeString(owner.MachineDigest().String())
	principal, _ := hex.DecodeString(owner.PrincipalDigest().String())
	refDigest, err := darwinKeyRefDigest(ref)
	if err != nil {
		return nil, err
	}
	result = append(result, machine...)
	result = append(result, principal...)
	result = append(result, refDigest...)
	result = append(result, key[:]...)
	return result, nil
}

func decodeDarwinKeyRecord(
	contents []byte,
	operationID install.OperationID,
	owner install.OwnerBinding,
) (darwinKeyRecord, error) {
	if len(contents) != darwinKeyRecordSize || !bytes.Equal(contents[:16], darwinKeyRecordMagic[:]) {
		return darwinKeyRecord{}, fmt.Errorf("%w: Darwin Keychain record format is invalid", bootstrapport.ErrIntegrity)
	}
	offset := 16
	operationDigest := darwinOperationIdentityDigest(operationID)
	if !bytes.Equal(contents[offset:offset+sha256.Size], operationDigest[:]) {
		return darwinKeyRecord{}, fmt.Errorf("%w: Darwin Keychain operation changed", bootstrapport.ErrIntegrity)
	}
	offset += sha256.Size
	machine, _ := hex.DecodeString(owner.MachineDigest().String())
	if !bytes.Equal(contents[offset:offset+sha256.Size], machine) {
		return darwinKeyRecord{}, fmt.Errorf("%w: Darwin Keychain machine changed", bootstrapport.ErrIntegrity)
	}
	offset += sha256.Size
	principal, _ := hex.DecodeString(owner.PrincipalDigest().String())
	if !bytes.Equal(contents[offset:offset+sha256.Size], principal) {
		return darwinKeyRecord{}, fmt.Errorf("%w: Darwin Keychain principal changed", bootstrapport.ErrIntegrity)
	}
	offset += sha256.Size
	persistedRefDigest := contents[offset : offset+sha256.Size]
	offset += sha256.Size
	var key [sha256.Size]byte
	copy(key[:], contents[offset:offset+sha256.Size])
	ref, err := keyReference(operationID, owner, key[:])
	if err != nil {
		clear(key[:])
		return darwinKeyRecord{}, err
	}
	computedRefDigest, _ := darwinKeyRefDigest(ref)
	if !bytes.Equal(persistedRefDigest, computedRefDigest) {
		clear(key[:])
		return darwinKeyRecord{}, fmt.Errorf("%w: Darwin Keychain record was modified", bootstrapport.ErrIntegrity)
	}
	return darwinKeyRecord{ref: ref, key: key}, nil
}

func darwinKeychainAccount(operationID install.OperationID) string {
	digest := darwinOperationIdentityDigest(operationID)
	return "sha256-" + hex.EncodeToString(digest[:])
}

func darwinOperationIdentityDigest(operationID install.OperationID) [sha256.Size]byte {
	return sha256.Sum256(append([]byte("agentmemory:darwin-keychain-operation:v1\x00"), operationID.String()...))
}

func darwinKeyRefDigest(ref install.BootstrapKeyRef) ([]byte, error) {
	value := ref.String()
	separator := strings.LastIndexByte(value, ':')
	if separator < 0 {
		return nil, fmt.Errorf("%w: Darwin key reference is invalid", bootstrapport.ErrIntegrity)
	}
	decoded, err := hex.DecodeString(value[separator+1:])
	if err != nil || len(decoded) != sha256.Size {
		return nil, fmt.Errorf("%w: Darwin key reference is invalid", bootstrapport.ErrIntegrity)
	}
	return decoded, nil
}
