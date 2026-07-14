package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const operationHMACKeyBytes = 32

type memoryKeyRecord struct {
	owner install.OwnerBinding
	ref   install.BootstrapKeyRef
	key   [operationHMACKeyBytes]byte
}

// MemoryOperationKeySource is a concurrency-safe, non-persistent key source
// for contract tests. Production composition must use a certified OS-protected
// source; this adapter deliberately cannot survive process restart.
type MemoryOperationKeySource struct {
	entropy io.Reader
	mu      sync.Mutex
	records map[string]memoryKeyRecord
}

var _ bootstrapport.OperationKeySource = (*MemoryOperationKeySource)(nil)

// NewMemoryOperationKeySource creates the local test key source.
func NewMemoryOperationKeySource(entropy io.Reader) (*MemoryOperationKeySource, error) {
	if nilDependency(entropy) {
		return nil, errors.New("operation key entropy source is required")
	}
	return &MemoryOperationKeySource{entropy: entropy, records: make(map[string]memoryKeyRecord)}, nil
}

// Ensure idempotently creates one owner-bound operation key.
func (s *MemoryOperationKeySource) Ensure(
	ctx context.Context,
	operationID install.OperationID,
	owner install.OwnerBinding,
) (install.BootstrapKeyRef, error) {
	if err := ctx.Err(); err != nil {
		return install.BootstrapKeyRef{}, err
	}
	if operationID.IsZero() || owner.IsZero() {
		return install.BootstrapKeyRef{}, fmt.Errorf("%w: operation and owner are required", bootstrapport.ErrIntegrity)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, exists := s.records[operationID.String()]; exists {
		if !existing.owner.Equal(owner) {
			return install.BootstrapKeyRef{}, fmt.Errorf("%w: operation owner changed", bootstrapport.ErrIntegrity)
		}
		return existing.ref, nil
	}

	var key [operationHMACKeyBytes]byte
	if _, err := io.ReadFull(s.entropy, key[:]); err != nil {
		return install.BootstrapKeyRef{}, errors.New("generate operation HMAC key")
	}
	ref, err := keyReference(operationID, owner, key[:])
	if err != nil {
		clear(key[:])
		return install.BootstrapKeyRef{}, err
	}
	s.records[operationID.String()] = memoryKeyRecord{owner: owner, ref: ref, key: key}
	clear(key[:])
	return ref, nil
}

// UseHMACKey resolves a temporary key copy for one bounded callback.
func (s *MemoryOperationKeySource) UseHMACKey(
	ctx context.Context,
	keyRef install.BootstrapKeyRef,
	operationID install.OperationID,
	owner install.OwnerBinding,
	consumer bootstrapport.OperationKeyConsumer,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if keyRef.IsZero() || operationID.IsZero() || owner.IsZero() || consumer == nil {
		return fmt.Errorf("%w: complete key access binding is required", bootstrapport.ErrIntegrity)
	}
	s.mu.Lock()
	record, exists := s.records[operationID.String()]
	if !exists || !record.owner.Equal(owner) || !record.ref.Equal(keyRef) {
		s.mu.Unlock()
		return fmt.Errorf("%w: operation key binding mismatch", bootstrapport.ErrIntegrity)
	}
	temporary := append([]byte(nil), record.key[:]...)
	s.mu.Unlock()
	defer clear(temporary)
	return consumer(temporary)
}

func keyReference(operationID install.OperationID, owner install.OwnerBinding, key []byte) (install.BootstrapKeyRef, error) {
	canonical := append([]byte("agentmemory:bootstrap-key-ref:v1\x00"), operationID.String()...)
	canonical = append(canonical, 0)
	canonical = append(canonical, owner.Fingerprint().String()...)
	canonical = append(canonical, 0)
	canonical = append(canonical, key...)
	return install.BootstrapKeyRefFromDigest(install.DigestBytes(canonical))
}
