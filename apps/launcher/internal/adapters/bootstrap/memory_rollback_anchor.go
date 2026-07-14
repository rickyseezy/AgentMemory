package bootstrap

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"sync"

	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

type memoryAnchorRecord struct {
	anchor install.RollbackAnchor
	mac    [sha256.Size]byte
}

// MemoryRollbackAnchorStore is the deterministic contract-test adapter for a
// protected monotonic store. It does not provide persistence across restart.
type MemoryRollbackAnchorStore struct {
	keys    bootstrapport.OperationKeySource
	mu      sync.Mutex
	records map[string]memoryAnchorRecord
}

var _ bootstrapport.RollbackAnchorStore = (*MemoryRollbackAnchorStore)(nil)

// NewMemoryRollbackAnchorStore creates an HMAC-protected in-memory anchor.
func NewMemoryRollbackAnchorStore(keys bootstrapport.OperationKeySource) (*MemoryRollbackAnchorStore, error) {
	if nilDependency(keys) {
		return nil, errors.New("rollback anchor operation key source is required")
	}
	return &MemoryRollbackAnchorStore{keys: keys, records: make(map[string]memoryAnchorRecord)}, nil
}

// Load authenticates the latest owner-bound anchor.
func (s *MemoryRollbackAnchorStore) Load(
	ctx context.Context,
	keyRef install.BootstrapKeyRef,
	operationID install.OperationID,
	owner install.OwnerBinding,
) (install.RollbackAnchor, error) {
	var result install.RollbackAnchor
	err := s.keys.UseHMACKey(ctx, keyRef, operationID, owner, func(key []byte) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		record, exists := s.records[operationID.String()]
		if !exists {
			return bootstrapport.ErrNotFound
		}
		if !record.anchor.Owner().Equal(owner) || record.anchor.OperationID() != operationID || !validAnchorMAC(key, record) {
			return bootstrapport.ErrIntegrity
		}
		result = record.anchor
		return nil
	})
	return result, err
}

// Advance performs an authenticated monotonic compare-and-swap.
func (s *MemoryRollbackAnchorStore) Advance(
	ctx context.Context,
	keyRef install.BootstrapKeyRef,
	expectedSequence uint64,
	next install.RollbackAnchor,
) error {
	if expectedSequence == math.MaxUint64 || next.Sequence() != expectedSequence+1 {
		return fmt.Errorf("%w: rollback anchor sequence is not the next value", bootstrapport.ErrConflict)
	}
	return s.keys.UseHMACKey(ctx, keyRef, next.OperationID(), next.Owner(), func(key []byte) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		existing, exists := s.records[next.OperationID().String()]
		switch {
		case !exists && expectedSequence != 0:
			return bootstrapport.ErrConflict
		case exists && !validAnchorMAC(key, existing):
			return bootstrapport.ErrIntegrity
		case exists && (!existing.anchor.Owner().Equal(next.Owner()) || existing.anchor.OperationID() != next.OperationID()):
			return bootstrapport.ErrIntegrity
		case exists && existing.anchor.Sequence() != expectedSequence:
			return bootstrapport.ErrConflict
		}
		s.records[next.OperationID().String()] = memoryAnchorRecord{anchor: next, mac: calculateAnchorMAC(key, next)}
		return nil
	})
}

// ConfirmDurable re-authenticates the exact in-memory record. The adapter has
// no host durability boundary; production composition uses an OS adapter.
func (s *MemoryRollbackAnchorStore) ConfirmDurable(
	ctx context.Context,
	keyRef install.BootstrapKeyRef,
	expected install.RollbackAnchor,
) error {
	return s.keys.UseHMACKey(ctx, keyRef, expected.OperationID(), expected.Owner(), func(key []byte) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		record, exists := s.records[expected.OperationID().String()]
		if !exists {
			return bootstrapport.ErrNotFound
		}
		if !validAnchorMAC(key, record) || !exactAnchor(record.anchor, expected) {
			return bootstrapport.ErrIntegrity
		}
		return nil
	})
}

func calculateAnchorMAC(key []byte, anchor install.RollbackAnchor) [sha256.Size]byte {
	authenticator := hmac.New(sha256.New, key)
	_, _ = authenticator.Write(anchor.CanonicalBytes())
	var result [sha256.Size]byte
	copy(result[:], authenticator.Sum(nil))
	return result
}

func validAnchorMAC(key []byte, record memoryAnchorRecord) bool {
	expected := calculateAnchorMAC(key, record.anchor)
	return hmac.Equal(expected[:], record.mac[:])
}
