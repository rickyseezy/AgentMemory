package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"testing"

	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001MemoryRollbackAnchorAdvanceRejectsTamperedRecord(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	keys, _ := NewMemoryOperationKeySource(bytes.NewReader(bytes.Repeat([]byte{0xa1}, 64)))
	store, _ := NewMemoryRollbackAnchorStore(keys)
	operationID, _ := install.NewOperationID("memory-tampered-advance")
	owner, _ := install.BindOwner("machine", "linux:uid:1000")
	keyRef, _ := keys.Ensure(ctx, operationID, owner)
	first, _ := install.NewRollbackAnchor(operationID, owner, 1, install.DigestBytes([]byte("first")))
	second, _ := install.NewRollbackAnchor(operationID, owner, 2, install.DigestBytes([]byte("second")))
	if err := store.Advance(ctx, keyRef, 0, first); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	record := store.records[operationID.String()]
	record.mac[0] ^= 0xff
	store.records[operationID.String()] = record
	store.mu.Unlock()
	if err := store.Advance(ctx, keyRef, 1, second); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("advance over tampered anchor error = %v", err)
	}
}

func TestPF001MemoryRollbackAnchorAdvanceRejectsForeignOwnerWithValidMAC(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	keys, _ := NewMemoryOperationKeySource(bytes.NewReader(bytes.Repeat([]byte{0xa2}, 64)))
	store, _ := NewMemoryRollbackAnchorStore(keys)
	operationID, _ := install.NewOperationID("memory-foreign-owner-advance")
	owner, _ := install.BindOwner("machine", "linux:uid:1000")
	foreignOwner, _ := install.BindOwner("other-machine", "linux:uid:1000")
	keyRef, _ := keys.Ensure(ctx, operationID, owner)
	foreign, _ := install.NewRollbackAnchor(
		operationID,
		foreignOwner,
		1,
		install.DigestBytes([]byte("foreign owner")),
	)
	var foreignRecord memoryAnchorRecord
	if err := keys.UseHMACKey(ctx, keyRef, operationID, owner, func(key []byte) error {
		foreignRecord = memoryAnchorRecord{anchor: foreign, mac: calculateAnchorMAC(key, foreign)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.records[operationID.String()] = foreignRecord
	store.mu.Unlock()
	next, _ := install.NewRollbackAnchor(operationID, owner, 2, install.DigestBytes([]byte("next")))
	if err := store.Advance(ctx, keyRef, 1, next); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("advance over foreign owner anchor error = %v", err)
	}
}

func TestPF001MemoryRollbackAnchorConfirmRejectsMissingRecord(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	keys, _ := NewMemoryOperationKeySource(bytes.NewReader(bytes.Repeat([]byte{0xa3}, 64)))
	store, _ := NewMemoryRollbackAnchorStore(keys)
	operationID, _ := install.NewOperationID("memory-missing-confirmation")
	owner, _ := install.BindOwner("machine", "linux:uid:1000")
	keyRef, _ := keys.Ensure(ctx, operationID, owner)
	expected, _ := install.NewRollbackAnchor(
		operationID,
		owner,
		1,
		install.DigestBytes([]byte("missing")),
	)
	if err := store.ConfirmDurable(ctx, keyRef, expected); !errors.Is(err, bootstrapport.ErrNotFound) {
		t.Fatalf("missing anchor confirmation error = %v", err)
	}
}
