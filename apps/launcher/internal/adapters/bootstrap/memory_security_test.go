package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001MemoryOperationKeySourceBindsKeyToOperationAndOwner(t *testing.T) {
	t.Parallel()
	source, err := NewMemoryOperationKeySource(bytes.NewReader(bytes.Repeat([]byte{0x42}, 128)))
	if err != nil {
		t.Fatal(err)
	}
	operationID, _ := install.NewOperationID("key-operation")
	owner, _ := install.BindOwner("machine-a", "linux:uid:1000")
	wrongOwner, _ := install.BindOwner("machine-a", "linux:uid:1001")
	keyRef, err := source.Ensure(context.Background(), operationID, owner)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := source.Ensure(context.Background(), operationID, owner)
	if err != nil || !repeated.Equal(keyRef) {
		t.Fatalf("idempotent key ensure = %q, %v", repeated.String(), err)
	}
	if _, err := source.Ensure(context.Background(), operationID, wrongOwner); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("wrong owner error = %v", err)
	}

	var retained []byte
	err = source.UseHMACKey(context.Background(), keyRef, operationID, owner, func(key []byte) error {
		if len(key) != 32 {
			t.Fatalf("key length = %d", len(key))
		}
		retained = key
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range retained {
		if value != 0 {
			t.Fatal("temporary key copy was not cleared after use")
		}
	}
	otherID, _ := install.NewOperationID("other-operation")
	otherRef, err := source.Ensure(context.Background(), otherID, owner)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.UseHMACKey(context.Background(), otherRef, operationID, owner, func([]byte) error { return nil }); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("wrong key reference error = %v", err)
	}
}

func TestPF001MemoryOperationKeySourceIsConcurrentAndIdempotent(t *testing.T) {
	t.Parallel()
	source, err := NewMemoryOperationKeySource(bytes.NewReader(bytes.Repeat([]byte{0x19}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	operationID, _ := install.NewOperationID("concurrent-key")
	owner, _ := install.BindOwner("machine", "linux:uid:1000")
	const count = 32
	results := make(chan install.BootstrapKeyRef, count)
	errorsChannel := make(chan error, count)
	var waitGroup sync.WaitGroup
	for index := 0; index < count; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			keyRef, ensureError := source.Ensure(context.Background(), operationID, owner)
			results <- keyRef
			errorsChannel <- ensureError
		}()
	}
	waitGroup.Wait()
	close(results)
	close(errorsChannel)
	var expected install.BootstrapKeyRef
	for ensureError := range errorsChannel {
		if ensureError != nil {
			t.Fatal(ensureError)
		}
	}
	for keyRef := range results {
		if expected.IsZero() {
			expected = keyRef
		}
		if !keyRef.Equal(expected) {
			t.Fatal("concurrent ensure returned different key references")
		}
	}
}

func TestPF001MemoryOperationKeySourceFailsClosedAtEveryBoundary(t *testing.T) {
	t.Parallel()
	var typedNilEntropy *bytes.Reader
	if _, err := NewMemoryOperationKeySource(nil); err == nil {
		t.Fatal("nil key entropy was accepted")
	}
	if _, err := NewMemoryOperationKeySource(typedNilEntropy); err == nil {
		t.Fatal("typed nil key entropy was accepted")
	}
	operationID, _ := install.NewOperationID("key-boundaries")
	owner, _ := install.BindOwner("machine", "linux:uid:1000")
	shortSource, _ := NewMemoryOperationKeySource(bytes.NewReader([]byte{1, 2, 3}))
	if _, err := shortSource.Ensure(context.Background(), operationID, owner); err == nil {
		t.Fatal("short entropy was accepted")
	}
	source, _ := NewMemoryOperationKeySource(bytes.NewReader(bytes.Repeat([]byte{0x81}, 64)))
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Ensure(cancelled, operationID, owner); err == nil {
		t.Fatal("cancelled key ensure was accepted")
	}
	if _, err := source.Ensure(context.Background(), install.OperationID{}, owner); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("zero operation error = %v", err)
	}
	keyRef, _ := source.Ensure(context.Background(), operationID, owner)
	if err := source.UseHMACKey(cancelled, keyRef, operationID, owner, func([]byte) error { return nil }); err == nil {
		t.Fatal("cancelled key use was accepted")
	}
	if err := source.UseHMACKey(context.Background(), keyRef, operationID, owner, nil); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("nil consumer error = %v", err)
	}
	missingID, _ := install.NewOperationID("missing-key")
	if err := source.UseHMACKey(context.Background(), keyRef, missingID, owner, func([]byte) error { return nil }); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("missing key error = %v", err)
	}
	consumerError := errors.New("consumer failed")
	if err := source.UseHMACKey(context.Background(), keyRef, operationID, owner, func([]byte) error { return consumerError }); !errors.Is(err, consumerError) {
		t.Fatalf("consumer error was not preserved: %v", err)
	}
}

func TestPF001MemoryRollbackAnchorRejectsRollbackTamperWrongOwnerAndKey(t *testing.T) {
	t.Parallel()
	keySource, _ := NewMemoryOperationKeySource(bytes.NewReader(bytes.Repeat([]byte{0x33}, 128)))
	store, err := NewMemoryRollbackAnchorStore(keySource)
	if err != nil {
		t.Fatal(err)
	}
	operationID, _ := install.NewOperationID("rollback-operation")
	owner, _ := install.BindOwner("machine", "linux:uid:1000")
	wrongOwner, _ := install.BindOwner("other-machine", "linux:uid:1000")
	keyRef, _ := keySource.Ensure(context.Background(), operationID, owner)
	anchor1, _ := install.NewRollbackAnchor(operationID, owner, 1, install.DigestBytes([]byte("revision-one")))
	if err := store.Advance(context.Background(), keyRef, 0, anchor1); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(context.Background(), keyRef, operationID, owner)
	if err != nil || loaded.Sequence() != 1 || !loaded.StateDigest().Equal(anchor1.StateDigest()) {
		t.Fatalf("loaded anchor = %#v, %v", loaded, err)
	}
	if err := store.ConfirmDurable(context.Background(), keyRef, anchor1); err != nil {
		t.Fatalf("confirmed memory anchor = %v", err)
	}
	if err := store.Advance(context.Background(), keyRef, 0, anchor1); !errors.Is(err, bootstrapport.ErrConflict) {
		t.Fatalf("rollback error = %v", err)
	}
	if _, err := store.Load(context.Background(), keyRef, operationID, wrongOwner); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("wrong owner load error = %v", err)
	}
	otherID, _ := install.NewOperationID("other-key-operation")
	otherRef, _ := keySource.Ensure(context.Background(), otherID, owner)
	if _, err := store.Load(context.Background(), otherRef, operationID, owner); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("wrong key load error = %v", err)
	}

	store.mu.Lock()
	record := store.records[operationID.String()]
	record.mac[0] ^= 0xff
	store.records[operationID.String()] = record
	store.mu.Unlock()
	if _, err := store.Load(context.Background(), keyRef, operationID, owner); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("tampered anchor error = %v", err)
	}
	if err := store.ConfirmDurable(context.Background(), keyRef, anchor1); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("tampered anchor confirmation error = %v", err)
	}
}

func TestPF001MemoryRollbackAnchorCASAllowsOneConcurrentWinner(t *testing.T) {
	t.Parallel()
	keySource, _ := NewMemoryOperationKeySource(bytes.NewReader(bytes.Repeat([]byte{0x71}, 64)))
	store, _ := NewMemoryRollbackAnchorStore(keySource)
	operationID, _ := install.NewOperationID("rollback-concurrency")
	owner, _ := install.BindOwner("machine", "linux:uid:1000")
	keyRef, _ := keySource.Ensure(context.Background(), operationID, owner)
	const count = 24
	results := make(chan error, count)
	var waitGroup sync.WaitGroup
	for index := 0; index < count; index++ {
		index := index
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			anchor, _ := install.NewRollbackAnchor(operationID, owner, 1, install.DigestBytes([]byte(fmt.Sprintf("anchor-%d", index))))
			results <- store.Advance(context.Background(), keyRef, 0, anchor)
		}()
	}
	waitGroup.Wait()
	close(results)
	winners := 0
	conflicts := 0
	for result := range results {
		switch {
		case result == nil:
			winners++
		case errors.Is(result, bootstrapport.ErrConflict):
			conflicts++
		default:
			t.Fatalf("unexpected CAS error: %v", result)
		}
	}
	if winners != 1 || conflicts != count-1 {
		t.Fatalf("CAS winners/conflicts = %d/%d", winners, conflicts)
	}
}

func TestPF001MemoryRollbackAnchorHandlesNotFoundProgressionAndInvalidSequence(t *testing.T) {
	t.Parallel()
	if _, err := NewMemoryRollbackAnchorStore(nil); err == nil {
		t.Fatal("nil rollback key source was accepted")
	}
	keySource, _ := NewMemoryOperationKeySource(bytes.NewReader(bytes.Repeat([]byte{0x91}, 64)))
	store, _ := NewMemoryRollbackAnchorStore(keySource)
	operationID, _ := install.NewOperationID("rollback-progression")
	owner, _ := install.BindOwner("machine", "linux:uid:1000")
	keyRef, _ := keySource.Ensure(context.Background(), operationID, owner)
	if _, err := store.Load(context.Background(), keyRef, operationID, owner); !errors.Is(err, bootstrapport.ErrNotFound) {
		t.Fatalf("missing anchor error = %v", err)
	}
	first, _ := install.NewRollbackAnchor(operationID, owner, 1, install.DigestBytes([]byte("first")))
	second, _ := install.NewRollbackAnchor(operationID, owner, 2, install.DigestBytes([]byte("second")))
	if err := store.Advance(context.Background(), keyRef, 1, second); !errors.Is(err, bootstrapport.ErrConflict) {
		t.Fatalf("missing predecessor error = %v", err)
	}
	if err := store.Advance(context.Background(), keyRef, 0, second); !errors.Is(err, bootstrapport.ErrConflict) {
		t.Fatalf("skipped sequence error = %v", err)
	}
	if err := store.Advance(context.Background(), keyRef, 0, first); err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(context.Background(), keyRef, 1, second); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(context.Background(), keyRef, operationID, owner)
	if err != nil || loaded.Sequence() != 2 {
		t.Fatalf("progressed anchor = %#v, %v", loaded, err)
	}
}
