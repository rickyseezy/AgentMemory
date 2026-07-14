//go:build linux

package filesystem

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001LinuxFileRollbackAnchorRejectsRollbackTamperOwnerAndSymlink(t *testing.T) {
	t.Parallel()
	locator, _ := bootstrapadapter.NewOperationLocator(filepath.Join(t.TempDir(), "config"))
	owner, _ := install.BindOwner("linux:machine-id:0123456789abcdef0123456789abcdef", "linux:uid:1000")
	wrongOwner, _ := install.BindOwner("linux:machine-id:fedcba9876543210fedcba9876543210", "linux:uid:1000")
	ownerSource := linuxOwnerBindingStub{owner: owner}
	keys, _ := newLinuxFileOperationKeySource(locator, ownerSource, bytes.NewReader(bytes.Repeat([]byte{0x51}, 128)))
	store, err := NewLinuxFileRollbackAnchorStore(locator, keys, ownerSource)
	if err != nil {
		t.Fatal(err)
	}
	operationID, _ := install.NewOperationID("linux-rollback-anchor")
	keyRef, _ := keys.Ensure(context.Background(), operationID, owner)
	first, _ := install.NewRollbackAnchor(operationID, owner, 1, install.DigestBytes([]byte("revision-one")))
	second, _ := install.NewRollbackAnchor(operationID, owner, 2, install.DigestBytes([]byte("revision-two")))
	if err := store.Advance(context.Background(), keyRef, 0, first); err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(context.Background(), keyRef, 1, second); err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(context.Background(), keyRef, 1, second); !errors.Is(err, bootstrapport.ErrConflict) {
		t.Fatalf("rollback replay error = %v", err)
	}
	if _, err := store.Load(context.Background(), keyRef, operationID, wrongOwner); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("wrong owner anchor error = %v", err)
	}
	loaded, err := store.Load(context.Background(), keyRef, operationID, owner)
	if err != nil || loaded.Sequence() != 2 {
		t.Fatalf("loaded anchor = %#v, %v", loaded, err)
	}
	if err := store.ConfirmDurable(context.Background(), keyRef, second); err != nil {
		t.Fatalf("confirmed anchor = %v", err)
	}
	if err := store.ConfirmDurable(context.Background(), keyRef, first); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("stale anchor confirmation error = %v", err)
	}

	anchorPath, _ := locator.RollbackAnchorPath(operationID)
	//nolint:gosec // G304: anchorPath is emitted by the digest-only locator in an isolated adversarial fixture; owner=security expiry=2027-07-13.
	contents, err := os.ReadFile(anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	contents[len(contents)-1] ^= 0xff
	//nolint:gosec // G703: anchorPath is digest-derived and this deliberate mutation tests HMAC verification; owner=security expiry=2027-07-13.
	if err := os.WriteFile(anchorPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(context.Background(), keyRef, operationID, owner); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("tampered anchor error = %v", err)
	}
	if err := store.ConfirmDurable(context.Background(), keyRef, second); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("tampered anchor confirmation error = %v", err)
	}

	symlinkOperation, _ := install.NewOperationID("linux-rollback-symlink")
	symlinkRef, _ := keys.Ensure(context.Background(), symlinkOperation, owner)
	symlinkAnchor, _ := install.NewRollbackAnchor(symlinkOperation, owner, 1, install.DigestBytes([]byte("symlink-anchor")))
	symlinkPath, _ := locator.RollbackAnchorPath(symlinkOperation)
	if err := os.Symlink(filepath.Join(t.TempDir(), "target"), symlinkPath); err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(context.Background(), symlinkRef, 0, symlinkAnchor); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("symlink anchor error = %v", err)
	}
}

func TestPF001LinuxFileRollbackAnchorCASAllowsOneConcurrentWinner(t *testing.T) {
	t.Parallel()
	locator, _ := bootstrapadapter.NewOperationLocator(filepath.Join(t.TempDir(), "config"))
	owner, _ := install.BindOwner("linux:machine-id:0123456789abcdef0123456789abcdef", "linux:uid:1000")
	ownerSource := linuxOwnerBindingStub{owner: owner}
	keys, _ := newLinuxFileOperationKeySource(locator, ownerSource, bytes.NewReader(bytes.Repeat([]byte{0x61}, 64)))
	store, _ := NewLinuxFileRollbackAnchorStore(locator, keys, ownerSource)
	operationID, _ := install.NewOperationID("linux-rollback-concurrency")
	keyRef, _ := keys.Ensure(context.Background(), operationID, owner)
	const count = 16
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
	for result := range results {
		if result == nil {
			winners++
			continue
		}
		if !errors.Is(result, bootstrapport.ErrConflict) {
			t.Fatalf("unexpected CAS error = %v", result)
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent anchor winners = %d, want 1", winners)
	}
}
