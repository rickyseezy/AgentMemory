//go:build darwin && cgo

package filesystem

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001DarwinControlledOperationDirectoryRejectsACLsAndSymlinks(t *testing.T) {
	t.Parallel()
	operationID, _ := install.NewOperationID("darwin-controlled-directory")

	t.Run("creates and verifies the closed tree", func(t *testing.T) {
		root := newDarwinTestConfigRoot(t)
		locator, _ := bootstrapadapter.NewOperationLocator(root)
		directory, _ := locator.OperationDirectory(operationID)
		if err := ensureDarwinOperationDirectory(context.Background(), root, directory); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{
			filepath.Join(root, "AgentMemory"),
			filepath.Join(root, "AgentMemory", "bootstrap"),
			directory,
		} {
			info, err := os.Lstat(path)
			if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
				t.Fatalf("controlled directory %q = %#v, %v", path, info, err)
			}
		}
	})

	for _, test := range []struct {
		name    string
		prepare func(*testing.T, string, string)
	}{
		{
			name: "AgentMemory symlink",
			prepare: func(t *testing.T, root, _ string) {
				t.Helper()
				target := filepath.Join(t.TempDir(), "attacker")
				if err := os.Mkdir(target, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, filepath.Join(root, "AgentMemory")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "bootstrap symlink",
			prepare: func(t *testing.T, root, _ string) {
				t.Helper()
				if err := os.Mkdir(filepath.Join(root, "AgentMemory"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(t.TempDir(), filepath.Join(root, "AgentMemory", "bootstrap")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "operation symlink",
			prepare: func(t *testing.T, _, directory string) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(directory), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(t.TempDir(), directory); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "controlled ancestor ACL",
			prepare: func(t *testing.T, root, _ string) {
				t.Helper()
				path := filepath.Join(root, "AgentMemory")
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				addDarwinTestACL(t, path)
			},
		},
		{
			name: "operation ACL",
			prepare: func(t *testing.T, _, directory string) {
				t.Helper()
				if err := os.MkdirAll(directory, 0o700); err != nil {
					t.Fatal(err)
				}
				addDarwinTestACL(t, directory)
			},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			root := newDarwinTestConfigRoot(t)
			locator, _ := bootstrapadapter.NewOperationLocator(root)
			directory, _ := locator.OperationDirectory(operationID)
			test.prepare(t, root, directory)
			if err := ensureDarwinOperationDirectory(context.Background(), root, directory); !errors.Is(err, bootstrapport.ErrIntegrity) {
				t.Fatalf("unsafe controlled tree error = %v", err)
			}
		})
	}
}

func TestPF001DarwinRollbackAnchorRejectsReplayTamperOwnerACLAndSymlink(t *testing.T) {
	t.Parallel()
	root := newDarwinTestConfigRoot(t)
	locator, _ := bootstrapadapter.NewOperationLocator(root)
	owner, _ := install.BindOwner("darwin:platform-uuid:01234567-89ab-cdef-0123-456789abcdef", "darwin:uid:501:user-uuid:fedcba98-7654-3210-fedc-ba9876543210")
	wrongOwner, _ := install.BindOwner("darwin:platform-uuid:11111111-89ab-cdef-0123-456789abcdef", "darwin:uid:501:user-uuid:fedcba98-7654-3210-fedc-ba9876543210")
	owners := darwinFilesystemOwnerStub{owner: owner}
	keys, _ := bootstrapadapter.NewMemoryOperationKeySource(bytes.NewReader(bytes.Repeat([]byte{0x51}, 128)))
	store, err := NewDarwinFileRollbackAnchorStore(locator, keys, owners)
	if err != nil {
		t.Fatal(err)
	}
	operationID, _ := install.NewOperationID("darwin-rollback-anchor")
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
		t.Fatalf("wrong owner error = %v", err)
	}
	loaded, err := store.Load(context.Background(), keyRef, operationID, owner)
	if err != nil || loaded.Sequence() != 2 {
		t.Fatalf("loaded anchor = %#v, %v", loaded, err)
	}
	if err := store.ConfirmDurable(context.Background(), keyRef, second); err != nil {
		t.Fatalf("durability confirmation = %v", err)
	}
	if err := store.ConfirmDurable(context.Background(), keyRef, first); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("stale durability confirmation = %v", err)
	}

	anchorPath, _ := locator.RollbackAnchorPath(operationID)
	//nolint:gosec // G304: digest-only path in an isolated adversarial fixture; owner=security expiry=2027-07-14.
	original, err := os.ReadFile(anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	mutated := append([]byte(nil), original...)
	mutated[len(mutated)-1] ^= 0xff
	//nolint:gosec // G703: deliberate digest-path mutation verifies HMAC rejection; owner=security expiry=2027-07-14.
	if err := os.WriteFile(anchorPath, mutated, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(context.Background(), keyRef, operationID, owner); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("tampered anchor error = %v", err)
	}
	//nolint:gosec // G703: restores the closed fixture for the ACL attack; owner=security expiry=2027-07-14.
	if err := os.WriteFile(anchorPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	addDarwinTestACL(t, anchorPath)
	if _, err := store.Load(context.Background(), keyRef, operationID, owner); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("anchor ACL error = %v", err)
	}

	symlinkID, _ := install.NewOperationID("darwin-rollback-symlink")
	symlinkRef, _ := keys.Ensure(context.Background(), symlinkID, owner)
	symlinkAnchor, _ := install.NewRollbackAnchor(symlinkID, owner, 1, install.DigestBytes([]byte("symlink-anchor")))
	symlinkPath, _ := locator.RollbackAnchorPath(symlinkID)
	directory, _ := locator.OperationDirectory(symlinkID)
	if err := ensureDarwinOperationDirectory(context.Background(), root, directory); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "target"), symlinkPath); err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(context.Background(), symlinkRef, 0, symlinkAnchor); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("symlink anchor error = %v", err)
	}
}

func TestPF001DarwinRollbackAnchorCASAllowsOneConcurrentWinner(t *testing.T) {
	t.Parallel()
	root := newDarwinTestConfigRoot(t)
	locator, _ := bootstrapadapter.NewOperationLocator(root)
	owner, _ := install.BindOwner("darwin-machine", "darwin-user")
	owners := darwinFilesystemOwnerStub{owner: owner}
	keys, _ := bootstrapadapter.NewMemoryOperationKeySource(bytes.NewReader(bytes.Repeat([]byte{0x61}, 64)))
	store, _ := NewDarwinFileRollbackAnchorStore(locator, keys, owners)
	operationID, _ := install.NewOperationID("darwin-rollback-concurrency")
	keyRef, _ := keys.Ensure(context.Background(), operationID, owner)
	const count = 16
	results := make(chan error, count)
	var waitGroup sync.WaitGroup
	for index := range count {
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
		t.Fatalf("concurrent winners = %d, want 1", winners)
	}
}

func TestPF001DarwinOperationJournalProviderIsOwnerKeyAndOperationBound(t *testing.T) {
	t.Parallel()
	root := newDarwinTestConfigRoot(t)
	locator, _ := bootstrapadapter.NewOperationLocator(root)
	owner, _ := install.BindOwner("darwin-machine", "darwin-user")
	owners := darwinFilesystemOwnerStub{owner: owner}
	keys, _ := bootstrapadapter.NewMemoryOperationKeySource(bytes.NewReader(bytes.Repeat([]byte{0x73}, 128)))
	anchors, _ := NewDarwinFileRollbackAnchorStore(locator, keys, owners)
	provider, err := NewDarwinOperationJournalProvider(locator, keys, owners, anchors)
	if err != nil {
		t.Fatal(err)
	}
	firstID, _ := install.NewOperationID("darwin-provider-a")
	secondID, _ := install.NewOperationID("darwin-provider-b")
	first, err := provider.JournalFor(context.Background(), firstID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := provider.JournalFor(context.Background(), secondID)
	if err != nil {
		t.Fatal(err)
	}
	for operationID, journal := range map[install.OperationID]journalport.Journal{firstID: first, secondID: second} {
		if err := journal.Append(context.Background(), 0, journalport.Snapshot{
			OperationID: operationID.String(),
			Revision:    1,
			CapturedAt:  time.Date(2026, time.July, 14, 0, 0, 0, 0, time.UTC),
			Payload:     json.RawMessage(`{"state":"running"}`),
		}); err != nil {
			t.Fatal(err)
		}
	}
	firstLatest, err := first.LoadLatest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	secondLatest, err := second.LoadLatest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if firstLatest.OperationID != firstID.String() || secondLatest.OperationID != secondID.String() {
		t.Fatal("Darwin provider crossed operation identities")
	}
	if err := first.ConfirmDurable(context.Background(), firstID.String(), 1); err != nil {
		t.Fatal(err)
	}

	wrongOwner, _ := install.BindOwner("different-machine", "darwin-user")
	wrongProvider, _ := NewDarwinOperationJournalProvider(locator, keys, darwinFilesystemOwnerStub{owner: wrongOwner}, anchors)
	if _, err := wrongProvider.JournalFor(context.Background(), firstID); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("wrong provider owner error = %v", err)
	}
}

func TestPF001DarwinOperationJournalProviderRejectsOldAuthenticatedReplay(t *testing.T) {
	t.Parallel()
	root := newDarwinTestConfigRoot(t)
	locator, _ := bootstrapadapter.NewOperationLocator(root)
	owner, _ := install.BindOwner("darwin-machine", "darwin-user")
	owners := darwinFilesystemOwnerStub{owner: owner}
	keys, _ := bootstrapadapter.NewMemoryOperationKeySource(bytes.NewReader(bytes.Repeat([]byte{0x83}, 64)))
	anchors, _ := NewDarwinFileRollbackAnchorStore(locator, keys, owners)
	provider, _ := NewDarwinOperationJournalProvider(locator, keys, owners, anchors)
	operationID, _ := install.NewOperationID("darwin-provider-old-valid-replay")
	journal, err := provider.JournalFor(context.Background(), operationID)
	if err != nil {
		t.Fatal(err)
	}
	first := journalport.Snapshot{
		OperationID: operationID.String(),
		Revision:    1,
		CapturedAt:  time.Date(2026, time.July, 14, 1, 0, 0, 0, time.UTC),
		Payload:     json.RawMessage(`{"state":"first"}`),
	}
	if err := journal.Append(context.Background(), 0, first); err != nil {
		t.Fatal(err)
	}
	journalPath, _ := locator.JournalPath(operationID)
	//nolint:gosec // G304: digest-only path in an isolated rollback fixture; owner=security expiry=2027-07-14.
	oldValidBytes, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Append(context.Background(), 1, journalport.Snapshot{
		OperationID: operationID.String(),
		Revision:    2,
		CapturedAt:  first.CapturedAt.Add(time.Second),
		Payload:     json.RawMessage(`{"state":"second"}`),
	}); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // G703: deliberate old authenticated replay verifies the monotonic anchor; owner=security expiry=2027-07-14.
	if err := os.WriteFile(journalPath, oldValidBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.LoadLatest(context.Background()); !errors.Is(err, journalport.ErrCorrupt) {
		t.Fatalf("old authenticated replay error = %v", err)
	}
}

func TestPF001DarwinOperationJournalProviderPropagatesSecurityBoundaries(t *testing.T) {
	t.Parallel()
	root := newDarwinTestConfigRoot(t)
	locator, _ := bootstrapadapter.NewOperationLocator(root)
	owner, _ := install.BindOwner("darwin-machine", "darwin-user")
	operationID, _ := install.NewOperationID("darwin-provider-boundaries")
	keyRef, _ := install.BootstrapKeyRefFromDigest(install.DigestBytes([]byte("darwin-provider-key")))
	sentinel := errors.New("security boundary failed")

	if _, err := NewDarwinFileRollbackAnchorStore(nil, nil, nil); err == nil {
		t.Fatal("nil Darwin anchor dependencies were accepted")
	}
	if _, err := NewDarwinOperationJournalProvider(nil, nil, nil, nil); err == nil {
		t.Fatal("nil Darwin provider dependencies were accepted")
	}

	for _, test := range []struct {
		name      string
		owners    bootstrapport.OwnerBindingSource
		keys      bootstrapport.OperationKeySource
		operation install.OperationID
		want      error
	}{
		{name: "owner lookup", owners: darwinFilesystemOwnerStub{err: sentinel}, keys: darwinOperationKeyStub{ref: keyRef}, operation: operationID, want: sentinel},
		{name: "key provisioning", owners: darwinFilesystemOwnerStub{owner: owner}, keys: darwinOperationKeyStub{ref: keyRef, ensureErr: sentinel}, operation: operationID, want: sentinel},
		{name: "invalid operation", owners: darwinFilesystemOwnerStub{owner: owner}, keys: darwinOperationKeyStub{ref: keyRef}, operation: install.OperationID{}, want: journalport.ErrInvalidSnapshot},
		{name: "key access", owners: darwinFilesystemOwnerStub{owner: owner}, keys: darwinOperationKeyStub{ref: keyRef, useErr: sentinel}, operation: operationID, want: sentinel},
		{name: "key callback omitted", owners: darwinFilesystemOwnerStub{owner: owner}, keys: darwinOperationKeyStub{ref: keyRef, skipConsumer: true}, operation: operationID, want: errDarwinOperationKeyNotProvided},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			provider, err := NewDarwinOperationJournalProvider(locator, test.keys, test.owners, darwinRollbackAnchorStub{})
			if err != nil {
				t.Fatal(err)
			}
			_, err = provider.JournalFor(context.Background(), test.operation)
			if !errors.Is(err, test.want) {
				t.Fatalf("JournalFor() error = %v, want %v", err, test.want)
			}
		})
	}
}

func newDarwinTestConfigRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "config")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

type darwinFilesystemOwnerStub struct {
	owner install.OwnerBinding
	err   error
}

func (s darwinFilesystemOwnerStub) Current(ctx context.Context) (install.OwnerBinding, error) {
	if err := ctx.Err(); err != nil {
		return install.OwnerBinding{}, err
	}
	return s.owner, s.err
}

type darwinOperationKeyStub struct {
	ref          install.BootstrapKeyRef
	ensureErr    error
	useErr       error
	skipConsumer bool
}

func (s darwinOperationKeyStub) Ensure(
	context.Context,
	install.OperationID,
	install.OwnerBinding,
) (install.BootstrapKeyRef, error) {
	return s.ref, s.ensureErr
}

func (s darwinOperationKeyStub) UseHMACKey(
	_ context.Context,
	_ install.BootstrapKeyRef,
	_ install.OperationID,
	_ install.OwnerBinding,
	consumer bootstrapport.OperationKeyConsumer,
) error {
	if s.useErr != nil {
		return s.useErr
	}
	if s.skipConsumer {
		return nil
	}
	return consumer(bytes.Repeat([]byte{0xc3}, 32))
}

type darwinRollbackAnchorStub struct{}

func (darwinRollbackAnchorStub) Load(
	context.Context,
	install.BootstrapKeyRef,
	install.OperationID,
	install.OwnerBinding,
) (install.RollbackAnchor, error) {
	return install.RollbackAnchor{}, bootstrapport.ErrNotFound
}

func (darwinRollbackAnchorStub) Advance(
	context.Context,
	install.BootstrapKeyRef,
	uint64,
	install.RollbackAnchor,
) error {
	return nil
}

func (darwinRollbackAnchorStub) ConfirmDurable(
	context.Context,
	install.BootstrapKeyRef,
	install.RollbackAnchor,
) error {
	return nil
}
