//go:build linux

package filesystem

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001LinuxBootstrapSecurityConstructorsAndBoundariesFailClosed(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "config")
	locator, _ := bootstrapadapter.NewOperationLocator(root)
	owner, _ := install.BindOwner("linux:machine-id:0123456789abcdef0123456789abcdef", "linux:uid:1000")
	ownerSource := linuxOwnerBindingStub{owner: owner}
	if _, err := NewLinuxFileOperationKeySource(locator, ownerSource); err != nil {
		t.Fatal(err)
	}
	if _, err := newLinuxFileOperationKeySource(nil, ownerSource, bytes.NewReader(make([]byte, 32))); err == nil {
		t.Fatal("nil key locator was accepted")
	}
	if _, err := NewLinuxFileRollbackAnchorStore(nil, nil, nil); err == nil {
		t.Fatal("nil anchor dependencies were accepted")
	}
	if _, err := NewLinuxOperationJournalProvider(nil, nil, nil, nil); err == nil {
		t.Fatal("nil journal-provider dependencies were accepted")
	}

	operationID, _ := install.NewOperationID("linux-edge-key")
	shortSource, _ := newLinuxFileOperationKeySource(locator, ownerSource, bytes.NewReader([]byte{1}))
	if _, err := shortSource.Ensure(context.Background(), operationID, owner); err == nil {
		t.Fatal("short Linux key entropy was accepted")
	}
	source, _ := newLinuxFileOperationKeySource(locator, ownerSource, bytes.NewReader(bytes.Repeat([]byte{0x92}, 64)))
	keyRef, err := source.Ensure(context.Background(), operationID, owner)
	if err != nil {
		t.Fatal(err)
	}
	repeatedRef, err := source.Ensure(context.Background(), operationID, owner)
	if err != nil || !repeatedRef.Equal(keyRef) {
		t.Fatalf("repeated key ensure = %q, %v", repeatedRef.String(), err)
	}
	if err := source.UseHMACKey(context.Background(), install.BootstrapKeyRef{}, operationID, owner, func([]byte) error { return nil }); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("zero key reference error = %v", err)
	}
	if err := source.UseHMACKey(context.Background(), keyRef, operationID, owner, nil); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("nil key consumer error = %v", err)
	}
	missingID, _ := install.NewOperationID("linux-edge-missing")
	if err := source.UseHMACKey(context.Background(), keyRef, missingID, owner, func([]byte) error { return nil }); !errors.Is(err, bootstrapport.ErrNotFound) {
		t.Fatalf("missing key file error = %v", err)
	}
	ownerFailure := errors.New("owner lookup failed")
	failingSource, _ := newLinuxFileOperationKeySource(locator, linuxOwnerBindingStub{err: ownerFailure}, bytes.NewReader(make([]byte, 32)))
	if _, err := failingSource.Ensure(context.Background(), operationID, owner); !errors.Is(err, ownerFailure) {
		t.Fatalf("owner source error was not preserved: %v", err)
	}
	if err := failingSource.UseHMACKey(context.Background(), keyRef, operationID, owner, func([]byte) error { return nil }); !errors.Is(err, ownerFailure) {
		t.Fatalf("key-use owner source error was not preserved: %v", err)
	}
	if _, err := source.Ensure(context.Background(), install.OperationID{}, owner); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("zero operation key error = %v", err)
	}
	if err := source.UseHMACKey(context.Background(), keyRef, install.OperationID{}, owner, func([]byte) error { return nil }); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("zero operation key-use error = %v", err)
	}
	if _, err := source.Ensure(context.Background(), operationID, install.OwnerBinding{}); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("zero key owner error = %v", err)
	}
	if _, err := keyRefDigest(install.BootstrapKeyRef{}); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("invalid key-ref digest error = %v", err)
	}

	anchorStore, _ := NewLinuxFileRollbackAnchorStore(locator, source, ownerSource)
	anchorID, _ := install.NewOperationID("linux-edge-anchor")
	anchorRef, _ := source.Ensure(context.Background(), anchorID, owner)
	if _, err := anchorStore.Load(context.Background(), anchorRef, anchorID, owner); !errors.Is(err, bootstrapport.ErrNotFound) {
		t.Fatalf("missing anchor error = %v", err)
	}
	if _, err := anchorStore.Load(context.Background(), anchorRef, install.OperationID{}, owner); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("zero anchor operation error = %v", err)
	}
	if _, err := anchorStore.Load(context.Background(), anchorRef, anchorID, install.OwnerBinding{}); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("zero anchor owner error = %v", err)
	}
	failingAnchorStore, _ := NewLinuxFileRollbackAnchorStore(locator, source, linuxOwnerBindingStub{err: ownerFailure})
	if _, err := failingAnchorStore.Load(context.Background(), anchorRef, anchorID, owner); !errors.Is(err, ownerFailure) {
		t.Fatalf("anchor owner-source error was not preserved: %v", err)
	}
	second, _ := install.NewRollbackAnchor(anchorID, owner, 2, install.DigestBytes([]byte("second")))
	if err := anchorStore.Advance(context.Background(), anchorRef, 1, second); !errors.Is(err, bootstrapport.ErrConflict) {
		t.Fatalf("missing anchor predecessor error = %v", err)
	}
	if err := anchorStore.Advance(context.Background(), anchorRef, 0, second); !errors.Is(err, bootstrapport.ErrConflict) {
		t.Fatalf("skipped anchor sequence error = %v", err)
	}
}

func TestPF001LinuxBootstrapSecurityRejectsUncreatableOperationDirectory(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "config-file")
	if err := os.WriteFile(root, []byte("not-a-directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	locator, _ := bootstrapadapter.NewOperationLocator(root)
	owner, _ := install.BindOwner("linux:machine-id:0123456789abcdef0123456789abcdef", "linux:uid:1000")
	source, _ := newLinuxFileOperationKeySource(locator, linuxOwnerBindingStub{owner: owner}, bytes.NewReader(make([]byte, 32)))
	operationID, _ := install.NewOperationID("linux-uncreatable-directory")
	if _, err := source.Ensure(context.Background(), operationID, owner); err == nil {
		t.Fatal("operation key creation beneath a regular file succeeded")
	}
}

func TestPF001LinuxBootstrapSecurityRejectsEveryKeyRecordBindingMutation(t *testing.T) {
	t.Parallel()
	locator, _ := bootstrapadapter.NewOperationLocator(filepath.Join(t.TempDir(), "config"))
	owner, _ := install.BindOwner("linux:machine-id:0123456789abcdef0123456789abcdef", "linux:uid:1000")
	source, _ := newLinuxFileOperationKeySource(locator, linuxOwnerBindingStub{owner: owner}, bytes.NewReader(bytes.Repeat([]byte{0xa2}, 64)))
	operationID, _ := install.NewOperationID("linux-key-record-mutations")
	keyRef, _ := source.Ensure(context.Background(), operationID, owner)
	keyPath, _ := locator.KeyPath(operationID)
	//nolint:gosec // G304: keyPath is digest-derived inside the isolated fixture; owner=security expiry=2027-07-13.
	original, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{0, 16, 48, 80, 112, 144} {
		mutated := append([]byte(nil), original...)
		mutated[offset] ^= 0xff
		//nolint:gosec // G703: deliberate mutation of a digest-derived fixture verifies every record binding; owner=security expiry=2027-07-13.
		if err := os.WriteFile(keyPath, mutated, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := source.UseHMACKey(context.Background(), keyRef, operationID, owner, func([]byte) error { return nil }); !errors.Is(err, bootstrapport.ErrIntegrity) {
			t.Fatalf("key mutation at offset %d error = %v", offset, err)
		}
		if offset == 0 {
			if _, err := source.Ensure(context.Background(), operationID, owner); !errors.Is(err, bootstrapport.ErrIntegrity) {
				t.Fatalf("key ensure mutation error = %v", err)
			}
		}
	}
	//nolint:gosec // G703: restores the digest-derived fixture for the size and mode attacks below; owner=security expiry=2027-07-13.
	if err := os.WriteFile(keyPath, original[:len(original)-1], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := source.UseHMACKey(context.Background(), keyRef, operationID, owner, func([]byte) error { return nil }); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("truncated key record error = %v", err)
	}
	//nolint:gosec // G302: deliberately unsafe permission fixture verifies fail-closed key reads; owner=security expiry=2027-07-13.
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := source.UseHMACKey(context.Background(), keyRef, operationID, owner, func([]byte) error { return nil }); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("unsafe key mode error = %v", err)
	}
}

func TestPF001LinuxBootstrapSecurityRejectsEveryAnchorRecordMutation(t *testing.T) {
	t.Parallel()
	locator, _ := bootstrapadapter.NewOperationLocator(filepath.Join(t.TempDir(), "config"))
	owner, _ := install.BindOwner("linux:machine-id:0123456789abcdef0123456789abcdef", "linux:uid:1000")
	ownerSource := linuxOwnerBindingStub{owner: owner}
	keys, _ := newLinuxFileOperationKeySource(locator, ownerSource, bytes.NewReader(bytes.Repeat([]byte{0xb2}, 64)))
	store, _ := NewLinuxFileRollbackAnchorStore(locator, keys, ownerSource)
	operationID, _ := install.NewOperationID("linux-anchor-record-mutations")
	keyRef, _ := keys.Ensure(context.Background(), operationID, owner)
	anchor, _ := install.NewRollbackAnchor(operationID, owner, 1, install.DigestBytes([]byte("anchor")))
	if err := store.Advance(context.Background(), keyRef, 0, anchor); err != nil {
		t.Fatal(err)
	}
	anchorPath, _ := locator.RollbackAnchorPath(operationID)
	//nolint:gosec // G304: anchorPath is digest-derived inside the isolated fixture; owner=security expiry=2027-07-13.
	original, err := os.ReadFile(anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{0, 16, 48, 80, 112, 120, 152} {
		mutated := append([]byte(nil), original...)
		mutated[offset] ^= 0xff
		//nolint:gosec // G703: deliberate mutation of a digest-derived fixture verifies every anchor field; owner=security expiry=2027-07-13.
		if err := os.WriteFile(anchorPath, mutated, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(context.Background(), keyRef, operationID, owner); !errors.Is(err, bootstrapport.ErrIntegrity) {
			t.Fatalf("anchor mutation at offset %d error = %v", offset, err)
		}
	}
	for _, mutation := range []struct {
		name  string
		start int
		end   int
	}{
		{name: "zero sequence", start: 112, end: 120},
		{name: "zero state digest", start: 120, end: 152},
	} {
		mutated := append([]byte(nil), original...)
		clear(mutated[mutation.start:mutation.end])
		//nolint:gosec // G703: deliberate digest-derived fixture mutation exercises fail-closed parsing; owner=security expiry=2027-07-13.
		if err := os.WriteFile(anchorPath, mutated, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(context.Background(), keyRef, operationID, owner); !errors.Is(err, bootstrapport.ErrIntegrity) {
			t.Fatalf("anchor %s error = %v", mutation.name, err)
		}
	}
}

func TestPF001LinuxProtectedFileHelpersRejectUnsafeTargets(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(root, "missing")
	if _, err := readProtectedFile(missing, 1); !errors.Is(err, bootstrapport.ErrNotFound) {
		t.Fatalf("missing protected file error = %v", err)
	}
	short := filepath.Join(root, "short")
	if err := os.WriteFile(short, []byte{1}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedFile(short, 2); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("short protected file error = %v", err)
	}
	unsafe := filepath.Join(root, "unsafe")
	if err := os.WriteFile(unsafe, []byte{1}, 0o600); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // G302: deliberately unsafe permission fixture verifies fail-closed protected reads; owner=security expiry=2027-07-13.
	if err := os.Chmod(unsafe, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedFile(unsafe, 1); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("unsafe protected file error = %v", err)
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replaceProtectedFile(context.Background(), target, []byte("new")); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // G304: target is an isolated fixed test path used to verify replacement output; owner=security expiry=2027-07-13.
	contents, err := os.ReadFile(target)
	if err != nil || string(contents) != "new" {
		t.Fatalf("atomic replacement = %q, %v", contents, err)
	}
	symlink := filepath.Join(root, "symlink")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if err := replaceProtectedFile(context.Background(), symlink, []byte("attack")); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("symlink replacement error = %v", err)
	}
}
