//go:build linux

package filesystem

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001LinuxFileOperationKeySourceRejectsWrongOwnerKeyAndSymlink(t *testing.T) {
	t.Parallel()
	locator, err := bootstrapadapter.NewOperationLocator(filepath.Join(t.TempDir(), "config"))
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := install.BindOwner("linux:machine-id:0123456789abcdef0123456789abcdef", "linux:uid:1000")
	wrongOwner, _ := install.BindOwner("linux:machine-id:fedcba9876543210fedcba9876543210", "linux:uid:1000")
	source, err := newLinuxFileOperationKeySource(locator, linuxOwnerBindingStub{owner: owner}, bytes.NewReader(bytes.Repeat([]byte{0x42}, 128)))
	if err != nil {
		t.Fatal(err)
	}
	operationID, _ := install.NewOperationID("linux-key-operation")
	keyRef, err := source.Ensure(context.Background(), operationID, owner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Ensure(context.Background(), operationID, wrongOwner); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("wrong owner ensure error = %v", err)
	}
	wrongRef, _ := install.BootstrapKeyRefFromDigest(install.DigestBytes([]byte("wrong-key-reference")))
	if err := source.UseHMACKey(context.Background(), wrongRef, operationID, owner, func([]byte) error { return nil }); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("wrong key reference error = %v", err)
	}

	keyPath, _ := locator.KeyPath(operationID)
	//nolint:gosec // G304: keyPath is emitted by the digest-only locator in an isolated adversarial fixture; owner=security expiry=2027-07-13.
	contents, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	contents[len(contents)-1] ^= 0xff
	//nolint:gosec // G703: keyPath is digest-derived and this deliberate mutation tests key authentication; owner=security expiry=2027-07-13.
	if err := os.WriteFile(keyPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := source.UseHMACKey(context.Background(), keyRef, operationID, owner, func([]byte) error { return nil }); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("modified key error = %v", err)
	}

	symlinkOperation, _ := install.NewOperationID("linux-key-symlink")
	symlinkRef, err := source.Ensure(context.Background(), symlinkOperation, owner)
	if err != nil {
		t.Fatal(err)
	}
	symlinkPath, _ := locator.KeyPath(symlinkOperation)
	if err := os.Remove(symlinkPath); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "attacker-key")
	if err := os.WriteFile(target, bytes.Repeat([]byte{0x11}, linuxKeyRecordSize), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if err := source.UseHMACKey(context.Background(), symlinkRef, symlinkOperation, owner, func([]byte) error { return nil }); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("symlink key error = %v", err)
	}
}

func TestPF001LinuxFileOperationKeySourceConvergesAcrossConcurrentSources(t *testing.T) {
	t.Parallel()
	locator, _ := bootstrapadapter.NewOperationLocator(filepath.Join(t.TempDir(), "config"))
	owner, _ := install.BindOwner("linux:machine-id:0123456789abcdef0123456789abcdef", "linux:uid:1000")
	first, _ := newLinuxFileOperationKeySource(locator, linuxOwnerBindingStub{owner: owner}, bytes.NewReader(bytes.Repeat([]byte{0x10}, 64)))
	second, _ := newLinuxFileOperationKeySource(locator, linuxOwnerBindingStub{owner: owner}, bytes.NewReader(bytes.Repeat([]byte{0x20}, 64)))
	operationID, _ := install.NewOperationID("linux-key-concurrency")
	results := make(chan install.BootstrapKeyRef, 2)
	errorsChannel := make(chan error, 2)
	var waitGroup sync.WaitGroup
	for _, source := range []*LinuxFileOperationKeySource{first, second} {
		source := source
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			keyRef, err := source.Ensure(context.Background(), operationID, owner)
			results <- keyRef
			errorsChannel <- err
		}()
	}
	waitGroup.Wait()
	close(results)
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatal(err)
		}
	}
	var expected install.BootstrapKeyRef
	for keyRef := range results {
		if expected.IsZero() {
			expected = keyRef
		}
		if !keyRef.Equal(expected) {
			t.Fatal("concurrent Linux key sources returned different references")
		}
	}
}

func TestPF001LinuxFileOperationKeySourceRejectsSymlinkOperationDirectory(t *testing.T) {
	t.Parallel()
	locator, _ := bootstrapadapter.NewOperationLocator(filepath.Join(t.TempDir(), "config"))
	owner, _ := install.BindOwner("linux:machine-id:0123456789abcdef0123456789abcdef", "linux:uid:1000")
	source, _ := newLinuxFileOperationKeySource(locator, linuxOwnerBindingStub{owner: owner}, bytes.NewReader(bytes.Repeat([]byte{0x31}, 64)))
	operationID, _ := install.NewOperationID("linux-directory-symlink")
	operationDirectory, _ := locator.OperationDirectory(operationID)
	if err := os.MkdirAll(filepath.Dir(operationDirectory), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), operationDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Ensure(context.Background(), operationID, owner); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("symlink operation directory error = %v", err)
	}
}

type linuxOwnerBindingStub struct {
	owner install.OwnerBinding
	err   error
}

func (s linuxOwnerBindingStub) Current(ctx context.Context) (install.OwnerBinding, error) {
	if err := ctx.Err(); err != nil {
		return install.OwnerBinding{}, err
	}
	return s.owner, s.err
}
