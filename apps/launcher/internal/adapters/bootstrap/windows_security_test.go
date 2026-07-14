//go:build windows

package bootstrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001WindowsOwnerBindingUsesMachineGUIDAndInvokingSID(t *testing.T) {
	t.Parallel()
	identity := windowsIdentityStub{
		machineGUID: "01234567-89AB-CDEF-0123-456789ABCDEF",
		userSID:     "S-1-5-21-111111111-222222222-333333333-1001",
	}
	source, err := newWindowsOwnerBindingSource(identity)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := source.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expected, _ := install.BindOwner(
		"windows:machine-guid:01234567-89ab-cdef-0123-456789abcdef",
		"windows:sid:S-1-5-21-111111111-222222222-333333333-1001",
	)
	if !owner.Equal(expected) {
		t.Fatal("Windows owner binding omitted or changed native identity")
	}
}

func TestPF001WindowsOwnerBindingFailsClosed(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("native identity failed")
	for _, test := range []windowsIdentityStub{
		{err: sentinel},
		{machineGUID: "not-a-guid", userSID: "S-1-5-21-1"},
		{machineGUID: "01234567-89ab-cdef-0123-456789abcdef", userSID: "not-a-sid"},
	} {
		source, err := newWindowsOwnerBindingSource(test)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := source.Current(context.Background()); err == nil {
			t.Fatal("unsafe Windows identity was accepted")
		}
	}
	if _, err := newWindowsOwnerBindingSource(nil); err == nil {
		t.Fatal("nil Windows identity capability was accepted")
	}
}

func TestPF001WindowsDPAPIOperationKeySourceBindsAndClearsKey(t *testing.T) {
	t.Parallel()
	owner, _ := install.BindOwner("windows-machine", "windows-user")
	wrongOwner, _ := install.BindOwner("different-machine", "windows-user")
	owners := windowsOwnerSourceStub{owner: owner}
	store := newWindowsKeyStoreStub()
	protector := windowsDPAPIStub{}
	source, err := newWindowsDPAPIOperationKeySource(
		owners,
		protector,
		store,
		bytes.NewReader(bytes.Repeat([]byte{0x41}, 64)),
		&windowsOperationLockStub{},
	)
	if err != nil {
		t.Fatal(err)
	}
	operationID, _ := install.NewOperationID("windows-dpapi-key")
	keyRef, err := source.Ensure(context.Background(), operationID, owner)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := source.Ensure(context.Background(), operationID, owner)
	if err != nil || !repeated.Equal(keyRef) {
		t.Fatalf("repeated key ensure = %q, %v", repeated.String(), err)
	}
	var observed []byte
	if err := source.UseHMACKey(context.Background(), keyRef, operationID, owner, func(key []byte) error {
		observed = key
		if !bytes.Equal(key, bytes.Repeat([]byte{0x41}, 32)) {
			t.Fatal("unexpected DPAPI key bytes")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(observed, make([]byte, 32)) {
		t.Fatal("Windows key callback copy was retained after use")
	}
	if err := source.UseHMACKey(context.Background(), keyRef, operationID, wrongOwner, func([]byte) error { return nil }); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("wrong owner error = %v", err)
	}
	wrongRef, _ := install.BootstrapKeyRefFromDigest(install.DigestBytes([]byte("wrong-ref")))
	if err := source.UseHMACKey(context.Background(), wrongRef, operationID, owner, func([]byte) error { return nil }); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("wrong key reference error = %v", err)
	}
	if store.plaintextPublished() {
		t.Fatal("operation key was persisted without DPAPI protection")
	}
}

func TestPF001WindowsDPAPIOperationKeySourceConvergesAcrossInstances(t *testing.T) {
	t.Parallel()
	owner, _ := install.BindOwner("windows-machine", "windows-user")
	owners := windowsOwnerSourceStub{owner: owner}
	store := newWindowsKeyStoreStub()
	lock := &windowsOperationLockStub{}
	first, _ := newWindowsDPAPIOperationKeySource(owners, windowsDPAPIStub{}, store, bytes.NewReader(bytes.Repeat([]byte{0x11}, 32)), lock)
	second, _ := newWindowsDPAPIOperationKeySource(owners, windowsDPAPIStub{}, store, bytes.NewReader(bytes.Repeat([]byte{0x22}, 32)), lock)
	operationID, _ := install.NewOperationID("windows-dpapi-convergence")
	results := make(chan install.BootstrapKeyRef, 2)
	errorsChannel := make(chan error, 2)
	var waitGroup sync.WaitGroup
	for _, source := range []*WindowsDPAPIOperationKeySource{first, second} {
		source := source
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			ref, err := source.Ensure(context.Background(), operationID, owner)
			results <- ref
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
	var firstRef install.BootstrapKeyRef
	for ref := range results {
		if firstRef.IsZero() {
			firstRef = ref
		} else if !firstRef.Equal(ref) {
			t.Fatal("concurrent Windows key sources did not converge")
		}
	}
}

func TestPF001WindowsCredentialTargetIsDigestOnlyAndOperationSpecific(t *testing.T) {
	t.Parallel()
	firstID, _ := install.NewOperationID("private raw operation name")
	secondID, _ := install.NewOperationID("another operation")
	first, err := windowsCredentialTarget(firstID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := windowsCredentialTarget(secondID)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || !strings.HasPrefix(first, "AgentMemory/bootstrap-hmac/v1/sha256-") {
		t.Fatalf("credential targets are not fixed digest identities: %q, %q", first, second)
	}
	if strings.Contains(first, firstID.String()) {
		t.Fatal("raw operation identity leaked into the Windows Credential Manager target")
	}
}

func TestPF001WindowsDPAPIKeySourceFailsClosedWhenOperationLockFails(t *testing.T) {
	t.Parallel()
	owner, _ := install.BindOwner("windows-machine", "windows-user")
	sentinel := errors.New("operation lock unavailable")
	source, err := newWindowsDPAPIOperationKeySource(
		windowsOwnerSourceStub{owner: owner},
		windowsDPAPIStub{},
		newWindowsKeyStoreStub(),
		bytes.NewReader(bytes.Repeat([]byte{0x71}, 32)),
		&windowsOperationLockStub{err: sentinel},
	)
	if err != nil {
		t.Fatal(err)
	}
	operationID, _ := install.NewOperationID("windows-lock-failure")
	if _, err := source.Ensure(context.Background(), operationID, owner); !errors.Is(err, sentinel) {
		t.Fatalf("operation lock failure = %v", err)
	}
}

func TestPF001WindowsProductionCredentialKeySourceConverges(t *testing.T) {
	locator, err := NewOperationLocator(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	owners, err := NewWindowsOwnerBindingSource()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := owners.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var randomSuffix [8]byte
	if _, err := rand.Read(randomSuffix[:]); err != nil {
		t.Fatal(err)
	}
	operationID, err := install.NewOperationID("windows-credential-integration-" + hex.EncodeToString(randomSuffix[:]))
	if err != nil {
		t.Fatal(err)
	}
	target, _ := windowsCredentialTarget(operationID)
	_ = windowssecurity.DeleteGenericCredential(context.Background(), target)
	t.Cleanup(func() { _ = windowssecurity.DeleteGenericCredential(context.Background(), target) })

	first, err := NewWindowsDPAPIOperationKeySource(locator, owners)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewWindowsDPAPIOperationKeySource(locator, owners)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan install.BootstrapKeyRef, 2)
	errorsChannel := make(chan error, 2)
	var waitGroup sync.WaitGroup
	for _, source := range []*WindowsDPAPIOperationKeySource{first, second} {
		source := source
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			ref, ensureError := source.Ensure(context.Background(), operationID, owner)
			results <- ref
			errorsChannel <- ensureError
		}()
	}
	waitGroup.Wait()
	close(results)
	close(errorsChannel)
	for ensureError := range errorsChannel {
		if ensureError != nil {
			t.Fatal(ensureError)
		}
	}
	var keyRef install.BootstrapKeyRef
	for result := range results {
		if keyRef.IsZero() {
			keyRef = result
		} else if !keyRef.Equal(result) {
			t.Fatal("native Credential Manager key sources did not converge")
		}
	}
	var key []byte
	if err := first.UseHMACKey(context.Background(), keyRef, operationID, owner, func(value []byte) error {
		key = append([]byte(nil), value...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	if len(key) != 32 {
		t.Fatalf("native operation key length = %d", len(key))
	}
	record, err := windowssecurity.ReadGenericCredential(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(record)
	if bytes.Contains(record, key) {
		t.Fatal("Windows Credential Manager record exposed plaintext HMAC key bytes")
	}
}

type windowsIdentityStub struct {
	machineGUID string
	userSID     string
	err         error
}

func (s windowsIdentityStub) MachineGUID(context.Context) (string, error) {
	return s.machineGUID, s.err
}
func (s windowsIdentityStub) UserSID(context.Context) (string, error) { return s.userSID, s.err }

type windowsOwnerSourceStub struct {
	owner install.OwnerBinding
	err   error
}

func (s windowsOwnerSourceStub) Current(context.Context) (install.OwnerBinding, error) {
	return s.owner, s.err
}

type windowsDPAPIStub struct{}

func (windowsDPAPIStub) Protect(_ context.Context, plaintext, entropy []byte) ([]byte, error) {
	result := append([]byte("DPAPI:"), entropy...)
	result = append(result, plaintext...)
	return result, nil
}

type windowsOperationLockStub struct {
	mu  sync.Mutex
	err error
}

func (s *windowsOperationLockStub) WithExclusive(
	_ context.Context,
	_ install.OperationID,
	_ install.OwnerBinding,
	action func() error,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	return action()
}

func (windowsDPAPIStub) Unprotect(_ context.Context, ciphertext, entropy []byte) ([]byte, error) {
	prefix := append([]byte("DPAPI:"), entropy...)
	if !bytes.HasPrefix(ciphertext, prefix) {
		return nil, errors.New("DPAPI binding mismatch")
	}
	return append([]byte(nil), ciphertext[len(prefix):]...), nil
}

type windowsKeyStoreStub struct {
	mu      sync.Mutex
	records map[string][]byte
}

func newWindowsKeyStoreStub() *windowsKeyStoreStub {
	return &windowsKeyStoreStub{records: make(map[string][]byte)}
}

func (s *windowsKeyStoreStub) Load(_ context.Context, operationID install.OperationID) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.records[operationID.String()]
	if !exists {
		return nil, bootstrapport.ErrNotFound
	}
	return append([]byte(nil), record...), nil
}

func (s *windowsKeyStoreStub) Publish(_ context.Context, operationID install.OperationID, record []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.records[operationID.String()]; exists {
		return false, nil
	}
	s.records[operationID.String()] = append([]byte(nil), record...)
	return true, nil
}

func (s *windowsKeyStoreStub) plaintextPublished() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range s.records {
		if !bytes.HasPrefix(record, []byte("DPAPI:")) {
			return true
		}
	}
	return false
}
