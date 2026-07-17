//go:build darwin

package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"

	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001DarwinOwnerBindingUsesPlatformAndInvokingUserUUID(t *testing.T) {
	t.Parallel()
	identity := darwinIdentityStub{
		platformUUID: "01234567-89AB-CDEF-0123-456789ABCDEF",
		userUUID:     "FEDCBA98-7654-3210-FEDC-BA9876543210",
	}
	source, err := newDarwinOwnerBindingSource(&identity, func() int { return 501 })
	if err != nil {
		t.Fatal(err)
	}
	actual, err := source.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expected, _ := install.BindOwner(
		"darwin:platform-uuid:01234567-89ab-cdef-0123-456789abcdef",
		"darwin:uid:501:user-uuid:fedcba98-7654-3210-fedc-ba9876543210",
	)
	if !actual.Equal(expected) || actual.IsZero() {
		t.Fatal("Darwin owner binding did not bind both immutable native identities")
	}
	if identity.lastUID() != 501 {
		t.Fatalf("native identity lookup UID = %d", identity.lastUID())
	}
}

func TestPF001DarwinOwnerBindingFailsClosedAtEveryNativeBoundary(t *testing.T) {
	t.Parallel()
	validPlatform := "01234567-89ab-cdef-0123-456789abcdef"
	validUser := "fedcba98-7654-3210-fedc-ba9876543210"
	sentinel := errors.New("native identity unavailable")
	tests := []struct {
		name     string
		identity *darwinIdentityStub
		euid     int
	}{
		{name: "platform lookup", identity: &darwinIdentityStub{platformErr: sentinel}, euid: 501},
		{name: "user lookup", identity: &darwinIdentityStub{platformUUID: validPlatform, userErr: sentinel}, euid: 501},
		{name: "malformed platform UUID", identity: &darwinIdentityStub{platformUUID: "not-a-uuid", userUUID: validUser}, euid: 501},
		{name: "malformed user UUID", identity: &darwinIdentityStub{platformUUID: validPlatform, userUUID: "not-a-uuid"}, euid: 501},
		{name: "invalid effective UID", identity: &darwinIdentityStub{platformUUID: validPlatform, userUUID: validUser}, euid: -1},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			source, err := newDarwinOwnerBindingSource(test.identity, func() int { return test.euid })
			if err != nil {
				t.Fatal(err)
			}
			if _, err := source.Current(context.Background()); err == nil {
				t.Fatal("unsafe Darwin owner identity was accepted")
			}
		})
	}
	if _, err := newDarwinOwnerBindingSource(nil, nil); err == nil {
		t.Fatal("nil Darwin owner dependencies were accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	source, _ := newDarwinOwnerBindingSource(
		&darwinIdentityStub{platformUUID: validPlatform, userUUID: validUser},
		func() int { return 501 },
	)
	if _, err := source.Current(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled owner lookup error = %v", err)
	}
}

func TestPF001DarwinKeychainOperationKeySourceBindsAndClearsKeyMaterial(t *testing.T) {
	t.Parallel()
	owner, _ := install.BindOwner("darwin-machine", "darwin-user")
	wrongOwner, _ := install.BindOwner("other-machine", "darwin-user")
	owners := darwinOwnerSourceStub{owner: owner}
	keychain := newDarwinKeychainStub()
	source, err := newDarwinKeychainOperationKeySource(
		owners,
		keychain,
		bytes.NewReader(bytes.Repeat([]byte{0x42}, 64)),
	)
	if err != nil {
		t.Fatal(err)
	}
	operationID, _ := install.NewOperationID("darwin-key-operation")
	keyRef, err := source.Ensure(context.Background(), operationID, owner)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := source.Ensure(context.Background(), operationID, owner)
	if err != nil || !repeated.Equal(keyRef) {
		t.Fatalf("idempotent key reference = %q, %v", repeated.String(), err)
	}
	if _, err := source.Ensure(context.Background(), operationID, wrongOwner); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("wrong owner Ensure() error = %v", err)
	}
	var callbackBytes []byte
	err = source.UseHMACKey(context.Background(), keyRef, operationID, owner, func(key []byte) error {
		callbackBytes = key
		if !bytes.Equal(key, bytes.Repeat([]byte{0x42}, sha256.Size)) {
			t.Fatalf("key bytes = %x", key)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range callbackBytes {
		if value != 0 {
			t.Fatal("Darwin callback key copy was retained after use")
		}
	}
	wrongRef, _ := install.BootstrapKeyRefFromDigest(install.DigestBytes([]byte("wrong")))
	if err := source.UseHMACKey(context.Background(), wrongRef, operationID, owner, func([]byte) error { return nil }); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("wrong key reference error = %v", err)
	}
	if keychain.addCalls() != 1 {
		t.Fatalf("Keychain add calls = %d, want one", keychain.addCalls())
	}
}

func TestPF001DarwinKeychainOperationKeySourceConvergesAcrossProcesses(t *testing.T) {
	t.Parallel()
	owner, _ := install.BindOwner("darwin-machine", "darwin-user")
	owners := darwinOwnerSourceStub{owner: owner}
	keychain := newDarwinKeychainStub()
	first, _ := newDarwinKeychainOperationKeySource(owners, keychain, bytes.NewReader(bytes.Repeat([]byte{0x11}, 64)))
	second, _ := newDarwinKeychainOperationKeySource(owners, keychain, bytes.NewReader(bytes.Repeat([]byte{0x22}, 64)))
	operationID, _ := install.NewOperationID("darwin-key-concurrency")
	results := make(chan install.BootstrapKeyRef, 2)
	errorsChannel := make(chan error, 2)
	var waitGroup sync.WaitGroup
	for _, source := range []*DarwinKeychainOperationKeySource{first, second} {
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
			t.Fatal("concurrent Keychain sources returned different keys")
		}
	}
}

func TestPF001DarwinKeychainOperationKeySourceRejectsTamperAndCapabilityFailure(t *testing.T) {
	t.Parallel()
	owner, _ := install.BindOwner("darwin-machine", "darwin-user")
	owners := darwinOwnerSourceStub{owner: owner}
	operationID, _ := install.NewOperationID("darwin-key-tamper")
	for _, offset := range []int{0, 16, 48, 80, 112, 144} {
		keychain := newDarwinKeychainStub()
		source, _ := newDarwinKeychainOperationKeySource(
			owners,
			keychain,
			bytes.NewReader(bytes.Repeat([]byte{0x72}, 64)),
		)
		keyRef, err := source.Ensure(context.Background(), operationID, owner)
		if err != nil {
			t.Fatal(err)
		}
		keychain.mutate(operationID, func(record []byte) { record[offset] ^= 0xff })
		if err := source.UseHMACKey(context.Background(), keyRef, operationID, owner, func([]byte) error { return nil }); !errors.Is(err, bootstrapport.ErrIntegrity) {
			t.Fatalf("record mutation at %d error = %v", offset, err)
		}
	}
	sentinel := errors.New("Keychain interaction would be required")
	failing := newDarwinKeychainStub()
	failing.err = sentinel
	source, _ := newDarwinKeychainOperationKeySource(owners, failing, bytes.NewReader(make([]byte, 32)))
	if _, err := source.Ensure(context.Background(), operationID, owner); !errors.Is(err, sentinel) {
		t.Fatalf("Keychain capability error was not preserved: %v", err)
	}
	if _, err := newDarwinKeychainOperationKeySource(nil, nil, nil); err == nil {
		t.Fatal("nil Darwin key dependencies were accepted")
	}
}

type darwinIdentityStub struct {
	mu           sync.Mutex
	platformUUID string
	userUUID     string
	platformErr  error
	userErr      error
	uid          int
}

func (s *darwinIdentityStub) PlatformUUID(context.Context) (string, error) {
	return s.platformUUID, s.platformErr
}

func (s *darwinIdentityStub) UserUUID(_ context.Context, uid int) (string, error) {
	s.mu.Lock()
	s.uid = uid
	s.mu.Unlock()
	return s.userUUID, s.userErr
}

func (s *darwinIdentityStub) lastUID() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.uid
}

type darwinOwnerSourceStub struct {
	owner install.OwnerBinding
	err   error
}

func (s darwinOwnerSourceStub) Current(context.Context) (install.OwnerBinding, error) {
	return s.owner, s.err
}

type darwinKeychainStub struct {
	mu      sync.Mutex
	records map[string][]byte
	adds    int
	err     error
}

func newDarwinKeychainStub() *darwinKeychainStub {
	return &darwinKeychainStub{records: make(map[string][]byte)}
}

func (s *darwinKeychainStub) Add(_ context.Context, account string, record []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.adds++
	if _, exists := s.records[account]; exists {
		return errDarwinKeychainDuplicate
	}
	s.records[account] = append([]byte(nil), record...)
	return nil
}

func (s *darwinKeychainStub) Get(_ context.Context, account string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	record, exists := s.records[account]
	if !exists {
		return nil, errDarwinKeychainNotFound
	}
	return append([]byte(nil), record...), nil
}

func (s *darwinKeychainStub) mutate(operationID install.OperationID, mutate func([]byte)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	account := darwinKeychainAccount(operationID)
	record := s.records[account]
	mutate(record)
	s.records[account] = record
}

func (s *darwinKeychainStub) addCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.adds
}
