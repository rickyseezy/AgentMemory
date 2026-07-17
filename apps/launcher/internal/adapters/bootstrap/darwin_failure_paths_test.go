//go:build darwin

package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"testing"

	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001DarwinKeychainEnsureRejectsInvalidInputAndCorruptExistingRecord(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	owner, _ := install.BindOwner("darwin-machine", "darwin-user")
	operationID, _ := install.NewOperationID("darwin-ensure-failures")

	missing := scriptedDarwinKeychainCapability{
		get: func(context.Context, string) ([]byte, error) {
			return nil, errDarwinKeychainNotFound
		},
	}
	source, err := newDarwinKeychainOperationKeySource(
		darwinOwnerSourceStub{owner: owner},
		missing,
		bytes.NewReader(bytes.Repeat([]byte{0x51}, 32)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Ensure(ctx, install.OperationID{}, owner); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("zero operation Ensure() error = %v", err)
	}
	if _, err := source.Ensure(ctx, operationID, install.OwnerBinding{}); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("zero owner Ensure() error = %v", err)
	}

	ownerFailure := errors.New("native owner lookup failed")
	ownerFailing, _ := newDarwinKeychainOperationKeySource(
		darwinOwnerSourceStub{err: ownerFailure},
		missing,
		bytes.NewReader(bytes.Repeat([]byte{0x52}, 32)),
	)
	if _, err := ownerFailing.Ensure(ctx, operationID, owner); !errors.Is(err, ownerFailure) {
		t.Fatalf("owner lookup Ensure() error = %v", err)
	}

	corrupt := scriptedDarwinKeychainCapability{
		get: func(context.Context, string) ([]byte, error) {
			return []byte("not an owner-bound key record"), nil
		},
	}
	corruptSource, _ := newDarwinKeychainOperationKeySource(
		darwinOwnerSourceStub{owner: owner},
		corrupt,
		bytes.NewReader(bytes.Repeat([]byte{0x53}, 32)),
	)
	if _, err := corruptSource.Ensure(ctx, operationID, owner); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("corrupt existing Keychain record error = %v", err)
	}

	shortEntropy, _ := newDarwinKeychainOperationKeySource(
		darwinOwnerSourceStub{owner: owner},
		missing,
		bytes.NewReader([]byte{1, 2, 3}),
	)
	if _, err := shortEntropy.Ensure(ctx, operationID, owner); err == nil {
		t.Fatal("short Darwin HMAC entropy was accepted")
	}
}

func TestPF001DarwinKeychainSourceRequiresEachIndependentCapability(t *testing.T) {
	t.Parallel()
	owner, _ := install.BindOwner("darwin-machine", "darwin-user")
	owners := bootstrapport.OwnerBindingSource(darwinOwnerSourceStub{owner: owner})
	keychain := darwinKeychainCapability(scriptedDarwinKeychainCapability{
		get: func(context.Context, string) ([]byte, error) { return nil, errDarwinKeychainNotFound },
	})
	entropy := io.Reader(bytes.NewReader(bytes.Repeat([]byte{0x41}, 32)))
	for name, candidate := range map[string]struct {
		owners   bootstrapport.OwnerBindingSource
		keychain darwinKeychainCapability
		entropy  io.Reader
	}{
		"owner":    {keychain: keychain, entropy: entropy},
		"keychain": {owners: owners, entropy: entropy},
		"entropy":  {owners: owners, keychain: keychain},
	} {
		t.Run(name, func(t *testing.T) {
			source, err := newDarwinKeychainOperationKeySource(
				candidate.owners, candidate.keychain, candidate.entropy,
			)
			if source != nil || err == nil {
				t.Fatalf("missing %s source=%+v error=%v", name, source, err)
			}
		})
	}
}

func TestPF001DarwinKeychainSourcePropagatesContextAndClearsEveryReadBuffer(t *testing.T) {
	t.Parallel()
	owner, _ := install.BindOwner("darwin-machine", "darwin-user")
	operationID, _ := install.NewOperationID("darwin-context-binding")
	type contextKey struct{}
	token := &struct{}{}
	ctx := context.WithValue(context.Background(), contextKey{}, token)
	assertContext := func(got context.Context) {
		t.Helper()
		if got == nil || got.Value(contextKey{}) != token {
			t.Fatalf("context token was not propagated: %+v", got)
		}
	}
	var stored, lastRead []byte
	keychain := scriptedDarwinKeychainCapability{
		get: func(got context.Context, _ string) ([]byte, error) {
			assertContext(got)
			if stored == nil {
				return nil, errDarwinKeychainNotFound
			}
			lastRead = append([]byte(nil), stored...)
			return lastRead, nil
		},
		add: func(got context.Context, _ string, record []byte) error {
			assertContext(got)
			stored = append([]byte(nil), record...)
			return nil
		},
	}
	owners := darwinOwnerContextSource{
		current: func(got context.Context) (install.OwnerBinding, error) {
			assertContext(got)
			return owner, nil
		},
	}
	source, err := newDarwinKeychainOperationKeySource(
		owners, keychain, bytes.NewReader(bytes.Repeat([]byte{0x7a}, 32)),
	)
	if err != nil {
		t.Fatal(err)
	}
	keyRef, err := source.Ensure(ctx, operationID, owner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Ensure(ctx, operationID, owner); err != nil {
		t.Fatal(err)
	}
	assertClearedDarwinBytes(t, lastRead, "idempotent Ensure record")
	consumerFailure := errors.New("consumer rejected key")
	err = source.UseHMACKey(ctx, keyRef, operationID, owner, func(key []byte) error {
		if !bytes.Equal(key, bytes.Repeat([]byte{0x7a}, sha256.Size)) {
			t.Fatalf("consumer key=%x", key)
		}
		return consumerFailure
	})
	if !errors.Is(err, consumerFailure) {
		t.Fatalf("consumer error=%v", err)
	}
	assertClearedDarwinBytes(t, lastRead, "UseHMACKey record")
}

func TestPF001DarwinKeychainEnsureReconcilesDuplicatePublicationFailures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	owner, _ := install.BindOwner("darwin-machine", "darwin-user")
	operationID, _ := install.NewOperationID("darwin-duplicate-publication")
	winnerRecord, winnerRef := encodedDarwinKeyRecordFixture(t, operationID, owner, 0x91)

	t.Run("accept exact winner", func(t *testing.T) {
		getCalls := 0
		var winnerRead []byte
		keychain := scriptedDarwinKeychainCapability{
			get: func(got context.Context, _ string) ([]byte, error) {
				if got != ctx {
					t.Fatalf("winner Get context=%+v", got)
				}
				getCalls++
				if getCalls == 1 {
					return nil, errDarwinKeychainNotFound
				}
				winnerRead = append([]byte(nil), winnerRecord...)
				return winnerRead, nil
			},
			add: func(got context.Context, _ string, _ []byte) error {
				if got != ctx {
					t.Fatalf("winner Add context=%+v", got)
				}
				return errDarwinKeychainDuplicate
			},
		}
		source, _ := newDarwinKeychainOperationKeySource(
			darwinOwnerSourceStub{owner: owner},
			keychain,
			bytes.NewReader(bytes.Repeat([]byte{0x92}, 32)),
		)
		ref, err := source.Ensure(ctx, operationID, owner)
		if err != nil || !ref.Equal(winnerRef) {
			t.Fatalf("duplicate publication winner = %q, %v", ref.String(), err)
		}
		assertClearedDarwinBytes(t, winnerRead, "duplicate winner")
	})

	t.Run("reject unreadable winner", func(t *testing.T) {
		winnerReadFailure := errors.New("winner Keychain read failed")
		getCalls := 0
		keychain := scriptedDarwinKeychainCapability{
			get: func(context.Context, string) ([]byte, error) {
				getCalls++
				if getCalls == 1 {
					return nil, errDarwinKeychainNotFound
				}
				return nil, winnerReadFailure
			},
			add: func(context.Context, string, []byte) error {
				return errDarwinKeychainDuplicate
			},
		}
		source, _ := newDarwinKeychainOperationKeySource(
			darwinOwnerSourceStub{owner: owner},
			keychain,
			bytes.NewReader(bytes.Repeat([]byte{0x93}, 32)),
		)
		if _, err := source.Ensure(ctx, operationID, owner); !errors.Is(err, winnerReadFailure) {
			t.Fatalf("winner read failure = %v", err)
		}
	})

	t.Run("reject corrupt winner", func(t *testing.T) {
		getCalls := 0
		keychain := scriptedDarwinKeychainCapability{
			get: func(context.Context, string) ([]byte, error) {
				getCalls++
				if getCalls == 1 {
					return nil, errDarwinKeychainNotFound
				}
				return []byte("corrupt winner"), nil
			},
			add: func(context.Context, string, []byte) error {
				return errDarwinKeychainDuplicate
			},
		}
		source, _ := newDarwinKeychainOperationKeySource(
			darwinOwnerSourceStub{owner: owner},
			keychain,
			bytes.NewReader(bytes.Repeat([]byte{0x94}, 32)),
		)
		if _, err := source.Ensure(ctx, operationID, owner); !errors.Is(err, bootstrapport.ErrIntegrity) {
			t.Fatalf("corrupt publication winner error = %v", err)
		}
	})

	t.Run("preserve publication failure", func(t *testing.T) {
		publicationFailure := errors.New("Keychain publication failed")
		keychain := scriptedDarwinKeychainCapability{
			get: func(context.Context, string) ([]byte, error) {
				return nil, errDarwinKeychainNotFound
			},
			add: func(context.Context, string, []byte) error {
				return publicationFailure
			},
		}
		source, _ := newDarwinKeychainOperationKeySource(
			darwinOwnerSourceStub{owner: owner},
			keychain,
			bytes.NewReader(bytes.Repeat([]byte{0x95}, 32)),
		)
		if _, err := source.Ensure(ctx, operationID, owner); !errors.Is(err, publicationFailure) {
			t.Fatalf("Keychain publication failure = %v", err)
		}
	})
}

func TestPF001DarwinKeychainUseFailsClosedAtEveryLookupBoundary(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	owner, _ := install.BindOwner("darwin-machine", "darwin-user")
	operationID, _ := install.NewOperationID("darwin-use-failures")
	keyRef, _ := install.BootstrapKeyRefFromDigest(install.DigestBytes([]byte("Darwin key reference")))
	consumer := func([]byte) error { return nil }

	missing := scriptedDarwinKeychainCapability{
		get: func(context.Context, string) ([]byte, error) {
			return nil, errDarwinKeychainNotFound
		},
	}
	missingSource, _ := newDarwinKeychainOperationKeySource(
		darwinOwnerSourceStub{owner: owner},
		missing,
		bytes.NewReader(bytes.Repeat([]byte{0x61}, 32)),
	)
	if err := missingSource.UseHMACKey(ctx, install.BootstrapKeyRef{}, operationID, owner, consumer); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("zero key reference UseHMACKey() error = %v", err)
	}
	if err := missingSource.UseHMACKey(ctx, keyRef, install.OperationID{}, owner, consumer); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("zero operation UseHMACKey() error = %v", err)
	}
	if err := missingSource.UseHMACKey(ctx, keyRef, operationID, install.OwnerBinding{}, consumer); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("zero owner UseHMACKey() error = %v", err)
	}
	if err := missingSource.UseHMACKey(ctx, keyRef, operationID, owner, nil); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("nil consumer UseHMACKey() error = %v", err)
	}
	if err := missingSource.UseHMACKey(ctx, keyRef, operationID, owner, consumer); !errors.Is(err, bootstrapport.ErrNotFound) {
		t.Fatalf("missing Keychain record error = %v", err)
	}

	lookupFailure := errors.New("Keychain lookup failed")
	failing := scriptedDarwinKeychainCapability{
		get: func(context.Context, string) ([]byte, error) {
			return nil, lookupFailure
		},
	}
	failingSource, _ := newDarwinKeychainOperationKeySource(
		darwinOwnerSourceStub{owner: owner},
		failing,
		bytes.NewReader(bytes.Repeat([]byte{0x62}, 32)),
	)
	if err := failingSource.UseHMACKey(ctx, keyRef, operationID, owner, consumer); !errors.Is(err, lookupFailure) {
		t.Fatalf("Keychain lookup failure = %v", err)
	}

	ownerFailure := errors.New("owner binding unavailable")
	ownerFailing, _ := newDarwinKeychainOperationKeySource(
		darwinOwnerSourceStub{err: ownerFailure},
		missing,
		bytes.NewReader(bytes.Repeat([]byte{0x63}, 32)),
	)
	if err := ownerFailing.UseHMACKey(ctx, keyRef, operationID, owner, consumer); !errors.Is(err, ownerFailure) {
		t.Fatalf("owner lookup UseHMACKey() error = %v", err)
	}
}

func TestPF001DarwinKeyRecordEncodingRejectsInvalidReference(t *testing.T) {
	t.Parallel()
	owner, _ := install.BindOwner("darwin-machine", "darwin-user")
	operationID, _ := install.NewOperationID("darwin-invalid-record-reference")
	if _, err := encodeDarwinKeyRecord(operationID, owner, install.BootstrapKeyRef{}, [32]byte{}); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("zero record reference error = %v", err)
	}
	if _, err := darwinKeyRefDigest(install.BootstrapKeyRef{}); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("zero digest reference error = %v", err)
	}
}

func TestPF001DarwinOwnerBindingRejectsUnconfiguredLateCancellationAndMalformedUUIDs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var unconfigured *DarwinOwnerBindingSource
	if _, err := unconfigured.Current(ctx); !errors.Is(err, bootstrapport.ErrIntegrity) {
		t.Fatalf("unconfigured Darwin owner source error = %v", err)
	}

	cancellable, cancel := context.WithCancel(ctx)
	source, err := newDarwinOwnerBindingSource(
		cancellingDarwinIdentity{cancel: cancel},
		func() int { return 501 },
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Current(cancellable); !errors.Is(err, context.Canceled) {
		t.Fatalf("late-cancelled Darwin owner lookup error = %v", err)
	}

	for _, malformed := range []string{
		"01234567_89ab-cdef-0123-456789abcdef",
		"g1234567-89ab-cdef-0123-456789abcdef",
	} {
		if _, ok := canonicalDarwinUUID(malformed); ok {
			t.Fatalf("malformed Darwin UUID %q was accepted", malformed)
		}
	}
}

func encodedDarwinKeyRecordFixture(
	t *testing.T,
	operationID install.OperationID,
	owner install.OwnerBinding,
	keyByte byte,
) ([]byte, install.BootstrapKeyRef) {
	t.Helper()
	var key [32]byte
	copy(key[:], bytes.Repeat([]byte{keyByte}, len(key)))
	ref, err := keyReference(operationID, owner, key[:])
	if err != nil {
		t.Fatal(err)
	}
	record, err := encodeDarwinKeyRecord(operationID, owner, ref, key)
	if err != nil {
		t.Fatal(err)
	}
	return record, ref
}

type scriptedDarwinKeychainCapability struct {
	add func(context.Context, string, []byte) error
	get func(context.Context, string) ([]byte, error)
}

type cancellingDarwinIdentity struct {
	cancel context.CancelFunc
}

type darwinOwnerContextSource struct {
	current func(context.Context) (install.OwnerBinding, error)
}

func (s darwinOwnerContextSource) Current(ctx context.Context) (install.OwnerBinding, error) {
	return s.current(ctx)
}

func assertClearedDarwinBytes(t testing.TB, contents []byte, label string) {
	t.Helper()
	if len(contents) == 0 {
		t.Fatalf("%s was not observed", label)
	}
	for _, value := range contents {
		if value != 0 {
			t.Fatalf("%s retained key material", label)
		}
	}
}

func (c cancellingDarwinIdentity) PlatformUUID(context.Context) (string, error) {
	return "01234567-89ab-cdef-0123-456789abcdef", nil
}

func (c cancellingDarwinIdentity) UserUUID(context.Context, int) (string, error) {
	c.cancel()
	return "fedcba98-7654-3210-fedc-ba9876543210", nil
}

func (s scriptedDarwinKeychainCapability) Add(ctx context.Context, account string, record []byte) error {
	if s.add == nil {
		return nil
	}
	return s.add(ctx, account, record)
}

func (s scriptedDarwinKeychainCapability) Get(ctx context.Context, account string) ([]byte, error) {
	return s.get(ctx, account)
}
