package mcpsessioncredential

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpsessionapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/mcpsession"
)

var credentialTime = time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)

func TestPF005CredentialMintStoresSecretAndRegistersOnlyDigest(t *testing.T) {
	t.Parallel()
	secret := bytes.Repeat([]byte{0xa5}, credentialBytes)
	registrar := &registrarPort{}
	store := &storePort{path: "/owner/sessions/session.credential"}
	adapter, err := NewWithEntropy(registrar, store, fixedClock{}, bytes.NewReader(secret))
	if err != nil {
		t.Fatal(err)
	}
	lease, err := adapter.Mint(t.Context(), credentialScope())
	if err != nil {
		t.Fatal(err)
	}
	digestBytes := sha256.Sum256(secret)
	digest := hex.EncodeToString(digestBytes[:])
	if lease.Digest() != digest || lease.ProtectedFile() != store.path ||
		!lease.IssuedAt().Equal(credentialTime) || !lease.ExpiresAt().Equal(credentialTime.Add(12*time.Hour)) {
		t.Fatalf("lease=%#v", lease)
	}
	if !bytes.Equal(store.written, secret) || registrar.registration.Digest != digest ||
		registrar.registration.Scope != credentialScope() {
		t.Fatalf("write/registration=%x/%#v", store.written, registrar.registration)
	}
}

func TestPF005CredentialMintCompensatesRegistrationFailure(t *testing.T) {
	t.Parallel()
	registrar := &registrarPort{registerError: errors.New("core unavailable")}
	store := &storePort{path: "/owner/sessions/session.credential"}
	adapter, _ := NewWithEntropy(
		registrar, store, fixedClock{}, bytes.NewReader(bytes.Repeat([]byte{1}, credentialBytes)),
	)
	if _, err := adapter.Mint(t.Context(), credentialScope()); err == nil {
		t.Fatal("Mint(registration failure) error=nil")
	}
	if store.deleteCalls != 1 || store.deletedPath != store.path || store.deletedDigest == "" {
		t.Fatalf("compensation=%d %q %q", store.deleteCalls, store.deletedPath, store.deletedDigest)
	}
}

func TestPF005CredentialRevokeInvalidatesCoreBeforeExactDeletion(t *testing.T) {
	t.Parallel()
	registrar := &registrarPort{}
	store := &storePort{path: "/owner/sessions/session.credential"}
	adapter, _ := NewWithEntropy(
		registrar, store, fixedClock{}, bytes.NewReader(bytes.Repeat([]byte{2}, credentialBytes)),
	)
	lease, _ := adapter.Mint(t.Context(), credentialScope())
	store.events = nil
	registrar.events = nil
	if err := adapter.Revoke(t.Context(), lease); err != nil {
		t.Fatal(err)
	}
	if registrar.revokeDigest != lease.Digest() || store.deletedDigest != lease.Digest() ||
		len(registrar.events) != 1 || registrar.events[0] != "revoke" ||
		len(store.events) != 1 || store.events[0] != "delete" {
		t.Fatalf("revoke/delete=%#v/%#v", registrar, store)
	}
}

func TestPF005CredentialAdapterRejectsPartialInvalidAndCancelledAuthority(t *testing.T) {
	t.Parallel()
	if _, err := NewWithEntropy(nil, &storePort{}, fixedClock{}, strings.NewReader("entropy")); err == nil {
		t.Fatal("NewWithEntropy(nil registrar) error=nil")
	}
	var typedNil *registrarPort
	if _, err := NewWithEntropy(typedNil, &storePort{}, fixedClock{}, strings.NewReader("entropy")); err == nil {
		t.Fatal("NewWithEntropy(typed nil) error=nil")
	}
	adapter, _ := NewWithEntropy(
		&registrarPort{}, &storePort{}, fixedClock{}, bytes.NewReader(make([]byte, credentialBytes)),
	)
	invalid := credentialScope()
	invalid.SessionID = "invalid"
	if _, err := adapter.Mint(t.Context(), invalid); err == nil {
		t.Fatal("Mint(invalid scope) error=nil")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := adapter.Mint(ctx, credentialScope()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Mint(cancelled) error=%v", err)
	}
}

func TestPF005CredentialAdapterFailureMatrixFailsClosedAndCompensates(t *testing.T) {
	t.Parallel()
	registrar := &registrarPort{}
	if adapter, err := New(registrar, &storePort{}, fixedClock{}); err != nil || adapter == nil {
		t.Fatalf("New()=%v/%v", adapter, err)
	}
	shortEntropy, _ := NewWithEntropy(registrar, &storePort{}, fixedClock{}, strings.NewReader("short"))
	if _, err := shortEntropy.Mint(t.Context(), credentialScope()); err == nil {
		t.Fatal("Mint(short entropy) error=nil")
	}
	storageFailure, _ := NewWithEntropy(
		registrar,
		&storePort{writeError: errors.New("disk")},
		fixedClock{},
		bytes.NewReader(bytes.Repeat([]byte{3}, credentialBytes)),
	)
	if _, err := storageFailure.Mint(t.Context(), credentialScope()); err == nil {
		t.Fatal("Mint(storage failure) error=nil")
	}
	zeroTime, _ := NewWithEntropy(
		registrar,
		&storePort{},
		zeroClock{},
		bytes.NewReader(bytes.Repeat([]byte{4}, credentialBytes)),
	)
	if _, err := zeroTime.Mint(t.Context(), credentialScope()); err == nil {
		t.Fatal("Mint(zero clock) error=nil")
	}
	invalidPathStore := &storePort{}
	invalidLease, _ := NewWithEntropy(
		registrar,
		invalidPathStore,
		fixedClock{},
		bytes.NewReader(bytes.Repeat([]byte{5}, credentialBytes)),
	)
	if _, err := invalidLease.Mint(t.Context(), credentialScope()); err == nil ||
		invalidPathStore.deleteCalls != 1 {
		t.Fatalf("Mint(invalid protected path)=%v deletes=%d", err, invalidPathStore.deleteCalls)
	}

	revokeRegistrar := &registrarPort{revokeError: errors.New("core")}
	revokeStore := &storePort{
		path: "/owner/session.credential", deleteError: errors.New("disk"),
	}
	revoker, _ := NewWithEntropy(
		revokeRegistrar,
		revokeStore,
		fixedClock{},
		bytes.NewReader(bytes.Repeat([]byte{6}, credentialBytes)),
	)
	lease, err := revoker.Mint(t.Context(), credentialScope())
	if err != nil {
		t.Fatal(err)
	}
	if err := revoker.Revoke(t.Context(), lease); err == nil ||
		revokeRegistrar.revokeDigest != lease.Digest() || revokeStore.deleteCalls != 1 {
		t.Fatalf("Revoke(joined failures)=%v registrar=%#v store=%#v", err, revokeRegistrar, revokeStore)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := revoker.Revoke(ctx, lease); !errors.Is(err, context.Canceled) {
		t.Fatalf("Revoke(cancelled)=%v", err)
	}
	var nilAdapter *Adapter
	if _, err := nilAdapter.Mint(t.Context(), credentialScope()); err == nil {
		t.Fatal("nil Mint accepted")
	}
	if err := nilAdapter.Revoke(t.Context(), lease); err == nil {
		t.Fatal("nil Revoke accepted")
	}
}

func TestPF005CredentialScopeGitMatrixIsClosed(t *testing.T) {
	t.Parallel()
	complete := credentialScope()
	complete.GitCoverage = mcpsession.GitCoverageComplete
	complete.GitRepositoryID = strings.Repeat("a", 64)
	complete.GitWorktreeID = strings.Repeat("b", 64)
	if !validScope(complete) {
		t.Fatal("complete Git scope rejected")
	}
	partial := complete
	partial.GitCoverage = mcpsession.GitCoveragePartial
	if !validScope(partial) {
		t.Fatal("partial Git scope rejected")
	}
	partial.GitWorktreeID = ""
	if validScope(partial) {
		t.Fatal("incomplete Git scope accepted")
	}
	invalid := credentialScope()
	invalid.GitCoverage = mcpsession.GitCoverage("foreign")
	if validScope(invalid) {
		t.Fatal("foreign Git coverage accepted")
	}
	invalid = credentialScope()
	invalid.DeviceIdentity = "device\nforeign"
	if validScope(invalid) {
		t.Fatal("multiline device identity accepted")
	}
}

func credentialScope() mcpsessionapp.CredentialScope {
	return mcpsessionapp.CredentialScope{
		SessionID:            "019d2b4e-7a10-7def-8abc-0123456789ab",
		InstallationID:       "019d2b4e-7a11-7def-8abc-0123456789ab",
		BrainID:              "019d2b4e-7a12-7def-8abc-0123456789ab",
		ActorID:              "019d2b4e-7a13-7def-8abc-0123456789ab",
		GrantID:              "019d2b4e-7a14-7def-8abc-0123456789ab",
		AgentID:              "codex",
		WorkspaceFingerprint: strings.Repeat("a", 64), DeviceIdentity: "dev:1",
		GitCoverage: mcpsession.GitCoverageNone, SecurityEpoch: 7, TTL: 12 * time.Hour,
	}
}

type registrarPort struct {
	registration  mcpsessionapp.CredentialRegistration
	registerError error
	revokeDigest  string
	revokeError   error
	events        []string
}

func (p *registrarPort) Register(
	_ context.Context,
	registration mcpsessionapp.CredentialRegistration,
) error {
	p.registration = registration
	p.events = append(p.events, "register")
	return p.registerError
}

func (p *registrarPort) Revoke(_ context.Context, digest string) error {
	p.revokeDigest = digest
	p.events = append(p.events, "revoke")
	return p.revokeError
}

type storePort struct {
	path          string
	written       []byte
	writeError    error
	deleteError   error
	deletedPath   string
	deletedDigest string
	deleteCalls   int
	events        []string
}

func (p *storePort) Write(_ context.Context, _ string, secret []byte) (string, error) {
	p.written = append([]byte(nil), secret...)
	return p.path, p.writeError
}

func (p *storePort) Delete(_ context.Context, path, digest string) error {
	p.deletedPath, p.deletedDigest = path, digest
	p.deleteCalls++
	p.events = append(p.events, "delete")
	return p.deleteError
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return credentialTime }

type zeroClock struct{}

func (zeroClock) Now() time.Time { return time.Time{} }
