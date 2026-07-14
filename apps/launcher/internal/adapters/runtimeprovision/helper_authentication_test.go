package runtimeprovision

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestEd25519PrivilegeReceiptAuthenticatorVerifiesExactHelperAndRequest(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	helper := runtimeinstall.Sum([]byte("signed-linux-privilege-helper"))
	request, input := privilegeAuthenticationFixture(t, helper)
	receipt := signedPrivilegeAuthenticationReceipt(t, private, input)
	authenticator, err := NewEd25519PrivilegeReceiptAuthenticator(public, helper)
	if err != nil || authenticator.VerifyPrivilegeReceipt(t.Context(), request, receipt) != nil {
		t.Fatalf("authenticator=%v error=%v", authenticator, err)
	}

	foreignPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	foreign, _ := NewEd25519PrivilegeReceiptAuthenticator(foreignPublic, helper)
	wrongHelper, _ := NewEd25519PrivilegeReceiptAuthenticator(public, runtimeinstall.Sum([]byte("foreign-helper")))
	for name, candidate := range map[string]*Ed25519PrivilegeReceiptAuthenticator{
		"foreign key": foreign, "foreign helper": wrongHelper, "nil": nil,
	} {
		if err := candidate.VerifyPrivilegeReceipt(t.Context(), request, receipt); !errors.Is(err, runtimeport.ErrPrivilegeIntegrity) {
			t.Fatalf("%s error=%v", name, err)
		}
	}
	for _, input := range []struct {
		key    ed25519.PublicKey
		helper runtimeinstall.Hash
	}{{}, {key: public}} {
		if candidate, err := NewEd25519PrivilegeReceiptAuthenticator(input.key, input.helper); candidate != nil ||
			!errors.Is(err, ErrProvisionIntegrity) {
			t.Fatalf("invalid constructor accepted: %v,%v", candidate, err)
		}
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := authenticator.VerifyPrivilegeReceipt(cancelled, request, receipt); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
	input.Signature = receipt.Signature()
	input.Signature[0] ^= 1
	forged, err := runtimeport.NewPrivilegeReceipt(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := authenticator.VerifyPrivilegeReceipt(t.Context(), request, forged); !errors.Is(err, runtimeport.ErrPrivilegeIntegrity) {
		t.Fatalf("forged signature error=%v", err)
	}
}

func TestEd25519DesktopMutationAuthenticatorVerifiesDomainSeparatedStatement(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	request, input := desktopAuthenticationFixture(t)
	receipt := signedDesktopAuthenticationReceipt(t, private, input)
	authenticator, err := NewEd25519DesktopMutationAuthenticator(public)
	if err != nil || authenticator.VerifyDesktopMutation(t.Context(), request, receipt) != nil {
		t.Fatalf("authenticator=%v error=%v", authenticator, err)
	}
	if candidate, err := NewEd25519DesktopMutationAuthenticator(nil); candidate != nil ||
		!errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("empty key accepted: %v,%v", candidate, err)
	}
	foreignPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	foreign, _ := NewEd25519DesktopMutationAuthenticator(foreignPublic)
	if err := foreign.VerifyDesktopMutation(t.Context(), request, receipt); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("foreign key error=%v", err)
	}
	input.Signature = receipt.Signature()
	input.Signature[0] ^= 1
	input.SignatureDigest = runtimeinstall.Sum(input.Signature)
	forged, err := runtimeport.NewDesktopMutationReceipt(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := authenticator.VerifyDesktopMutation(t.Context(), request, forged); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("forged signature error=%v", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := authenticator.VerifyDesktopMutation(cancelled, request, receipt); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
	if err := (*Ed25519DesktopMutationAuthenticator)(nil).VerifyDesktopMutation(t.Context(), request, receipt); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("nil authenticator error=%v", err)
	}
}

func privilegeAuthenticationFixture(
	t *testing.T,
	helper runtimeinstall.Hash,
) (runtimeport.PrivilegeRequest, runtimeport.PrivilegeReceiptInput) {
	t.Helper()
	_, authority := adapterAuthority(t)
	now := time.Date(2026, 7, 15, 15, 0, 0, 0, time.UTC)
	expected, err := runtimeport.ExpectedPrivilegeState(authority, runtimeport.PrivilegeConfigureRepository)
	if err != nil {
		t.Fatal(err)
	}
	request, err := runtimeport.NewPrivilegeRequest(runtimeport.PrivilegeRequestInput{
		OperationID: "helper-auth-operation", Attempt: 1, Operation: runtimeport.PrivilegeConfigureRepository,
		Authority: authority, Nonce: runtimeport.Nonce{1}, IssuedAt: now,
		ExpiresAt: now.Add(time.Minute), ExpectedState: expected,
	})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := runtimeport.ExpectedRepositoryStateDigest(authority)
	if err != nil {
		t.Fatal(err)
	}
	return request, runtimeport.PrivilegeReceiptInput{
		RequestDigest: request.Digest(), OperationKey: request.OperationKey(), PlanDigest: authority.PlanDigest(),
		AuthorityDigest: authority.Digest(), Operation: request.Operation(), PrincipalID: authority.PrincipalID(),
		MachineDigest: authority.MachineDigest(), Nonce: request.Nonce(), ExpiresAt: request.ExpiresAt(),
		Result: runtimeport.PrivilegeResultCompleted, ObservedState: request.ExpectedState(),
		RepositoryDigest: repository, HelperDigest: helper,
	}
}

func signedPrivilegeAuthenticationReceipt(
	t testing.TB,
	private ed25519.PrivateKey,
	input runtimeport.PrivilegeReceiptInput,
) runtimeport.PrivilegeReceipt {
	t.Helper()
	input.Signature = make([]byte, ed25519.SignatureSize)
	unsigned, err := runtimeport.NewPrivilegeReceipt(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Signature = ed25519.Sign(private, unsigned.AuthenticationPayload())
	receipt, err := runtimeport.NewPrivilegeReceipt(input)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func desktopAuthenticationFixture(
	t testing.TB,
) (runtimeport.DesktopMutationRequest, runtimeport.DesktopMutationReceiptInput) {
	t.Helper()
	_, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformDarwin)
	now := time.Date(2026, 7, 15, 15, 0, 0, 0, time.UTC)
	request, err := runtimeport.NewDesktopMutationRequest(
		"desktop-helper-auth", 1, runtimeport.DesktopMutationInstallRuntime, authority,
		runtimeinstall.Sum([]byte("consent")), runtimeinstall.Sum([]byte("artifact")),
		runtimeport.Nonce{2}, now, now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	return request, runtimeport.DesktopMutationReceiptInput{
		RequestDigest: request.Digest(), AuthorityDigest: authority.Digest(), Nonce: request.Nonce(),
		PostState: request.ExpectedState(), CompletedAt: now.Add(time.Second), ExpiresAt: now.Add(time.Minute),
	}
}

func signedDesktopAuthenticationReceipt(
	t testing.TB,
	private ed25519.PrivateKey,
	input runtimeport.DesktopMutationReceiptInput,
) runtimeport.DesktopMutationReceipt {
	t.Helper()
	input.Signature = make([]byte, ed25519.SignatureSize)
	input.SignatureDigest = runtimeinstall.Sum(input.Signature)
	unsigned, err := runtimeport.NewDesktopMutationReceipt(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Signature = ed25519.Sign(private, unsigned.AuthenticationPayload())
	input.SignatureDigest = runtimeinstall.Sum(input.Signature)
	receipt, err := runtimeport.NewDesktopMutationReceipt(input)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}
