package runtimeprovision

import (
	"bytes"
	"errors"
	"testing"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF001DesktopHelperReplayRepositoryPersistsPendingAndSignedCompletion(t *testing.T) {
	t.Parallel()
	request, receipt := desktopReplayFixture(t)
	provider := newPrivilegeHelperReplayProvider(t)
	clock := &privilegeHelperClockStub{now: request.IssuedAt().Add(time.Second)}
	repository, err := NewAnchoredDesktopMutationHelperReplayRepository(provider, clock)
	if err != nil {
		t.Fatal(err)
	}
	if cached, complete, beginError := repository.BeginDesktopMutationRequest(t.Context(), request); beginError != nil ||
		complete || !cached.Digest().IsZero() {
		t.Fatalf("first begin cached=%s complete=%t error=%v", cached.Digest(), complete, beginError)
	}
	if cached, complete, beginError := repository.BeginDesktopMutationRequest(t.Context(), request); beginError != nil ||
		complete || !cached.Digest().IsZero() {
		t.Fatalf("pending begin cached=%s complete=%t error=%v", cached.Digest(), complete, beginError)
	}
	if err := repository.CompleteDesktopMutationRequest(t.Context(), request, receipt); err != nil {
		t.Fatal(err)
	}
	if err := repository.CompleteDesktopMutationRequest(t.Context(), request, receipt); err != nil {
		t.Fatalf("idempotent completion: %v", err)
	}
	restarted, _ := NewAnchoredDesktopMutationHelperReplayRepository(provider, clock)
	cached, complete, err := restarted.BeginDesktopMutationRequest(t.Context(), request)
	if err != nil || !complete || cached.Digest() != receipt.Digest() ||
		!bytes.Equal(cached.Signature(), receipt.Signature()) {
		t.Fatalf("restart cached=%s complete=%t error=%v", cached.Digest(), complete, err)
	}
	operation, _ := install.NewOperationID(request.OperationID())
	journal, _ := provider.JournalFor(t.Context(), operation)
	snapshot, err := journal.LoadLatest(t.Context())
	document, decodeError := decodeDesktopMutationHelperReplay(snapshot.Payload)
	if err != nil || decodeError != nil || document.Revision != 2 || len(document.Entries) != 1 ||
		document.Entries[0].Status != desktopMutationHelperReplayComplete {
		t.Fatalf("snapshot=%+v document=%+v errors=%v/%v", snapshot, document, err, decodeError)
	}
}

func TestPF001DesktopHelperReplayRepositoryRejectsRequestAndReceiptSubstitution(t *testing.T) {
	t.Parallel()
	request, receipt := desktopReplayFixture(t)
	provider := newPrivilegeHelperReplayProvider(t)
	clock := &privilegeHelperClockStub{now: request.IssuedAt().Add(time.Second)}
	repository, _ := NewAnchoredDesktopMutationHelperReplayRepository(provider, clock)
	if _, _, err := repository.BeginDesktopMutationRequest(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	substituted, err := runtimeport.NewDesktopMutationRequest(
		request.OperationID(), request.Attempt()+1, request.Operation(), request.Authority(),
		request.ConsentDigest(), request.ArtifactDigest(), request.Nonce(), request.IssuedAt(), request.ExpiresAt(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := repository.BeginDesktopMutationRequest(t.Context(), substituted); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("request substitution error=%v", err)
	}
	if err := repository.CompleteDesktopMutationRequest(t.Context(), request, receipt); err != nil {
		t.Fatal(err)
	}
	foreignInput := desktopReplayReceiptInput(request)
	foreignInput.Signature = bytes.Repeat([]byte{2}, 64)
	foreignInput.SignatureDigest = runtimeinstall.Sum(foreignInput.Signature)
	foreign, err := runtimeport.NewDesktopMutationReceipt(foreignInput)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.CompleteDesktopMutationRequest(t.Context(), request, foreign); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("receipt substitution error=%v", err)
	}
	if candidate, err := NewAnchoredDesktopMutationHelperReplayRepository(nil, clock); candidate != nil || err == nil {
		t.Fatalf("nil provider accepted: %+v %v", candidate, err)
	}
	if candidate, err := NewAnchoredDesktopMutationHelperReplayRepository(provider, nil); candidate != nil || err == nil {
		t.Fatalf("nil clock accepted: %+v %v", candidate, err)
	}
}

func desktopReplayFixture(t testing.TB) (runtimeport.DesktopMutationRequest, runtimeport.DesktopMutationReceipt) {
	t.Helper()
	_, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformWindows)
	now := time.Date(2026, 7, 15, 16, 0, 0, 0, time.UTC)
	request, err := runtimeport.NewDesktopMutationRequest(
		"019f5f23-5678-7def-9123-abcdef012348", 1, runtimeport.DesktopMutationInstallRuntime,
		authority, runtimeinstall.Sum([]byte("consent")), authority.ArtifactSHA256(),
		runtimeport.Nonce{4, 5, 6}, now, now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	input := desktopReplayReceiptInput(request)
	receipt, err := runtimeport.NewDesktopMutationReceipt(input)
	if err != nil {
		t.Fatal(err)
	}
	return request, receipt
}

func desktopReplayReceiptInput(request runtimeport.DesktopMutationRequest) runtimeport.DesktopMutationReceiptInput {
	signature := bytes.Repeat([]byte{1}, 64)
	return runtimeport.DesktopMutationReceiptInput{
		RequestDigest: request.Digest(), AuthorityDigest: request.Authority().Digest(), Nonce: request.Nonce(),
		PostState: request.ExpectedState(), CompletedAt: request.IssuedAt().Add(time.Second),
		ExpiresAt: request.ExpiresAt(), Signature: signature, SignatureDigest: runtimeinstall.Sum(signature),
	}
}
