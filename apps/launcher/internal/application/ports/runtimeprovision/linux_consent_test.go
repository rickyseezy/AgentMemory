package runtimeprovision

import (
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestLinuxConsentGrantBindsTheExactPlanPrincipalTermsAndPromptWindow(t *testing.T) {
	t.Parallel()
	plan := testPlan(t)
	authority, err := NewLinuxAuthority(testAuthorityInput(plan))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	nonce := Nonce{1}
	request, err := NewLinuxConsentRequest(
		"install-linux-1", 1, authority, nonce, now, now.Add(2*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := NewLinuxConsentReceipt(LinuxConsentReceiptInput{
		RequestDigest: request.Digest(), PlanDigest: authority.PlanDigest(),
		AuthorityDigest: authority.Digest(), CatalogDigest: authority.CatalogDigest(),
		ArtifactDigest: authority.ArtifactDigest(), TermsDigest: authority.TermsDigest(),
		PrincipalID: authority.PrincipalID(), MachineDigest: authority.MachineDigest(),
		Nonce: nonce, AcceptedAt: now.Add(time.Second), ExpiresAt: now.Add(24 * time.Hour),
		Signature: make([]byte, 64), SignatureDigest: runtimeinstall.Sum(make([]byte, 64)),
	})
	if err != nil || !receipt.Matches(request, now.Add(time.Second)) {
		t.Fatalf("NewLinuxConsentReceipt() = matches:%t error:%v", receipt.Matches(request, now.Add(time.Second)), err)
	}
	grant, err := NewLinuxConsentGrant(request, receipt)
	if err != nil || !grant.ValidFor("install-linux-1", authority) {
		t.Fatalf("NewLinuxConsentGrant() = valid:%t error:%v", grant.ValidFor("install-linux-1", authority), err)
	}
	if grant.Request().Digest() != request.Digest() || grant.Receipt().Digest() != receipt.Digest() {
		t.Fatal("grant did not preserve the authenticated request and receipt")
	}
	if receipt.Matches(request, now.Add(3*time.Minute)) {
		t.Fatal("expired consent response window remained valid")
	}
}

func TestLinuxConsentContractsRejectSubstitutionAndReplayFriendlyInputs(t *testing.T) {
	t.Parallel()
	plan := testPlan(t)
	authority, err := NewLinuxAuthority(testAuthorityInput(plan))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	valid := LinuxConsentRequestInput{
		OperationID: "install-linux-1", Attempt: 1, Authority: authority,
		Nonce: Nonce{1}, IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute),
	}
	for _, mutate := range []func(*LinuxConsentRequestInput){
		func(input *LinuxConsentRequestInput) { input.OperationID = "unsafe;operation" },
		func(input *LinuxConsentRequestInput) { input.Attempt = 0 },
		func(input *LinuxConsentRequestInput) { input.Authority = LinuxAuthority{} },
		func(input *LinuxConsentRequestInput) { input.Nonce = Nonce{} },
		func(input *LinuxConsentRequestInput) {
			input.IssuedAt = input.IssuedAt.In(time.FixedZone("offset", 3600))
		},
		func(input *LinuxConsentRequestInput) { input.ExpiresAt = input.IssuedAt.Add(6 * time.Minute) },
	} {
		candidate := valid
		mutate(&candidate)
		if _, requestError := NewLinuxConsentRequestFromInput(candidate); requestError == nil {
			t.Fatal("replay-friendly Linux consent request was accepted")
		}
	}
	request, err := NewLinuxConsentRequestFromInput(valid)
	if err != nil {
		t.Fatal(err)
	}
	base := LinuxConsentReceiptInput{
		RequestDigest: request.Digest(), PlanDigest: authority.PlanDigest(),
		AuthorityDigest: authority.Digest(), CatalogDigest: authority.CatalogDigest(),
		ArtifactDigest: authority.ArtifactDigest(), TermsDigest: authority.TermsDigest(),
		PrincipalID: authority.PrincipalID(), MachineDigest: authority.MachineDigest(),
		Nonce: valid.Nonce, AcceptedAt: now.Add(time.Second), ExpiresAt: now.Add(24 * time.Hour),
		Signature: make([]byte, 64), SignatureDigest: runtimeinstall.Sum(make([]byte, 64)),
	}
	for _, mutate := range []func(*LinuxConsentReceiptInput){
		func(input *LinuxConsentReceiptInput) { input.RequestDigest = runtimeinstall.Hash{} },
		func(input *LinuxConsentReceiptInput) { input.PlanDigest = runtimeinstall.Sum([]byte("other-plan")) },
		func(input *LinuxConsentReceiptInput) { input.TermsDigest = runtimeinstall.Sum([]byte("other-terms")) },
		func(input *LinuxConsentReceiptInput) { input.PrincipalID = "linux:uid:1001" },
		func(input *LinuxConsentReceiptInput) { input.Nonce = Nonce{2} },
		func(input *LinuxConsentReceiptInput) { input.AcceptedAt = now.Add(-time.Second) },
		func(input *LinuxConsentReceiptInput) { input.ExpiresAt = input.AcceptedAt },
		func(input *LinuxConsentReceiptInput) { input.Signature = nil },
	} {
		candidate := base
		mutate(&candidate)
		receipt, receiptError := NewLinuxConsentReceipt(candidate)
		if receiptError == nil && receipt.Matches(request, now.Add(time.Second)) {
			t.Fatal("substituted Linux consent receipt matched its request")
		}
	}
	validReceipt, err := NewLinuxConsentReceipt(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewLinuxConsentGrant(LinuxConsentRequest{}, validReceipt); err == nil {
		t.Fatal("grant accepted a zero request")
	}
}
