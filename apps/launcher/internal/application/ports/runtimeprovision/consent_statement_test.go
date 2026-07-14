package runtimeprovision

import (
	"bytes"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestLinuxConsentStatementRoundTripsSignedReceipt(t *testing.T) {
	t.Parallel()
	plan := testPlan(t)
	authority, err := NewLinuxAuthority(testAuthorityInput(plan))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	request, err := NewLinuxConsentRequest(
		"statement-linux-1", 1, authority, Nonce{1}, now, now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	statement := LinuxConsentStatement{
		RequestDigest: request.Digest(), PlanDigest: authority.PlanDigest(),
		AuthorityDigest: authority.Digest(), CatalogDigest: authority.CatalogDigest(),
		ArtifactDigest: authority.ArtifactDigest(), TermsDigest: authority.TermsDigest(),
		PrincipalID: authority.PrincipalID(), MachineDigest: authority.MachineDigest(),
		Nonce: request.Nonce(), AcceptedAt: now.Add(time.Second), ExpiresAt: now.Add(time.Hour),
	}
	canonical, err := statement.CanonicalBytes()
	if err != nil || len(canonical) == 0 {
		t.Fatalf("CanonicalBytes()=%q,%v", canonical, err)
	}
	signature := bytes.Repeat([]byte{0x5a}, 64)
	receipt, err := NewSignedLinuxConsentReceipt(statement, signature)
	if err != nil || receipt.Statement() != statement || !receipt.Matches(request, now.Add(time.Second)) {
		t.Fatalf("receipt=%+v error=%v", receipt, err)
	}
	signature[0] ^= 0xff
	if bytes.Equal(signature, receipt.Signature()) {
		t.Fatal("signed Linux receipt aliased signature bytes")
	}
	statement.TermsDigest = runtimeinstall.Sum([]byte("substituted"))
	changed, _ := statement.CanonicalBytes()
	if bytes.Equal(canonical, changed) {
		t.Fatal("terms substitution did not change Linux signing bytes")
	}
}

func TestDesktopConsentStatementRoundTripsSignedReceipt(t *testing.T) {
	t.Parallel()
	authority := desktopContractAuthority(t, runtimeinstall.PlatformWindows)
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	request, err := NewDesktopConsentRequest(
		"statement-desktop-1", 1, authority, Nonce{1}, now, now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	statement := DesktopConsentStatement{
		RequestDigest: request.Digest(), AuthorityDigest: authority.Digest(),
		PlanDigest: authority.PlanDigest(), TermsDigest: authority.Terms().Digest(),
		PrincipalID: authority.PrincipalID(), MachineDigest: authority.MachineDigest(),
		Nonce: request.Nonce(), ExplicitlyAccepted: true, AuthorityAndEntitlement: true,
		NonPreselectedConfirmation: true, AcceptedAt: now.Add(time.Second), ExpiresAt: now.Add(time.Hour),
	}
	canonical, err := statement.CanonicalBytes()
	if err != nil || len(canonical) == 0 {
		t.Fatalf("CanonicalBytes()=%q,%v", canonical, err)
	}
	receipt, err := NewSignedDesktopConsentReceipt(statement, bytes.Repeat([]byte{0xa5}, 64))
	if err != nil || receipt.Statement() != statement || !receipt.Matches(request, now.Add(time.Second)) {
		t.Fatalf("receipt=%+v error=%v", receipt, err)
	}
	statement.NonPreselectedConfirmation = false
	if _, err := statement.CanonicalBytes(); err == nil {
		t.Fatal("preselected desktop statement was accepted")
	}
}

func TestConsentStatementsRejectInvalidIdentityTimeAndSignature(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	linux := LinuxConsentStatement{
		RequestDigest: runtimeinstall.Sum([]byte("request")), PlanDigest: runtimeinstall.Sum([]byte("plan")),
		AuthorityDigest: runtimeinstall.Sum([]byte("authority")), CatalogDigest: runtimeinstall.Sum([]byte("catalog")),
		ArtifactDigest: runtimeinstall.Sum([]byte("artifact")), TermsDigest: runtimeinstall.Sum([]byte("terms")),
		PrincipalID: "linux:uid:1000", MachineDigest: runtimeinstall.Sum([]byte("machine")),
		Nonce: Nonce{1}, AcceptedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	for _, mutate := range []func(*LinuxConsentStatement){
		func(value *LinuxConsentStatement) { value.RequestDigest = runtimeinstall.Hash{} },
		func(value *LinuxConsentStatement) { value.PrincipalID = " bad " },
		func(value *LinuxConsentStatement) { value.AcceptedAt = value.AcceptedAt.Local() },
		func(value *LinuxConsentStatement) { value.ExpiresAt = value.AcceptedAt.Add(31 * 24 * time.Hour) },
	} {
		candidate := linux
		mutate(&candidate)
		if _, err := candidate.CanonicalBytes(); err == nil {
			t.Fatal("invalid Linux consent statement was accepted")
		}
	}
	if _, err := NewSignedLinuxConsentReceipt(linux, nil); err == nil {
		t.Fatal("unsigned Linux consent statement was accepted")
	}
}
