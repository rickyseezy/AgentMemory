package runtimeconsent

import (
	"context"
	"errors"
	"testing"
	"time"

	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestProtectedConsentSignerAuthenticatesLinuxAndDesktopStatements(t *testing.T) {
	t.Parallel()
	owners, keys := signerCapabilities(t)
	signer, err := NewProtectedSigner(owners, keys)
	if err != nil {
		t.Fatal(err)
	}
	linux := validLinuxStatement()
	receipt, err := signer.SignLinux(context.Background(), linux)
	if err != nil || signer.VerifyLinux(context.Background(), receipt) != nil || len(receipt.Signature()) != 64 {
		t.Fatalf("Linux signature error=%v verify=%v", err, signer.VerifyLinux(context.Background(), receipt))
	}
	desktop := validDesktopStatement()
	desktopReceipt, err := signer.SignDesktop(context.Background(), desktop)
	if err != nil || signer.VerifyDesktop(context.Background(), desktopReceipt) != nil {
		t.Fatalf("Desktop signature error=%v verify=%v", err, signer.VerifyDesktop(context.Background(), desktopReceipt))
	}
	removalReceipt, err := signer.SignManagedRuntimeRemovalConsent(
		context.Background(), removalConsentPlan(t), time.Date(2026, 7, 15, 19, 0, 0, 0, time.UTC),
	)
	if err != nil || removalReceipt.IsZero() {
		t.Fatalf("removal consent receipt=%s error=%v", removalReceipt, err)
	}
	if keys.ensureCalls != 5 || keys.useCalls != 5 {
		t.Fatalf("protected key calls ensure=%d use=%d", keys.ensureCalls, keys.useCalls)
	}
}

func TestProtectedConsentSignerRejectsTamperAndUnavailableAuthority(t *testing.T) {
	t.Parallel()
	owners, keys := signerCapabilities(t)
	signer, _ := NewProtectedSigner(owners, keys)
	receipt, err := signer.SignLinux(context.Background(), validLinuxStatement())
	if err != nil {
		t.Fatal(err)
	}
	otherOwners, otherKeys := signerCapabilities(t)
	otherKeys.key[0] ^= 0xff
	other, _ := NewProtectedSigner(otherOwners, otherKeys)
	if !errors.Is(other.VerifyLinux(context.Background(), receipt), runtimeport.ErrLinuxConsentIntegrity) {
		t.Fatal("receipt authenticated under another protected key")
	}
	if _, err := NewProtectedSigner(nil, keys); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("nil owner constructor error=%v", err)
	}
	owners.err = errors.New("private")
	if _, err := signer.SignDesktop(context.Background(), validDesktopStatement()); err == nil {
		t.Fatal("unavailable owner authority signed consent")
	}
	owners.err = nil
	keys.err = errors.New("private")
	if _, err := signer.SignLinux(context.Background(), validLinuxStatement()); err == nil {
		t.Fatal("unavailable key authority signed consent")
	}
}

type signerOwners struct {
	owner install.OwnerBinding
	err   error
}

func (s *signerOwners) Current(context.Context) (install.OwnerBinding, error) {
	return s.owner, s.err
}

type signerKeys struct {
	key         [32]byte
	reference   install.BootstrapKeyRef
	err         error
	ensureCalls int
	useCalls    int
}

func (s *signerKeys) Ensure(
	context.Context,
	install.OperationID,
	install.OwnerBinding,
) (install.BootstrapKeyRef, error) {
	s.ensureCalls++
	return s.reference, s.err
}

func (s *signerKeys) UseHMACKey(
	_ context.Context,
	_ install.BootstrapKeyRef,
	_ install.OperationID,
	_ install.OwnerBinding,
	consumer bootstrapport.OperationKeyConsumer,
) error {
	s.useCalls++
	if s.err != nil {
		return s.err
	}
	copyKey := append([]byte(nil), s.key[:]...)
	return consumer(copyKey)
}

func signerCapabilities(t testing.TB) (*signerOwners, *signerKeys) {
	t.Helper()
	owner, err := install.BindOwner("machine", "principal")
	if err != nil {
		t.Fatal(err)
	}
	reference, err := install.BootstrapKeyRefFromDigest(install.DigestBytes([]byte("key")))
	if err != nil {
		t.Fatal(err)
	}
	keys := &signerKeys{reference: reference}
	digest := runtimeinstall.Sum([]byte("protected-key"))
	copy(keys.key[:], digest[:])
	return &signerOwners{owner: owner}, keys
}

func validLinuxStatement() runtimeport.LinuxConsentStatement {
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	return runtimeport.LinuxConsentStatement{
		RequestDigest: runtimeinstall.Sum([]byte("request")), PlanDigest: runtimeinstall.Sum([]byte("plan")),
		AuthorityDigest: runtimeinstall.Sum([]byte("authority")), CatalogDigest: runtimeinstall.Sum([]byte("catalog")),
		ArtifactDigest: runtimeinstall.Sum([]byte("artifact")), TermsDigest: runtimeinstall.Sum([]byte("terms")),
		PrincipalID: "linux:uid:1000", MachineDigest: runtimeinstall.Sum([]byte("machine")),
		Nonce: runtimeport.Nonce{1}, AcceptedAt: now, ExpiresAt: now.Add(time.Hour),
	}
}

func validDesktopStatement() runtimeport.DesktopConsentStatement {
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	return runtimeport.DesktopConsentStatement{
		RequestDigest: runtimeinstall.Sum([]byte("request")), AuthorityDigest: runtimeinstall.Sum([]byte("authority")),
		PlanDigest: runtimeinstall.Sum([]byte("plan")), TermsDigest: runtimeinstall.Sum([]byte("terms")),
		PrincipalID: "sid:S-1-5-21-1000", MachineDigest: runtimeinstall.Sum([]byte("machine")),
		Nonce: runtimeport.Nonce{1}, ExplicitlyAccepted: true, AuthorityAndEntitlement: true,
		NonPreselectedConfirmation: true, AcceptedAt: now, ExpiresAt: now.Add(time.Hour),
	}
}
