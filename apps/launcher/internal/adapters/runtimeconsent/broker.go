package runtimeconsent

import (
	"context"
	"errors"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
)

const durableConsentLifetime = 29 * 24 * time.Hour

// Clock is the trusted local receipt clock.
type Clock interface{ Now() time.Time }

type statementSigner interface {
	SignLinux(context.Context, runtimeport.LinuxConsentStatement) (runtimeport.LinuxConsentReceipt, error)
	VerifyLinux(context.Context, runtimeport.LinuxConsentReceipt) error
	SignDesktop(context.Context, runtimeport.DesktopConsentStatement) (runtimeport.DesktopConsentReceipt, error)
	VerifyDesktop(context.Context, runtimeport.DesktopConsentReceipt) error
}

// Broker converts one operation-bound visible decision into a protected
// platform receipt and independently authenticates fresh and stored receipts.
type Broker struct {
	hub    *Hub
	signer statementSigner
	clock  Clock
}

// NewBroker requires the visible decision and protected signature authorities.
func NewBroker(hub *Hub, signer statementSigner, clock Clock) (*Broker, error) {
	if hub == nil || nilInterface(signer) || nilInterface(clock) {
		return nil, ErrIntegrity
	}
	return &Broker{hub: hub, signer: signer, clock: clock}, nil
}

// AwaitLinuxConsent implements the Linux visible consent boundary.
func (b *Broker) AwaitLinuxConsent(
	ctx context.Context,
	request runtimeport.LinuxConsentRequest,
) (runtimeport.LinuxConsentReceipt, error) {
	authority := request.Authority()
	if b == nil || ctx == nil || !authority.Valid() || request.Digest().IsZero() {
		return runtimeport.LinuxConsentReceipt{}, runtimeport.ErrLinuxConsentIntegrity
	}
	decision, err := b.hub.Await(ctx, Pending{
		OperationID: request.OperationID(), RuntimePlanDigest: authority.PlanDigest(),
		TermsDigest: authority.TermsDigest(),
	})
	if err != nil {
		return runtimeport.LinuxConsentReceipt{}, mapLinuxAwaitError(ctx, err)
	}
	if decision == DecisionDecline {
		return runtimeport.LinuxConsentReceipt{}, runtimeport.ErrLinuxConsentDeclined
	}
	acceptedAt, err := b.acceptedAt(ctx)
	if err != nil || decision != DecisionAccept {
		return runtimeport.LinuxConsentReceipt{}, runtimeport.ErrLinuxConsentIntegrity
	}
	return b.signer.SignLinux(ctx, runtimeport.LinuxConsentStatement{
		RequestDigest: request.Digest(), PlanDigest: authority.PlanDigest(),
		AuthorityDigest: authority.Digest(), CatalogDigest: authority.CatalogDigest(),
		ArtifactDigest: authority.ArtifactDigest(), TermsDigest: authority.TermsDigest(),
		PrincipalID: authority.PrincipalID(), MachineDigest: authority.MachineDigest(),
		Nonce: request.Nonce(), AcceptedAt: acceptedAt, ExpiresAt: acceptedAt.Add(durableConsentLifetime),
	})
}

// AwaitDesktopConsent implements the explicit Desktop license boundary.
func (b *Broker) AwaitDesktopConsent(
	ctx context.Context,
	request runtimeport.DesktopConsentRequest,
) (runtimeport.DesktopConsentReceipt, error) {
	authority := request.Authority()
	if b == nil || ctx == nil || !authority.Valid() || request.Digest().IsZero() {
		return runtimeport.DesktopConsentReceipt{}, runtimeport.ErrDesktopConsentIntegrity
	}
	decision, err := b.hub.Await(ctx, Pending{
		OperationID: request.OperationID(), RuntimePlanDigest: authority.PlanDigest(),
		TermsDigest: authority.Terms().Digest(),
	})
	if err != nil {
		return runtimeport.DesktopConsentReceipt{}, mapDesktopAwaitError(ctx, err)
	}
	if decision == DecisionDecline {
		return runtimeport.DesktopConsentReceipt{}, runtimeport.ErrDesktopConsentDeclined
	}
	acceptedAt, err := b.acceptedAt(ctx)
	if err != nil || decision != DecisionAccept {
		return runtimeport.DesktopConsentReceipt{}, runtimeport.ErrDesktopConsentIntegrity
	}
	return b.signer.SignDesktop(ctx, runtimeport.DesktopConsentStatement{
		RequestDigest: request.Digest(), AuthorityDigest: authority.Digest(),
		PlanDigest: authority.PlanDigest(), TermsDigest: authority.Terms().Digest(),
		PrincipalID: authority.PrincipalID(), MachineDigest: authority.MachineDigest(),
		Nonce: request.Nonce(), ExplicitlyAccepted: true, AuthorityAndEntitlement: true,
		NonPreselectedConfirmation: true, AcceptedAt: acceptedAt,
		ExpiresAt: acceptedAt.Add(durableConsentLifetime),
	})
}

// VerifyLinuxConsent verifies the request window and external signature.
func (b *Broker) VerifyLinuxConsent(
	ctx context.Context,
	request runtimeport.LinuxConsentRequest,
	receipt runtimeport.LinuxConsentReceipt,
) error {
	now, err := b.now(ctx)
	if err != nil || !receipt.Matches(request, now) || b.signer.VerifyLinux(ctx, receipt) != nil {
		return runtimeport.ErrLinuxConsentIntegrity
	}
	return nil
}

// VerifyStoredLinuxConsent revalidates authority, time, and signature.
func (b *Broker) VerifyStoredLinuxConsent(
	ctx context.Context,
	authority runtimeport.LinuxAuthority,
	receipt runtimeport.LinuxConsentReceipt,
) error {
	now, err := b.now(ctx)
	if err != nil || !receipt.Authorizes(authority, now) || b.signer.VerifyLinux(ctx, receipt) != nil {
		return runtimeport.ErrLinuxConsentIntegrity
	}
	return nil
}

// VerifyDesktopConsent verifies the request window and protected signature.
func (b *Broker) VerifyDesktopConsent(
	ctx context.Context,
	request runtimeport.DesktopConsentRequest,
	receipt runtimeport.DesktopConsentReceipt,
) error {
	now, err := b.now(ctx)
	if err != nil || !receipt.Matches(request, now) || b.signer.VerifyDesktop(ctx, receipt) != nil {
		return runtimeport.ErrDesktopConsentIntegrity
	}
	return nil
}

// VerifyStoredDesktopConsent revalidates authority, time, and signature.
func (b *Broker) VerifyStoredDesktopConsent(
	ctx context.Context,
	authority runtimeport.DesktopAuthority,
	receipt runtimeport.DesktopConsentReceipt,
) error {
	now, err := b.now(ctx)
	if err != nil || !receipt.Authorizes(authority, now) || b.signer.VerifyDesktop(ctx, receipt) != nil {
		return runtimeport.ErrDesktopConsentIntegrity
	}
	return nil
}

func (b *Broker) acceptedAt(ctx context.Context) (time.Time, error) {
	return b.now(ctx)
}

func (b *Broker) now(ctx context.Context) (time.Time, error) {
	if b == nil || ctx == nil || b.hub == nil || nilInterface(b.signer) || nilInterface(b.clock) {
		return time.Time{}, ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	now := b.clock.Now().UTC().Truncate(time.Microsecond)
	if now.IsZero() {
		return time.Time{}, ErrIntegrity
	}
	return now, nil
}

func mapLinuxAwaitError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return runtimeport.ErrLinuxConsentUnavailable
}

func mapDesktopAwaitError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return runtimeport.ErrDesktopConsentUnavailable
}

var (
	_ runtimeport.LinuxConsentBroker          = (*Broker)(nil)
	_ runtimeport.LinuxConsentAuthenticator   = (*Broker)(nil)
	_ runtimeport.DesktopConsentBroker        = (*Broker)(nil)
	_ runtimeport.DesktopConsentAuthenticator = (*Broker)(nil)
)
