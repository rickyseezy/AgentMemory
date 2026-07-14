package runtimeprovision

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const (
	linuxConsentRequestMaximumLifetime = 5 * time.Minute
	linuxConsentMaximumLifetime        = 30 * 24 * time.Hour
)

var (
	// ErrLinuxConsentUnavailable reports that no authenticated local consent
	// surface can display the exact package plan and third-party terms.
	ErrLinuxConsentUnavailable = errors.New("linux runtime consent surface is unavailable")
	// ErrLinuxConsentDeclined reports an explicit negative user decision.
	ErrLinuxConsentDeclined = errors.New("linux runtime consent was declined")
	// ErrLinuxConsentIntegrity rejects malformed, substituted, expired, or
	// unauthenticated Linux consent authority.
	ErrLinuxConsentIntegrity = errors.New("linux runtime consent receipt integrity validation failed")
)

// LinuxConsentRequestInput is copied into one bounded, exact-plan prompt
// authority. It contains no package-manager command, credential, or secret.
type LinuxConsentRequestInput struct {
	OperationID string
	Attempt     uint32
	Authority   LinuxAuthority
	Nonce       Nonce
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

// LinuxConsentRequest binds the visible decision to the complete signed Linux
// execution authority, including the exact vendor terms digest.
type LinuxConsentRequest struct {
	input  LinuxConsentRequestInput
	digest runtimeinstall.Hash
}

// NewLinuxConsentRequest is the narrow constructor used by the provisioner.
func NewLinuxConsentRequest(
	operationID string,
	attempt uint32,
	authority LinuxAuthority,
	nonce Nonce,
	issuedAt time.Time,
	expiresAt time.Time,
) (LinuxConsentRequest, error) {
	return NewLinuxConsentRequestFromInput(LinuxConsentRequestInput{
		OperationID: operationID, Attempt: attempt, Authority: authority,
		Nonce: nonce, IssuedAt: issuedAt, ExpiresAt: expiresAt,
	})
}

// NewLinuxConsentRequestFromInput validates and snapshots prompt authority.
func NewLinuxConsentRequestFromInput(input LinuxConsentRequestInput) (LinuxConsentRequest, error) {
	if !validOperationID(input.OperationID) || input.Attempt == 0 || !input.Authority.Valid() ||
		input.Nonce.IsZero() || input.IssuedAt.IsZero() || input.ExpiresAt.IsZero() ||
		input.IssuedAt.Location() != time.UTC || input.ExpiresAt.Location() != time.UTC ||
		!input.ExpiresAt.After(input.IssuedAt) ||
		input.ExpiresAt.Sub(input.IssuedAt) > linuxConsentRequestMaximumLifetime {
		return LinuxConsentRequest{}, ErrLinuxConsentIntegrity
	}
	request := LinuxConsentRequest{input: input}
	encoded, err := json.Marshal(struct {
		Artifact, Authority, Catalog, Machine, Operation, Plan, Principal, Terms string
		Attempt                                                                  uint32
		ExpiresAt, IssuedAt                                                      int64
		Nonce                                                                    Nonce
	}{
		Artifact:  input.Authority.ArtifactDigest().String(),
		Authority: input.Authority.Digest().String(), Catalog: input.Authority.CatalogDigest().String(),
		Machine: input.Authority.MachineDigest().String(), Operation: input.OperationID,
		Plan: input.Authority.PlanDigest().String(), Principal: input.Authority.PrincipalID(),
		Terms: input.Authority.TermsDigest().String(), Attempt: input.Attempt,
		ExpiresAt: input.ExpiresAt.UnixMicro(), IssuedAt: input.IssuedAt.UnixMicro(), Nonce: input.Nonce,
	})
	if err != nil {
		return LinuxConsentRequest{}, ErrLinuxConsentIntegrity
	}
	request.digest = runtimeinstall.Sum(encoded)
	if request.digest.IsZero() {
		return LinuxConsentRequest{}, ErrLinuxConsentIntegrity
	}
	return request, nil
}

// OperationID returns the exact parent operation.
func (r LinuxConsentRequest) OperationID() string { return r.input.OperationID }

// Attempt returns the one-based consent phase attempt.
func (r LinuxConsentRequest) Attempt() uint32 { return r.input.Attempt }

// Authority returns immutable signed Linux execution authority.
func (r LinuxConsentRequest) Authority() LinuxAuthority { return r.input.Authority }

// Nonce returns the single-use prompt challenge.
func (r LinuxConsentRequest) Nonce() Nonce { return r.input.Nonce }

// IssuedAt returns the trusted UTC issue time.
func (r LinuxConsentRequest) IssuedAt() time.Time { return r.input.IssuedAt }

// ExpiresAt returns the bounded response deadline.
func (r LinuxConsentRequest) ExpiresAt() time.Time { return r.input.ExpiresAt }

// Digest binds every request field.
func (r LinuxConsentRequest) Digest() runtimeinstall.Hash { return r.digest }

// LinuxConsentReceiptInput is emitted only by the visible authenticated
// consent surface after a non-preselected affirmative decision.
type LinuxConsentReceiptInput struct {
	RequestDigest   runtimeinstall.Hash
	PlanDigest      runtimeinstall.Hash
	AuthorityDigest runtimeinstall.Hash
	CatalogDigest   runtimeinstall.Hash
	ArtifactDigest  runtimeinstall.Hash
	TermsDigest     runtimeinstall.Hash
	PrincipalID     string
	MachineDigest   runtimeinstall.Hash
	Nonce           Nonce
	AcceptedAt      time.Time
	ExpiresAt       time.Time
	Signature       []byte
	SignatureDigest runtimeinstall.Hash
}

// LinuxConsentReceipt is an externally authenticated affirmative decision.
type LinuxConsentReceipt struct {
	input  LinuxConsentReceiptInput
	digest runtimeinstall.Hash
}

// NewLinuxConsentReceipt validates and snapshots the receipt. Signature
// authenticity is independently checked by LinuxConsentAuthenticator.
func NewLinuxConsentReceipt(input LinuxConsentReceiptInput) (LinuxConsentReceipt, error) {
	if input.RequestDigest.IsZero() || input.PlanDigest.IsZero() || input.AuthorityDigest.IsZero() ||
		input.CatalogDigest.IsZero() || input.ArtifactDigest.IsZero() || input.TermsDigest.IsZero() ||
		!validIdentity(input.PrincipalID) || input.MachineDigest.IsZero() || input.Nonce.IsZero() ||
		input.AcceptedAt.IsZero() || input.ExpiresAt.IsZero() || input.AcceptedAt.Location() != time.UTC ||
		input.ExpiresAt.Location() != time.UTC || !input.ExpiresAt.After(input.AcceptedAt) ||
		input.ExpiresAt.Sub(input.AcceptedAt) > linuxConsentMaximumLifetime ||
		!validDesktopSignature(input.Signature, input.SignatureDigest) {
		return LinuxConsentReceipt{}, ErrLinuxConsentIntegrity
	}
	copyInput := input
	copyInput.Signature = slices.Clone(input.Signature)
	encoded, err := json.Marshal(copyInput)
	if err != nil {
		return LinuxConsentReceipt{}, ErrLinuxConsentIntegrity
	}
	receipt := LinuxConsentReceipt{input: copyInput, digest: runtimeinstall.Sum(encoded)}
	if receipt.digest.IsZero() {
		return LinuxConsentReceipt{}, ErrLinuxConsentIntegrity
	}
	return receipt, nil
}

// Matches proves a fresh response is exact-request bound and arrived inside
// both the prompt and durable-consent validity windows.
func (r LinuxConsentReceipt) Matches(request LinuxConsentRequest, now time.Time) bool {
	authority := request.input.Authority
	return authority.Valid() && !r.digest.IsZero() && !request.digest.IsZero() &&
		r.input.RequestDigest == request.digest && r.authorizes(authority) &&
		r.input.Nonce == request.input.Nonce && !r.input.AcceptedAt.Before(request.input.IssuedAt) &&
		r.input.AcceptedAt.Before(request.input.ExpiresAt) && !now.Before(r.input.AcceptedAt) &&
		now.Before(request.input.ExpiresAt) && now.Before(r.input.ExpiresAt)
}

// Authorizes revalidates a stored consent against exact authority and trusted
// time before any later package or terms phase relies on it.
func (r LinuxConsentReceipt) Authorizes(authority LinuxAuthority, now time.Time) bool {
	return authority.Valid() && !r.digest.IsZero() && r.authorizes(authority) &&
		!now.Before(r.input.AcceptedAt) && now.Before(r.input.ExpiresAt)
}

func (r LinuxConsentReceipt) authorizes(authority LinuxAuthority) bool {
	return r.input.PlanDigest == authority.PlanDigest() && r.input.AuthorityDigest == authority.Digest() &&
		r.input.CatalogDigest == authority.CatalogDigest() && r.input.ArtifactDigest == authority.ArtifactDigest() &&
		r.input.TermsDigest == authority.TermsDigest() && r.input.PrincipalID == authority.PrincipalID() &&
		r.input.MachineDigest == authority.MachineDigest()
}

// Digest returns the complete authenticated receipt binding.
func (r LinuxConsentReceipt) Digest() runtimeinstall.Hash { return r.digest }

// Signature returns a defensive copy of the external signature.
func (r LinuxConsentReceipt) Signature() []byte { return slices.Clone(r.input.Signature) }

// LinuxConsentGrant retains the exact prompt/receipt pair for authenticated
// persistence and replay-safe later verification.
type LinuxConsentGrant struct {
	request LinuxConsentRequest
	receipt LinuxConsentReceipt
}

// NewLinuxConsentGrant accepts only an exact fresh request/receipt pair.
func NewLinuxConsentGrant(request LinuxConsentRequest, receipt LinuxConsentReceipt) (LinuxConsentGrant, error) {
	if request.digest.IsZero() || receipt.digest.IsZero() || !receipt.Matches(request, receipt.input.AcceptedAt) {
		return LinuxConsentGrant{}, ErrLinuxConsentIntegrity
	}
	return LinuxConsentGrant{request: request, receipt: receipt}, nil
}

// ValidFor proves persisted authority identity without treating this check as
// a trusted-time decision. Call Receipt().Authorizes before a side effect.
func (g LinuxConsentGrant) ValidFor(operationID string, authority LinuxAuthority) bool {
	return g.request.input.OperationID == operationID && g.request.input.Authority.Digest() == authority.Digest() &&
		g.receipt.authorizes(authority)
}

// Request returns immutable prompt authority.
func (g LinuxConsentGrant) Request() LinuxConsentRequest { return g.request }

// Receipt returns immutable accepted consent evidence.
func (g LinuxConsentGrant) Receipt() LinuxConsentReceipt { return g.receipt }

// LinuxConsentBroker obtains one visible, explicit package/terms decision.
type LinuxConsentBroker interface {
	AwaitLinuxConsent(context.Context, LinuxConsentRequest) (LinuxConsentReceipt, error)
}

// LinuxConsentAuthenticator verifies fresh and stored receipt signatures.
type LinuxConsentAuthenticator interface {
	VerifyLinuxConsent(context.Context, LinuxConsentRequest, LinuxConsentReceipt) error
	VerifyStoredLinuxConsent(context.Context, LinuxAuthority, LinuxConsentReceipt) error
}

// LinuxConsentRepository durably stores one exact authority-bound grant.
type LinuxConsentRepository interface {
	StoreLinuxConsent(context.Context, string, LinuxConsentGrant) error
	LoadLinuxConsent(context.Context, string, runtimeinstall.Hash) (LinuxConsentGrant, error)
}
