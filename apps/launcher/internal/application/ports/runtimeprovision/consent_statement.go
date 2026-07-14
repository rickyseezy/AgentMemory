package runtimeprovision

import (
	"encoding/json"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const (
	linuxConsentSignatureDomain   = "agentmemory.runtime-consent.linux.v1"
	desktopConsentSignatureDomain = "agentmemory.runtime-consent.desktop.v1"
)

// LinuxConsentStatement is the complete canonical message authenticated by
// the trusted local consent surface. Signature bytes are deliberately absent.
type LinuxConsentStatement struct {
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
}

// CanonicalBytes returns the purpose-separated message to sign or verify.
func (s LinuxConsentStatement) CanonicalBytes() ([]byte, error) {
	if s.RequestDigest.IsZero() || s.PlanDigest.IsZero() || s.AuthorityDigest.IsZero() ||
		s.CatalogDigest.IsZero() || s.ArtifactDigest.IsZero() || s.TermsDigest.IsZero() ||
		!validIdentity(s.PrincipalID) || s.MachineDigest.IsZero() || s.Nonce.IsZero() ||
		!validConsentWindow(s.AcceptedAt, s.ExpiresAt, linuxConsentMaximumLifetime) {
		return nil, ErrLinuxConsentIntegrity
	}
	return json.Marshal(struct {
		Domain    string
		Statement LinuxConsentStatement
	}{linuxConsentSignatureDomain, s})
}

// NewSignedLinuxConsentReceipt combines one validated statement with an
// external signature without changing the signed message.
func NewSignedLinuxConsentReceipt(
	statement LinuxConsentStatement,
	signature []byte,
) (LinuxConsentReceipt, error) {
	if _, err := statement.CanonicalBytes(); err != nil {
		return LinuxConsentReceipt{}, err
	}
	return NewLinuxConsentReceipt(LinuxConsentReceiptInput{
		RequestDigest: statement.RequestDigest, PlanDigest: statement.PlanDigest,
		AuthorityDigest: statement.AuthorityDigest, CatalogDigest: statement.CatalogDigest,
		ArtifactDigest: statement.ArtifactDigest, TermsDigest: statement.TermsDigest,
		PrincipalID: statement.PrincipalID, MachineDigest: statement.MachineDigest,
		Nonce: statement.Nonce, AcceptedAt: statement.AcceptedAt, ExpiresAt: statement.ExpiresAt,
		Signature: slices.Clone(signature), SignatureDigest: runtimeinstall.Sum(signature),
	})
}

// Statement returns the immutable message authenticated by this receipt.
func (r LinuxConsentReceipt) Statement() LinuxConsentStatement {
	return LinuxConsentStatement{
		RequestDigest: r.input.RequestDigest, PlanDigest: r.input.PlanDigest,
		AuthorityDigest: r.input.AuthorityDigest, CatalogDigest: r.input.CatalogDigest,
		ArtifactDigest: r.input.ArtifactDigest, TermsDigest: r.input.TermsDigest,
		PrincipalID: r.input.PrincipalID, MachineDigest: r.input.MachineDigest,
		Nonce: r.input.Nonce, AcceptedAt: r.input.AcceptedAt, ExpiresAt: r.input.ExpiresAt,
	}
}

// DesktopConsentStatement is the complete canonical desktop authorization
// message, including the three explicit non-preselected confirmations.
type DesktopConsentStatement struct {
	RequestDigest              runtimeinstall.Hash
	AuthorityDigest            runtimeinstall.Hash
	PlanDigest                 runtimeinstall.Hash
	TermsDigest                runtimeinstall.Hash
	PrincipalID                string
	MachineDigest              runtimeinstall.Hash
	Nonce                      Nonce
	ExplicitlyAccepted         bool
	AuthorityAndEntitlement    bool
	NonPreselectedConfirmation bool
	AcceptedAt                 time.Time
	ExpiresAt                  time.Time
}

// CanonicalBytes returns the purpose-separated desktop signing message.
func (s DesktopConsentStatement) CanonicalBytes() ([]byte, error) {
	if s.RequestDigest.IsZero() || s.AuthorityDigest.IsZero() || s.PlanDigest.IsZero() ||
		s.TermsDigest.IsZero() || !validConsentPrincipal(s.PrincipalID) ||
		s.MachineDigest.IsZero() || s.Nonce.IsZero() || !s.ExplicitlyAccepted ||
		!s.AuthorityAndEntitlement || !s.NonPreselectedConfirmation ||
		!validConsentWindow(s.AcceptedAt, s.ExpiresAt, desktopConsentMaximumLifetime) {
		return nil, ErrDesktopConsentIntegrity
	}
	return json.Marshal(struct {
		Domain    string
		Statement DesktopConsentStatement
	}{desktopConsentSignatureDomain, s})
}

// NewSignedDesktopConsentReceipt combines a statement and external signature.
func NewSignedDesktopConsentReceipt(
	statement DesktopConsentStatement,
	signature []byte,
) (DesktopConsentReceipt, error) {
	if _, err := statement.CanonicalBytes(); err != nil {
		return DesktopConsentReceipt{}, err
	}
	return NewDesktopConsentReceipt(DesktopConsentReceiptInput{
		RequestDigest: statement.RequestDigest, AuthorityDigest: statement.AuthorityDigest,
		PlanDigest: statement.PlanDigest, TermsDigest: statement.TermsDigest,
		PrincipalID: statement.PrincipalID, MachineDigest: statement.MachineDigest,
		Nonce: statement.Nonce, ExplicitlyAccepted: statement.ExplicitlyAccepted,
		AuthorityAndEntitlement:    statement.AuthorityAndEntitlement,
		NonPreselectedConfirmation: statement.NonPreselectedConfirmation,
		AcceptedAt:                 statement.AcceptedAt, ExpiresAt: statement.ExpiresAt,
		Signature: slices.Clone(signature), SignatureDigest: runtimeinstall.Sum(signature),
	})
}

// Statement returns the immutable desktop message authenticated by this receipt.
func (r DesktopConsentReceipt) Statement() DesktopConsentStatement {
	return DesktopConsentStatement{
		RequestDigest: r.input.RequestDigest, AuthorityDigest: r.input.AuthorityDigest,
		PlanDigest: r.input.PlanDigest, TermsDigest: r.input.TermsDigest,
		PrincipalID: r.input.PrincipalID, MachineDigest: r.input.MachineDigest,
		Nonce: r.input.Nonce, ExplicitlyAccepted: r.input.ExplicitlyAccepted,
		AuthorityAndEntitlement:    r.input.AuthorityAndEntitlement,
		NonPreselectedConfirmation: r.input.NonPreselectedConfirmation,
		AcceptedAt:                 r.input.AcceptedAt, ExpiresAt: r.input.ExpiresAt,
	}
}

func validConsentWindow(acceptedAt, expiresAt time.Time, maximum time.Duration) bool {
	return !acceptedAt.IsZero() && !expiresAt.IsZero() && acceptedAt.Location() == time.UTC &&
		expiresAt.Location() == time.UTC && expiresAt.After(acceptedAt) &&
		expiresAt.Sub(acceptedAt) <= maximum
}

func validConsentPrincipal(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
