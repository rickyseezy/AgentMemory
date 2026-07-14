// Package brainbootstrap defines the immutable PF-001 first-Brain bootstrap
// authority and privacy-safe idempotent receipt.
package brainbootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

var (
	// ErrIntegrity rejects malformed, contradictory, or replayed bootstrap data.
	ErrIntegrity = errors.New("local Brain bootstrap integrity violation")
	// ErrUnavailable reports that the authenticated local Core boundary could
	// not complete without exposing transport or protected-file detail.
	ErrUnavailable = errors.New("local Brain bootstrap unavailable")
)

// Disposition is the closed idempotent bootstrap result.
type Disposition string

const (
	// DispositionCreated means the exact aggregate was created atomically.
	DispositionCreated Disposition = "created"
	// DispositionAlreadyInitialized means the same exact aggregate already existed.
	DispositionAlreadyInitialized Disposition = "already_initialized"
)

// AuthorizationInput contains the exact parent-plan fields used by Core's
// bootstrap command. APICredentialPath is a protected reference, never bytes.
type AuthorizationInput struct {
	OperationID        install.OperationID
	ParentPlan         install.PlanDigest
	Attempt            uint32
	RuntimeOwnership   install.RuntimeOwnership
	CoreEndpoint       string
	APICredentialPath  string
	InstallationID     string
	OwnerPrincipalID   string
	OwnerGrantID       string
	OwnerSubjectDigest install.Digest
	BrainID            string
	BrainName          string
	ReleaseDigest      install.Digest
	GenerationID       string
}

// Authorization is one immutable, replay-resistant Core bootstrap command.
type Authorization struct {
	input         AuthorizationInput
	bindingDigest install.Digest
}

// NewAuthorization validates and binds every first-Brain identity.
func NewAuthorization(input AuthorizationInput) (Authorization, error) {
	if input.OperationID.IsZero() || input.ParentPlan.IsZero() || input.Attempt == 0 ||
		!input.RuntimeOwnership.Resolved() || !validCoreEndpoint(input.CoreEndpoint) ||
		!validProtectedReference(input.APICredentialPath) || !validUUIDv7(input.InstallationID) ||
		!validUUIDv7(input.OwnerPrincipalID) || !validUUIDv7(input.OwnerGrantID) ||
		input.OwnerSubjectDigest.IsZero() || !validUUIDv7(input.BrainID) ||
		!validBrainName(input.BrainName) || input.ReleaseDigest.IsZero() ||
		!validUUIDv7(input.GenerationID) {
		return Authorization{}, ErrIntegrity
	}
	authorization := Authorization{input: input}
	authorization.bindingDigest = digestAuthorization(authorization)
	return authorization, nil
}

// OperationID returns the idempotency/correlation identity.
func (a Authorization) OperationID() install.OperationID { return a.input.OperationID }

// ParentPlanDigest returns the canonical installation-plan binding.
func (a Authorization) ParentPlanDigest() install.PlanDigest { return a.input.ParentPlan }

// Attempt returns the one-based parent phase attempt.
func (a Authorization) Attempt() uint32 { return a.input.Attempt }

// RuntimeOwnership returns the resolved local runtime disposition.
func (a Authorization) RuntimeOwnership() install.RuntimeOwnership { return a.input.RuntimeOwnership }

// CoreEndpoint returns the exact literal loopback HTTP origin.
func (a Authorization) CoreEndpoint() string { return a.input.CoreEndpoint }

// APICredentialPath returns the protected 32-byte credential reference.
func (a Authorization) APICredentialPath() string { return a.input.APICredentialPath }

// InstallationID returns the installation aggregate identity.
func (a Authorization) InstallationID() string { return a.input.InstallationID }

// OwnerPrincipalID returns the local owner principal identity.
func (a Authorization) OwnerPrincipalID() string { return a.input.OwnerPrincipalID }

// OwnerGrantID returns the initial owner grant identity.
func (a Authorization) OwnerGrantID() string { return a.input.OwnerGrantID }

// OwnerSubjectDigest returns the non-reversible host-owner binding.
func (a Authorization) OwnerSubjectDigest() install.Digest { return a.input.OwnerSubjectDigest }

// BrainID returns the first local Brain identity.
func (a Authorization) BrainID() string { return a.input.BrainID }

// BrainName returns the normalized first local Brain name.
func (a Authorization) BrainName() string { return a.input.BrainName }

// ReleaseDigest returns the signed release-manifest binding.
func (a Authorization) ReleaseDigest() install.Digest { return a.input.ReleaseDigest }

// GenerationID returns the data generation identity.
func (a Authorization) GenerationID() string { return a.input.GenerationID }

// BindingDigest returns the complete canonical authorization digest.
func (a Authorization) BindingDigest() install.Digest { return a.bindingDigest }

// Valid reports whether all immutable fields still match the digest.
func (a Authorization) Valid() bool {
	rebuilt, err := NewAuthorization(a.input)
	return err == nil && !a.bindingDigest.IsZero() && a.bindingDigest.Equal(rebuilt.bindingDigest)
}

// Receipt proves Core accepted exactly one bootstrap authorization.
type Receipt struct {
	authorizationDigest install.Digest
	disposition         Disposition
	outputDigest        install.Digest
}

// NewReceiptForAdapter constructs an exact idempotent Core result.
func NewReceiptForAdapter(authorization Authorization, disposition Disposition) (Receipt, error) {
	if !authorization.Valid() || !validDisposition(disposition) {
		return Receipt{}, ErrIntegrity
	}
	receipt := Receipt{authorizationDigest: authorization.bindingDigest, disposition: disposition}
	receipt.outputDigest = digestReceipt(receipt)
	return receipt, nil
}

// Disposition returns created or already_initialized.
func (r Receipt) Disposition() Disposition { return r.disposition }

// OutputDigest returns the complete privacy-safe bootstrap receipt binding.
func (r Receipt) OutputDigest() install.Digest { return r.outputDigest }

// ValidFor rejects response replay across plan, attempt, owner, or Brain.
func (r Receipt) ValidFor(authorization Authorization) bool {
	return authorization.Valid() && validDisposition(r.disposition) &&
		r.authorizationDigest.Equal(authorization.bindingDigest) && !r.outputDigest.IsZero() &&
		r.outputDigest.Equal(digestReceipt(r))
}

// Bootstrapper is the authenticated local Core bootstrap boundary.
type Bootstrapper interface {
	BootstrapLocalBrain(context.Context, Authorization) (Receipt, error)
}

func validDisposition(value Disposition) bool {
	return value == DispositionCreated || value == DispositionAlreadyInitialized
}

func validCoreEndpoint(value string) bool {
	portText := ""
	switch {
	case strings.HasPrefix(value, "http://127.0.0.1:"):
		portText = strings.TrimPrefix(value, "http://127.0.0.1:")
	case strings.HasPrefix(value, "http://[::1]:"):
		portText = strings.TrimPrefix(value, "http://[::1]:")
	default:
		return false
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	return err == nil && port > 0 && strconv.FormatUint(port, 10) == portText
}

func validProtectedReference(value string) bool {
	return value != "" && len(value) <= 4096 && value == strings.TrimSpace(value) &&
		!strings.ContainsAny(value, "\x00\r\n")
}

func validUUIDv7(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' ||
		value[14] != '7' || (value[19] != '8' && value[19] != '9' && value[19] != 'a' && value[19] != 'b') {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validBrainName(value string) bool {
	if len(value) == 0 || len(value) > 63 ||
		(value[0] < 'a' || value[0] > 'z') && (value[0] < '0' || value[0] > '9') {
		return false
	}
	for _, character := range value[1:] {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func digestAuthorization(authorization Authorization) install.Digest {
	input := authorization.input
	canonical, err := json.Marshal(struct {
		OperationID        string `json:"operation_id"`
		ParentPlan         string `json:"parent_plan"`
		Attempt            uint32 `json:"attempt"`
		RuntimeOwnership   string `json:"runtime_ownership"`
		CoreEndpoint       string `json:"core_endpoint"`
		APICredentialPath  string `json:"api_credential_path"`
		InstallationID     string `json:"installation_id"`
		OwnerPrincipalID   string `json:"owner_principal_id"`
		OwnerGrantID       string `json:"owner_grant_id"`
		OwnerSubjectDigest string `json:"owner_subject_digest"`
		BrainID            string `json:"brain_id"`
		BrainName          string `json:"brain_name"`
		ReleaseDigest      string `json:"release_digest"`
		GenerationID       string `json:"generation_id"`
	}{
		OperationID: input.OperationID.String(), ParentPlan: input.ParentPlan.String(),
		Attempt: input.Attempt, RuntimeOwnership: input.RuntimeOwnership.String(),
		CoreEndpoint: input.CoreEndpoint, APICredentialPath: input.APICredentialPath,
		InstallationID: input.InstallationID, OwnerPrincipalID: input.OwnerPrincipalID,
		OwnerGrantID: input.OwnerGrantID, OwnerSubjectDigest: input.OwnerSubjectDigest.String(),
		BrainID: input.BrainID, BrainName: input.BrainName, ReleaseDigest: input.ReleaseDigest.String(),
		GenerationID: input.GenerationID,
	})
	if err != nil {
		return install.Digest{}
	}
	return install.DigestBytes(canonical)
}

func digestReceipt(receipt Receipt) install.Digest {
	canonical, err := json.Marshal(struct {
		Authorization string `json:"authorization"`
		Disposition   string `json:"disposition"`
	}{Authorization: receipt.authorizationDigest.String(), Disposition: string(receipt.disposition)})
	if err != nil {
		return install.Digest{}
	}
	return install.DigestBytes(canonical)
}
