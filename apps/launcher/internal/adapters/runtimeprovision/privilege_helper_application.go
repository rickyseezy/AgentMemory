package runtimeprovision

import (
	"context"
	"errors"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

// PrivilegeRequestEnvelope is untrusted canonical transport until a verifier
// independently re-establishes signed release, catalog, helper, host, and plan
// authority and BindAuthority reconstructs the exact request.
type PrivilegeRequestEnvelope interface {
	BindAuthority(runtimeport.LinuxAuthority) (runtimeport.PrivilegeRequest, error)
	Artifacts() []PrivilegeArtifactBinding
	SignedRelease() []byte
	SignedRuntimeCatalog() []byte
	CanonicalPlan() []byte
	RuntimeCatalogResourceID() string
	HelperResourceID() string
}

// PrivilegeRequestDecoder accepts only the canonical closed helper wire.
type PrivilegeRequestDecoder interface {
	DecodePrivilegeRequest([]byte) (PrivilegeRequestEnvelope, error)
}

// CanonicalPrivilegeRequestDecoder adapts the strict transport codec to the
// helper application boundary.
type CanonicalPrivilegeRequestDecoder struct{}

// DecodePrivilegeRequest rejects noncanonical, ambiguous, or oversized input.
func (CanonicalPrivilegeRequestDecoder) DecodePrivilegeRequest(
	raw []byte,
) (PrivilegeRequestEnvelope, error) {
	decoded, err := DecodeCanonicalPrivilegeRequest(raw)
	if err != nil {
		return nil, runtimeport.ErrPrivilegeIntegrity
	}
	return decoded, nil
}

// PrivilegeAuthorityEvidence is emitted only after independent helper-side
// release/catalog/host verification.
type PrivilegeAuthorityEvidence struct {
	authority runtimeport.LinuxAuthority
	helper    runtimeinstall.Hash
}

// NewPrivilegeAuthorityEvidence closes one independently verified authority.
func NewPrivilegeAuthorityEvidence(
	authority runtimeport.LinuxAuthority,
	helper runtimeinstall.Hash,
) (PrivilegeAuthorityEvidence, error) {
	if !authority.Valid() || helper.IsZero() {
		return PrivilegeAuthorityEvidence{}, runtimeport.ErrPrivilegeIntegrity
	}
	return PrivilegeAuthorityEvidence{authority: authority, helper: helper}, nil
}

// Authority returns the exact helper-side signed projection.
func (e PrivilegeAuthorityEvidence) Authority() runtimeport.LinuxAuthority { return e.authority }

// HelperDigest returns the exact self-verified helper executable digest.
func (e PrivilegeAuthorityEvidence) HelperDigest() runtimeinstall.Hash { return e.helper }

// PrivilegeAuthorityVerifier independently reconstructs helper authority from
// embedded public trust and current protected host evidence.
type PrivilegeAuthorityVerifier interface {
	VerifyPrivilegeAuthority(context.Context, PrivilegeRequestEnvelope) (PrivilegeAuthorityEvidence, error)
}

// PrivilegeArtifactSet exposes only root-owned transaction paths produced by
// the descriptor-verifying copier.
type PrivilegeArtifactSet interface {
	Root() string
	Artifacts() []PrivilegeTransactionArtifact
	PackagePaths() []string
	Artifact(string) (PrivilegeTransactionArtifact, bool)
}

// PrivilegeArtifactPreparer converts untrusted handoff paths into exact
// root-owned transaction descriptors.
type PrivilegeArtifactPreparer interface {
	PreparePrivilegeArtifacts(
		context.Context,
		runtimeport.PrivilegeRequest,
		[]PrivilegeArtifactBinding,
	) (PrivilegeArtifactSet, error)
}

// PrivilegeOperationObservationInput contains only post-state evidence. The
// application supplies every request/authority binding itself before signing.
type PrivilegeOperationObservationInput struct {
	Result                 runtimeport.PrivilegeResult
	ObservedState          runtimeinstall.Hash
	PackageStateDigest     runtimeinstall.Hash
	RepositoryDigest       runtimeinstall.Hash
	ServiceUnitDigest      runtimeinstall.Hash
	ServiceEnabled         bool
	ServiceActive          bool
	UserLingerEnabled      bool
	SubordinateIDs         uint32
	SubordinateUIDStart    uint32
	SubordinateGIDStart    uint32
	SubordinateStateDigest runtimeinstall.Hash
}

// PrivilegeOperationExecutor implements only the five closed operation kinds.
type PrivilegeOperationExecutor interface {
	ExecutePrivilegeOperation(
		context.Context,
		runtimeport.PrivilegeRequest,
		PrivilegeArtifactSet,
	) (PrivilegeOperationObservationInput, error)
}

// PrivilegeHelperClock supplies trusted UTC expiry time.
type PrivilegeHelperClock interface{ Now() time.Time }

// PrivilegeReceiptEncoder emits only canonical semantic receipt JSON.
type PrivilegeReceiptEncoder interface {
	EncodePrivilegeReceipt(runtimeport.PrivilegeReceipt) ([]byte, error)
}

// CanonicalPrivilegeReceiptEncoder adapts the strict receipt codec.
type CanonicalPrivilegeReceiptEncoder struct{}

// EncodePrivilegeReceipt returns canonical bounded JSON with no diagnostics.
func (CanonicalPrivilegeReceiptEncoder) EncodePrivilegeReceipt(
	receipt runtimeport.PrivilegeReceipt,
) ([]byte, error) {
	return EncodeCanonicalPrivilegeReceipt(receipt)
}

// PrivilegeHelperDependencies is the complete root-helper composition.
type PrivilegeHelperDependencies struct {
	Decoder   PrivilegeRequestDecoder
	Authority PrivilegeAuthorityVerifier
	Artifacts PrivilegeArtifactPreparer
	Executor  PrivilegeOperationExecutor
	Signer    PrivilegeReceiptSigner
	Clock     PrivilegeHelperClock
	Encoder   PrivilegeReceiptEncoder
}

// PrivilegeHelperApplication is the sole side-effect ordering boundary for
// the root helper.
type PrivilegeHelperApplication struct{ dependencies PrivilegeHelperDependencies }

// NewPrivilegeHelperApplication rejects every missing production capability.
func NewPrivilegeHelperApplication(
	dependencies PrivilegeHelperDependencies,
) (*PrivilegeHelperApplication, error) {
	if nilArtifactDependency(dependencies.Decoder) || nilArtifactDependency(dependencies.Authority) ||
		nilArtifactDependency(dependencies.Artifacts) || nilArtifactDependency(dependencies.Executor) ||
		nilArtifactDependency(dependencies.Signer) || nilArtifactDependency(dependencies.Clock) ||
		nilArtifactDependency(dependencies.Encoder) {
		return nil, errors.New("complete privilege helper dependencies are required")
	}
	return &PrivilegeHelperApplication{dependencies: dependencies}, nil
}

// ExecutePrivilegeRequest verifies and binds all authority before preparing
// files or executing one closed operation, then signs only exact post-state.
func (a *PrivilegeHelperApplication) ExecutePrivilegeRequest(
	ctx context.Context,
	raw []byte,
) ([]byte, error) {
	if a == nil || ctx == nil || len(raw) == 0 {
		return nil, runtimeport.ErrPrivilegeIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	envelope, err := a.dependencies.Decoder.DecodePrivilegeRequest(raw)
	if err != nil || nilArtifactDependency(envelope) {
		return nil, runtimeport.ErrPrivilegeIntegrity
	}
	authorityEvidence, err := a.dependencies.Authority.VerifyPrivilegeAuthority(ctx, envelope)
	if err != nil || !authorityEvidence.Authority().Valid() || authorityEvidence.HelperDigest().IsZero() {
		return nil, privilegeHelperContextOrIntegrity(ctx)
	}
	request, err := envelope.BindAuthority(authorityEvidence.Authority())
	if err != nil || request.Digest().IsZero() {
		return nil, runtimeport.ErrPrivilegeIntegrity
	}
	now := a.dependencies.Clock.Now()
	if now.IsZero() || now.Location() != time.UTC || now.Before(request.IssuedAt()) || !now.Before(request.ExpiresAt()) {
		return nil, runtimeport.ErrPrivilegeIntegrity
	}
	transaction, err := a.dependencies.Artifacts.PreparePrivilegeArtifacts(ctx, request, envelope.Artifacts())
	if err != nil || nilArtifactDependency(transaction) || transaction.Root() == "" {
		return nil, privilegeHelperContextOrIntegrity(ctx)
	}
	observation, err := a.dependencies.Executor.ExecutePrivilegeOperation(ctx, request, transaction)
	if err != nil {
		return nil, privilegeHelperContextOrIntegrity(ctx)
	}
	receipt, err := a.dependencies.Signer.SignPrivilegeReceipt(ctx, buildPrivilegeReceiptInput(
		request, authorityEvidence.HelperDigest(), observation,
	))
	if err != nil || !receipt.Matches(request, now) || receipt.HelperDigest() != authorityEvidence.HelperDigest() {
		return nil, privilegeHelperContextOrIntegrity(ctx)
	}
	encoded, err := a.dependencies.Encoder.EncodePrivilegeReceipt(receipt)
	if err != nil || len(encoded) == 0 {
		return nil, privilegeHelperContextOrIntegrity(ctx)
	}
	return encoded, nil
}

func buildPrivilegeReceiptInput(
	request runtimeport.PrivilegeRequest,
	helper runtimeinstall.Hash,
	observation PrivilegeOperationObservationInput,
) runtimeport.PrivilegeReceiptInput {
	authority := request.Authority()
	return runtimeport.PrivilegeReceiptInput{
		RequestDigest: request.Digest(), OperationKey: request.OperationKey(),
		PlanDigest: authority.PlanDigest(), AuthorityDigest: authority.Digest(), Operation: request.Operation(),
		PrincipalID: authority.PrincipalID(), MachineDigest: authority.MachineDigest(), Nonce: request.Nonce(),
		ExpiresAt: request.ExpiresAt(), Result: observation.Result, ObservedState: observation.ObservedState,
		PackageStateDigest: observation.PackageStateDigest, RepositoryDigest: observation.RepositoryDigest,
		ServiceUnitDigest: observation.ServiceUnitDigest, ServiceEnabled: observation.ServiceEnabled,
		ServiceActive: observation.ServiceActive, UserLingerEnabled: observation.UserLingerEnabled,
		SubordinateIDs: observation.SubordinateIDs, SubordinateUIDStart: observation.SubordinateUIDStart,
		SubordinateGIDStart:    observation.SubordinateGIDStart,
		SubordinateStateDigest: observation.SubordinateStateDigest, HelperDigest: helper,
	}
}

func privilegeHelperContextOrIntegrity(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return runtimeport.ErrPrivilegeIntegrity
}

var (
	_ PrivilegeRequestDecoder   = CanonicalPrivilegeRequestDecoder{}
	_ PrivilegeReceiptEncoder   = CanonicalPrivilegeReceiptEncoder{}
	_ PrivilegeArtifactSet      = PrivilegeArtifactTransaction{}
	_ PrivilegeArtifactPreparer = (*RootPrivilegeArtifactStore)(nil)
)
