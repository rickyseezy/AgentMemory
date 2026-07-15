package runtimeprovision

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

// DesktopMutationRequestEnvelope remains untrusted until the elevated helper
// independently re-establishes release, catalog, host, plan, and self
// authority, then calls BindAuthority.
type DesktopMutationRequestEnvelope interface {
	BindAuthority(runtimeport.DesktopAuthority) (runtimeport.DesktopMutationRequest, error)
	Artifact() (DesktopMutationArtifactBinding, bool)
	SignedRelease() []byte
	SignedRuntimeCatalog() []byte
	CanonicalPlan() []byte
	RuntimeCatalogResourceID() string
	HelperResourceID() string
}

// DesktopMutationRequestDecoder accepts only the canonical helper wire.
type DesktopMutationRequestDecoder interface {
	DecodeDesktopMutationRequest([]byte) (DesktopMutationRequestEnvelope, error)
}

// CanonicalDesktopMutationRequestDecoder adapts the strict transport codec to
// the elevated helper application boundary.
type CanonicalDesktopMutationRequestDecoder struct{}

// DecodeDesktopMutationRequest rejects ambiguous or oversized input.
func (CanonicalDesktopMutationRequestDecoder) DecodeDesktopMutationRequest(
	raw []byte,
) (DesktopMutationRequestEnvelope, error) {
	decoded, err := DecodeCanonicalDesktopMutationRequest(raw)
	if err != nil {
		return nil, runtimeport.ErrDesktopMutationIntegrity
	}
	return decoded, nil
}

// DesktopMutationAuthorityEvidence is emitted only after independent
// helper-side verification of all signed and protected host boundaries.
type DesktopMutationAuthorityEvidence struct {
	authority     runtimeport.DesktopAuthority
	helper        runtimeinstall.Hash
	release       runtimeinstall.Hash
	prerequisites []releaseinventory.Resource
	certificates  map[string]runtimeinstall.Hash
}

// NewDesktopMutationAuthorityEvidence closes one verified authority join.
func NewDesktopMutationAuthorityEvidence(
	authority runtimeport.DesktopAuthority,
	helper runtimeinstall.Hash,
	release runtimeinstall.Hash,
) (DesktopMutationAuthorityEvidence, error) {
	if !authority.Valid() || helper.IsZero() || release.IsZero() {
		return DesktopMutationAuthorityEvidence{}, runtimeport.ErrDesktopMutationIntegrity
	}
	return DesktopMutationAuthorityEvidence{authority: authority, helper: helper, release: release}, nil
}

// NewDesktopMutationAuthorityEvidenceWithPrerequisites binds the exact
// release-verified offline WSL MSI and distribution resources to a Windows
// helper request. macOS admits no prerequisite resources.
func NewDesktopMutationAuthorityEvidenceWithPrerequisites(
	authority runtimeport.DesktopAuthority,
	helper runtimeinstall.Hash,
	release runtimeinstall.Hash,
	prerequisites []releaseinventory.Resource,
	certificates map[string]runtimeinstall.Hash,
) (DesktopMutationAuthorityEvidence, error) {
	if !authority.Valid() || helper.IsZero() || release.IsZero() {
		return DesktopMutationAuthorityEvidence{}, runtimeport.ErrDesktopMutationIntegrity
	}
	validated, bindings, err := validateDesktopMutationPrerequisiteResources(authority, prerequisites, certificates)
	if err != nil {
		return DesktopMutationAuthorityEvidence{}, runtimeport.ErrDesktopMutationIntegrity
	}
	return DesktopMutationAuthorityEvidence{
		authority: authority, helper: helper, release: release,
		prerequisites: validated, certificates: bindings,
	}, nil
}

func validateDesktopMutationPrerequisiteResources(
	authority runtimeport.DesktopAuthority,
	resources []releaseinventory.Resource,
	certificates map[string]runtimeinstall.Hash,
) ([]releaseinventory.Resource, map[string]runtimeinstall.Hash, error) {
	if authority.Platform() == runtimeinstall.PlatformDarwin {
		if len(resources) != 0 || len(certificates) != 0 {
			return nil, nil, runtimeport.ErrDesktopMutationIntegrity
		}
		return nil, nil, nil
	}
	if authority.Platform() != runtimeinstall.PlatformWindows || len(resources) != 2 || len(certificates) != 1 {
		return nil, nil, runtimeport.ErrDesktopMutationIntegrity
	}
	copyResources := slices.Clone(resources)
	slices.SortFunc(copyResources, func(left, right releaseinventory.Resource) int {
		return strings.Compare(left.ID(), right.ID())
	})
	seen := map[releaseinventory.ResourceKind]bool{}
	copyCertificates := make(map[string]runtimeinstall.Hash, 1)
	for _, resource := range copyResources {
		if resource.ID() == "" || resource.Platform().OS() != runtimeinstall.PlatformWindows.String() ||
			resource.Platform().Architecture() != authority.Architecture().String() || resource.Digest().IsZero() ||
			resource.Size() == 0 || !strings.HasPrefix(resource.SourceRef(), "bundle://") {
			return nil, nil, runtimeport.ErrDesktopMutationIntegrity
		}
		if seen[resource.Kind()] {
			return nil, nil, runtimeport.ErrDesktopMutationIntegrity
		}
		seen[resource.Kind()] = true
		switch resource.Kind() {
		case releaseinventory.ResourceKindRuntimeInstaller:
			certificate := certificates[resource.ID()]
			if resource.Purpose() != releaseinventory.ResourcePurposeRuntimeInstaller ||
				resource.MediaType() != releaseinventory.MediaTypeRuntimeInstaller ||
				filepath.Ext(resource.SourceRef()) != ".msi" || resource.NativePublisherIdentity() == "" ||
				resource.NativePublisherPolicyID() == "" || certificate.IsZero() {
				return nil, nil, runtimeport.ErrDesktopMutationIntegrity
			}
			copyCertificates[resource.ID()] = certificate
		case releaseinventory.ResourceKindRuntimeDistribution:
			if resource.Purpose() != releaseinventory.ResourcePurposeRuntimeDistribution ||
				resource.MediaType() != releaseinventory.MediaTypeRuntimeDistribution ||
				filepath.Ext(resource.SourceRef()) != ".wsl" || resource.NativePublisherIdentity() != "" ||
				resource.NativePublisherPolicyID() != "" {
				return nil, nil, runtimeport.ErrDesktopMutationIntegrity
			}
		default:
			return nil, nil, runtimeport.ErrDesktopMutationIntegrity
		}
	}
	if !seen[releaseinventory.ResourceKindRuntimeInstaller] ||
		!seen[releaseinventory.ResourceKindRuntimeDistribution] || len(copyCertificates) != 1 {
		return nil, nil, runtimeport.ErrDesktopMutationIntegrity
	}
	return copyResources, copyCertificates, nil
}

// Authority returns the exact helper-side signed desktop projection.
func (e DesktopMutationAuthorityEvidence) Authority() runtimeport.DesktopAuthority {
	return e.authority
}

// HelperDigest returns the exact self-verified helper executable digest.
func (e DesktopMutationAuthorityEvidence) HelperDigest() runtimeinstall.Hash { return e.helper }

// ReleaseManifestDigest returns the independently verified authorizing release.
func (e DesktopMutationAuthorityEvidence) ReleaseManifestDigest() runtimeinstall.Hash {
	return e.release
}

// PrerequisiteResources returns the exact release-verified offline Windows
// prerequisite payloads. The returned slice cannot mutate evidence.
func (e DesktopMutationAuthorityEvidence) PrerequisiteResources() []releaseinventory.Resource {
	return slices.Clone(e.prerequisites)
}

// PrerequisiteCertificate returns the independently embedded Authenticode
// leaf-certificate binding for one release resource.
func (e DesktopMutationAuthorityEvidence) PrerequisiteCertificate(resourceID string) runtimeinstall.Hash {
	return e.certificates[resourceID]
}

// DesktopMutationAuthorityVerifier independently reconstructs helper authority
// from embedded public trust and current protected host evidence.
type DesktopMutationAuthorityVerifier interface {
	VerifyDesktopMutationAuthority(
		context.Context,
		DesktopMutationRequestEnvelope,
	) (DesktopMutationAuthorityEvidence, error)
}

// DesktopMutationArtifactSet exposes only a privileged transaction copy of the
// verified installer. A prerequisite-only request returns present=false.
type DesktopMutationArtifactSet interface {
	Installer() (DesktopMutationArtifactBinding, bool)
}

// DesktopMutationArtifactPreparer converts an untrusted handoff path into a
// descriptor-verified privileged transaction file.
type DesktopMutationArtifactPreparer interface {
	PrepareDesktopMutationArtifact(
		context.Context,
		runtimeport.DesktopMutationRequest,
		DesktopMutationArtifactBinding,
		bool,
	) (DesktopMutationArtifactSet, error)
}

// DesktopMutationObservationInput contains only closed post-state evidence.
type DesktopMutationObservationInput struct {
	ExitCode      uint32
	PostState     runtimeinstall.Hash
	RebootReceipt runtimeinstall.Hash
}

// DesktopMutationOperationExecutor implements only Docker Desktop installation
// and the exact Windows WSL prerequisite cell.
type DesktopMutationOperationExecutor interface {
	ExecuteDesktopMutation(
		context.Context,
		runtimeport.DesktopMutationRequest,
		DesktopMutationArtifactSet,
		DesktopMutationAuthorityEvidence,
	) (DesktopMutationObservationInput, error)
}

// DesktopMutationHelperReplayRepository durably reserves a verified request
// before mutation and publishes its exact signed receipt afterward.
type DesktopMutationHelperReplayRepository interface {
	BeginDesktopMutationRequest(
		context.Context,
		runtimeport.DesktopMutationRequest,
	) (runtimeport.DesktopMutationReceipt, bool, error)
	CompleteDesktopMutationRequest(
		context.Context,
		runtimeport.DesktopMutationRequest,
		runtimeport.DesktopMutationReceipt,
	) error
}

// DesktopMutationReceiptSigner is available only to the elevated helper.
type DesktopMutationReceiptSigner interface {
	SignDesktopMutationReceipt(
		context.Context,
		runtimeport.DesktopMutationReceiptInput,
	) (runtimeport.DesktopMutationReceipt, error)
}

// DesktopMutationHelperClock supplies trusted UTC expiry time.
type DesktopMutationHelperClock interface{ Now() time.Time }

// DesktopMutationReceiptEncoder emits canonical semantic receipt JSON only.
type DesktopMutationReceiptEncoder interface {
	EncodeDesktopMutationReceipt(runtimeport.DesktopMutationReceipt) ([]byte, error)
}

// CanonicalDesktopMutationReceiptEncoder delegates to the domain codec.
type CanonicalDesktopMutationReceiptEncoder struct{}

// EncodeDesktopMutationReceipt returns bounded canonical JSON.
func (CanonicalDesktopMutationReceiptEncoder) EncodeDesktopMutationReceipt(
	receipt runtimeport.DesktopMutationReceipt,
) ([]byte, error) {
	if receipt.Digest().IsZero() || len(receipt.CanonicalBytes()) == 0 {
		return nil, runtimeport.ErrDesktopMutationIntegrity
	}
	return receipt.CanonicalBytes(), nil
}

// DesktopMutationHelperDependencies is the complete elevated composition.
type DesktopMutationHelperDependencies struct {
	Decoder   DesktopMutationRequestDecoder
	Authority DesktopMutationAuthorityVerifier
	Artifacts DesktopMutationArtifactPreparer
	Executor  DesktopMutationOperationExecutor
	Replay    DesktopMutationHelperReplayRepository
	Signer    DesktopMutationReceiptSigner
	Clock     DesktopMutationHelperClock
	Encoder   DesktopMutationReceiptEncoder
}

// DesktopMutationHelperApplication is the sole desktop elevation side-effect
// ordering boundary.
type DesktopMutationHelperApplication struct {
	dependencies DesktopMutationHelperDependencies
}

// NewDesktopMutationHelperApplication rejects every missing capability.
func NewDesktopMutationHelperApplication(
	dependencies DesktopMutationHelperDependencies,
) (*DesktopMutationHelperApplication, error) {
	if nilArtifactDependency(dependencies.Decoder) || nilArtifactDependency(dependencies.Authority) ||
		nilArtifactDependency(dependencies.Artifacts) || nilArtifactDependency(dependencies.Executor) ||
		nilArtifactDependency(dependencies.Replay) || nilArtifactDependency(dependencies.Signer) ||
		nilArtifactDependency(dependencies.Clock) || nilArtifactDependency(dependencies.Encoder) {
		return nil, errors.New("complete desktop mutation helper dependencies are required")
	}
	return &DesktopMutationHelperApplication{dependencies: dependencies}, nil
}

// ExecuteDesktopMutationRequest verifies and binds every authority before any
// file preparation or native mutation, then signs only the exact post-state.
func (a *DesktopMutationHelperApplication) ExecuteDesktopMutationRequest(
	ctx context.Context,
	raw []byte,
) ([]byte, error) {
	if a == nil || ctx == nil || len(raw) == 0 || len(raw) > maximumPrivilegeWireBytes {
		return nil, runtimeport.ErrDesktopMutationIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	envelope, err := a.dependencies.Decoder.DecodeDesktopMutationRequest(raw)
	if err != nil || nilArtifactDependency(envelope) {
		return nil, runtimeport.ErrDesktopMutationIntegrity
	}
	evidence, err := a.dependencies.Authority.VerifyDesktopMutationAuthority(ctx, envelope)
	if err != nil || !evidence.Authority().Valid() || evidence.HelperDigest().IsZero() ||
		evidence.ReleaseManifestDigest().IsZero() {
		return nil, desktopMutationHelperContextOrIntegrity(ctx)
	}
	request, err := envelope.BindAuthority(evidence.Authority())
	if err != nil || request.Digest().IsZero() {
		return nil, runtimeport.ErrDesktopMutationIntegrity
	}
	now := a.dependencies.Clock.Now()
	if !validDesktopMutationHelperTime(now, request) {
		return nil, runtimeport.ErrDesktopMutationIntegrity
	}
	cached, completed, err := a.dependencies.Replay.BeginDesktopMutationRequest(ctx, request)
	if err != nil {
		return nil, desktopMutationHelperContextOrIntegrity(ctx)
	}
	if completed {
		if !cached.Matches(request, now) {
			return nil, runtimeport.ErrDesktopMutationIntegrity
		}
		return a.encodeReceipt(ctx, cached)
	}
	binding, present := envelope.Artifact()
	artifacts, err := a.dependencies.Artifacts.PrepareDesktopMutationArtifact(ctx, request, binding, present)
	if err != nil || nilArtifactDependency(artifacts) || !desktopMutationArtifactSetMatches(artifacts, binding, present) {
		return nil, desktopMutationHelperContextOrIntegrity(ctx)
	}
	observation, err := a.dependencies.Executor.ExecuteDesktopMutation(ctx, request, artifacts, evidence)
	if err != nil || observation.PostState != request.ExpectedState() {
		return nil, desktopMutationHelperContextOrIntegrity(ctx)
	}
	completedAt := a.dependencies.Clock.Now()
	if !validDesktopMutationHelperTime(completedAt, request) {
		return nil, runtimeport.ErrDesktopMutationIntegrity
	}
	receipt, err := a.dependencies.Signer.SignDesktopMutationReceipt(
		ctx,
		runtimeport.DesktopMutationReceiptInput{
			RequestDigest: request.Digest(), AuthorityDigest: request.Authority().Digest(),
			Nonce: request.Nonce(), ExitCode: observation.ExitCode, PostState: observation.PostState,
			RebootReceipt: observation.RebootReceipt, CompletedAt: completedAt, ExpiresAt: request.ExpiresAt(),
		},
	)
	if err != nil || !receipt.Matches(request, completedAt) {
		return nil, desktopMutationHelperContextOrIntegrity(ctx)
	}
	if err := a.dependencies.Replay.CompleteDesktopMutationRequest(ctx, request, receipt); err != nil {
		return nil, desktopMutationHelperContextOrIntegrity(ctx)
	}
	return a.encodeReceipt(ctx, receipt)
}

func (a *DesktopMutationHelperApplication) encodeReceipt(
	ctx context.Context,
	receipt runtimeport.DesktopMutationReceipt,
) ([]byte, error) {
	encoded, err := a.dependencies.Encoder.EncodeDesktopMutationReceipt(receipt)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumPrivilegeWireBytes {
		return nil, desktopMutationHelperContextOrIntegrity(ctx)
	}
	return encoded, nil
}

func validDesktopMutationHelperTime(
	now time.Time,
	request runtimeport.DesktopMutationRequest,
) bool {
	return !now.IsZero() && now.Location() == time.UTC && !now.Before(request.IssuedAt()) && now.Before(request.ExpiresAt())
}

func desktopMutationArtifactSetMatches(
	set DesktopMutationArtifactSet,
	expected DesktopMutationArtifactBinding,
	expectedPresent bool,
) bool {
	actual, present := set.Installer()
	return present == expectedPresent && (!present ||
		validDesktopMutationArtifactPath(actual.Path()) && actual.SHA256() == expected.SHA256() &&
			actual.Size() == expected.Size())
}

func desktopMutationHelperContextOrIntegrity(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return runtimeport.ErrDesktopMutationIntegrity
}

var (
	_ DesktopMutationRequestDecoder = CanonicalDesktopMutationRequestDecoder{}
	_ DesktopMutationReceiptEncoder = CanonicalDesktopMutationReceiptEncoder{}
)
