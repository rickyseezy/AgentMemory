// Package releaseverify verifies signed PF-001 release inventories before any
// artifact is executed or release state is activated.
package releaseverify

import (
	"context"
	"errors"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

// Typed outbound-port errors used for fail-closed application mapping.
var (
	ErrUntrustedSigner          = errors.New("release signer is not trusted")
	ErrSignatureInvalid         = errors.New("release signature is invalid")
	ErrSignatureModeUnsupported = errors.New("release signature mode is unsupported")
	ErrTrustEvidenceInvalid     = errors.New("offline release trust evidence is invalid")
	ErrTrustRootRevoked         = errors.New("release trust root is revoked")
	ErrResourceUnavailable      = errors.New("release resource is unavailable")
	ErrResourceDigestMismatch   = errors.New("release resource digest mismatch")
	ErrSBOMInvalid              = errors.New("release SBOM evidence is invalid")
	ErrProvenanceInvalid        = errors.New("release provenance evidence is invalid")
	ErrLicenseDenied            = errors.New("release license policy rejected the subject")
	ErrVulnerabilityDenied      = errors.New("release vulnerability policy rejected the subject")
	ErrNativePublisherInvalid   = errors.New("release native publisher is invalid")
	ErrOCIIndexInvalid          = errors.New("release OCI index binding is invalid")
	ErrReleaseAnchorNotFound    = errors.New("release anti-rollback anchor was not found")
	ErrReleaseAnchorConflict    = errors.New("release anti-rollback anchor changed")
	ErrReleaseAnchorIntegrity   = errors.New("release anti-rollback anchor integrity failed")
	ErrDependencyUnavailable    = errors.New("release verification dependency is unavailable")
)

// Clock supplies trusted local policy time. A production implementation must
// use the offline trusted-time decision established by TrustEvidenceVerifier;
// this clock alone never proves signing time.
type Clock interface {
	Now() time.Time
}

// PlatformProvider returns the certified current host tuple.
type PlatformProvider interface {
	CurrentPlatform(context.Context) (releaseinventory.Platform, error)
}

// ProtocolProvider returns the running launcher's protocol revision.
type ProtocolProvider interface {
	CurrentProtocol(context.Context) (uint32, error)
}

// ManifestSignatureVerifier verifies canonical manifest signature bytes.
type ManifestSignatureVerifier interface {
	VerifyManifestSignature(context.Context, releaseinventory.SignedManifest) error
}

// OfflineTrustEvidenceVerifier verifies revocation, trusted time, and any certificate/transparency proof.
type OfflineTrustEvidenceVerifier interface {
	VerifyOfflineTrustEvidence(context.Context, releaseinventory.SignedManifest) error
}

// ResourceDigestVerifier verifies exact bytes and declared length.
type ResourceDigestVerifier interface {
	VerifyResourceDigest(context.Context, releaseinventory.Resource) error
}

// SBOMVerifier verifies both CycloneDX and SPDX subject bindings.
type SBOMVerifier interface {
	VerifySBOMs(
		context.Context,
		releaseinventory.Resource,
		releaseinventory.Resource,
		releaseinventory.Resource,
	) error
}

// ProvenanceVerifier verifies SLSA subject, builder, source, and locked inputs.
// The immutable signed manifest is required so an adapter can bind provenance
// source/build identity to the release instead of trusting self-asserted
// evidence fields.
type ProvenanceVerifier interface {
	VerifyProvenance(
		context.Context,
		releaseinventory.Manifest,
		releaseinventory.Resource,
		releaseinventory.Resource,
	) error
}

// LicenseVerifier enforces the signed license-policy qualification result.
type LicenseVerifier interface {
	VerifyLicense(context.Context, releaseinventory.Resource, releaseinventory.Resource) error
}

// VulnerabilityVerifier enforces the signed, unexpired vulnerability result.
type VulnerabilityVerifier interface {
	VerifyVulnerabilities(context.Context, releaseinventory.Resource, releaseinventory.Resource) error
}

// NativePublisherVerifier enforces platform-native publisher policy.
type NativePublisherVerifier interface {
	VerifyNativePublisher(context.Context, releaseinventory.Resource) error
}

// OCIIndexVerifier binds the selected platform manifest to the exact signed
// index resource. Passing both resources prevents mutable-locator lookup or an
// adapter-local inventory reconstruction from becoming release authority.
type OCIIndexVerifier interface {
	VerifyOCIIndex(context.Context, releaseinventory.Resource, releaseinventory.Resource) error
}

// AntiRollbackRepository atomically persists one accepted sequence high-water
// mark per closed release channel.
type AntiRollbackRepository interface {
	LoadReleaseAnchor(context.Context, releaseinventory.ReleaseChannel) (ReleaseAnchor, error)
	CompareAndSwapReleaseAnchor(context.Context, *ReleaseAnchor, ReleaseAnchor) error
}
