package provideradapterapp

import (
	"context"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/provideradapter"
)

const maximumAdapterEvidenceBytes = 32 * 1024 * 1024

// EvidenceKind is the closed custom-adapter supply-chain evidence vocabulary.
type EvidenceKind string

const (
	// EvidenceSignatureBundle identifies the offline image signature bundle.
	EvidenceSignatureBundle EvidenceKind = "sigstore_bundle"
	// EvidenceCycloneDX identifies the CycloneDX SBOM.
	EvidenceCycloneDX EvidenceKind = "cyclonedx_sbom"
	// EvidenceSPDX identifies the independent SPDX SBOM.
	EvidenceSPDX EvidenceKind = "spdx_sbom"
	// EvidenceProvenance identifies SLSA provenance.
	EvidenceProvenance EvidenceKind = "slsa_provenance"
	// EvidenceLicense identifies the evaluated license-policy document.
	EvidenceLicense EvidenceKind = "license_policy"
	// EvidenceVulnerability identifies the evaluated vulnerability report.
	EvidenceVulnerability EvidenceKind = "vulnerability_policy"
)

// EvidenceSource returns immutable local evidence by digest. It must never resolve a tag.
type EvidenceSource interface {
	Load(context.Context, EvidenceKind, provideradapter.Digest, int64) ([]byte, error)
}

// ImageSignaturePolicy validates the OCI descriptor and offline signature bundle against trust roots.
type ImageSignaturePolicy interface {
	Verify(context.Context, string, provideradapter.Digest, []byte) error
}

// AdapterEvidencePolicy validates subject binding and policy for non-signature evidence.
type AdapterEvidencePolicy interface {
	Verify(context.Context, EvidenceKind, provideradapter.Digest, []byte) error
}

// DigestBoundSupplyChainVerifier performs every trust check before Docker can pull or start an image.
type DigestBoundSupplyChainVerifier struct {
	source    EvidenceSource
	signature ImageSignaturePolicy
	evidence  AdapterEvidencePolicy
}

// NewDigestBoundSupplyChainVerifier requires all independently replaceable trust ports.
func NewDigestBoundSupplyChainVerifier(
	source EvidenceSource,
	signature ImageSignaturePolicy,
	evidence AdapterEvidencePolicy,
) (*DigestBoundSupplyChainVerifier, error) {
	if source == nil || signature == nil || evidence == nil {
		return nil, ErrVerification
	}
	return &DigestBoundSupplyChainVerifier{source: source, signature: signature, evidence: evidence}, nil
}

// Verify loads exact digest-addressed bytes and evaluates signature, SBOM, provenance, license, and vulnerability policy.
func (v *DigestBoundSupplyChainVerifier) Verify(ctx context.Context, manifest provideradapter.Manifest) error {
	if v == nil || ctx == nil || manifest.Digest().IsZero() {
		return ErrVerification
	}
	evidence := manifest.Evidence()
	documents := []struct {
		kind   EvidenceKind
		digest provideradapter.Digest
	}{
		{EvidenceSignatureBundle, evidence.SignatureBundle},
		{EvidenceCycloneDX, evidence.CycloneDXSBOM},
		{EvidenceSPDX, evidence.SPDXSBOM},
		{EvidenceProvenance, evidence.Provenance},
		{EvidenceLicense, evidence.License},
		{EvidenceVulnerability, evidence.Vulnerability},
	}
	loaded := make(map[EvidenceKind][]byte, len(documents))
	for _, document := range documents {
		value, err := v.source.Load(ctx, document.kind, document.digest, maximumAdapterEvidenceBytes)
		if err != nil || len(value) == 0 || int64(len(value)) > maximumAdapterEvidenceBytes ||
			!provideradapter.DigestBytes(value).Equal(document.digest) {
			return errors.Join(ErrVerification, err)
		}
		loaded[document.kind] = append([]byte(nil), value...)
	}
	if err := v.signature.Verify(ctx, manifest.Image(), manifest.ImageDigest(), loaded[EvidenceSignatureBundle]); err != nil {
		return errors.Join(ErrVerification, err)
	}
	for _, document := range documents[1:] {
		if err := v.evidence.Verify(ctx, document.kind, manifest.ImageDigest(), loaded[document.kind]); err != nil {
			return errors.Join(ErrVerification, err)
		}
	}
	return nil
}

var _ SupplyChainVerifier = (*DigestBoundSupplyChainVerifier)(nil)
