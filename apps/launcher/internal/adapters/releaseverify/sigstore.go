package releaseverifyadapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	application "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const sigstoreBundleVersion = "v0.3"

// SigstoreTrustPolicyInput is externally composed, pre-distributed offline
// trust material. TrustedRootJSON must be an official Sigstore trusted-root
// document; no TUF, network, operating-system root, or ambient key lookup is
// performed by this adapter.
type SigstoreTrustPolicyInput struct {
	TrustRootID     string
	TrustedRootJSON []byte
	RekorLogID      string
	CertificateSAN  string
	OIDCIssuer      string
}

// SigstoreCertificateTransparencyVerifier verifies official Sigstore bundles
// against one immutable trust policy and one exact Rekor log.
type SigstoreCertificateTransparencyVerifier struct {
	trustRootID string
	rekorLogID  string
	identity    verify.CertificateIdentity
	verifier    offlineSigstoreVerifier
}

type offlineSigstoreVerifier interface {
	Verify(verify.SignedEntity, verify.PolicyBuilder) (*verify.VerificationResult, error)
}

var _ application.ManifestSignatureVerifier = (*SigstoreCertificateTransparencyVerifier)(nil)

// NewSigstoreCertificateTransparencyVerifier constructs an entirely offline
// verifier. All trust anchors must be explicitly injected by the composition
// root and are copied by parsing the supplied official trusted-root document.
func NewSigstoreCertificateTransparencyVerifier(
	input SigstoreTrustPolicyInput,
) (*SigstoreCertificateTransparencyVerifier, error) {
	if !validSafeEvidenceText(input.TrustRootID, 128) ||
		!validSHA256Hex(input.RekorLogID) ||
		!validSafeEvidenceText(input.CertificateSAN, 4096) ||
		!validSafeEvidenceText(input.OIDCIssuer, 4096) ||
		len(input.TrustedRootJSON) == 0 || len(input.TrustedRootJSON) > maximumEvidenceDocumentBytes {
		return nil, errors.New("sigstore release trust policy is invalid")
	}
	if err := rejectDuplicateEvidenceKeys(input.TrustedRootJSON); err != nil {
		return nil, errors.New("sigstore trusted root is invalid")
	}

	trustedRoot, err := root.NewTrustedRootFromJSON(append([]byte(nil), input.TrustedRootJSON...))
	if err != nil {
		return nil, errors.New("sigstore trusted root is invalid")
	}
	rekorLog, found := trustedRoot.RekorLogs()[input.RekorLogID]
	if !found || rekorLog == nil || hex.EncodeToString(rekorLog.ID) != input.RekorLogID ||
		rekorLog.PublicKey == nil || len(trustedRoot.FulcioCertificateAuthorities()) == 0 ||
		len(trustedRoot.CTLogs()) == 0 {
		return nil, errors.New("sigstore trusted root lacks the configured Fulcio, CT, or Rekor authority")
	}

	identity, err := verify.NewShortCertificateIdentity(
		input.OIDCIssuer,
		"",
		input.CertificateSAN,
		"",
	)
	if err != nil {
		return nil, errors.New("sigstore certificate identity policy is invalid")
	}
	material := exactRekorTrustedMaterial{trustedRoot: trustedRoot, rekorLogID: input.RekorLogID, rekorLog: rekorLog}
	offlineVerifier, err := verify.NewVerifier(
		material,
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
		verify.WithSignedCertificateTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("construct offline Sigstore verifier: %w", err)
	}
	return &SigstoreCertificateTransparencyVerifier{
		trustRootID: input.TrustRootID,
		rekorLogID:  input.RekorLogID,
		identity:    identity,
		verifier:    offlineVerifier,
	}, nil
}

// VerifyManifestSignature verifies the exact canonical manifest SHA-256,
// certificate chain, exact SAN and OIDC issuer, SCT, Rekor proof/checkpoint,
// Rekor observer timestamp, and bundle signature without online lookups.
func (v *SigstoreCertificateTransparencyVerifier) VerifyManifestSignature(
	ctx context.Context,
	signed releaseinventory.SignedManifest,
) error {
	if err := adapterContextError(ctx); err != nil {
		return err
	}
	if v == nil || adapterNil(v.verifier) {
		return application.ErrDependencyUnavailable
	}
	if signed.SignatureBundleSchemaVersion() != releaseinventory.SupportedSignatureBundleSchemaMajor ||
		signed.TrustMode() != releaseinventory.SignatureTrustModeCertificateTransparency {
		return application.ErrSignatureModeUnsupported
	}
	manifest := signed.Manifest()
	if signed.TrustRootID() != v.trustRootID || manifest.TrustPolicy().TrustRootID() != v.trustRootID ||
		manifest.TrustPolicy().TransparencyLogID() != v.rekorLogID {
		return application.ErrUntrustedSigner
	}

	digest := sha256.Sum256(signed.SignaturePayload())
	if digest != manifest.Digest() {
		return application.ErrSignatureInvalid
	}
	if err := v.verifyBundleDigest(signed.SigstoreBundle(), digest[:]); err != nil {
		return errors.Join(application.ErrSignatureInvalid, err)
	}
	if err := adapterContextError(ctx); err != nil {
		return err
	}
	return nil
}

func (v *SigstoreCertificateTransparencyVerifier) verifyBundleDigest(raw, digest []byte) error {
	if v == nil || adapterNil(v.verifier) || len(digest) != sha256.Size {
		return errEvidenceContent
	}
	parsed, err := decodeSigstoreBundle(raw, v.rekorLogID)
	if err != nil {
		return err
	}
	policy := verify.NewPolicy(
		verify.WithArtifactDigest("sha256", append([]byte(nil), digest...)),
		verify.WithCertificateIdentity(v.identity),
	)
	result, err := v.verifier.Verify(parsed, policy)
	if err != nil {
		return fmt.Errorf("offline Sigstore verification failed: %w", err)
	}
	if result == nil || result.Signature == nil || result.Signature.Certificate == nil ||
		result.VerifiedIdentity == nil || len(result.VerifiedTimestamps) < 1 {
		return errEvidenceContent
	}
	return nil
}

func decodeSigstoreBundle(raw []byte, rekorLogID string) (*bundle.Bundle, error) {
	if len(raw) == 0 || len(raw) > maximumEvidenceDocumentBytes || !validSHA256Hex(rekorLogID) {
		return nil, errEvidenceMalformed
	}
	if err := rejectDuplicateEvidenceKeys(raw); err != nil {
		return nil, err
	}
	parsed := &bundle.Bundle{}
	bundle.AllowCertificateChain()(parsed)
	if err := parsed.UnmarshalJSON(raw); err != nil {
		return nil, errors.Join(errEvidenceMalformed, err)
	}
	canonical, err := parsed.MarshalJSON()
	if err != nil {
		return nil, errors.Join(errEvidenceMalformed, err)
	}
	if !bytes.Equal(raw, canonical) {
		return nil, errEvidenceNonCanonical
	}
	messageSignature := parsed.GetMessageSignature()
	if messageSignature == nil || messageSignature.GetMessageDigest() == nil ||
		messageSignature.GetMessageDigest().GetAlgorithm().String() != "SHA2_256" ||
		len(messageSignature.GetMessageDigest().GetDigest()) != sha256.Size ||
		len(messageSignature.GetSignature()) == 0 {
		return nil, errEvidenceContent
	}
	version, err := parsed.Version()
	if err != nil || version != sigstoreBundleVersion {
		return nil, errEvidenceContent
	}
	entries, err := parsed.TlogEntries()
	if err != nil {
		return nil, errors.Join(errEvidenceContent, err)
	}
	foundExactProof := false
	for _, entry := range entries {
		if entry == nil || !entry.HasInclusionProof() {
			continue
		}
		entryLogID := hex.EncodeToString([]byte(entry.LogKeyID()))
		proof := entry.TransparencyLogEntry().GetInclusionProof()
		if entryLogID == rekorLogID && proof != nil &&
			strings.TrimSpace(proof.GetCheckpoint().GetEnvelope()) != "" {
			foundExactProof = true
		}
	}
	if !foundExactProof {
		return nil, errEvidenceContent
	}
	return parsed, nil
}

func validSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

type exactRekorTrustedMaterial struct {
	trustedRoot *root.TrustedRoot
	rekorLogID  string
	rekorLog    *root.TransparencyLog
}

func (m exactRekorTrustedMaterial) TimestampingAuthorities() []root.TimestampingAuthority {
	return m.trustedRoot.TimestampingAuthorities()
}

func (m exactRekorTrustedMaterial) FulcioCertificateAuthorities() []root.CertificateAuthority {
	return m.trustedRoot.FulcioCertificateAuthorities()
}

func (m exactRekorTrustedMaterial) RekorLogs() map[string]*root.TransparencyLog {
	return map[string]*root.TransparencyLog{m.rekorLogID: m.rekorLog}
}

func (m exactRekorTrustedMaterial) CTLogs() map[string]*root.TransparencyLog {
	return m.trustedRoot.CTLogs()
}

func (m exactRekorTrustedMaterial) PublicKeyVerifier(keyID string) (root.TimeConstrainedVerifier, error) {
	return m.trustedRoot.PublicKeyVerifier(keyID)
}
