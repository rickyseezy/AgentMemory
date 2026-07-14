package releaseverifyadapter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	application "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestEd25519KeyIDVerifierChecksExactRootAndCanonicalPayload(t *testing.T) {
	t.Parallel()

	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	unsigned := adapterManifest(t, releaseinventory.SignatureTrustModeKeyID)
	signature := ed25519.Sign(privateKey, unsignedPayload(t, unsigned))
	signed := adapterSignedManifest(t, unsigned, releaseinventory.SignatureTrustModeKeyID, "root-2026", signature)
	verifier, err := NewEd25519KeyIDVerifier(map[string]ed25519.PublicKey{"root-2026": publicKey})
	if err != nil {
		t.Fatalf("NewEd25519KeyIDVerifier() error = %v", err)
	}

	if err := verifier.VerifyManifestSignature(context.Background(), signed); err != nil {
		t.Fatalf("VerifyManifestSignature() error = %v", err)
	}

	tamperedSignature := signed.Signature()
	tamperedSignature[0] ^= 0xff
	tampered := adapterSignedManifest(
		t,
		unsigned,
		releaseinventory.SignatureTrustModeKeyID,
		"root-2026",
		tamperedSignature,
	)
	if err := verifier.VerifyManifestSignature(context.Background(), tampered); !errors.Is(err, application.ErrSignatureInvalid) {
		t.Fatalf("tampered error = %v, want ErrSignatureInvalid", err)
	}

	wrongSigner := adapterSignedManifest(
		t,
		unsigned,
		releaseinventory.SignatureTrustModeKeyID,
		"other-root",
		signature,
	)
	if err := verifier.VerifyManifestSignature(context.Background(), wrongSigner); !errors.Is(err, application.ErrUntrustedSigner) {
		t.Fatalf("wrong signer error = %v, want ErrUntrustedSigner", err)
	}
}

func TestEd25519KeyIDVerifierRefusesCertificateTransparencyMode(t *testing.T) {
	t.Parallel()

	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	manifest := adapterManifest(t, releaseinventory.SignatureTrustModeCertificateTransparency)
	signed := adapterSignedManifest(
		t,
		manifest,
		releaseinventory.SignatureTrustModeCertificateTransparency,
		"root-2026",
		[]byte("certificate signature bytes"),
	)
	verifier, err := NewEd25519KeyIDVerifier(map[string]ed25519.PublicKey{"root-2026": publicKey})
	if err != nil {
		t.Fatalf("NewEd25519KeyIDVerifier() error = %v", err)
	}
	if err := verifier.VerifyManifestSignature(context.Background(), signed); !errors.Is(err, application.ErrSignatureModeUnsupported) {
		t.Fatalf("certificate mode error = %v, want ErrSignatureModeUnsupported", err)
	}
}

func TestEd25519KeyIDVerifierRejectsInvalidTrustRootsAndCancellation(t *testing.T) {
	t.Parallel()

	if _, err := NewEd25519KeyIDVerifier(nil); err == nil {
		t.Fatal("NewEd25519KeyIDVerifier() accepted no roots")
	}
	if _, err := NewEd25519KeyIDVerifier(map[string]ed25519.PublicKey{"root": []byte("short")}); err == nil {
		t.Fatal("NewEd25519KeyIDVerifier() accepted an invalid key")
	}
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x2a}, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	verifier, _ := NewEd25519KeyIDVerifier(map[string]ed25519.PublicKey{"root-2026": publicKey})
	manifest := adapterManifest(t, releaseinventory.SignatureTrustModeKeyID)
	signed := adapterSignedManifest(
		t,
		manifest,
		releaseinventory.SignatureTrustModeKeyID,
		"root-2026",
		ed25519.Sign(privateKey, unsignedPayload(t, manifest)),
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifier.VerifyManifestSignature(ctx, signed); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v, want context.Canceled", err)
	}
	//lint:ignore SA1012 Deliberate nil-context attack proves release signature verification fails closed.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if err := verifier.VerifyManifestSignature(nil, signed); !errors.Is(err, application.ErrDependencyUnavailable) {
		t.Fatalf("nil context error = %v, want ErrDependencyUnavailable", err)
	}
}

func adapterManifest(t *testing.T, mode releaseinventory.SignatureTrustMode) releaseinventory.Manifest {
	t.Helper()
	platform, _ := releaseinventory.NewPlatform("linux", "amd64")
	resources := adapterReleaseResources(t, platform)
	protocol, _ := releaseinventory.NewProtocolRange(1, 1)
	versionRange, _ := releaseinventory.NewVersionRange(releaseinventory.VersionRangeInput{
		Minimum: "1.0.0", Maximum: "1.0.0",
	})
	compatibility, _ := releaseinventory.NewCompatibility(releaseinventory.CompatibilityInput{
		Launcher: versionRange, CoreAPI: versionRange, MCP: versionRange,
		Provider: versionRange, Schema: versionRange, Compose: versionRange,
		SQLite: versionRange, Neo4j: versionRange, RuntimeCatalog: versionRange,
	})
	logID := ""
	if mode == releaseinventory.SignatureTrustModeCertificateTransparency {
		logID = "rekor-production"
	}
	trust, err := releaseinventory.NewTrustPolicy(
		mode,
		"root-2026",
		releaseinventory.DigestBytes([]byte("revocations")),
		logID,
	)
	if err != nil {
		t.Fatalf("NewTrustPolicy() error = %v", err)
	}
	labels := []releaseinventory.TopologyLabelInput{{Key: "com.agentmemory.managed", Value: "true"}}
	topology, err := releaseinventory.NewDockerTopology(releaseinventory.DockerTopologyInput{
		Profiles: []string{"default"},
		Networks: []releaseinventory.DockerNetworkInput{{ID: "internal", Internal: true, Labels: labels}},
		HealthProbes: []releaseinventory.HealthProbeInput{{
			ID: "ready", Kind: releaseinventory.HealthProbeKindHTTP, HTTPPath: "/ready", Port: 8080,
			IntervalSeconds: 10, TimeoutSeconds: 3, Retries: 3,
		}},
		Services: []releaseinventory.DockerServiceInput{{
			ID: "core", ImageResourceIDs: []string{"image"}, Profiles: []string{"default"},
			NetworkIDs: []string{"internal"}, HealthProbeID: "ready", UserID: 1000, GroupID: 1000,
			ReadOnlyRootFilesystem: true, NoNewPrivileges: true, Labels: labels,
		}},
	})
	if err != nil {
		t.Fatalf("NewDockerTopology() error = %v", err)
	}
	history, _ := releaseinventory.NewReleaseHistory(nil, nil)
	manifest, err := releaseinventory.NewManifest(releaseinventory.ManifestInput{
		SchemaVersion:             1,
		ReleaseID:                 "release-1",
		Version:                   "1.0.0",
		BuildID:                   "build-1",
		SourceCommit:              strings.Repeat("a", 40),
		BuildTimestamp:            time.Date(2025, 12, 31, 23, 0, 0, 0, time.UTC),
		Channel:                   releaseinventory.ReleaseChannelStable,
		Sequence:                  1,
		DataGeneration:            1,
		ValidFrom:                 time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		ValidUntil:                time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		Protocol:                  protocol,
		Compatibility:             compatibility,
		TrustPolicy:               trust,
		ReleaseHistory:            history,
		LicensePolicyDigest:       releaseinventory.DigestBytes([]byte("license-policy")),
		VulnerabilityPolicyDigest: releaseinventory.DigestBytes([]byte("vulnerability-policy")),
		DockerTopology:            topology,
		Resources:                 resources,
	})
	if err != nil {
		t.Fatalf("NewManifest() error = %v", err)
	}
	return manifest
}

func adapterReleaseResources(
	t *testing.T,
	platform releaseinventory.Platform,
) []releaseinventory.Resource {
	t.Helper()
	indexDigest := releaseinventory.DigestBytes([]byte("index"))
	imageDigest := releaseinventory.DigestBytes([]byte("image"))
	subjects := []releaseinventory.ResourceInput{
		{
			ID: "image", Kind: releaseinventory.ResourceKindOCIImage,
			Purpose:   releaseinventory.ResourcePurposeOCIPlatformManifest,
			MediaType: releaseinventory.MediaTypeOCIManifest, Platform: platform,
			Digest: imageDigest, OCIIndexDigest: indexDigest, OCIIndexResourceID: "image-index", Size: 5,
			SourceRef: "registry.example/agentmemory/image@sha256:" + imageDigest.Hex(),
		},
		{
			ID: "image-index", Kind: releaseinventory.ResourceKindOCIIndex,
			Purpose: releaseinventory.ResourcePurposeOCIIndex, MediaType: releaseinventory.MediaTypeOCIIndex,
			Digest: indexDigest, Size: 5,
			SourceRef: "registry.example/agentmemory/image-index@sha256:" + indexDigest.Hex(),
		},
	}
	resources := make([]releaseinventory.Resource, 0, len(subjects)*6)
	for _, subject := range subjects {
		subject.SourceAllowlist = []string{subject.SourceRef}
		subject.CycloneDXSBOMResourceID = subject.ID + "-cyclonedx"
		subject.SPDXSBOMResourceID = subject.ID + "-spdx"
		subject.ProvenanceResourceID = subject.ID + "-provenance"
		subject.LicenseResourceID = subject.ID + "-licenses"
		subject.VulnerabilityResourceID = subject.ID + "-vulnerabilities"
		resources = append(resources, mustAdapterResource(t, subject))
		resources = append(resources, adapterEvidenceResources(t, subject)...)
	}
	return resources
}

func adapterEvidenceResources(
	t *testing.T,
	subject releaseinventory.ResourceInput,
) []releaseinventory.Resource {
	t.Helper()
	types := []struct {
		kind      releaseinventory.ResourceKind
		suffix    string
		purpose   releaseinventory.ResourcePurpose
		mediaType string
	}{
		{releaseinventory.ResourceKindCycloneDXSBOM, "cyclonedx", releaseinventory.ResourcePurposeCycloneDXSBOM, releaseinventory.MediaTypeCycloneDX},
		{releaseinventory.ResourceKindSPDXSBOM, "spdx", releaseinventory.ResourcePurposeSPDXSBOM, releaseinventory.MediaTypeSPDX},
		{releaseinventory.ResourceKindProvenance, "provenance", releaseinventory.ResourcePurposeSLSAProvenance, releaseinventory.MediaTypeSLSAProvenance},
		{releaseinventory.ResourceKindLicense, "licenses", releaseinventory.ResourcePurposeLicenseEvaluation, releaseinventory.MediaTypeLicenseEvaluation},
		{releaseinventory.ResourceKindVulnerabilityReport, "vulnerabilities", releaseinventory.ResourcePurposeVulnerabilityReport, releaseinventory.MediaTypeVulnerabilityEvaluation},
	}
	resources := make([]releaseinventory.Resource, 0, len(types))
	for _, evidenceType := range types {
		id := subject.ID + "-" + evidenceType.suffix
		sourceRef := "bundle://" + id
		input := releaseinventory.ResourceInput{
			ID: id, Kind: evidenceType.kind, Purpose: evidenceType.purpose, MediaType: evidenceType.mediaType,
			Digest: releaseinventory.DigestBytes([]byte(id)), Size: uint64(len(id)),
			SourceRef: sourceRef, SourceAllowlist: []string{sourceRef},
			SubjectResourceID: subject.ID, SubjectDigest: subject.Digest,
		}
		if evidenceType.kind == releaseinventory.ResourceKindLicense {
			input.PolicySnapshotDigest = releaseinventory.DigestBytes([]byte("license-policy"))
			input.QualificationResult = releaseinventory.QualificationResultPassed
		}
		if evidenceType.kind == releaseinventory.ResourceKindVulnerabilityReport {
			input.PolicySnapshotDigest = releaseinventory.DigestBytes([]byte("vulnerability-policy"))
			input.QualificationResult = releaseinventory.QualificationResultPassed
			input.QualificationExpiresAt = time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC)
		}
		resources = append(resources, mustAdapterResource(t, input))
	}
	return resources
}

func mustAdapterResource(t *testing.T, input releaseinventory.ResourceInput) releaseinventory.Resource {
	t.Helper()
	resource, err := releaseinventory.NewResource(input)
	if err != nil {
		t.Fatalf("NewResource(%q) error = %v", input.ID, err)
	}
	return resource
}

func unsignedPayload(t *testing.T, manifest releaseinventory.Manifest) []byte {
	t.Helper()
	placeholder := bytes.Repeat([]byte{0}, releaseinventory.ManifestSignatureSize)
	signed := adapterSignedManifest(
		t,
		manifest,
		releaseinventory.SignatureTrustModeKeyID,
		"root-2026",
		placeholder,
	)
	return signed.SignaturePayload()
}

func adapterSignedManifest(
	t *testing.T,
	manifest releaseinventory.Manifest,
	mode releaseinventory.SignatureTrustMode,
	rootID string,
	signature []byte,
) releaseinventory.SignedManifest {
	t.Helper()
	input := releaseinventory.SignatureBundleInput{
		SchemaVersion:       releaseinventory.SupportedSignatureBundleSchemaMajor,
		TrustMode:           mode,
		TrustRootID:         rootID,
		Signature:           signature,
		RevocationSet:       []byte("revocations"),
		TrustedTimeEvidence: []byte("trusted time"),
	}
	if mode == releaseinventory.SignatureTrustModeCertificateTransparency {
		input.Signature = nil
		input.SigstoreBundle = []byte("official Sigstore bundle")
	}
	signed, err := releaseinventory.NewSignedManifest(manifest, input)
	if err != nil {
		t.Fatalf("NewSignedManifest() error = %v", err)
	}
	return signed
}
