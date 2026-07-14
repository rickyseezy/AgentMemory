package releaseverifyadapter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	application "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestCanonicalSBOMVerifierAcceptsExactCycloneDXAndSPDXBindings(t *testing.T) {
	t.Parallel()

	subject := evidenceSubject(t, "core", []byte("subject bytes"), releaseinventory.ResourceKindComposeBundle)
	cycloneRaw := validCycloneDXBytes(t, subject)
	spdxRaw := validSPDXBytes(t, subject)
	cyclone := evidenceResource(t, "core-cyclonedx", releaseinventory.ResourceKindCycloneDXSBOM, subject, cycloneRaw, releaseinventory.Digest{}, time.Time{})
	spdx := evidenceResource(t, "core-spdx", releaseinventory.ResourceKindSPDXSBOM, subject, spdxRaw, releaseinventory.Digest{}, time.Time{})
	verifier, err := NewCanonicalSBOMVerifier(resourceBytesSource{
		cyclone.ID(): cycloneRaw,
		spdx.ID():    spdxRaw,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifySBOMs(context.Background(), subject, cyclone, spdx); err != nil {
		t.Fatalf("VerifySBOMs() error = %v", err)
	}
	//lint:ignore SA1012 Deliberate nil-context attack proves SBOM verification fails closed.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if err := verifier.VerifySBOMs(nil, subject, cyclone, spdx); !errors.Is(err, application.ErrDependencyUnavailable) {
		t.Fatalf("nil context error = %v, want ErrDependencyUnavailable", err)
	}
}

func TestCanonicalSBOMVerifierRejectsTamperSchemaAndBindingFailures(t *testing.T) {
	t.Parallel()

	subject := evidenceSubject(t, "core", []byte("subject bytes"), releaseinventory.ResourceKindComposeBundle)
	validCyclone := validCycloneDXBytes(t, subject)
	validSPDX := validSPDXBytes(t, subject)
	tests := []struct {
		name        string
		cycloneRaw  []byte
		spdxRaw     []byte
		wrongSource bool
	}{
		{name: "cyclonedx subject digest", cycloneRaw: replaceJSONText(validCyclone, subject.Digest().Hex(), releaseinventory.DigestBytes([]byte("wrong")).Hex()), spdxRaw: validSPDX},
		{name: "spdx subject digest", cycloneRaw: validCyclone, spdxRaw: replaceJSONText(validSPDX, subject.Digest().Hex(), releaseinventory.DigestBytes([]byte("wrong")).Hex())},
		{name: "unknown field", cycloneRaw: injectJSONField(validCyclone), spdxRaw: validSPDX},
		{name: "duplicate field", cycloneRaw: duplicateFirstJSONField(validCyclone), spdxRaw: validSPDX},
		{name: "noncanonical", cycloneRaw: append([]byte(" "), validCyclone...), spdxRaw: validSPDX},
		{name: "source unavailable", cycloneRaw: validCyclone, spdxRaw: validSPDX, wrongSource: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			cyclone := evidenceResource(t, "core-cyclonedx", releaseinventory.ResourceKindCycloneDXSBOM, subject, test.cycloneRaw, releaseinventory.Digest{}, time.Time{})
			spdx := evidenceResource(t, "core-spdx", releaseinventory.ResourceKindSPDXSBOM, subject, test.spdxRaw, releaseinventory.Digest{}, time.Time{})
			source := resourceBytesSource{cyclone.ID(): test.cycloneRaw, spdx.ID(): test.spdxRaw}
			if test.wrongSource {
				delete(source, cyclone.ID())
			}
			verifier, _ := NewCanonicalSBOMVerifier(source)
			err := verifier.VerifySBOMs(context.Background(), subject, cyclone, spdx)
			if !errors.Is(err, application.ErrSBOMInvalid) {
				t.Fatalf("VerifySBOMs() error = %v, want ErrSBOMInvalid", err)
			}
		})
	}
	if _, err := NewCanonicalSBOMVerifier(nil); err == nil {
		t.Fatal("NewCanonicalSBOMVerifier() accepted nil source")
	}
}

func TestSLSAProvenanceVerifierBindsReleaseAndBuildPolicy(t *testing.T) {
	t.Parallel()

	manifest := adapterManifest(t, releaseinventory.SignatureTrustModeKeyID)
	subject := findResource(t, manifest.Resources(), "image")
	recipe := releaseinventory.DigestBytes([]byte("reviewed recipe"))
	policy := provenancePolicy(t, recipe)
	raw := validSLSABytes(t, manifest, subject, recipe)
	evidence := evidenceResource(t, "image-provenance", releaseinventory.ResourceKindProvenance, subject, raw, releaseinventory.Digest{}, time.Time{})
	verifier, err := NewSLSAProvenanceVerifier(resourceBytesSource{evidence.ID(): raw}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyProvenance(context.Background(), manifest, subject, evidence); err != nil {
		t.Fatalf("VerifyProvenance() error = %v", err)
	}
	//lint:ignore SA1012 Deliberate nil-context attack proves provenance verification fails closed.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if err := verifier.VerifyProvenance(nil, manifest, subject, evidence); !errors.Is(err, application.ErrDependencyUnavailable) {
		t.Fatalf("nil context error = %v, want ErrDependencyUnavailable", err)
	}

	for _, mutation := range []struct {
		name string
		old  string
		new  string
	}{
		{name: "builder", old: "https://github.com/actions/runner", new: "https://evil.example/builder"},
		{name: "source commit", old: manifest.SourceCommit(), new: strings.Repeat("b", len(manifest.SourceCommit()))},
		{name: "workflow", old: ".github/workflows/release.yml", new: ".github/workflows/unreviewed.yml"},
		{name: "subject", old: subject.Digest().Hex(), new: releaseinventory.DigestBytes([]byte("other")).Hex()},
	} {
		mutation := mutation
		t.Run(mutation.name, func(t *testing.T) {
			t.Parallel()
			tamperedRaw := replaceJSONText(raw, mutation.old, mutation.new)
			tamperedEvidence := evidenceResource(t, "image-provenance", releaseinventory.ResourceKindProvenance, subject, tamperedRaw, releaseinventory.Digest{}, time.Time{})
			tampered, _ := NewSLSAProvenanceVerifier(resourceBytesSource{tamperedEvidence.ID(): tamperedRaw}, policy)
			if err := tampered.VerifyProvenance(context.Background(), manifest, subject, tamperedEvidence); !errors.Is(err, application.ErrProvenanceInvalid) {
				t.Fatalf("VerifyProvenance() error = %v, want ErrProvenanceInvalid", err)
			}
		})
	}
}

func TestProvenancePolicyAndVerifierRejectIncompleteComposition(t *testing.T) {
	t.Parallel()

	recipe := releaseinventory.DigestBytes([]byte("recipe"))
	identity := ProvenanceBuildIdentity{
		BuilderID: "builder", BuildType: "build", SourceRepository: "repo", WorkflowPath: "workflow",
	}
	valid := ProvenanceTrustPolicyInput{
		BuildIdentities: []ProvenanceBuildIdentity{identity}, RecipeDigests: []releaseinventory.Digest{recipe},
	}
	tests := []struct {
		name   string
		mutate func(*ProvenanceTrustPolicyInput)
	}{
		{name: "builders", mutate: func(input *ProvenanceTrustPolicyInput) { input.BuildIdentities = nil }},
		{name: "duplicate", mutate: func(input *ProvenanceTrustPolicyInput) {
			input.BuildIdentities = []ProvenanceBuildIdentity{identity, identity}
		}},
		{name: "repository", mutate: func(input *ProvenanceTrustPolicyInput) {
			invalid := identity
			invalid.SourceRepository = "bad value"
			input.BuildIdentities = []ProvenanceBuildIdentity{invalid}
		}},
		{name: "workflow", mutate: func(input *ProvenanceTrustPolicyInput) {
			invalid := identity
			invalid.WorkflowPath = ""
			input.BuildIdentities = []ProvenanceBuildIdentity{invalid}
		}},
		{name: "recipes", mutate: func(input *ProvenanceTrustPolicyInput) { input.RecipeDigests = nil }},
		{name: "zero recipe", mutate: func(input *ProvenanceTrustPolicyInput) { input.RecipeDigests = []releaseinventory.Digest{{}} }},
	}
	for _, test := range tests {
		input := valid
		test.mutate(&input)
		if _, err := NewProvenanceTrustPolicy(input); err == nil {
			t.Fatalf("NewProvenanceTrustPolicy(%s) accepted invalid input", test.name)
		}
	}
	policy := provenancePolicy(t, recipe)
	if _, err := NewSLSAProvenanceVerifier(nil, policy); err == nil {
		t.Fatal("NewSLSAProvenanceVerifier() accepted nil source")
	}
}

func TestCanonicalOCIIndexVerifierBindsExactDescriptor(t *testing.T) {
	t.Parallel()

	platform, _ := releaseinventory.NewPlatform("linux", "amd64")
	subjectContent := []byte("platform manifest")
	subjectDigest := releaseinventory.DigestBytes(subjectContent)
	indexDocument := ociIndexDocument{
		Manifests: []ociDescriptor{{
			Digest: "sha256:" + subjectDigest.Hex(), MediaType: releaseinventory.MediaTypeOCIManifest,
			Platform: ociPlatform{Architecture: platform.Architecture(), OS: platform.OS()},
			Size:     uint64(len(subjectContent)),
		}},
		MediaType: releaseinventory.MediaTypeOCIIndex, SchemaVersion: 2,
	}
	indexRaw := mustJSON(t, indexDocument)
	index := ociIndexResource(t, "core-index", indexRaw)
	subject := ociSubject(t, "core-image", subjectContent, platform, index)
	verifier, err := NewCanonicalOCIIndexVerifier(resourceBytesSource{index.ID(): indexRaw})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyOCIIndex(context.Background(), subject, index); err != nil {
		t.Fatalf("VerifyOCIIndex() error = %v", err)
	}
	//lint:ignore SA1012 Deliberate nil-context attack proves OCI index verification fails closed.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if err := verifier.VerifyOCIIndex(nil, subject, index); !errors.Is(err, application.ErrDependencyUnavailable) {
		t.Fatalf("nil context error = %v, want ErrDependencyUnavailable", err)
	}

	wrongDocument := indexDocument
	wrongDocument.Manifests = append(wrongDocument.Manifests, wrongDocument.Manifests[0])
	wrongRaw := mustJSON(t, wrongDocument)
	wrongIndex := ociIndexResource(t, "core-index", wrongRaw)
	wrongSubject := ociSubject(t, "core-image", subjectContent, platform, wrongIndex)
	wrongVerifier, _ := NewCanonicalOCIIndexVerifier(resourceBytesSource{wrongIndex.ID(): wrongRaw})
	if err := wrongVerifier.VerifyOCIIndex(context.Background(), wrongSubject, wrongIndex); !errors.Is(err, application.ErrOCIIndexInvalid) {
		t.Fatalf("duplicate descriptor error = %v, want ErrOCIIndexInvalid", err)
	}
	if _, err := NewCanonicalOCIIndexVerifier(nil); err == nil {
		t.Fatal("NewCanonicalOCIIndexVerifier() accepted nil source")
	}
}

func TestSignedQualificationVerifierRequiresAuthorityAndCurrentPolicy(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x72}, ed25519.SeedSize))
	licensePolicy := releaseinventory.DigestBytes([]byte("license policy"))
	vulnerabilityPolicy := releaseinventory.DigestBytes([]byte("vulnerability policy"))
	policy := qualificationPolicy(t, privateKey.Public().(ed25519.PublicKey), licensePolicy, vulnerabilityPolicy)
	subject := evidenceSubject(t, "core", []byte("subject bytes"), releaseinventory.ResourceKindComposeBundle)

	licenseRaw := signedQualificationBytes(t, privateKey, qualificationPayload{
		EvidenceResourceID: "core-license", EvaluatedAt: now.Add(-time.Hour).UnixMicro(), ExpiresAt: 0,
		PolicySnapshotDigest: licensePolicy.Hex(), QualificationResult: "passed", SchemaVersion: 1,
		SubjectDigest: subject.Digest().Hex(), SubjectResourceID: subject.ID(),
	})
	license := evidenceResource(t, "core-license", releaseinventory.ResourceKindLicense, subject, licenseRaw, licensePolicy, time.Time{})
	expiresAt := now.Add(24 * time.Hour)
	vulnerabilityRaw := signedQualificationBytes(t, privateKey, qualificationPayload{
		EvidenceResourceID: "core-vulnerabilities", EvaluatedAt: now.Add(-time.Hour).UnixMicro(), ExpiresAt: expiresAt.UnixMicro(),
		PolicySnapshotDigest: vulnerabilityPolicy.Hex(), QualificationResult: "passed", SchemaVersion: 1,
		SubjectDigest: subject.Digest().Hex(), SubjectResourceID: subject.ID(),
	})
	vulnerability := evidenceResource(t, "core-vulnerabilities", releaseinventory.ResourceKindVulnerabilityReport, subject, vulnerabilityRaw, vulnerabilityPolicy, expiresAt)
	source := resourceBytesSource{license.ID(): licenseRaw, vulnerability.ID(): vulnerabilityRaw}
	verifier, err := NewSignedQualificationVerifier(source, fixedClock{now: now}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyLicense(context.Background(), subject, license); err != nil {
		t.Fatalf("VerifyLicense() error = %v", err)
	}
	if err := verifier.VerifyVulnerabilities(context.Background(), subject, vulnerability); err != nil {
		t.Fatalf("VerifyVulnerabilities() error = %v", err)
	}
	//lint:ignore SA1012 Deliberate nil-context attack proves qualification verification fails closed.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if err := verifier.VerifyLicense(nil, subject, license); !errors.Is(err, application.ErrDependencyUnavailable) {
		t.Fatalf("nil context error = %v, want ErrDependencyUnavailable", err)
	}

	tamperedRaw := append([]byte(nil), vulnerabilityRaw...)
	tamperedRaw[len(tamperedRaw)-3] ^= 1
	tampered := evidenceResource(t, "core-vulnerabilities", releaseinventory.ResourceKindVulnerabilityReport, subject, tamperedRaw, vulnerabilityPolicy, expiresAt)
	tamperedVerifier, _ := NewSignedQualificationVerifier(resourceBytesSource{tampered.ID(): tamperedRaw}, fixedClock{now: now}, policy)
	if err := tamperedVerifier.VerifyVulnerabilities(context.Background(), subject, tampered); !errors.Is(err, application.ErrVulnerabilityDenied) {
		t.Fatalf("tampered signature error = %v, want ErrVulnerabilityDenied", err)
	}
	expiredVerifier, _ := NewSignedQualificationVerifier(source, fixedClock{now: expiresAt}, policy)
	if err := expiredVerifier.VerifyVulnerabilities(context.Background(), subject, vulnerability); !errors.Is(err, application.ErrVulnerabilityDenied) {
		t.Fatalf("expired evaluation error = %v, want ErrVulnerabilityDenied", err)
	}
}

func TestQualificationTrustPolicyRejectsInvalidComposition(t *testing.T) {
	t.Parallel()

	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x12}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	digest := releaseinventory.DigestBytes([]byte("policy"))
	valid := QualificationTrustPolicyInput{
		PublicKeys:                 map[string]ed25519.PublicKey{"qualifier": key},
		LicensePolicySigners:       map[releaseinventory.Digest]string{digest: "qualifier"},
		VulnerabilityPolicySigners: map[releaseinventory.Digest]string{digest: "qualifier"},
	}
	for _, input := range []QualificationTrustPolicyInput{
		{},
		{PublicKeys: map[string]ed25519.PublicKey{"qualifier": []byte("short")}, LicensePolicySigners: valid.LicensePolicySigners, VulnerabilityPolicySigners: valid.VulnerabilityPolicySigners},
		{PublicKeys: valid.PublicKeys, LicensePolicySigners: nil, VulnerabilityPolicySigners: valid.VulnerabilityPolicySigners},
		{PublicKeys: valid.PublicKeys, LicensePolicySigners: map[releaseinventory.Digest]string{digest: "missing"}, VulnerabilityPolicySigners: valid.VulnerabilityPolicySigners},
	} {
		if _, err := NewQualificationTrustPolicy(input); err == nil {
			t.Fatal("NewQualificationTrustPolicy() accepted invalid input")
		}
	}
	policy, _ := NewQualificationTrustPolicy(valid)
	if _, err := NewSignedQualificationVerifier(nil, fixedClock{now: time.Now()}, policy); err == nil {
		t.Fatal("NewSignedQualificationVerifier() accepted nil source")
	}
}

type resourceBytesSource map[string][]byte

func (s resourceBytesSource) OpenResource(
	_ context.Context,
	resource releaseinventory.Resource,
) (io.ReadCloser, error) {
	raw, ok := s[resource.ID()]
	if !ok {
		return nil, errors.New("resource unavailable")
	}
	return io.NopCloser(bytes.NewReader(raw)), nil
}

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func evidenceSubject(
	t *testing.T,
	id string,
	content []byte,
	kind releaseinventory.ResourceKind,
) releaseinventory.Resource {
	t.Helper()
	purpose := releaseinventory.ResourcePurposeComposeLock
	mediaType := releaseinventory.MediaTypeComposeLock
	if kind == releaseinventory.ResourceKindSchema {
		purpose = releaseinventory.ResourcePurposeContractBundle
		mediaType = releaseinventory.MediaTypeContractBundle
	}
	input := releaseinventory.ResourceInput{
		ID: id, Kind: kind, Purpose: purpose, MediaType: mediaType,
		Digest: releaseinventory.DigestBytes(content), Size: uint64(len(content)),
		SourceRef: "bundle://" + id, SourceAllowlist: []string{"bundle://" + id},
		CycloneDXSBOMResourceID: id + "-cyclonedx", SPDXSBOMResourceID: id + "-spdx",
		ProvenanceResourceID: id + "-provenance", LicenseResourceID: id + "-license",
		VulnerabilityResourceID: id + "-vulnerabilities",
	}
	if kind == releaseinventory.ResourceKindComposeBundle {
		input.ExpandedTarget = releaseinventory.ReleaseExpandedTargetInput{
			Kind: releaseinventory.ExpandedTargetComposeBundle, StorageID: "compose/compose.yaml",
			Digest: input.Digest, Bytes: input.Size,
		}
	}
	resource, err := releaseinventory.NewResource(input)
	if err != nil {
		t.Fatalf("NewResource(subject) error = %v", err)
	}
	return resource
}

func evidenceResource(
	t *testing.T,
	id string,
	kind releaseinventory.ResourceKind,
	subject releaseinventory.Resource,
	raw []byte,
	policyDigest releaseinventory.Digest,
	expiresAt time.Time,
) releaseinventory.Resource {
	t.Helper()
	purpose, mediaType := evidenceKindMetadata(kind)
	input := releaseinventory.ResourceInput{
		ID: id, Kind: kind, Purpose: purpose, MediaType: mediaType,
		Digest: releaseinventory.DigestBytes(raw), Size: uint64(len(raw)),
		SourceRef: "bundle://" + id, SourceAllowlist: []string{"bundle://" + id},
		SubjectResourceID: subject.ID(), SubjectDigest: subject.Digest(),
	}
	if kind == releaseinventory.ResourceKindLicense || kind == releaseinventory.ResourceKindVulnerabilityReport {
		input.PolicySnapshotDigest = policyDigest
		input.QualificationResult = releaseinventory.QualificationResultPassed
		input.QualificationExpiresAt = expiresAt
	}
	resource, err := releaseinventory.NewResource(input)
	if err != nil {
		t.Fatalf("NewResource(evidence %s) error = %v", id, err)
	}
	return resource
}

func evidenceKindMetadata(kind releaseinventory.ResourceKind) (releaseinventory.ResourcePurpose, string) {
	//nolint:exhaustive // This test helper intentionally accepts only evidence-resource kinds.
	switch kind {
	case releaseinventory.ResourceKindCycloneDXSBOM:
		return releaseinventory.ResourcePurposeCycloneDXSBOM, releaseinventory.MediaTypeCycloneDX
	case releaseinventory.ResourceKindSPDXSBOM:
		return releaseinventory.ResourcePurposeSPDXSBOM, releaseinventory.MediaTypeSPDX
	case releaseinventory.ResourceKindProvenance:
		return releaseinventory.ResourcePurposeSLSAProvenance, releaseinventory.MediaTypeSLSAProvenance
	case releaseinventory.ResourceKindLicense:
		return releaseinventory.ResourcePurposeLicenseEvaluation, releaseinventory.MediaTypeLicenseEvaluation
	case releaseinventory.ResourceKindVulnerabilityReport:
		return releaseinventory.ResourcePurposeVulnerabilityReport, releaseinventory.MediaTypeVulnerabilityEvaluation
	default:
		return "", ""
	}
}

func validCycloneDXBytes(t *testing.T, subject releaseinventory.Resource) []byte {
	t.Helper()
	return mustJSON(t, cycloneDXDocument{
		BOMFormat: "CycloneDX", Components: []cycloneDXComponent{},
		Metadata: cycloneDXMetadata{
			Component: cycloneDXComponent{
				BOMRef: subject.ID(), Hashes: []cycloneDXHash{{Algorithm: "SHA-256", Content: subject.Digest().Hex()}},
				Name: subject.ID(), PURL: "pkg:generic/agentmemory/" + subject.ID() + "@1.0.0",
				Type: "application", Version: "1.0.0",
			},
			Timestamp: "2026-07-13T12:00:00Z",
		},
		SerialNumber: "urn:uuid:123e4567-e89b-12d3-a456-426614174000", SpecVersion: "1.6", Version: 1,
	})
}

func validSPDXBytes(t *testing.T, subject releaseinventory.Resource) []byte {
	t.Helper()
	id := "SPDXRef-" + subject.ID()
	return mustJSON(t, spdxDocument{
		CreationInfo: spdxCreationInfo{Created: "2026-07-13T12:00:00Z", Creators: []string{"Tool: agentmemory-release/1.0.0"}},
		DataLicense:  "CC0-1.0", DocumentDescribes: []string{id},
		DocumentNamespace: "https://agentmemory.local/spdx/123e4567-e89b-12d3-a456-426614174000",
		Name:              subject.ID() + "-sbom",
		Packages: []spdxPackage{{
			Checksums:     []spdxChecksum{{Algorithm: "SHA256", ChecksumValue: subject.Digest().Hex()}},
			CopyrightText: "NOASSERTION", DownloadLocation: "NOASSERTION", FilesAnalyzed: false,
			LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", Name: subject.ID(),
			SPDXID: id, VersionInfo: "1.0.0",
		}},
		SPDXID: "SPDXRef-DOCUMENT", SPDXVersion: "SPDX-2.3",
	})
}

func provenancePolicy(t *testing.T, recipe releaseinventory.Digest) ProvenanceTrustPolicy {
	t.Helper()
	policy, err := NewProvenanceTrustPolicy(ProvenanceTrustPolicyInput{
		BuildIdentities: []ProvenanceBuildIdentity{{
			BuilderID:        "https://github.com/actions/runner",
			BuildType:        "https://agentmemory.local/build/release/v1",
			SourceRepository: "https://github.com/rickyseezy/AgentMemory",
			WorkflowPath:     ".github/workflows/release.yml",
		}},
		RecipeDigests: []releaseinventory.Digest{recipe},
	})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func validSLSABytes(
	t *testing.T,
	manifest releaseinventory.Manifest,
	subject releaseinventory.Resource,
	recipe releaseinventory.Digest,
) []byte {
	t.Helper()
	return mustJSON(t, slsaStatement{
		Type: inTotoStatementV1,
		Predicate: slsaPredicate{
			BuildDefinition: slsaBuildDefinition{
				BuildType: "https://agentmemory.local/build/release/v1",
				ExternalParameters: slsaExternalParameters{
					RecipeDigest: recipe.Hex(),
					Source:       slsaSource{Digest: map[string]string{"sha1": manifest.SourceCommit()}, Repository: "https://github.com/rickyseezy/AgentMemory"},
					Workflow:     slsaWorkflow{Path: ".github/workflows/release.yml", Ref: manifest.SourceCommit()},
				},
				InternalParameters: slsaInternalParameters{Hermetic: true, Reproducible: true},
				ResolvedDependencies: []slsaDependency{{
					Digest: map[string]string{"sha256": releaseinventory.DigestBytes([]byte("dependency")).Hex()},
					URI:    "registry.example/build/tool@sha256:" + releaseinventory.DigestBytes([]byte("dependency")).Hex(),
				}},
			},
			RunDetails: slsaRunDetails{
				Builder: slsaBuilder{ID: "https://github.com/actions/runner"},
				Metadata: slsaMetadata{
					FinishedOn: manifest.BuildTimestamp().Format(time.RFC3339Nano), InvocationID: manifest.BuildID(),
					StartedOn: manifest.BuildTimestamp().Add(-time.Hour).Format(time.RFC3339Nano),
				},
			},
		},
		PredicateType: slsaProvenanceV1,
		Subject:       []slsaSubject{{Digest: map[string]string{"sha256": subject.Digest().Hex()}, Name: subject.ID()}},
	})
}

func ociIndexResource(t *testing.T, id string, raw []byte) releaseinventory.Resource {
	t.Helper()
	digest := releaseinventory.DigestBytes(raw)
	resource, err := releaseinventory.NewResource(releaseinventory.ResourceInput{
		ID: id, Kind: releaseinventory.ResourceKindOCIIndex, Purpose: releaseinventory.ResourcePurposeOCIIndex,
		MediaType: releaseinventory.MediaTypeOCIIndex, Digest: digest, Size: uint64(len(raw)),
		SourceRef:               "registry.example/agentmemory/" + id + "@sha256:" + digest.Hex(),
		SourceAllowlist:         []string{"registry.example/agentmemory/" + id + "@sha256:" + digest.Hex()},
		CycloneDXSBOMResourceID: id + "-cyclonedx", SPDXSBOMResourceID: id + "-spdx",
		ProvenanceResourceID: id + "-provenance", LicenseResourceID: id + "-license",
		VulnerabilityResourceID: id + "-vulnerabilities",
	})
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func ociSubject(
	t *testing.T,
	id string,
	content []byte,
	platform releaseinventory.Platform,
	index releaseinventory.Resource,
) releaseinventory.Resource {
	t.Helper()
	digest := releaseinventory.DigestBytes(content)
	resource, err := releaseinventory.NewResource(releaseinventory.ResourceInput{
		ID: id, Kind: releaseinventory.ResourceKindOCIImage, Purpose: releaseinventory.ResourcePurposeOCIPlatformManifest,
		MediaType: releaseinventory.MediaTypeOCIManifest, Platform: platform, Digest: digest,
		OCIIndexDigest: index.Digest(), OCIIndexResourceID: index.ID(), Size: uint64(len(content)),
		SourceRef:               "registry.example/agentmemory/" + id + "@sha256:" + digest.Hex(),
		SourceAllowlist:         []string{"registry.example/agentmemory/" + id + "@sha256:" + digest.Hex()},
		CycloneDXSBOMResourceID: id + "-cyclonedx", SPDXSBOMResourceID: id + "-spdx",
		ProvenanceResourceID: id + "-provenance", LicenseResourceID: id + "-license",
		VulnerabilityResourceID: id + "-vulnerabilities",
	})
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func qualificationPolicy(
	t *testing.T,
	publicKey ed25519.PublicKey,
	licensePolicy releaseinventory.Digest,
	vulnerabilityPolicy releaseinventory.Digest,
) QualificationTrustPolicy {
	t.Helper()
	policy, err := NewQualificationTrustPolicy(QualificationTrustPolicyInput{
		PublicKeys:                 map[string]ed25519.PublicKey{"qualifier": publicKey},
		LicensePolicySigners:       map[releaseinventory.Digest]string{licensePolicy: "qualifier"},
		VulnerabilityPolicySigners: map[releaseinventory.Digest]string{vulnerabilityPolicy: "qualifier"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func signedQualificationBytes(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	payload qualificationPayload,
) []byte {
	t.Helper()
	payloadRaw := mustJSON(t, payload)
	signature := ed25519.Sign(privateKey, payloadRaw)
	return mustJSON(t, qualificationEnvelope{
		Payload:   payload,
		Signature: qualificationSignature{Algorithm: "ed25519", KeyID: "qualifier", Value: base64.StdEncoding.EncodeToString(signature)},
	})
}

func findResource(t *testing.T, resources []releaseinventory.Resource, id string) releaseinventory.Resource {
	t.Helper()
	for _, resource := range resources {
		if resource.ID() == id {
			return resource
		}
	}
	t.Fatalf("resource %q not found", id)
	return releaseinventory.Resource{}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func replaceJSONText(raw []byte, old string, replacement string) []byte {
	return bytes.ReplaceAll(raw, []byte(old), []byte(replacement))
}

func injectJSONField(raw []byte) []byte {
	return bytes.Replace(raw, []byte("{"), []byte(`{"unknown":"field",`), 1)
}

func duplicateFirstJSONField(raw []byte) []byte {
	return bytes.Replace(raw, []byte("{"), []byte(`{"bomFormat":"CycloneDX",`), 1)
}
