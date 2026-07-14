package releaseinventory

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestReleaseManifestCanonicalEncodingIsDeterministicAndImmutable(t *testing.T) {
	t.Parallel()

	resources := completeResources(t, mustPlatform(t, "linux", "amd64"))
	manifestA := mustManifest(t, resources)
	reversed := append([]Resource(nil), resources...)
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	manifestB := mustManifest(t, reversed)

	if !bytes.Equal(manifestA.CanonicalBytes(), manifestB.CanonicalBytes()) {
		t.Fatal("canonical encoding depends on input resource order")
	}
	if !manifestA.Digest().Equal(manifestB.Digest()) {
		t.Fatal("manifest digest depends on input resource order")
	}

	resources[0] = Resource{}
	returned := manifestA.Resources()
	returned[0] = Resource{}
	if len(manifestA.Resources()) == 0 || manifestA.Resources()[0].ID() == "" {
		t.Fatal("manifest retained caller-owned resource storage")
	}
	canonical := manifestA.CanonicalBytes()
	canonical[0] ^= 0xff
	if bytes.Equal(canonical, manifestA.CanonicalBytes()) {
		t.Fatal("CanonicalBytes exposed mutable storage")
	}
}

func TestReleaseManifestRejectsMalformedOrAmbiguousInventory(t *testing.T) {
	t.Parallel()

	platform := mustPlatform(t, "linux", "amd64")
	valid := completeResources(t, platform)
	tests := []struct {
		name      string
		resources func() []Resource
		mutate    func(*ManifestInput)
	}{
		{
			name:      "unsupported schema major",
			resources: func() []Resource { return valid },
			mutate:    func(input *ManifestInput) { input.SchemaVersion = SupportedManifestSchemaMajor + 1 },
		},
		{
			name:      "non-stable semantic version",
			resources: func() []Resource { return valid },
			mutate:    func(input *ManifestInput) { input.Version = "1.0.0-rc.1" },
		},
		{
			name:      "empty resource inventory",
			resources: func() []Resource { return valid },
			mutate:    func(input *ManifestInput) { input.Resources = nil },
		},
		{
			name: "zero-value resource",
			resources: func() []Resource {
				candidate := append([]Resource(nil), valid...)
				candidate[0] = Resource{}
				return candidate
			},
		},
		{
			name: "duplicate resource",
			resources: func() []Resource {
				return append(append([]Resource(nil), valid...), valid[0])
			},
		},
		{
			name: "missing sbom target",
			resources: func() []Resource {
				candidate := append([]Resource(nil), valid...)
				candidate[resourceIndex(t, candidate, "launcher")] = mustResource(t, ResourceInput{
					ID: "launcher", Kind: ResourceKindLauncher, Platform: platform,
					Purpose: ResourcePurposeNativeLauncher, MediaType: MediaTypeNativeExecutable,
					Digest: digestText("launcher"), Size: 8, SourceRef: "bundle://launcher",
					SourceAllowlist:         []string{"bundle://launcher"},
					NativePublisherIdentity: "agentmemory.publisher", NativePublisherPolicyID: "agentmemory-native-2026",
					CycloneDXSBOMResourceID: "missing", SPDXSBOMResourceID: "launcher-spdx",
					ProvenanceResourceID: "launcher-provenance", LicenseResourceID: "launcher-licenses",
					VulnerabilityResourceID: "launcher-vulnerabilities",
				})
				return candidate
			},
		},
		{
			name: "association has wrong kind",
			resources: func() []Resource {
				candidate := append([]Resource(nil), valid...)
				candidate[resourceIndex(t, candidate, "launcher")] = mustResource(t, ResourceInput{
					ID: "launcher", Kind: ResourceKindLauncher, Platform: platform,
					Purpose: ResourcePurposeNativeLauncher, MediaType: MediaTypeNativeExecutable,
					Digest: digestText("launcher"), Size: 8, SourceRef: "bundle://launcher",
					SourceAllowlist:         []string{"bundle://launcher"},
					NativePublisherIdentity: "agentmemory.publisher", NativePublisherPolicyID: "agentmemory-native-2026",
					CycloneDXSBOMResourceID: "launcher-provenance", SPDXSBOMResourceID: "launcher-spdx",
					ProvenanceResourceID: "launcher-provenance", LicenseResourceID: "launcher-licenses",
					VulnerabilityResourceID: "launcher-vulnerabilities",
				})
				return candidate
			},
		},
		{
			name:      "invalid sequence",
			resources: func() []Resource { return valid },
			mutate:    func(input *ManifestInput) { input.Sequence = 0 },
		},
		{
			name:      "invalid data generation",
			resources: func() []Resource { return valid },
			mutate:    func(input *ManifestInput) { input.DataGeneration = 0 },
		},
		{
			name:      "unknown channel",
			resources: func() []Resource { return valid },
			mutate:    func(input *ManifestInput) { input.Channel = "production-ish" },
		},
		{
			name:      "noncanonical source commit",
			resources: func() []Resource { return valid },
			mutate:    func(input *ManifestInput) { input.SourceCommit = strings.Repeat("A", 40) },
		},
		{
			name:      "short source commit",
			resources: func() []Resource { return valid },
			mutate:    func(input *ManifestInput) { input.SourceCommit = "abc123" },
		},
		{
			name:      "build after publication",
			resources: func() []Resource { return valid },
			mutate:    func(input *ManifestInput) { input.BuildTimestamp = input.ValidFrom.Add(time.Second) },
		},
		{
			name:      "invalid validity window",
			resources: func() []Resource { return valid },
			mutate:    func(input *ManifestInput) { input.ValidUntil = input.ValidFrom },
		},
		{
			name:      "invalid protocol range",
			resources: func() []Resource { return valid },
			mutate:    func(input *ManifestInput) { input.Protocol = ProtocolRange{} },
		},
		{
			name:      "missing compatibility matrix",
			resources: func() []Resource { return valid },
			mutate:    func(input *ManifestInput) { input.Compatibility = Compatibility{} },
		},
		{
			name:      "missing license policy",
			resources: func() []Resource { return valid },
			mutate:    func(input *ManifestInput) { input.LicensePolicyDigest = Digest{} },
		},
		{
			name:      "missing validity start",
			resources: func() []Resource { return valid },
			mutate:    func(input *ManifestInput) { input.ValidFrom = time.Time{} },
		},
		{
			name:      "missing build timestamp",
			resources: func() []Resource { return valid },
			mutate:    func(input *ManifestInput) { input.BuildTimestamp = time.Time{} },
		},
		{
			name:      "license policy mismatch",
			resources: func() []Resource { return valid },
			mutate: func(input *ManifestInput) {
				input.LicensePolicyDigest = digestText("other-license-policy")
			},
		},
		{
			name:      "vulnerability policy mismatch",
			resources: func() []Resource { return valid },
			mutate: func(input *ManifestInput) {
				input.VulnerabilityPolicyDigest = digestText("other-vulnerability-policy")
			},
		},
		{
			name:      "self rollback source",
			resources: func() []Resource { return valid },
			mutate: func(input *ManifestInput) {
				history, _ := NewReleaseHistory([]PriorReleaseInput{{
					ReleaseID: input.ReleaseID, ManifestDigest: digestText("previous"),
					MinimumDataGeneration: 1, MaximumDataGeneration: 1,
				}}, nil)
				input.ReleaseHistory = history
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := validManifestInput(test.resources())
			if test.mutate != nil {
				test.mutate(&input)
			}
			if _, err := NewManifest(input); err == nil {
				t.Fatal("NewManifest() accepted invalid inventory")
			}
		})
	}
}

func TestReleaseResourceRejectsMutableOrMalformedReferences(t *testing.T) {
	t.Parallel()

	platform := mustPlatform(t, "linux", "amd64")
	digest := digestText("image")
	tests := []struct {
		name  string
		input ResourceInput
	}{
		{name: "missing ID", input: ResourceInput{Kind: ResourceKindCycloneDXSBOM, Digest: digest, Size: 1, SourceRef: "bundle://sbom"}},
		{name: "zero digest", input: ResourceInput{ID: "sbom", Kind: ResourceKindCycloneDXSBOM, Size: 1, SourceRef: "bundle://sbom"}},
		{name: "zero size", input: ResourceInput{ID: "sbom", Kind: ResourceKindCycloneDXSBOM, Digest: digest, SourceRef: "bundle://sbom"}},
		{name: "source with whitespace", input: ResourceInput{ID: "sbom", Kind: ResourceKindCycloneDXSBOM, Digest: digest, Size: 1, SourceRef: "bundle://bad ref"}},
		{
			name: "mutable image tag",
			input: ResourceInput{ID: "image", Kind: ResourceKindOCIImage, Platform: platform, Digest: digest, Size: 1,
				OCIIndexDigest: digestText("index"), SourceRef: "registry.example/agentmemory:latest", CycloneDXSBOMResourceID: "cyclonedx", SPDXSBOMResourceID: "spdx",
				ProvenanceResourceID: "provenance", LicenseResourceID: "licenses", VulnerabilityResourceID: "vulnerabilities"},
		},
		{
			name: "image reference digest mismatch",
			input: ResourceInput{ID: "image", Kind: ResourceKindOCIImage, Platform: platform, Digest: digest, Size: 1,
				OCIIndexDigest: digestText("index"), SourceRef: "registry.example/agentmemory@sha256:" + digestText("other").Hex(), CycloneDXSBOMResourceID: "cyclonedx", SPDXSBOMResourceID: "spdx",
				ProvenanceResourceID: "provenance", LicenseResourceID: "licenses", VulnerabilityResourceID: "vulnerabilities"},
		},
		{
			name: "image missing exact platform",
			input: ResourceInput{ID: "image", Kind: ResourceKindOCIImage, Digest: digest, Size: 1,
				OCIIndexDigest: digestText("index"), SourceRef: "registry.example/agentmemory@sha256:" + digest.Hex(), CycloneDXSBOMResourceID: "cyclonedx", SPDXSBOMResourceID: "spdx",
				ProvenanceResourceID: "provenance", LicenseResourceID: "licenses", VulnerabilityResourceID: "vulnerabilities"},
		},
		{
			name: "non-image with index digest",
			input: ResourceInput{ID: "compose", Kind: ResourceKindComposeBundle, Platform: platform, Digest: digest, Size: 1,
				OCIIndexDigest: digestText("index"), SourceRef: "bundle://compose", CycloneDXSBOMResourceID: "cyclonedx", SPDXSBOMResourceID: "spdx",
				ProvenanceResourceID: "provenance", LicenseResourceID: "licenses", VulnerabilityResourceID: "vulnerabilities"},
		},
		{
			name: "launcher missing native publisher policy",
			input: ResourceInput{ID: "launcher", Kind: ResourceKindLauncher, Platform: platform, Digest: digest, Size: 1,
				SourceRef: "bundle://launcher", CycloneDXSBOMResourceID: "cyclonedx", SPDXSBOMResourceID: "spdx",
				ProvenanceResourceID: "provenance", LicenseResourceID: "licenses", VulnerabilityResourceID: "vulnerabilities"},
		},
		{
			name: "launcher missing exact platform",
			input: ResourceInput{ID: "launcher", Kind: ResourceKindLauncher, Digest: digest, Size: 1,
				SourceRef: "bundle://launcher", NativePublisherPolicyID: "agentmemory-native-2026", CycloneDXSBOMResourceID: "cyclonedx", SPDXSBOMResourceID: "spdx",
				ProvenanceResourceID: "provenance", LicenseResourceID: "licenses", VulnerabilityResourceID: "vulnerabilities"},
		},
		{
			name: "non-native with native publisher policy",
			input: ResourceInput{ID: "compose", Kind: ResourceKindComposeBundle, Platform: platform, Digest: digest, Size: 1,
				SourceRef: "bundle://compose", NativePublisherPolicyID: "agentmemory-native-2026", CycloneDXSBOMResourceID: "cyclonedx", SPDXSBOMResourceID: "spdx",
				ProvenanceResourceID: "provenance", LicenseResourceID: "licenses", VulnerabilityResourceID: "vulnerabilities"},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewResource(test.input); err == nil {
				t.Fatal("NewResource() accepted invalid resource")
			}
		})
	}
}

func TestReleaseResourceSourceAllowlistIsExactClosedAndCredentialFree(t *testing.T) {
	t.Parallel()

	source := "https://releases.agentmemory.dev/evidence/launcher.cdx.json"
	base := ResourceInput{
		ID: "launcher-cyclonedx", Kind: ResourceKindCycloneDXSBOM,
		Purpose: ResourcePurposeCycloneDXSBOM, MediaType: MediaTypeCycloneDX,
		Digest: digestText("launcher-cyclonedx"), Size: 10,
		SourceRef: source, SourceAllowlist: []string{source},
		SubjectResourceID: "launcher", SubjectDigest: digestText("launcher"),
	}
	resource, err := NewResource(base)
	if err != nil || resource.SourceRef() != source {
		t.Fatalf("NewResource(HTTPS allowlist) = %v/%v", resource, err)
	}
	tests := []struct {
		name   string
		mutate func(*ResourceInput)
	}{
		{name: "plaintext HTTP", mutate: func(input *ResourceInput) {
			input.SourceRef = "http://releases.agentmemory.dev/evidence/launcher.cdx.json"
			input.SourceAllowlist = []string{input.SourceRef}
		}},
		{name: "embedded credentials", mutate: func(input *ResourceInput) {
			input.SourceRef = "https://user@releases.agentmemory.dev/evidence/launcher.cdx.json"
			input.SourceAllowlist = []string{input.SourceRef}
		}},
		{name: "query mutation", mutate: func(input *ResourceInput) {
			input.SourceRef = source + "?latest=true"
			input.SourceAllowlist = []string{input.SourceRef}
		}},
		{name: "path traversal", mutate: func(input *ResourceInput) {
			input.SourceRef = "https://releases.agentmemory.dev/evidence/../private"
			input.SourceAllowlist = []string{input.SourceRef}
		}},
		{name: "unlisted selected source", mutate: func(input *ResourceInput) {
			input.SourceRef = "bundle://launcher-cyclonedx"
		}},
		{name: "duplicate source", mutate: func(input *ResourceInput) {
			input.SourceAllowlist = []string{source, source}
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := base
			input.SourceAllowlist = append([]string(nil), base.SourceAllowlist...)
			test.mutate(&input)
			if _, err := NewResource(input); err == nil {
				t.Fatal("NewResource() accepted unsafe acquisition authority")
			}
		})
	}
}

func TestReleaseResourceRejectsPurposeMediaPublisherAndProviderRoleConfusion(t *testing.T) {
	t.Parallel()

	platform := mustPlatform(t, "linux", "amd64")
	base := fixtureSubjectInput("compose", ResourceKindComposeBundle, platform, digestText("compose"), 7)
	base.CycloneDXSBOMResourceID = "compose-cyclonedx"
	base.SPDXSBOMResourceID = "compose-spdx"
	base.ProvenanceResourceID = "compose-provenance"
	base.LicenseResourceID = "compose-licenses"
	base.VulnerabilityResourceID = "compose-vulnerabilities"
	if _, err := NewResource(base); err != nil {
		t.Fatalf("NewResource(valid compose) error = %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*ResourceInput)
	}{
		{name: "purpose mismatch", mutate: func(input *ResourceInput) { input.Purpose = ResourcePurposeMigrationSet }},
		{name: "media mismatch", mutate: func(input *ResourceInput) { input.MediaType = MediaTypeMigrationSet }},
		{name: "foreign provider role", mutate: func(input *ResourceInput) { input.ProviderRole = LocalProviderRoleEmbedding }},
		{name: "foreign publisher", mutate: func(input *ResourceInput) {
			input.NativePublisherIdentity = "other.publisher"
			input.NativePublisherPolicyID = "other-policy"
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := base
			test.mutate(&input)
			if _, err := NewResource(input); err == nil {
				t.Fatal("NewResource() accepted conflicting execution metadata")
			}
		})
	}
	model := fixtureSubjectInput("model-embedding", ResourceKindModel, platform, digestText("model"), 5)
	model.CycloneDXSBOMResourceID = "model-cyclonedx"
	model.SPDXSBOMResourceID = "model-spdx"
	model.ProvenanceResourceID = "model-provenance"
	model.LicenseResourceID = "model-licenses"
	model.VulnerabilityResourceID = "model-vulnerabilities"
	if _, err := NewResource(model); err == nil {
		t.Fatal("NewResource() accepted a provider artifact without an exact role")
	}
	launcher := fixtureSubjectInput("launcher", ResourceKindLauncher, platform, digestText("launcher"), 8)
	launcher.CycloneDXSBOMResourceID = "launcher-cyclonedx"
	launcher.SPDXSBOMResourceID = "launcher-spdx"
	launcher.ProvenanceResourceID = "launcher-provenance"
	launcher.LicenseResourceID = "launcher-licenses"
	launcher.VulnerabilityResourceID = "launcher-vulnerabilities"
	launcher.NativePublisherIdentity = ""
	if _, err := NewResource(launcher); err == nil {
		t.Fatal("NewResource() accepted a native artifact without publisher identity")
	}
}

func TestSignedManifestCopiesSignatureAndSignsExactCanonicalPayload(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, completeResources(t, mustPlatform(t, "linux", "amd64")))
	signature := bytes.Repeat([]byte{0x5a}, ManifestSignatureSize)
	signed, err := NewSignedManifest(manifest, SignatureBundleInput{
		SchemaVersion:       SupportedSignatureBundleSchemaMajor,
		TrustMode:           SignatureTrustModeKeyID,
		TrustRootID:         "release-root-2026",
		Signature:           signature,
		RevocationSet:       []byte("signed revocation set"),
		TrustedTimeEvidence: []byte("trusted time evidence"),
	})
	if err != nil {
		t.Fatalf("NewSignedManifest() error = %v", err)
	}
	signature[0] ^= 0xff
	returned := signed.Signature()
	returned[1] ^= 0xff
	if signed.Signature()[0] != 0x5a || signed.Signature()[1] != 0x5a {
		t.Fatal("signed manifest exposed mutable signature storage")
	}
	if !bytes.Equal(signed.SignaturePayload(), manifest.CanonicalBytes()) {
		t.Fatal("signature payload differs from RFC 8785 canonical manifest bytes")
	}
	if _, err := NewSignedManifest(manifest, SignatureBundleInput{
		SchemaVersion: SupportedSignatureBundleSchemaMajor,
		TrustMode:     SignatureTrustModeKeyID, TrustRootID: "bad signer/id",
		Signature: bytes.Repeat([]byte{1}, ManifestSignatureSize),
	}); err == nil {
		t.Fatal("NewSignedManifest() accepted invalid signer ID")
	}
	if _, err := NewSignedManifest(manifest, SignatureBundleInput{
		SchemaVersion: SupportedSignatureBundleSchemaMajor,
		TrustMode:     SignatureTrustModeKeyID, TrustRootID: "release-root-2026", Signature: []byte("short"),
	}); err == nil {
		t.Fatal("NewSignedManifest() accepted invalid signature length")
	}
	if _, err := NewSignedManifest(manifest, SignatureBundleInput{
		SchemaVersion: SupportedSignatureBundleSchemaMajor,
		TrustMode:     SignatureTrustModeKeyID, TrustRootID: "release-root-2026",
		Signature: bytes.Repeat([]byte{1}, ManifestSignatureSize), SigstoreBundle: []byte("foreign"),
	}); err == nil {
		t.Fatal("NewSignedManifest() accepted a Sigstore bundle in key-ID mode")
	}
	if _, err := NewSignedManifest(manifest, SignatureBundleInput{
		SchemaVersion: SupportedSignatureBundleSchemaMajor,
		TrustMode:     SignatureTrustModeCertificateTransparency, TrustRootID: "release-root-2026",
		Signature: []byte("split signature"), SigstoreBundle: []byte("bundle"),
	}); err == nil {
		t.Fatal("NewSignedManifest() accepted a split signature in certificate-transparency mode")
	}
	if _, err := NewSignedManifest(manifest, SignatureBundleInput{
		SchemaVersion: SupportedSignatureBundleSchemaMajor,
		TrustMode:     "future-trust-mode", TrustRootID: "release-root-2026", Signature: signature,
	}); err == nil {
		t.Fatal("NewSignedManifest() accepted an unknown trust mode")
	}
	if _, err := NewSignedManifest(manifest, SignatureBundleInput{
		SchemaVersion: SupportedSignatureBundleSchemaMajor - 1,
		TrustMode:     SignatureTrustModeCertificateTransparency, TrustRootID: "release-root-2026",
	}); err == nil {
		t.Fatal("NewSignedManifest() accepted an obsolete signature-bundle schema")
	}
}

func TestManifestSelectsOnlyTargetResourcesAndTheirEvidence(t *testing.T) {
	t.Parallel()

	linux := mustPlatform(t, "linux", "amd64")
	macOS := mustPlatform(t, "darwin", "arm64")
	resources := append(completeResources(t, linux), platformResources(t, macOS)...)
	manifest := mustManifest(t, resources)
	if _, err := manifest.ResourcesFor(Platform{}); !errors.Is(err, ErrTargetUnsupported) {
		t.Fatalf("ResourcesFor(any) error = %v, want ErrTargetUnsupported", err)
	}

	selected, err := manifest.ResourcesFor(linux)
	if err != nil {
		t.Fatalf("ResourcesFor() error = %v", err)
	}
	for _, resource := range selected {
		if !resource.Platform().IsAny() && resource.Platform() != linux {
			t.Fatalf("selected foreign resource %s for %s", resource.ID(), resource.Platform())
		}
	}
	if !containsResource(selected, "launcher") || containsResource(selected, "launcher-darwin-arm64") == true {
		t.Fatalf("target resource selection = %v", resourceIDs(selected))
	}
	if !containsResource(selected, "launcher-cyclonedx") || !containsResource(selected, "launcher-spdx") ||
		!containsResource(selected, "launcher-provenance") || !containsResource(selected, "launcher-licenses") ||
		!containsResource(selected, "launcher-vulnerabilities") {
		t.Fatal("target resource selection omitted linked verification evidence")
	}
}

func TestManifestRequiresEveryProviderArtifactAndEveryServicePlatformImage(t *testing.T) {
	t.Parallel()

	linux := mustPlatform(t, "linux", "amd64")
	resources := completeResources(t, linux)
	missingTokenizer := removeSubjectAndEvidence(
		resources,
		"tokenizer-"+string(LocalProviderRoleExtraction),
	)
	manifest := mustManifest(t, missingTokenizer)
	if _, err := manifest.ResourcesFor(linux); !errors.Is(err, ErrTargetInventoryIncomplete) {
		t.Fatalf("ResourcesFor() missing extraction tokenizer error = %v", err)
	}

	missingInstallPlan := removeSubjectAndEvidence(resources, "install-plan")
	manifest = mustManifest(t, missingInstallPlan)
	if _, err := manifest.ResourcesFor(linux); !errors.Is(err, ErrTargetInventoryIncomplete) {
		t.Fatalf("ResourcesFor() missing signed install-plan template error = %v", err)
	}

	duplicateInput := fixtureSubjectInput(
		"install-plan-duplicate", ResourceKindInstallPlanTemplate, linux,
		digestText("install-plan-duplicate"), 12,
	)
	duplicateInput.CycloneDXSBOMResourceID = duplicateInput.ID + "-cyclonedx"
	duplicateInput.SPDXSBOMResourceID = duplicateInput.ID + "-spdx"
	duplicateInput.ProvenanceResourceID = duplicateInput.ID + "-provenance"
	duplicateInput.LicenseResourceID = duplicateInput.ID + "-licenses"
	duplicateInput.VulnerabilityResourceID = duplicateInput.ID + "-vulnerabilities"
	duplicateResources := append(append([]Resource(nil), resources...), mustResource(t, duplicateInput))
	duplicateResources = append(duplicateResources, fixtureEvidenceResources(t, duplicateInput)...)
	manifest = mustManifest(t, duplicateResources)
	if _, err := manifest.ResourcesFor(linux); !errors.Is(err, ErrTargetInventoryIncomplete) {
		t.Fatalf("ResourcesFor() ambiguous signed install-plan templates error = %v", err)
	}

	macOS := mustPlatform(t, "darwin", "arm64")
	multiPlatformResources := append(completeResources(t, linux), platformResources(t, macOS)...)
	input := validManifestInput(multiPlatformResources)
	topologyInput := validDockerTopologyInput()
	topologyInput.Services[0].ImageResourceIDs = []string{"image"}
	secondService := topologyInput.Services[0]
	secondService.ID = "worker"
	secondService.ImageResourceIDs = []string{"image-darwin-arm64"}
	secondService.PublishedPorts = nil
	topologyInput.Services = append(topologyInput.Services, secondService)
	topology, err := NewDockerTopology(topologyInput)
	if err != nil {
		t.Fatalf("NewDockerTopology() error = %v", err)
	}
	input.DockerTopology = topology
	manifest, err = NewManifest(input)
	if err != nil {
		t.Fatalf("NewManifest() error = %v", err)
	}
	if _, err := manifest.ResourcesFor(linux); !errors.Is(err, ErrTargetInventoryIncomplete) {
		t.Fatalf("ResourcesFor() service without linux image error = %v", err)
	}
}

func TestReleaseInventoryValueAccessorsAndValidityBoundaries(t *testing.T) {
	t.Parallel()

	platform := mustPlatform(t, "linux", "amd64")
	manifest := mustManifest(t, completeResources(t, platform))
	if manifest.SchemaVersion() != SupportedManifestSchemaMajor ||
		manifest.ReleaseID() != "agentmemory-1.0.0" || manifest.Version() != "1.0.0" ||
		manifest.BuildID() != "build-20260701-1" || len(manifest.SourceCommit()) != 40 ||
		manifest.Channel() != ReleaseChannelStable || manifest.DataGeneration() != 6 ||
		manifest.BuildTimestamp().IsZero() || manifest.ValidFrom().IsZero() || manifest.ValidUntil().IsZero() ||
		manifest.Sequence() != 42 || !manifest.Protocol().Contains(2) || manifest.Protocol().Contains(4) ||
		!manifest.Compatibility().CoreAPI().Contains("1.0.0") ||
		manifest.LicensePolicyDigest().IsZero() || manifest.VulnerabilityPolicyDigest().IsZero() ||
		len(manifest.ReleaseHistory().PriorReleases()) != 0 || len(manifest.DockerTopology().Services()) != 1 ||
		manifest.TrustPolicy().TrustRootID() != "release-root-2026" {
		t.Fatal("manifest accessors did not preserve validated values")
	}
	if !manifest.ValidAt(time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC)) ||
		manifest.ValidAt(time.Date(2027, time.July, 1, 0, 0, 0, 0, time.UTC)) ||
		manifest.ValidAt(time.Time{}) {
		t.Fatal("manifest validity window is not [from, until)")
	}
	manifestResources := manifest.Resources()
	launcher := manifestResources[resourceIndex(t, manifestResources, "launcher")]
	image := manifestResources[resourceIndex(t, manifestResources, "image")]
	providerModel := manifestResources[resourceIndex(t, manifestResources, "model-embedding")]
	vulnerability := manifestResources[resourceIndex(t, manifestResources, "launcher-vulnerabilities")]
	sources := launcher.SourceAllowlist()
	sources[0] = "bundle://tampered"
	if launcher.Purpose() != ResourcePurposeNativeLauncher || launcher.MediaType() != MediaTypeNativeExecutable ||
		launcher.NativePublisherIdentity() != "agentmemory.publisher" ||
		launcher.NativePublisherPolicyID() != "agentmemory-native-2026" ||
		launcher.SourceAllowlist()[0] != "bundle://launcher" ||
		image.OCIIndexResourceID() != "image-index" || image.OCIIndexDigest().IsZero() ||
		providerModel.ProviderRole() != LocalProviderRoleEmbedding ||
		vulnerability.SubjectResourceID() != "launcher" || vulnerability.SubjectDigest().IsZero() ||
		vulnerability.PolicySnapshotDigest().IsZero() ||
		vulnerability.QualificationResult() != QualificationResultPassed ||
		vulnerability.QualificationExpiresAt().IsZero() {
		t.Fatal("resource accessors lost signed execution or evidence authority")
	}
	if platform.String() != "linux/amd64" || (Platform{}).String() != "any" {
		t.Fatal("platform string vocabulary changed")
	}

	digest := manifest.Digest()
	parsed, err := ParseDigest(digest.Hex())
	if err != nil || !parsed.Equal(digest) {
		t.Fatalf("ParseDigest() = %v/%v, want manifest digest", parsed, err)
	}
	if _, err := ParseDigest(strings.ToUpper(digest.Hex())); err == nil {
		t.Fatal("ParseDigest() accepted uppercase input")
	}
	if _, err := ParseDigest(strings.Repeat("0", 64)); err == nil {
		t.Fatal("ParseDigest() accepted the zero digest")
	}

	signed, err := NewSignedManifest(manifest, SignatureBundleInput{
		SchemaVersion:       SupportedSignatureBundleSchemaMajor,
		TrustMode:           SignatureTrustModeCertificateTransparency,
		TrustRootID:         "release-root-2026",
		SigstoreBundle:      []byte("official Sigstore bundle"),
		RevocationSet:       []byte("revocations"),
		TrustedTimeEvidence: []byte("trusted time"),
	})
	if err != nil {
		t.Fatalf("NewSignedManifest() error = %v", err)
	}
	if signed.Manifest().ReleaseID() != manifest.ReleaseID() ||
		signed.SignatureBundleSchemaVersion() != SupportedSignatureBundleSchemaMajor ||
		signed.TrustMode() != SignatureTrustModeCertificateTransparency ||
		signed.TrustRootID() != "release-root-2026" || len(signed.SigstoreBundle()) == 0 ||
		len(signed.RevocationSet()) == 0 || len(signed.TrustedTimeEvidence()) == 0 {
		t.Fatal("signed-manifest evidence accessors lost data")
	}
}

func TestTrustAndPlatformConstructorsRejectClosedVocabularyViolations(t *testing.T) {
	t.Parallel()

	if _, err := NewPlatform("freebsd", "amd64"); err == nil {
		t.Fatal("NewPlatform() accepted an unsupported OS")
	}
	if _, err := NewPlatform("linux", "386"); err == nil {
		t.Fatal("NewPlatform() accepted an unsupported architecture")
	}
	if _, err := NewProtocolRange(3, 2); err == nil {
		t.Fatal("NewProtocolRange() accepted an inverted range")
	}
	revocations := DigestBytes([]byte("revocations"))
	if _, err := NewTrustPolicy(SignatureTrustMode("unknown"), "root", revocations, ""); err == nil {
		t.Fatal("NewTrustPolicy() accepted an unknown mode")
	}
	if _, err := NewTrustPolicy(SignatureTrustModeCertificateTransparency, "root", revocations, ""); err == nil {
		t.Fatal("NewTrustPolicy() accepted transparency mode without a log")
	}
	if _, err := NewTrustPolicy(SignatureTrustModeKeyID, "root", revocations, "rekor"); err == nil {
		t.Fatal("NewTrustPolicy() accepted a log in key-ID mode")
	}
	policy, err := NewTrustPolicyWithRuntimeRoot(
		SignatureTrustModeKeyID,
		"release-root",
		"runtime-root",
		revocations,
		"",
	)
	if err != nil || policy.RuntimeTrustRootID() != "runtime-root" {
		t.Fatalf("NewTrustPolicyWithRuntimeRoot() = %v/%v", policy, err)
	}
}

func validManifestInput(resources []Resource) ManifestInput {
	protocol, _ := NewProtocolRange(1, 3)
	versionRange, _ := NewVersionRange(VersionRangeInput{Minimum: "1.0.0", Maximum: "1.0.0"})
	compatibility, _ := NewCompatibility(CompatibilityInput{
		Launcher: versionRange, CoreAPI: versionRange, MCP: versionRange,
		Provider: versionRange, Schema: versionRange, Compose: versionRange,
		SQLite: versionRange, Neo4j: versionRange, RuntimeCatalog: versionRange,
	})
	trustPolicy, _ := NewTrustPolicy(
		SignatureTrustModeKeyID,
		"release-root-2026",
		DigestBytes([]byte("signed revocation set")),
		"",
	)
	topologyInput := validDockerTopologyInput()
	topologyInput.Services[0].ImageResourceIDs = nil
	for _, resource := range resources {
		if resource.Kind() == ResourceKindOCIImage {
			topologyInput.Services[0].ImageResourceIDs = append(
				topologyInput.Services[0].ImageResourceIDs,
				resource.ID(),
			)
		}
	}
	topology, _ := NewDockerTopology(topologyInput)
	history, _ := NewReleaseHistory(nil, nil)
	return ManifestInput{
		SchemaVersion:             1,
		ReleaseID:                 "agentmemory-1.0.0",
		Version:                   "1.0.0",
		BuildID:                   "build-20260701-1",
		SourceCommit:              strings.Repeat("a", 40),
		BuildTimestamp:            time.Date(2026, time.June, 30, 23, 0, 0, 0, time.UTC),
		Channel:                   ReleaseChannelStable,
		Sequence:                  42,
		DataGeneration:            6,
		ValidFrom:                 time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC),
		ValidUntil:                time.Date(2027, time.July, 1, 0, 0, 0, 0, time.UTC),
		Protocol:                  protocol,
		Compatibility:             compatibility,
		TrustPolicy:               trustPolicy,
		ReleaseHistory:            history,
		LicensePolicyDigest:       digestText("license-policy"),
		VulnerabilityPolicyDigest: digestText("vulnerability_report-policy"),
		DockerTopology:            topology,
		Resources:                 resources,
	}
}

func mustManifest(t testing.TB, resources []Resource) Manifest {
	t.Helper()
	manifest, err := NewManifest(validManifestInput(resources))
	if err != nil {
		t.Fatalf("NewManifest() error = %v", err)
	}
	return manifest
}

func completeResources(t testing.TB, platform Platform) []Resource {
	t.Helper()
	return platformResources(t, platform)
}

func platformResources(t testing.TB, platform Platform) []Resource {
	t.Helper()
	suffix := ""
	launcherID := "launcher"
	if platform.OS() != "linux" || platform.Architecture() != "amd64" {
		suffix = "-" + platform.OS() + "-" + platform.Architecture()
		launcherID += suffix
	}
	inputs := make([]ResourceInput, 0, 16)
	inputs = append(inputs,
		fixtureSubjectInput(launcherID, ResourceKindLauncher, platform, digestText("launcher"+suffix), 8),
		fixtureSubjectInput("helper"+suffix, ResourceKindHelper, platform, digestText("helper"+suffix), 6),
		fixtureSubjectInput("compose"+suffix, ResourceKindComposeBundle, platform, digestText("compose"+suffix), 7),
		fixtureSubjectInput("schema"+suffix, ResourceKindSchema, platform, digestText("schema"+suffix), 6),
		fixtureSubjectInput("migration"+suffix, ResourceKindMigration, platform, digestText("migration"+suffix), 9),
		fixtureSubjectInput("verifier"+suffix, ResourceKindVerifier, platform, digestText("verifier"+suffix), 8),
		fixtureSubjectInput("setup-ui"+suffix, ResourceKindSetupUI, platform, digestText("setup-ui"+suffix), 8),
		fixtureSubjectInput("install-plan"+suffix, ResourceKindInstallPlanTemplate, platform, digestText("install-plan"+suffix), 12),
		fixtureSubjectInput("runtime-catalog"+suffix, ResourceKindRuntimeCatalog, platform, digestText("runtime-catalog"+suffix), 8),
	)
	for _, role := range []LocalProviderRole{
		LocalProviderRoleEmbedding,
		LocalProviderRoleReranking,
		LocalProviderRoleExtraction,
	} {
		for _, kind := range []ResourceKind{ResourceKindModel, ResourceKindTokenizer, ResourceKindTemplate} {
			id := string(kind) + "-" + string(role) + suffix
			input := fixtureSubjectInput(id, kind, platform, digestText(id), uint64(len(id)))
			input.ProviderRole = role
			inputs = append(inputs, input)
		}
	}
	imageDigest := digestText("image" + suffix)
	indexDigest := digestText("image-index" + suffix)
	indexID := "image-index" + suffix
	index := fixtureSubjectInput(indexID, ResourceKindOCIIndex, Platform{}, indexDigest, 5)
	image := fixtureSubjectInput("image"+suffix, ResourceKindOCIImage, platform, imageDigest, 5)
	image.OCIIndexDigest = indexDigest
	image.OCIIndexResourceID = indexID
	inputs = append(inputs, image, index)
	resources := make([]Resource, 0, len(inputs)*6)
	for _, input := range inputs {
		input.CycloneDXSBOMResourceID = input.ID + "-cyclonedx"
		input.SPDXSBOMResourceID = input.ID + "-spdx"
		input.ProvenanceResourceID = input.ID + "-provenance"
		input.LicenseResourceID = input.ID + "-licenses"
		input.VulnerabilityResourceID = input.ID + "-vulnerabilities"
		resources = append(resources, mustResource(t, input))
		resources = append(resources, fixtureEvidenceResources(t, input)...)
	}
	return resources
}

func fixtureSubjectInput(id string, kind ResourceKind, platform Platform, digest Digest, size uint64) ResourceInput {
	sourceRef := "bundle://" + id
	if kind == ResourceKindOCIImage || kind == ResourceKindOCIIndex {
		sourceRef = "registry.example/agentmemory/" + id + "@sha256:" + digest.Hex()
	}
	input := ResourceInput{
		ID: id, Kind: kind, Purpose: expectedPurpose(kind), MediaType: expectedMediaType(kind),
		Platform: platform, Digest: digest, Size: size, SourceRef: sourceRef,
		SourceAllowlist: []string{sourceRef},
	}
	if kind == ResourceKindLauncher || kind == ResourceKindVerifier || kind == ResourceKindHelper {
		input.NativePublisherIdentity = "agentmemory.publisher"
		input.NativePublisherPolicyID = "agentmemory-native-2026"
	}
	if kind == ResourceKindComposeBundle {
		input.ExpandedTarget = ReleaseExpandedTargetInput{
			Kind: ExpandedTargetComposeBundle, StorageID: "compose/compose.yaml", Digest: digest, Bytes: size,
		}
	}
	return input
}

func TestPF001ResourceConstructorReachesEveryDeepCrossBindingRejection(t *testing.T) {
	t.Parallel()
	digest := digestText("deep-resource")
	platform := mustPlatform(t, "linux", "amd64")
	base := fixtureSubjectInput("compose-deep", ResourceKindComposeBundle, platform, digest, 64)
	base.CycloneDXSBOMResourceID = "compose-deep-cyclonedx"
	base.SPDXSBOMResourceID = "compose-deep-spdx"
	base.ProvenanceResourceID = "compose-deep-provenance"
	base.LicenseResourceID = "compose-deep-licenses"
	base.VulnerabilityResourceID = "compose-deep-vulnerabilities"
	if _, err := NewResource(base); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func() ResourceInput{
		"unsafe size":               func() ResourceInput { v := base; v.Size = uint64(1 << 53); return v },
		"missing evidence":          func() ResourceInput { v := base; v.CycloneDXSBOMResourceID = ""; return v },
		"subject qualification":     func() ResourceInput { v := base; v.QualificationResult = QualificationResultPassed; return v },
		"non OCI index":             func() ResourceInput { v := base; v.OCIIndexDigest = digest; v.OCIIndexResourceID = "index"; return v },
		"invalid compose expansion": func() ResourceInput { v := base; v.ExpandedTarget.Bytes++; return v },
		"non compose expansion": func() ResourceInput {
			v := base
			v.Kind = ResourceKindMigration
			v.Purpose = expectedPurpose(v.Kind)
			v.MediaType = expectedMediaType(v.Kind)
			return v
		},
	}
	evidence := ResourceInput{ID: "subject-cyclonedx", Kind: ResourceKindCycloneDXSBOM,
		Purpose: expectedPurpose(ResourceKindCycloneDXSBOM), MediaType: expectedMediaType(ResourceKindCycloneDXSBOM),
		Digest: digest, Size: 1, SourceRef: "bundle://subject-cyclonedx", SourceAllowlist: []string{"bundle://subject-cyclonedx"},
		SubjectResourceID: "subject", SubjectDigest: digest}
	tests["evidence attestations"] = func() ResourceInput { v := evidence; v.CycloneDXSBOMResourceID = "foreign"; return v }
	tests["evidence subject"] = func() ResourceInput { v := evidence; v.SubjectResourceID = ""; return v }
	oci := fixtureSubjectInput("image-deep", ResourceKindOCIImage, platform, digest, 64)
	oci.CycloneDXSBOMResourceID, oci.SPDXSBOMResourceID = "image-cyclonedx", "image-spdx"
	oci.ProvenanceResourceID, oci.LicenseResourceID, oci.VulnerabilityResourceID = "image-provenance", "image-licenses", "image-vulnerabilities"
	tests["OCI index"] = func() ResourceInput { return oci }
	tests["OCI digest ref"] = func() ResourceInput {
		v := oci
		v.OCIIndexDigest = digest
		v.OCIIndexResourceID = "index"
		v.SourceRef = "registry.example/image@sha256:" + digestText("other").Hex()
		v.SourceAllowlist = []string{v.SourceRef}
		return v
	}
	tests["OCI any platform"] = func() ResourceInput {
		v := oci
		v.OCIIndexDigest = digest
		v.OCIIndexResourceID = "index"
		v.Platform = Platform{}
		return v
	}
	index := oci
	index.Kind, index.Purpose, index.MediaType = ResourceKindOCIIndex, expectedPurpose(ResourceKindOCIIndex), expectedMediaType(ResourceKindOCIIndex)
	index.OCIIndexDigest, index.OCIIndexResourceID, index.Platform = Digest{}, "", platform
	tests["index exact platform"] = func() ResourceInput { return index }
	for name, build := range tests {
		if _, err := NewResource(build()); err == nil {
			t.Fatalf("%s invalid cross-binding accepted", name)
		}
	}
}

func fixtureEvidenceResources(t testing.TB, subject ResourceInput) []Resource {
	t.Helper()
	types := []ResourceKind{
		ResourceKindCycloneDXSBOM, ResourceKindSPDXSBOM, ResourceKindProvenance,
		ResourceKindLicense, ResourceKindVulnerabilityReport,
	}
	resources := make([]Resource, 0, len(types))
	for _, kind := range types {
		id := subject.ID + "-" + string(kind)
		//nolint:exhaustive // The fixture invokes this switch only with the evidence kinds above.
		switch kind {
		case ResourceKindCycloneDXSBOM:
			id = subject.ID + "-cyclonedx"
		case ResourceKindSPDXSBOM:
			id = subject.ID + "-spdx"
		case ResourceKindProvenance:
			id = subject.ID + "-provenance"
		case ResourceKindLicense:
			id = subject.ID + "-licenses"
		case ResourceKindVulnerabilityReport:
			id = subject.ID + "-vulnerabilities"
		}
		digest := digestText(id)
		sourceRef := "bundle://" + id
		input := ResourceInput{
			ID: id, Kind: kind, Purpose: expectedPurpose(kind), MediaType: expectedMediaType(kind),
			Digest: digest, Size: uint64(len(id)), SourceRef: sourceRef,
			SourceAllowlist: []string{sourceRef}, SubjectResourceID: subject.ID, SubjectDigest: subject.Digest,
		}
		if kind == ResourceKindLicense || kind == ResourceKindVulnerabilityReport {
			input.PolicySnapshotDigest = digestText(string(kind) + "-policy")
			input.QualificationResult = QualificationResultPassed
		}
		if kind == ResourceKindVulnerabilityReport {
			input.QualificationExpiresAt = time.Date(2027, time.August, 1, 0, 0, 0, 0, time.UTC)
		}
		resources = append(resources, mustResource(t, input))
	}
	return resources
}

func mustResource(t testing.TB, input ResourceInput) Resource {
	t.Helper()
	resource, err := NewResource(input)
	if err != nil {
		t.Fatalf("NewResource(%q) error = %v", input.ID, err)
	}
	return resource
}

func mustPlatform(t testing.TB, operatingSystem, architecture string) Platform {
	t.Helper()
	platform, err := NewPlatform(operatingSystem, architecture)
	if err != nil {
		t.Fatalf("NewPlatform() error = %v", err)
	}
	return platform
}

func digestText(value string) Digest { return DigestBytes([]byte(value)) }

func containsResource(resources []Resource, id string) bool {
	for _, resource := range resources {
		if resource.ID() == id {
			return true
		}
	}
	return false
}

func resourceIDs(resources []Resource) []string {
	ids := make([]string, 0, len(resources))
	for _, resource := range resources {
		ids = append(ids, resource.ID())
	}
	return ids
}

func removeSubjectAndEvidence(resources []Resource, subjectID string) []Resource {
	result := make([]Resource, 0, len(resources))
	for _, resource := range resources {
		if resource.ID() == subjectID || resource.SubjectResourceID() == subjectID {
			continue
		}
		result = append(result, resource)
	}
	return result
}

func resourceIndex(t *testing.T, resources []Resource, id string) int {
	t.Helper()
	for index, resource := range resources {
		if resource.ID() == id {
			return index
		}
	}
	t.Fatalf("resource %q not found", id)
	return -1
}
