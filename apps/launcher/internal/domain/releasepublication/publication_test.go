package releasepublication

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001PublicationCanonicalRoundTripBindsExactPromotedObjects(t *testing.T) {
	t.Parallel()
	input := validPublicationInput(t)
	// Prove the domain, rather than caller ordering, owns canonical order.
	input.Artifacts[0], input.Artifacts[len(input.Artifacts)-1] =
		input.Artifacts[len(input.Artifacts)-1], input.Artifacts[0]
	publication, err := NewPublication(input)
	if err != nil {
		t.Fatalf("NewPublication() error=%v", err)
	}
	raw, err := EncodeV1(publication)
	if err != nil {
		t.Fatalf("EncodeV1() error=%v", err)
	}
	decoded, err := DecodeV1(raw)
	if err != nil {
		t.Fatalf("DecodeV1() error=%v", err)
	}
	if decoded.ReleaseID() != input.ReleaseID || decoded.Version() != input.Version ||
		decoded.BuildID() != input.BuildID || decoded.SourceCommit() != input.SourceCommit ||
		!decoded.DistributionEnvelopeDigest().Equal(input.DistributionEnvelopeDigest) ||
		decoded.DistributionEnvelopeSize() != input.DistributionEnvelopeSize ||
		!bytes.Equal(decoded.Canonical(), raw) {
		t.Fatalf("decoded publication lost an authority binding: %+v", decoded)
	}
	artifacts := decoded.Artifacts()
	if len(artifacts) != 8 || artifacts[0].ID() != "agentmemory-darwin-amd64-pkg" ||
		artifacts[len(artifacts)-1].ID() != "agentmemory-windows-amd64-msi" {
		t.Fatalf("canonical artifacts=%+v", artifacts)
	}
	artifacts[0] = Artifact{}
	if decoded.Artifacts()[0].ID() == "" {
		t.Fatal("publication exposed mutable artifact storage")
	}
}

func TestPF001PublicationRequiresClosedCertifiedNativePackageMatrix(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*PublicationInput){
		"missing package": func(input *PublicationInput) { input.Artifacts = input.Artifacts[1:] },
		"duplicate package": func(input *PublicationInput) {
			input.Artifacts = append(input.Artifacts, input.Artifacts[0])
		},
		"foreign architecture": func(input *PublicationInput) {
			input.Artifacts[0].Architecture = "riscv64"
		},
		"wrong package format": func(input *PublicationInput) { input.Artifacts[0].Format = FormatMSI },
		"publisher downgrade": func(input *PublicationInput) {
			input.Artifacts[0].NativePublisherPolicy = PublisherPolicyLinuxPackage
		},
		"missing offline bundle": func(input *PublicationInput) {
			input.Artifacts = input.Artifacts[:len(input.Artifacts)-1]
		},
		"duplicate object digest": func(input *PublicationInput) {
			input.Artifacts[1].Digest = input.Artifacts[0].Digest
		},
		"distribution aliases object": func(input *PublicationInput) {
			input.DistributionEnvelopeDigest = input.Artifacts[0].Digest
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			input := validPublicationInput(t)
			mutate(&input)
			if _, err := NewPublication(input); err == nil {
				t.Fatal("NewPublication() error=nil")
			}
		})
	}
}

func TestPF001PublicationRejectsUnsafeArtifactAndIdentityInputs(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*PublicationInput){
		"schema":        func(input *PublicationInput) { input.SchemaVersion++ },
		"release id":    func(input *PublicationInput) { input.ReleaseID = "../../release" },
		"version":       func(input *PublicationInput) { input.Version = "latest" },
		"build id":      func(input *PublicationInput) { input.BuildID = "" },
		"commit":        func(input *PublicationInput) { input.SourceCommit = strings.Repeat("A", 40) },
		"timestamp":     func(input *PublicationInput) { input.BuildTimestamp = time.Time{} },
		"envelope size": func(input *PublicationInput) { input.DistributionEnvelopeSize = 0 },
		"unsafe name":   func(input *PublicationInput) { input.Artifacts[0].FileName = "../agentmemory.pkg" },
		"empty object":  func(input *PublicationInput) { input.Artifacts[0].Size = 0 },
		"missing SBOM":  func(input *PublicationInput) { input.Artifacts[0].CycloneDXSBOMDigest = releaseinventory.Digest{} },
		"missing provenance": func(input *PublicationInput) {
			input.Artifacts[0].ProvenanceDigest = releaseinventory.Digest{}
		},
		"missing signature bundle": func(input *PublicationInput) {
			input.Artifacts[0].SignatureBundleDigest = releaseinventory.Digest{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			input := validPublicationInput(t)
			mutate(&input)
			if _, err := NewPublication(input); err == nil {
				t.Fatal("NewPublication() error=nil")
			}
		})
	}
}

func TestPF001PublicationDecoderRejectsNonCanonicalOrOpenJSON(t *testing.T) {
	t.Parallel()
	publication, err := NewPublication(validPublicationInput(t))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeV1(publication)
	if err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string][]byte{
		"empty":          nil,
		"trailing":       append(append([]byte(nil), raw...), '\n'),
		"unknown":        bytes.Replace(raw, []byte(`"version":`), []byte(`"unexpected":true,"version":`), 1),
		"duplicate":      bytes.Replace(raw, []byte(`"version":`), []byte(`"version":"1.2.3","version":`), 1),
		"wrong ordering": bytes.Replace(raw, []byte(`"build_id":"build-17","build_timestamp"`), []byte(`"build_timestamp"`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeV1(candidate); err == nil {
				t.Fatal("DecodeV1() error=nil")
			}
		})
	}
}

func validPublicationInput(t testing.TB) PublicationInput {
	t.Helper()
	digest := func(label string) releaseinventory.Digest {
		return releaseinventory.DigestBytes([]byte(label))
	}
	artifact := func(id, operatingSystem, architecture string, format Format, policy NativePublisherPolicy) ArtifactInput {
		return ArtifactInput{
			ID: id, Kind: ArtifactKindNativePackage, OperatingSystem: operatingSystem,
			Architecture: architecture, Format: format, FileName: id + "." + string(format),
			MediaType: "application/vnd.agentmemory.native-package", Digest: digest(id), Size: 4096,
			CycloneDXSBOMDigest: digest(id + "-cyclonedx"), ProvenanceDigest: digest(id + "-provenance"),
			SignatureBundleDigest: digest(id + "-sigstore"), NativePublisherPolicy: policy,
		}
	}
	artifacts := []ArtifactInput{
		artifact("agentmemory-darwin-amd64-pkg", "darwin", "amd64", FormatPKG, PublisherPolicyAppleNotarized),
		artifact("agentmemory-darwin-arm64-pkg", "darwin", "arm64", FormatPKG, PublisherPolicyAppleNotarized),
		artifact("agentmemory-linux-amd64-deb", "linux", "amd64", FormatDEB, PublisherPolicyLinuxPackage),
		artifact("agentmemory-linux-amd64-rpm", "linux", "amd64", FormatRPM, PublisherPolicyLinuxPackage),
		artifact("agentmemory-linux-arm64-deb", "linux", "arm64", FormatDEB, PublisherPolicyLinuxPackage),
		artifact("agentmemory-linux-arm64-rpm", "linux", "arm64", FormatRPM, PublisherPolicyLinuxPackage),
		artifact("agentmemory-windows-amd64-msi", "windows", "amd64", FormatMSI, PublisherPolicyMicrosoftAuthenticode),
		{
			ID: "agentmemory-offline-bundle", Kind: ArtifactKindOfflineBundle, Format: FormatTarZstd,
			FileName: "agentmemory-offline-bundle.tar.zst", MediaType: "application/vnd.agentmemory.offline-bundle",
			Digest: digest("offline-bundle"), Size: 16384,
			CycloneDXSBOMDigest: digest("offline-cyclonedx"), ProvenanceDigest: digest("offline-provenance"),
			SignatureBundleDigest: digest("offline-sigstore"), NativePublisherPolicy: PublisherPolicyManifestOnly,
		},
	}
	return PublicationInput{
		SchemaVersion: SupportedSchemaMajor, ReleaseID: "release-2026-07", Version: "1.2.3", BuildID: "build-17",
		SourceCommit: strings.Repeat("a", 40), BuildTimestamp: time.Unix(1_784_073_600, 0).UTC(),
		DistributionEnvelopeDigest: digest("distribution-envelope"), DistributionEnvelopeSize: 8192,
		Artifacts: artifacts,
	}
}
