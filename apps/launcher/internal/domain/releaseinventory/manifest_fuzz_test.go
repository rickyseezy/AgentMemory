package releaseinventory

import (
	"bytes"
	"strings"
	"testing"
)

func FuzzParseDigestRoundTrip(f *testing.F) {
	f.Add(DigestBytes([]byte("release")).Hex())
	f.Add(strings.Repeat("0", 64))
	f.Add("not-a-digest")

	f.Fuzz(func(t *testing.T, value string) {
		digest, err := ParseDigest(value)
		if err != nil {
			return
		}
		if digest.IsZero() || digest.Hex() != value {
			t.Fatalf("ParseDigest(%q) produced a noncanonical digest", value)
		}
	})
}

func FuzzOCIResourceNeverAcceptsMutableOrMismatchedReference(f *testing.F) {
	digest := DigestBytes([]byte("platform image"))
	f.Add("registry.example/agentmemory@sha256:" + digest.Hex())
	f.Add("registry.example/agentmemory:latest")
	f.Add("registry.example/agentmemory@sha256:" + DigestBytes([]byte("other")).Hex())

	f.Fuzz(func(t *testing.T, sourceRef string) {
		platform, err := NewPlatform("linux", "amd64")
		if err != nil {
			t.Fatalf("NewPlatform() error = %v", err)
		}
		resource, err := NewResource(ResourceInput{
			ID: "image", Kind: ResourceKindOCIImage, Purpose: ResourcePurposeOCIPlatformManifest,
			MediaType: MediaTypeOCIManifest, Platform: platform,
			Digest: digest, OCIIndexDigest: DigestBytes([]byte("index")), OCIIndexResourceID: "index", Size: 1,
			SourceRef: sourceRef, SourceAllowlist: []string{sourceRef},
			CycloneDXSBOMResourceID: "cyclonedx", SPDXSBOMResourceID: "spdx",
			ProvenanceResourceID: "provenance", LicenseResourceID: "licenses",
			VulnerabilityResourceID: "vulnerabilities",
		})
		if err != nil {
			return
		}
		wantSuffix := "@sha256:" + digest.Hex()
		if strings.Count(resource.SourceRef(), "@") != 1 || !strings.HasSuffix(resource.SourceRef(), wantSuffix) {
			t.Fatalf("NewResource() accepted mutable or mismatched OCI reference %q", resource.SourceRef())
		}
	})
}

func FuzzDecodeManifestV1NeverNormalizesUntrustedInput(f *testing.F) {
	manifest := mustManifest(f, completeResources(f, mustPlatform(f, "linux", "amd64")))
	f.Add(manifest.CanonicalBytes())
	f.Add([]byte(`{"schema_version":1}`))
	f.Add([]byte(`{"a":1,"a":2}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		manifest, err := DecodeManifestV1(raw)
		if err != nil {
			return
		}
		encoded, err := EncodeManifestV1(manifest)
		if err != nil {
			t.Fatalf("EncodeManifestV1() error = %v", err)
		}
		if !bytes.Equal(encoded, raw) {
			t.Fatal("DecodeManifestV1() accepted bytes that it normalized")
		}
	})
}
