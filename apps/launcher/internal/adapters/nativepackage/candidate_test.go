package nativepackage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releasepublication"
)

func TestPF001CandidateVerifierBindsExactBytesAndPublisher(t *testing.T) {
	t.Parallel()
	artifact, content := candidateArtifactFixture(t)
	root := t.TempDir()
	path := filepath.Join(root, artifact.FileName())
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	publisher := &publisherStub{}
	verifier, err := NewCandidateVerifier(root, publisher)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyCandidate(context.Background(), artifact); err != nil {
		t.Fatalf("VerifyCandidate() error = %v", err)
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if publisher.path != filepath.Join(canonicalRoot, artifact.FileName()) ||
		publisher.artifact.ID() != artifact.ID() {
		t.Fatalf("publisher received %q/%q", publisher.path, publisher.artifact.ID())
	}
}

func TestPF001CandidateVerifierRejectsSubstitutionAndPublisherFailure(t *testing.T) {
	t.Parallel()
	artifact, content := candidateArtifactFixture(t)
	for name, mutate := range map[string]func(string, *publisherStub){
		"different bytes": func(path string, _ *publisherStub) {
			_ = os.WriteFile(path, []byte("substituted package"), 0o600)
		},
		"symlink": func(path string, _ *publisherStub) {
			_ = os.Remove(path)
			_ = os.Symlink("missing", path)
		},
		"publisher": func(_ string, publisher *publisherStub) {
			publisher.err = errors.New("private signer detail")
		},
		"changed during publisher": func(path string, publisher *publisherStub) {
			publisher.mutate = func() { _ = os.WriteFile(path, []byte(strings.Repeat("x", len(content))), 0o600) }
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			path := filepath.Join(root, artifact.FileName())
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatal(err)
			}
			publisher := &publisherStub{}
			mutate(path, publisher)
			verifier, err := NewCandidateVerifier(root, publisher)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifier.VerifyCandidate(context.Background(), artifact); !errors.Is(err, ErrCandidateIntegrity) {
				t.Fatalf("VerifyCandidate() error = %v", err)
			}
		})
	}
}

func TestPF001CandidateVerifierRejectsInvalidCompositionAndCancellation(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if verifier, err := NewCandidateVerifier("relative", &publisherStub{}); verifier != nil ||
		!errors.Is(err, ErrCandidateIntegrity) {
		t.Fatalf("relative root = %T, %v", verifier, err)
	}
	if verifier, err := NewCandidateVerifier(root, (*publisherStub)(nil)); verifier != nil ||
		!errors.Is(err, ErrCandidateIntegrity) {
		t.Fatalf("nil publisher = %T, %v", verifier, err)
	}
	artifact, content := candidateArtifactFixture(t)
	if err := os.WriteFile(filepath.Join(root, artifact.FileName()), content, 0o600); err != nil {
		t.Fatal(err)
	}
	verifier, err := NewCandidateVerifier(root, &publisherStub{})
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifier.VerifyCandidate(cancelled, artifact); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
	var absent *CandidateVerifier
	if err := absent.VerifyCandidate(context.Background(), artifact); !errors.Is(err, ErrCandidateIntegrity) {
		t.Fatalf("nil verifier error = %v", err)
	}
}

type publisherStub struct {
	path     string
	artifact releasepublication.Artifact
	err      error
	mutate   func()
}

func (p *publisherStub) VerifyPublisher(
	_ context.Context,
	path string,
	artifact releasepublication.Artifact,
) error {
	p.path, p.artifact = path, artifact
	if p.mutate != nil {
		p.mutate()
	}
	return p.err
}

func candidateArtifactFixture(t testing.TB) (releasepublication.Artifact, []byte) {
	t.Helper()
	return candidateArtifactFixtureWithSignature(t, releaseinventory.Digest{})
}

func candidateArtifactFixtureWithSignature(
	t testing.TB,
	signatureDigest releaseinventory.Digest,
) (releasepublication.Artifact, []byte) {
	t.Helper()
	publication, content := candidatePublicationFixture(t, signatureDigest)
	artifact, err := publication.NativePackage("linux", "amd64", releasepublication.FormatDEB)
	if err != nil {
		t.Fatal(err)
	}
	return artifact, content
}

func candidatePublicationFixture(
	t testing.TB,
	signatureDigest releaseinventory.Digest,
) (releasepublication.Publication, []byte) {
	t.Helper()
	content := []byte("exact native package fixture")
	digest := func(value string) releaseinventory.Digest { return releaseinventory.DigestBytes([]byte(value)) }
	target := nativeArtifactWithContent("agentmemory-linux-amd64-deb", "linux", "amd64", releasepublication.FormatDEB, releasepublication.PublisherPolicyLinuxPackage, content, digest)
	if !signatureDigest.IsZero() {
		target.SignatureBundleDigest = signatureDigest
	}
	artifacts := []releasepublication.ArtifactInput{
		nativeArtifact("agentmemory-darwin-amd64-pkg", "darwin", "amd64", releasepublication.FormatPKG, releasepublication.PublisherPolicyAppleNotarized, digest),
		nativeArtifact("agentmemory-darwin-arm64-pkg", "darwin", "arm64", releasepublication.FormatPKG, releasepublication.PublisherPolicyAppleNotarized, digest),
		target,
		nativeArtifact("agentmemory-linux-amd64-rpm", "linux", "amd64", releasepublication.FormatRPM, releasepublication.PublisherPolicyLinuxPackage, digest),
		nativeArtifact("agentmemory-linux-arm64-deb", "linux", "arm64", releasepublication.FormatDEB, releasepublication.PublisherPolicyLinuxPackage, digest),
		nativeArtifact("agentmemory-linux-arm64-rpm", "linux", "arm64", releasepublication.FormatRPM, releasepublication.PublisherPolicyLinuxPackage, digest),
		nativeArtifact("agentmemory-windows-amd64-msi", "windows", "amd64", releasepublication.FormatMSI, releasepublication.PublisherPolicyMicrosoftAuthenticode, digest),
		{
			ID: "agentmemory-offline-bundle", Kind: releasepublication.ArtifactKindOfflineBundle,
			Format: releasepublication.FormatTarZstd, FileName: "agentmemory-offline-bundle.tar.zst",
			MediaType: "application/vnd.agentmemory.offline", Digest: digest("offline"), Size: 100,
			CycloneDXSBOMDigest: digest("offline-sbom"), ProvenanceDigest: digest("offline-provenance"),
			SignatureBundleDigest: digest("offline-signature"),
			NativePublisherPolicy: releasepublication.PublisherPolicyManifestOnly,
		},
	}
	publication, err := releasepublication.NewPublication(releasepublication.PublicationInput{
		SchemaVersion: releasepublication.SupportedSchemaMajor, ReleaseID: "release-2026-07",
		Version: "1.2.3", BuildID: "build-17", SourceCommit: strings.Repeat("a", 40),
		BuildTimestamp: time.Unix(1_784_073_600, 0).UTC(), DistributionEnvelopeDigest: digest("manifest"),
		DistributionEnvelopeSize: 100, ReleaseTrustDigest: digest("trust"), ReleaseTrustSize: 100,
		Artifacts: artifacts,
	})
	if err != nil {
		t.Fatal(err)
	}
	return publication, content
}

type digestFactory func(string) releaseinventory.Digest

func nativeArtifact(
	id string, operatingSystem string, architecture string, format releasepublication.Format,
	policy releasepublication.NativePublisherPolicy, digest digestFactory,
) releasepublication.ArtifactInput {
	content := []byte("object:" + id)
	return nativeArtifactWithContent(id, operatingSystem, architecture, format, policy, content, digest)
}

func nativeArtifactWithContent(
	id string, operatingSystem string, architecture string, format releasepublication.Format,
	policy releasepublication.NativePublisherPolicy, content []byte, digest digestFactory,
) releasepublication.ArtifactInput {
	return releasepublication.ArtifactInput{
		ID: id, Kind: releasepublication.ArtifactKindNativePackage, OperatingSystem: operatingSystem,
		Architecture: architecture, Format: format, FileName: id + "." + string(format),
		MediaType: "application/vnd.agentmemory.package", Digest: releaseinventory.DigestBytes(content),
		Size: uint64(len(content)), CycloneDXSBOMDigest: digest(id + "-sbom"),
		ProvenanceDigest: digest(id + "-provenance"), SignatureBundleDigest: digest(id + "-signature"),
		NativePublisherPolicy: policy,
	}
}
