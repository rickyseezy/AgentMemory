package nativepackage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releasepublication"
)

func TestPF001InstalledProductVerifierBindsOuterReleaseAndInnerExecutables(t *testing.T) {
	t.Parallel()
	fixture := newInstalledFixture(t)
	verifier, err := NewInstalledProductVerifier(
		fixture.layout, "linux", "amd64", fixture.decode,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyInstalled(context.Background(), fixture.publication, fixture.artifact); err != nil {
		t.Fatalf("VerifyInstalled() error = %v", err)
	}
	if fixture.decodeCalls != 1 {
		t.Fatalf("decoder calls = %d", fixture.decodeCalls)
	}
}

func TestPF001InstalledProductVerifierRejectsEveryPostconditionSubstitution(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*installedFixture){
		"distribution bytes": func(fixture *installedFixture) {
			_ = os.WriteFile(fixture.layout.DistributionEnvelope, []byte("substituted distribution"), 0o600)
		},
		"decoder": func(fixture *installedFixture) {
			fixture.decodeError = errors.New("private decoder detail")
		},
		"release identity": func(fixture *installedFixture) {
			fixture.authority.releaseID = "another-release"
		},
		"launcher": func(fixture *installedFixture) {
			_ = os.WriteFile(fixture.layout.Launcher, []byte("substituted launcher"), 0o600)
		},
		"helper": func(fixture *installedFixture) {
			_ = os.WriteFile(fixture.layout.RuntimeHelper, []byte("substituted helper"), 0o600)
		},
		"aliased executables": func(fixture *installedFixture) {
			fixture.authority.runtimeHelper = fixture.authority.launcher
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newInstalledFixture(t)
			mutate(fixture)
			verifier, err := NewInstalledProductVerifier(fixture.layout, "linux", "amd64", fixture.decode)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifier.VerifyInstalled(context.Background(), fixture.publication, fixture.artifact); !errors.Is(err, ErrInstalledProductIntegrity) {
				t.Fatalf("VerifyInstalled() error = %v", err)
			}
		})
	}
}

func TestPF001InstalledProductVerifierRejectsInvalidCompositionTargetAndContext(t *testing.T) {
	t.Parallel()
	fixture := newInstalledFixture(t)
	invalid := fixture.layout
	invalid.RuntimeHelper = invalid.Launcher
	if verifier, err := NewInstalledProductVerifier(invalid, "linux", "amd64", fixture.decode); verifier != nil || !errors.Is(err, ErrInstalledProductIntegrity) {
		t.Fatalf("invalid layout = %T, %v", verifier, err)
	}
	if verifier, err := NewInstalledProductVerifier(fixture.layout, "linux", "amd64", nil); verifier != nil || !errors.Is(err, ErrInstalledProductIntegrity) {
		t.Fatalf("nil decoder = %T, %v", verifier, err)
	}
	verifier, err := NewInstalledProductVerifier(fixture.layout, "linux", "amd64", fixture.decode)
	if err != nil {
		t.Fatal(err)
	}
	wrong := selectedNativeArtifact(t, "linux", "arm64", releasepublication.FormatDEB)
	if err := verifier.VerifyInstalled(context.Background(), fixture.publication, wrong); !errors.Is(err, ErrInstalledProductIntegrity) {
		t.Fatalf("wrong target error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifier.VerifyInstalled(cancelled, fixture.publication, fixture.artifact); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
	var absent *InstalledProductVerifier
	if err := absent.VerifyInstalled(context.Background(), fixture.publication, fixture.artifact); !errors.Is(err, ErrInstalledProductIntegrity) {
		t.Fatalf("nil verifier error = %v", err)
	}
	if _, err := decodeInstalledDistribution([]byte(`{"not":"authority"}`), "linux", "amd64"); !errors.Is(err, ErrInstalledProductIntegrity) {
		t.Fatalf("malformed distribution error = %v", err)
	}
}

func TestPF001NativeInstalledLayoutUsesOnlyPlatformOwnedAbsoluteLocations(t *testing.T) {
	t.Parallel()
	layout, err := nativeInstalledLayout()
	if err != nil || !validInstalledLayout(layout) {
		t.Fatalf("nativeInstalledLayout() = %+v, %v", layout, err)
	}
	verifier, err := NewNativeInstalledProductVerifier()
	if err != nil || verifier == nil {
		t.Fatalf("NewNativeInstalledProductVerifier() = %T, %v", verifier, err)
	}
	root, err := NativeInstalledReleaseBundleRoot()
	if err != nil || root != filepath.Dir(filepath.Dir(layout.DistributionEnvelope)) {
		t.Fatalf("NativeInstalledReleaseBundleRoot() = %q, %v", root, err)
	}
}

func TestPF001InstalledDistributionProjectionSelectsExactNativeResources(t *testing.T) {
	t.Parallel()
	platform, err := releaseinventory.NewPlatform("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	launcher := installedSubjectResource(t, "launcher", releaseinventory.ResourceKindLauncher, platform)
	helper := installedSubjectResource(t, "helper", releaseinventory.ResourceKindHelper, platform)
	manifest := &installedManifestStub{resources: []releaseinventory.Resource{launcher, helper}}
	authority, err := projectInstalledDistribution(manifest, "linux", "amd64")
	if err != nil {
		t.Fatalf("projectInstalledDistribution() error = %v", err)
	}
	if authority.releaseID != manifest.releaseID || authority.version != manifest.version ||
		authority.buildID != manifest.buildID || authority.sourceCommit != manifest.sourceCommit ||
		!authority.buildTimestamp.Equal(manifest.buildTimestamp) ||
		!authority.launcher.digest.Equal(launcher.Digest()) || authority.launcher.size != launcher.Size() ||
		!authority.runtimeHelper.digest.Equal(helper.Digest()) || authority.runtimeHelper.size != helper.Size() {
		t.Fatalf("projected authority = %+v", authority)
	}
}

func TestPF001InstalledDistributionProjectionRejectsAmbiguousAuthority(t *testing.T) {
	t.Parallel()
	platform, err := releaseinventory.NewPlatform("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	launcher := installedSubjectResource(t, "launcher", releaseinventory.ResourceKindLauncher, platform)
	helper := installedSubjectResource(t, "helper", releaseinventory.ResourceKindHelper, platform)
	foreign, err := releaseinventory.NewPlatform("linux", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	for name, manifest := range map[string]*installedManifestStub{
		"resource query":     {resourceError: errors.New("private query detail")},
		"missing helper":     {resources: []releaseinventory.Resource{launcher}},
		"duplicate launcher": {resources: []releaseinventory.Resource{launcher, launcher, helper}},
		"foreign launcher": {
			resources: []releaseinventory.Resource{
				installedSubjectResource(t, "foreign-launcher", releaseinventory.ResourceKindLauncher, foreign), helper,
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := projectInstalledDistribution(manifest, "linux", "amd64"); !errors.Is(err, ErrInstalledProductIntegrity) {
				t.Fatalf("projectInstalledDistribution() error = %v", err)
			}
		})
	}
	if _, err := projectInstalledDistribution(nil, "linux", "amd64"); !errors.Is(err, ErrInstalledProductIntegrity) {
		t.Fatalf("nil manifest error = %v", err)
	}
	if _, err := projectInstalledDistribution(&installedManifestStub{}, "unknown", "amd64"); !errors.Is(err, ErrInstalledProductIntegrity) {
		t.Fatalf("invalid platform error = %v", err)
	}
}

type installedManifestStub struct {
	releaseID      string
	version        string
	buildID        string
	sourceCommit   string
	buildTimestamp time.Time
	resources      []releaseinventory.Resource
	resourceError  error
}

func (s *installedManifestStub) ReleaseID() string         { return s.releaseID }
func (s *installedManifestStub) Version() string           { return s.version }
func (s *installedManifestStub) BuildID() string           { return s.buildID }
func (s *installedManifestStub) SourceCommit() string      { return s.sourceCommit }
func (s *installedManifestStub) BuildTimestamp() time.Time { return s.buildTimestamp }
func (s *installedManifestStub) ResourcesFor(releaseinventory.Platform) ([]releaseinventory.Resource, error) {
	return s.resources, s.resourceError
}

func installedSubjectResource(
	t testing.TB,
	id string,
	kind releaseinventory.ResourceKind,
	platform releaseinventory.Platform,
) releaseinventory.Resource {
	t.Helper()
	purpose := releaseinventory.ResourcePurposeNativeLauncher
	if kind == releaseinventory.ResourceKindHelper {
		purpose = releaseinventory.ResourcePurposeNativeHelper
	}
	resource, err := releaseinventory.NewResource(releaseinventory.ResourceInput{
		ID: id, Kind: kind, Purpose: purpose, MediaType: releaseinventory.MediaTypeNativeExecutable,
		Platform: platform, Digest: releaseinventory.DigestBytes([]byte(id)), Size: uint64(len(id)),
		SourceRef: "bundle://" + id, SourceAllowlist: []string{"bundle://" + id},
		CycloneDXSBOMResourceID: id + "-cyclonedx", SPDXSBOMResourceID: id + "-spdx",
		ProvenanceResourceID: id + "-provenance", LicenseResourceID: id + "-license",
		VulnerabilityResourceID: id + "-vulnerability", NativePublisherIdentity: "agentmemory.publisher",
		NativePublisherPolicyID: "agentmemory-native-2026",
	})
	if err != nil {
		t.Fatalf("NewResource(%q) error = %v", id, err)
	}
	return resource
}

type installedFixture struct {
	layout      InstalledLayout
	publication releasepublication.Publication
	artifact    releasepublication.Artifact
	authority   installedDistributionAuthority
	decodeCalls int
	decodeError error
}

func (f *installedFixture) decode(
	_ []byte,
	_ string,
	_ string,
) (installedDistributionAuthority, error) {
	f.decodeCalls++
	return f.authority, f.decodeError
}

func newInstalledFixture(t testing.TB) *installedFixture {
	t.Helper()
	root := t.TempDir()
	distribution := []byte("exact canonical signed distribution envelope")
	launcher := []byte("exact installed launcher")
	helper := []byte("exact installed runtime helper")
	layout := InstalledLayout{
		Launcher: filepath.Join(root, "agentmemory"), RuntimeHelper: filepath.Join(root, "agentmemory-runtime-helper"),
		DistributionEnvelope: filepath.Join(root, "distribution-manifest.json"),
	}
	for path, content := range map[string][]byte{
		layout.DistributionEnvelope: distribution, layout.Launcher: launcher, layout.RuntimeHelper: helper,
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	publication := publicationWithDistribution(t, distribution)
	artifact, err := publication.NativePackage("linux", "amd64", releasepublication.FormatDEB)
	if err != nil {
		t.Fatal(err)
	}
	return &installedFixture{
		layout: layout, publication: publication, artifact: artifact,
		authority: installedDistributionAuthority{
			releaseID: publication.ReleaseID(), version: publication.Version(), buildID: publication.BuildID(),
			sourceCommit: publication.SourceCommit(), buildTimestamp: publication.BuildTimestamp(),
			launcher:      installedFileAuthority{digest: releaseinventory.DigestBytes(launcher), size: uint64(len(launcher))},
			runtimeHelper: installedFileAuthority{digest: releaseinventory.DigestBytes(helper), size: uint64(len(helper))},
		},
	}
}

func publicationWithDistribution(t testing.TB, distribution []byte) releasepublication.Publication {
	t.Helper()
	base, _ := candidatePublicationFixture(t, releaseinventory.Digest{})
	inputs := make([]releasepublication.ArtifactInput, 0, len(base.Artifacts()))
	for _, artifact := range base.Artifacts() {
		inputs = append(inputs, releasepublication.ArtifactInput{
			ID: artifact.ID(), Kind: artifact.Kind(), OperatingSystem: artifact.OperatingSystem(),
			Architecture: artifact.Architecture(), Format: artifact.Format(), FileName: artifact.FileName(),
			MediaType: artifact.MediaType(), Digest: artifact.Digest(), Size: artifact.Size(),
			CycloneDXSBOMDigest: artifact.CycloneDXSBOMDigest(), ProvenanceDigest: artifact.ProvenanceDigest(),
			SignatureBundleDigest: artifact.SignatureBundleDigest(),
			NativePublisherPolicy: artifact.NativePublisherPolicy(),
		})
	}
	publication, err := releasepublication.NewPublication(releasepublication.PublicationInput{
		SchemaVersion: base.SchemaVersion(), ReleaseID: base.ReleaseID(), Version: base.Version(),
		BuildID: base.BuildID(), SourceCommit: base.SourceCommit(), BuildTimestamp: base.BuildTimestamp(),
		DistributionEnvelopeDigest: releaseinventory.DigestBytes(distribution),
		DistributionEnvelopeSize:   uint64(len(distribution)), ReleaseTrustDigest: base.ReleaseTrustDigest(),
		ReleaseTrustSize: base.ReleaseTrustSize(), Artifacts: inputs,
	})
	if err != nil {
		t.Fatal(err)
	}
	return publication
}
