package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releasepublication"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/testsupport/releasefixture"
)

func TestPF001PublicationAssemblerHashesClosedCandidateTree(t *testing.T) {
	t.Parallel()
	fixture := newCandidateFixture(t)
	if err := AssemblePublication(context.Background(), fixture.options, compileFixturePublication); err != nil {
		t.Fatalf("AssemblePublication() error=%v", err)
	}
	raw, err := os.ReadFile(fixture.options.Output)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := releasepublication.DecodeV1(raw)
	if err != nil {
		t.Fatalf("DecodeV1() error=%v", err)
	}
	info, err := os.Lstat(fixture.options.Output)
	if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) ||
		info.ModTime().Unix() != fixture.options.SourceEpoch {
		t.Fatalf("output info=%+v error=%v", info, err)
	}
	if publication.ReleaseID() != fixture.options.ReleaseID || publication.Version() != fixture.options.Version ||
		publication.BuildID() != fixture.options.BuildID || publication.SourceCommit() != fixture.options.SourceCommit ||
		publication.BuildTimestamp().Unix() != fixture.options.SourceEpoch ||
		publication.SchemaVersion() != releasepublication.SupportedSchemaMajor ||
		len(publication.Artifacts()) != len(candidateArtifacts) {
		t.Fatalf("publication=%+v", publication)
	}
	distribution, err := os.ReadFile(filepath.Join(fixture.options.CandidateRoot, distributionEnvelopeName))
	if err != nil || !publication.DistributionEnvelopeDigest().Equal(digestBytes(distribution)) ||
		publication.DistributionEnvelopeSize() != uint64(len(distribution)) {
		t.Fatalf("distribution binding error=%v", err)
	}
	releaseTrust, err := os.ReadFile(filepath.Join(fixture.options.CandidateRoot, releaseTrustName))
	if err != nil || !publication.ReleaseTrustDigest().Equal(digestBytes(releaseTrust)) ||
		publication.ReleaseTrustSize() != uint64(len(releaseTrust)) {
		t.Fatalf("release-trust binding error=%v", err)
	}
	parts, err := inspectCandidate(fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	actual := publication.Artifacts()
	expected := append([]releasepublication.ArtifactInput(nil), parts.artifacts...)
	sort.Slice(expected, func(left, right int) bool { return expected[left].ID < expected[right].ID })
	for index := range actual {
		if !publicationArtifactMatchesInput(actual[index], expected[index]) {
			t.Fatalf("artifact[%d]=%+v expected=%+v", index, actual[index], expected[index])
		}
	}
}

func TestPF001PublicationCandidateDefinitionsAreExact(t *testing.T) {
	t.Parallel()
	definition := candidate(
		"package-id", "linux", "arm64", releasepublication.FormatRPM, "application/x-rpm",
		releasepublication.PublisherPolicyLinuxPackage,
	)
	if definition.id != "package-id" || definition.objectPath != "objects/package-id.rpm" ||
		definition.cycloneDXPath != "evidence/package-id.cyclonedx.json" ||
		definition.provenancePath != "evidence/package-id.provenance.json" ||
		definition.signaturePath != "evidence/package-id.sigstore.json" ||
		definition.kind != releasepublication.ArtifactKindNativePackage || definition.operatingSystem != "linux" ||
		definition.architecture != "arm64" || definition.format != releasepublication.FormatRPM ||
		definition.mediaType != "application/x-rpm" ||
		definition.publisherPolicy != releasepublication.PublisherPolicyLinuxPackage {
		t.Fatalf("candidate()=%+v", definition)
	}
}

func TestPF001PublicationStaticAuthorityIsExact(t *testing.T) {
	t.Parallel()
	if distributionEnvelopeName != "distribution-manifest.json" || releaseTrustName != "release-trust.json" ||
		maximumEvidenceSize != 64*1024*1024 || maximumEnvelopeSize != 32*1024*1024 ||
		maximumSafeFileSize != int64(1<<53-1) {
		t.Fatal("publication security boundaries changed")
	}
	want := []candidateArtifact{
		candidate("agentmemory-darwin-amd64-pkg", "darwin", "amd64", releasepublication.FormatPKG,
			"application/vnd.apple.installer+xml", releasepublication.PublisherPolicyAppleNotarized),
		candidate("agentmemory-darwin-arm64-pkg", "darwin", "arm64", releasepublication.FormatPKG,
			"application/vnd.apple.installer+xml", releasepublication.PublisherPolicyAppleNotarized),
		candidate("agentmemory-linux-amd64-deb", "linux", "amd64", releasepublication.FormatDEB,
			"application/vnd.debian.binary-package", releasepublication.PublisherPolicyLinuxPackage),
		candidate("agentmemory-linux-amd64-rpm", "linux", "amd64", releasepublication.FormatRPM,
			"application/x-rpm", releasepublication.PublisherPolicyLinuxPackage),
		candidate("agentmemory-linux-arm64-deb", "linux", "arm64", releasepublication.FormatDEB,
			"application/vnd.debian.binary-package", releasepublication.PublisherPolicyLinuxPackage),
		candidate("agentmemory-linux-arm64-rpm", "linux", "arm64", releasepublication.FormatRPM,
			"application/x-rpm", releasepublication.PublisherPolicyLinuxPackage),
		candidate("agentmemory-windows-amd64-msi", "windows", "amd64", releasepublication.FormatMSI,
			"application/x-msi", releasepublication.PublisherPolicyMicrosoftAuthenticode),
		{
			id: "agentmemory-offline-bundle", objectPath: "objects/agentmemory-offline-bundle.tar.zst",
			cycloneDXPath:   "evidence/agentmemory-offline-bundle.cyclonedx.json",
			provenancePath:  "evidence/agentmemory-offline-bundle.provenance.json",
			signaturePath:   "evidence/agentmemory-offline-bundle.sigstore.json",
			kind:            releasepublication.ArtifactKindOfflineBundle,
			format:          releasepublication.FormatTarZstd,
			mediaType:       "application/vnd.agentmemory.offline-bundle+zstd",
			publisherPolicy: releasepublication.PublisherPolicyManifestOnly,
		},
	}
	if len(candidateArtifacts) != len(want) {
		t.Fatalf("candidate artifact count=%d want=%d", len(candidateArtifacts), len(want))
	}
	for index := range want {
		if candidateArtifacts[index] != want[index] {
			t.Fatalf("candidateArtifacts[%d]=%+v want=%+v", index, candidateArtifacts[index], want[index])
		}
	}
}

func TestPF001PublicationAssemblerRejectsOpenOrChangedCandidateTrees(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*candidateFixture){
		"missing object": func(fixture *candidateFixture) {
			_ = os.Remove(filepath.Join(fixture.options.CandidateRoot, candidateArtifacts[0].objectPath))
		},
		"extra object": func(fixture *candidateFixture) {
			_ = os.WriteFile(filepath.Join(fixture.options.CandidateRoot, "unreviewed"), []byte("extra"), 0o600)
		},
		"extra directory": func(fixture *candidateFixture) {
			_ = os.Mkdir(filepath.Join(fixture.options.CandidateRoot, "unreviewed"), 0o700)
		},
		"object directory": func(fixture *candidateFixture) {
			path := filepath.Join(fixture.options.CandidateRoot, candidateArtifacts[0].objectPath)
			_ = os.Remove(path)
			_ = os.Mkdir(path, 0o700)
		},
		"symlink": func(fixture *candidateFixture) {
			path := filepath.Join(fixture.options.CandidateRoot, candidateArtifacts[0].objectPath)
			_ = os.Remove(path)
			_ = os.Symlink(distributionEnvelopeName, path)
		},
		"empty evidence": func(fixture *candidateFixture) {
			_ = os.WriteFile(filepath.Join(fixture.options.CandidateRoot, candidateArtifacts[0].cycloneDXPath), nil, 0o600)
		},
		"existing output": func(fixture *candidateFixture) {
			_ = os.WriteFile(fixture.options.Output, []byte("existing"), 0o600)
		},
		"output parent link": func(fixture *candidateFixture) {
			parent := filepath.Join(filepath.Dir(fixture.options.Output), "real-parent")
			_ = os.Mkdir(parent, 0o700)
			link := filepath.Join(filepath.Dir(fixture.options.Output), "parent-link")
			_ = os.Symlink(parent, link)
			fixture.options.Output = filepath.Join(link, "publication.json")
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newCandidateFixture(t)
			mutate(fixture)
			if err := AssemblePublication(context.Background(), fixture.options, compileFixturePublication); err == nil {
				t.Fatal("AssemblePublication() error=nil")
			}
		})
	}
}

func TestPF001PublicationAssemblerRejectsInvalidCapabilitiesAndIdentity(t *testing.T) {
	t.Parallel()
	fixture := newCandidateFixture(t)
	if err := AssemblePublication(context.Background(), fixture.options, nil); err == nil {
		t.Fatal("nil compiler accepted")
	}
	if err := AssemblePublication(context.Background(), fixture.options,
		func(publicationParts) ([]byte, error) { return nil, errors.New("compile") }); err == nil {
		t.Fatal("compiler failure accepted")
	}
	if err := AssemblePublication(context.Background(), fixture.options,
		func(publicationParts) ([]byte, error) { return nil, nil }); err == nil {
		t.Fatal("empty compiler output accepted")
	}
	if err := AssemblePublication(context.Background(), fixture.options,
		func(publicationParts) ([]byte, error) { return make([]byte, maximumEnvelopeSize+1), nil }); err == nil {
		t.Fatal("oversized compiler output accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := AssemblePublication(cancelled, fixture.options, compileFixturePublication); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
	for name, mutate := range map[string]func(*PublicationOptions){
		"root":    func(options *PublicationOptions) { options.CandidateRoot = "" },
		"release": func(options *PublicationOptions) { options.ReleaseID = "" },
		"version": func(options *PublicationOptions) { options.Version = "latest" },
		"build":   func(options *PublicationOptions) { options.BuildID = "" },
		"commit":  func(options *PublicationOptions) { options.SourceCommit = strings.Repeat("A", 40) },
		"epoch":   func(options *PublicationOptions) { options.SourceEpoch = 0 },
		"output":  func(options *PublicationOptions) { options.Output = "" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := newCandidateFixture(t)
			mutate(&candidate.options)
			if err := AssemblePublication(context.Background(), candidate.options, compileFixturePublication); err == nil {
				t.Fatal("AssemblePublication() error=nil")
			}
		})
	}
}

func TestPF001PublicationResolverAndCompilerBoundariesAreExact(t *testing.T) {
	t.Parallel()
	for name, clearField := range map[string]func(*PublicationOptions){
		"candidate root": func(value *PublicationOptions) { value.CandidateRoot = "" },
		"output":         func(value *PublicationOptions) { value.Output = "" },
		"release ID":     func(value *PublicationOptions) { value.ReleaseID = "" },
		"version":        func(value *PublicationOptions) { value.Version = "" },
		"build ID":       func(value *PublicationOptions) { value.BuildID = "" },
		"source commit":  func(value *PublicationOptions) { value.SourceCommit = "" },
		"zero epoch":     func(value *PublicationOptions) { value.SourceEpoch = 0 },
		"negative epoch": func(value *PublicationOptions) { value.SourceEpoch = -1 },
	} {
		fixture := newCandidateFixture(t)
		clearField(&fixture.options)
		resolved, err := resolveOptions(fixture.options)
		if resolved != (PublicationOptions{}) || err == nil ||
			err.Error() != "publication assembly inputs are incomplete" {
			t.Fatalf("%s resolved=%+v error=%v", name, resolved, err)
		}
	}
	fixture := newCandidateFixture(t)
	resolved, err := resolveOptions(fixture.options)
	if err != nil || !filepath.IsAbs(resolved.CandidateRoot) || !filepath.IsAbs(resolved.Output) ||
		resolved.ReleaseID != fixture.options.ReleaseID || resolved.Version != fixture.options.Version ||
		resolved.BuildID != fixture.options.BuildID || resolved.SourceCommit != fixture.options.SourceCommit ||
		resolved.SourceEpoch != fixture.options.SourceEpoch {
		t.Fatalf("resolveOptions(valid)=%+v,%v", resolved, err)
	}

	for name, compile := range map[string]publicationCompiler{
		"error": func(publicationParts) ([]byte, error) {
			return []byte(`{"schema_version":1}`), errors.New("compiler")
		},
		"empty": func(publicationParts) ([]byte, error) { return nil, nil },
		"oversized": func(publicationParts) ([]byte, error) {
			return make([]byte, maximumEnvelopeSize+1), nil
		},
	} {
		candidate := newCandidateFixture(t)
		err := AssemblePublication(t.Context(), candidate.options, compile)
		if err == nil || err.Error() != "publication compiler rejected the qualified candidate" {
			t.Fatalf("%s compiler error=%v", name, err)
		}
	}
}

func TestPF001PublicationInspectionReportsEveryAuthorityStage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		path   func(*candidateFixture) string
		prefix string
	}{
		{
			name: "distribution", path: func(fixture *candidateFixture) string {
				return filepath.Join(fixture.options.CandidateRoot, distributionEnvelopeName)
			}, prefix: "read distribution envelope: ",
		},
		{
			name: "release trust", path: func(fixture *candidateFixture) string {
				return filepath.Join(fixture.options.CandidateRoot, releaseTrustName)
			}, prefix: "hash release trust: ",
		},
		{
			name: "object", path: func(fixture *candidateFixture) string {
				return filepath.Join(fixture.options.CandidateRoot, candidateArtifacts[0].objectPath)
			}, prefix: "hash candidate " + candidateArtifacts[0].id + ": ",
		},
		{
			name: "cyclonedx", path: func(fixture *candidateFixture) string {
				return filepath.Join(fixture.options.CandidateRoot, candidateArtifacts[0].cycloneDXPath)
			}, prefix: "hash candidate evidence " + candidateArtifacts[0].id + ": ",
		},
		{
			name: "provenance", path: func(fixture *candidateFixture) string {
				return filepath.Join(fixture.options.CandidateRoot, candidateArtifacts[0].provenancePath)
			}, prefix: "hash candidate evidence " + candidateArtifacts[0].id + ": ",
		},
		{
			name: "signature", path: func(fixture *candidateFixture) string {
				return filepath.Join(fixture.options.CandidateRoot, candidateArtifacts[0].signaturePath)
			}, prefix: "hash candidate evidence " + candidateArtifacts[0].id + ": ",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newCandidateFixture(t)
			if err := os.WriteFile(test.path(fixture), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := inspectCandidate(fixture.options)
			if err == nil || errors.Unwrap(err) == nil || !strings.HasPrefix(err.Error(), test.prefix) {
				t.Fatalf("inspectCandidate() error=%v", err)
			}
		})
	}
}

func TestPF001ProductionPublicationRejectsEachDistributionIdentitySubstitution(t *testing.T) {
	t.Parallel()
	fixture := newProductionCandidateFixture(t)
	parts, err := inspectCandidate(fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*PublicationOptions){
		"release ID":    func(value *PublicationOptions) { value.ReleaseID = "other-release" },
		"version":       func(value *PublicationOptions) { value.Version = "2.0.0" },
		"build ID":      func(value *PublicationOptions) { value.BuildID = "other-build" },
		"source commit": func(value *PublicationOptions) { value.SourceCommit = strings.Repeat("b", 40) },
		"source epoch":  func(value *PublicationOptions) { value.SourceEpoch++ },
	} {
		changed := parts.clone()
		mutate(&changed.options)
		if _, err := compilePublication(changed); err == nil ||
			err.Error() != "distribution identity disagrees with publication identity" {
			t.Fatalf("%s error=%v", name, err)
		}
	}
}

func TestPF001PublicationPartsCloneAndAuthorityComparisonAreExact(t *testing.T) {
	t.Parallel()
	fixture := newCandidateFixture(t)
	parts, err := inspectCandidate(fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := compilePublicationRecord(parts)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := releasepublication.DecodeV1(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !publicationMatchesParts(publication, parts) {
		t.Fatal("exact publication did not match inspected candidate")
	}
	clone := parts.clone()
	clone.distribution[0] ^= 0xff
	clone.artifacts[0].ID = "different-id"
	if bytes.Equal(clone.distribution, parts.distribution) || clone.artifacts[0].ID == parts.artifacts[0].ID {
		t.Fatal("publicationParts.clone() aliased mutable input")
	}

	mutations := []struct {
		name string
		edit func(*publicationParts)
	}{
		{"release ID", func(value *publicationParts) { value.options.ReleaseID = "other-release" }},
		{"version", func(value *publicationParts) { value.options.Version = "9.9.9" }},
		{"build ID", func(value *publicationParts) { value.options.BuildID = "other-build" }},
		{"source commit", func(value *publicationParts) { value.options.SourceCommit = strings.Repeat("b", 40) }},
		{"source epoch", func(value *publicationParts) { value.options.SourceEpoch++ }},
		{"distribution digest", func(value *publicationParts) { value.distributionDigest[0] ^= 0xff }},
		{"distribution size", func(value *publicationParts) { value.distributionSize++ }},
		{"release trust digest", func(value *publicationParts) { value.releaseTrustDigest[0] ^= 0xff }},
		{"release trust size", func(value *publicationParts) { value.releaseTrustSize++ }},
		{"artifact count", func(value *publicationParts) { value.artifacts = value.artifacts[1:] }},
		{"artifact ID", func(value *publicationParts) { value.artifacts[0].ID = "other-id" }},
		{"artifact kind", func(value *publicationParts) { value.artifacts[0].Kind = releasepublication.ArtifactKindOfflineBundle }},
		{"artifact OS", func(value *publicationParts) { value.artifacts[0].OperatingSystem = "other" }},
		{"artifact architecture", func(value *publicationParts) { value.artifacts[0].Architecture = "other" }},
		{"artifact format", func(value *publicationParts) { value.artifacts[0].Format = releasepublication.FormatRPM }},
		{"artifact filename", func(value *publicationParts) { value.artifacts[0].FileName = "other.pkg" }},
		{"artifact media type", func(value *publicationParts) { value.artifacts[0].MediaType = "application/other" }},
		{"artifact digest", func(value *publicationParts) { value.artifacts[0].Digest[0] ^= 0xff }},
		{"artifact size", func(value *publicationParts) { value.artifacts[0].Size++ }},
		{"artifact SBOM", func(value *publicationParts) { value.artifacts[0].CycloneDXSBOMDigest[0] ^= 0xff }},
		{"artifact provenance", func(value *publicationParts) { value.artifacts[0].ProvenanceDigest[0] ^= 0xff }},
		{"artifact signature", func(value *publicationParts) { value.artifacts[0].SignatureBundleDigest[0] ^= 0xff }},
		{"artifact publisher", func(value *publicationParts) {
			value.artifacts[0].NativePublisherPolicy = releasepublication.PublisherPolicyLinuxPackage
		}},
	}
	for _, mutation := range mutations {
		mutation := mutation
		t.Run(mutation.name, func(t *testing.T) {
			t.Parallel()
			changed := parts.clone()
			mutation.edit(&changed)
			if publicationMatchesParts(publication, changed) {
				t.Fatal("substituted publication authority matched")
			}
		})
	}
}

func TestPF001PublicationFileReadersEnforceExactBoundsAndTypes(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	one := filepath.Join(root, "one")
	if err := os.WriteFile(one, []byte{'x'}, 0o600); err != nil {
		t.Fatal(err)
	}
	content, err := readBoundedRegular(one, 1)
	if err != nil || string(content) != "x" {
		t.Fatalf("readBoundedRegular()=%q,%v", content, err)
	}
	digest, size, err := digestRegularFile(one, 1)
	if err != nil || size != 1 || !digest.Equal(digestBytes([]byte{'x'})) {
		t.Fatalf("digestRegularFile()=%s,%d,%v", digest.Hex(), size, err)
	}
	empty := filepath.Join(root, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(one, link); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"missing": filepath.Join(root, "missing"), "directory": root, "empty": empty, "link": link} {
		if _, err := readBoundedRegular(path, 1); err == nil {
			t.Fatalf("readBoundedRegular(%s) accepted", name)
		}
		if _, _, err := digestRegularFile(path, 1); err == nil {
			t.Fatalf("digestRegularFile(%s) accepted", name)
		}
	}
	if _, err := readBoundedRegular(one, 0); err == nil {
		t.Fatal("readBoundedRegular accepted an over-limit file")
	}
	if _, _, err := digestRegularFile(one, 0); err == nil {
		t.Fatal("digestRegularFile accepted an over-limit file")
	}
}

func TestPF001PublicationVerifierRehashesBeforePromotion(t *testing.T) {
	t.Parallel()
	fixture := newCandidateFixture(t)
	if err := AssemblePublication(context.Background(), fixture.options, compileFixturePublication); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPublication(
		context.Background(), fixture.options.CandidateRoot, fixture.options.Output,
	); err != nil {
		t.Fatalf("VerifyPublication() error=%v", err)
	}
	object := filepath.Join(fixture.options.CandidateRoot, candidateArtifacts[0].objectPath)
	if err := os.WriteFile(object, []byte("substituted exact object"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPublication(context.Background(), fixture.options.CandidateRoot, fixture.options.Output); err == nil {
		t.Fatal("changed candidate was accepted")
	}
}

func TestPF001PublicationVerifierRejectsMalformedAuthorityAndCapabilities(t *testing.T) {
	t.Parallel()
	fixture := newCandidateFixture(t)
	if err := AssemblePublication(context.Background(), fixture.options, compileFixturePublication); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.options.Output, []byte(`{"open":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPublication(context.Background(), fixture.options.CandidateRoot, fixture.options.Output); err == nil {
		t.Fatal("malformed publication was accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := VerifyPublication(cancelled, fixture.options.CandidateRoot, fixture.options.Output); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
}

func TestPF001PublicationVerifierInputAndPathFailuresAreExact(t *testing.T) {
	t.Parallel()
	fixture := newCandidateFixture(t)
	for name, test := range map[string]struct {
		ctx          context.Context
		root, record string
	}{
		"nil context":    {nil, fixture.options.CandidateRoot, fixture.options.Output},
		"missing root":   {t.Context(), "", fixture.options.Output},
		"missing record": {t.Context(), fixture.options.CandidateRoot, ""},
	} {
		err := VerifyPublication(test.ctx, test.root, test.record)
		if err == nil || err.Error() != "publication verification inputs are incomplete" {
			t.Fatalf("%s error=%v", name, err)
		}
	}
	rootFile := filepath.Join(t.TempDir(), "candidate-file")
	if err := os.WriteFile(rootFile, []byte("candidate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPublication(t.Context(), rootFile, fixture.options.Output); err == nil ||
		err.Error() != "candidate root must be a non-symlink directory" {
		t.Fatalf("file root error=%v", err)
	}
	rootLink := filepath.Join(t.TempDir(), "candidate-link")
	if err := os.Symlink(fixture.options.CandidateRoot, rootLink); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPublication(t.Context(), rootLink, fixture.options.Output); err == nil ||
		err.Error() != "candidate root must be a non-symlink directory" {
		t.Fatalf("linked root error=%v", err)
	}
	missingRecord := filepath.Join(t.TempDir(), "missing-publication.json")
	if err := VerifyPublication(t.Context(), fixture.options.CandidateRoot, missingRecord); err == nil ||
		errors.Unwrap(err) == nil || !strings.HasPrefix(err.Error(), "read publication record: ") {
		t.Fatalf("missing record error=%v", err)
	}
}

func TestPF001PublicationCommandFailsClosed(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"positional"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run(positional)=%d", code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), nil, &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "Publication record creation failed") {
		t.Fatalf("run(invalid)=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestPF001PublicationCommandVerifiesCandidateMode(t *testing.T) {
	t.Parallel()
	fixture := newCandidateFixture(t)
	if err := AssemblePublication(context.Background(), fixture.options, compileFixturePublication); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{
		"-candidate-root", fixture.options.CandidateRoot,
		"-verify-record", fixture.options.Output,
	}, &stdout, &stderr)
	if code != 0 || stdout.String() != fixture.options.Output+"\n" || stderr.Len() != 0 {
		t.Fatalf("run(verify)=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestPF001PublicationCommandVerificationModeIsClosed(t *testing.T) {
	t.Parallel()
	fixture := newCandidateFixture(t)
	if err := AssemblePublication(context.Background(), fixture.options, compileFixturePublication); err != nil {
		t.Fatal(err)
	}
	conflicts := [][]string{
		{"-output", "out"}, {"-release-id", "release"}, {"-version", "1.2.3"},
		{"-build-id", "build"}, {"-source-commit", strings.Repeat("a", 40)},
		{"-source-date-epoch", "1"},
	}
	for _, conflict := range conflicts {
		args := append([]string{"-candidate-root", fixture.options.CandidateRoot, "-verify-record", fixture.options.Output}, conflict...)
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), args, &stdout, &stderr); code != 2 || stdout.Len() != 0 ||
			stderr.String() != "verification mode accepts only -candidate-root and -verify-record\n" {
			t.Fatalf("run(%v)=%d stdout=%q stderr=%q", conflict, code, stdout.String(), stderr.String())
		}
	}
	var stderr bytes.Buffer
	if code := run(context.Background(), []string{
		"-candidate-root", fixture.options.CandidateRoot, "-verify-record", fixture.options.Output,
	}, failingWriter{}, &stderr); code != 1 {
		t.Fatalf("run(stdout failure)=%d stderr=%q", code, stderr.String())
	}
}

func TestPF001PublicationCommandParsesTheCompleteCreationContract(t *testing.T) {
	t.Parallel()
	fixture := newCandidateFixture(t)
	args := []string{
		"-candidate-root", fixture.options.CandidateRoot,
		"-output", fixture.options.Output,
		"-release-id", fixture.options.ReleaseID,
		"-version", fixture.options.Version,
		"-build-id", fixture.options.BuildID,
		"-source-commit", fixture.options.SourceCommit,
		"-source-date-epoch", "1784073600",
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), args, &stdout, &stderr); code != 1 || stdout.Len() != 0 ||
		!strings.HasPrefix(stderr.String(), "Publication record creation failed: ") {
		t.Fatalf("run(full contract)=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"-unknown"}, &stdout, &stderr); code != 2 || stderr.Len() == 0 {
		t.Fatalf("run(unknown)=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestPF001ProductionPublicationCompilerRejectsUnboundDistributionIdentity(t *testing.T) {
	t.Parallel()
	fixture := newCandidateFixture(t)
	parts, err := inspectCandidate(fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compilePublication(parts); err == nil {
		t.Fatal("noncanonical distribution envelope was accepted by the production compiler")
	}
	parts.distribution = nil
	if _, err := compilePublication(parts); err == nil {
		t.Fatal("missing distribution envelope was accepted by the production compiler")
	}
}

func TestPF001ProductionPublicationCompilerCommandAndVerifierPublishExactAuthority(t *testing.T) {
	t.Parallel()
	fixture := newProductionCandidateFixture(t)
	if err := AssemblePublication(t.Context(), fixture.options, compilePublication); err != nil {
		t.Fatalf("AssemblePublication(production) error=%v", err)
	}
	raw, err := os.ReadFile(fixture.options.Output)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := releasepublication.DecodeV1(raw)
	if err != nil {
		t.Fatalf("DecodeV1() error=%v", err)
	}
	distribution, err := os.ReadFile(filepath.Join(fixture.options.CandidateRoot, distributionEnvelopeName))
	if err != nil {
		t.Fatal(err)
	}
	if publication.ReleaseID() != releasefixture.ReleaseID || publication.Version() != releasefixture.Version ||
		publication.BuildID() != releasefixture.BuildID || publication.SourceCommit() != releasefixture.SourceCommit ||
		publication.BuildTimestamp().Unix() != releasefixture.SourceEpoch ||
		!publication.DistributionEnvelopeDigest().Equal(releaseinventory.DigestBytes(distribution)) ||
		publication.DistributionEnvelopeSize() != uint64(len(distribution)) ||
		len(publication.Artifacts()) != len(candidateArtifacts) {
		t.Fatal("production publication lost qualified candidate authority")
	}
	info, err := os.Stat(fixture.options.Output)
	if err != nil || info.ModTime().Unix() != releasefixture.SourceEpoch || info.ModTime().Nanosecond() != 0 {
		t.Fatalf("production publication timestamp=%v error=%v", info, err)
	}
	if err := VerifyPublication(t.Context(), fixture.options.CandidateRoot, fixture.options.Output); err != nil {
		t.Fatalf("VerifyPublication(production) error=%v", err)
	}

	command := newProductionCandidateFixture(t)
	args := []string{
		"-candidate-root", command.options.CandidateRoot,
		"-output", command.options.Output,
		"-release-id", command.options.ReleaseID,
		"-version", command.options.Version,
		"-build-id", command.options.BuildID,
		"-source-commit", command.options.SourceCommit,
		"-source-date-epoch", strconv.FormatInt(command.options.SourceEpoch, 10),
	}
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), args, &stdout, &stderr); code != 0 ||
		stdout.String() != command.options.Output+"\n" || stderr.Len() != 0 {
		t.Fatalf("run(production)=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

type candidateFixture struct {
	options PublicationOptions
}

func compileFixturePublication(parts publicationParts) ([]byte, error) {
	return compilePublicationRecord(parts)
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func newCandidateFixture(t testing.TB) *candidateFixture {
	t.Helper()
	root := t.TempDir()
	candidate := filepath.Join(root, "candidate")
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(relative string, content []byte) {
		path := filepath.Join(candidate, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(distributionEnvelopeName, []byte(`{"signed":"distribution"}`))
	write(releaseTrustName, []byte(`{"schemaVersion":1,"publicAuthority":"fixture"}`))
	for _, artifact := range candidateArtifacts {
		write(artifact.objectPath, []byte("object:"+artifact.id))
		write(artifact.cycloneDXPath, []byte(`{"bomFormat":"CycloneDX","subject":"`+artifact.id+`"}`))
		write(artifact.provenancePath, []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":"`+artifact.id+`"}`))
		write(artifact.signaturePath, []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","subject":"`+artifact.id+`"}`))
	}
	return &candidateFixture{options: PublicationOptions{
		CandidateRoot: candidate, Output: filepath.Join(root, "publication.json"),
		ReleaseID: "release-2026-07", Version: "1.2.3", BuildID: "build-17",
		SourceCommit: strings.Repeat("a", 40), SourceEpoch: 1_784_073_600,
	}}
}

func newProductionCandidateFixture(t testing.TB) *candidateFixture {
	t.Helper()
	fixture := newCandidateFixture(t)
	distribution, err := releasefixture.SignedEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(fixture.options.CandidateRoot, distributionEnvelopeName), distribution, 0o600,
	); err != nil {
		t.Fatal(err)
	}
	fixture.options.ReleaseID = releasefixture.ReleaseID
	fixture.options.Version = releasefixture.Version
	fixture.options.BuildID = releasefixture.BuildID
	fixture.options.SourceCommit = releasefixture.SourceCommit
	fixture.options.SourceEpoch = releasefixture.SourceEpoch
	return fixture
}
