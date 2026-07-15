package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releasepublication"
)

func TestPF001HostPackageBuildsVerifiedDeterministicVendorArchives(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		host, operatingSystem, architecture, extension, manifest string
	}{
		{"claude", "darwin", "arm64", ".mcpb", "manifest.json"},
		{"gemini", "linux", "amd64", ".zip", "gemini-extension.json"},
		{"generic", "windows", "amd64", ".zip", "agentmemory-mcp.json"},
	} {
		test := test
		t.Run(test.host+"-"+test.operatingSystem, func(t *testing.T) {
			t.Parallel()
			fixture := newHostPackageFixture(t, test.host, test.operatingSystem, test.architecture, test.extension)
			verifiers := &verifierSet{}
			if err := AssembleHostPackage(context.Background(), fixture.options, verifiers.factory); err != nil {
				t.Fatalf("AssembleHostPackage() error=%v", err)
			}
			if verifiers.publication.calls != 1 || verifiers.object.calls < 2 {
				t.Fatalf("signature calls publication/object=%d/%d", verifiers.publication.calls, verifiers.object.calls)
			}
			archive, err := zip.OpenReader(fixture.options.Output)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = archive.Close() }()
			names := make([]string, 0, len(archive.File))
			for _, file := range archive.File {
				names = append(names, file.Name)
				if file.Modified.Unix() != fixture.options.SourceEpoch {
					t.Fatalf("%s timestamp=%v", file.Name, file.Modified)
				}
				if file.Name == "bin/"+fixture.executable && file.Mode().Perm() != 0o755 {
					t.Fatalf("bootstrap mode=%o", file.Mode().Perm())
				}
			}
			if len(names) == 0 || !sort.StringsAreSorted(names) || !contains(names, test.manifest) ||
				!contains(names, "bin/"+fixture.executable) {
				t.Fatalf("archive names=%v", names)
			}
			record, err := os.ReadFile(fixture.options.RecordOutput)
			if err != nil || !bytes.Contains(record, []byte(filepath.Base(fixture.options.Output))) ||
				!bytes.Contains(record, []byte(fixture.options.SourceCommit)) {
				t.Fatalf("record=%s error=%v", record, err)
			}
			first, err := os.ReadFile(fixture.options.Output)
			if err != nil {
				t.Fatal(err)
			}
			second := newHostPackageFixture(t, test.host, test.operatingSystem, test.architecture, test.extension)
			if err := AssembleHostPackage(context.Background(), second.options, (&verifierSet{}).factory); err != nil {
				t.Fatal(err)
			}
			secondRaw, _ := os.ReadFile(second.options.Output)
			if !bytes.Equal(first, secondRaw) {
				t.Fatal("identical host package inputs were not reproducible")
			}
		})
	}
}

func TestPF001HostPackageRejectsSubstitutionAndInvalidAuthority(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*hostPackageFixture, *verifierSet){
		"publication identity":  func(f *hostPackageFixture, _ *verifierSet) { f.options.Version = "1.2.4" },
		"publication signature": func(_ *hostPackageFixture, v *verifierSet) { v.publication.err = errors.New("bad") },
		"bootstrap signature":   func(_ *hostPackageFixture, v *verifierSet) { v.object.failCall = 1 },
		"bootstrap link": func(f *hostPackageFixture, _ *verifierSet) {
			_ = os.Remove(f.options.Bootstrap)
			_ = os.Symlink(f.options.TrustDocument, f.options.Bootstrap)
		},
		"native object": func(f *hostPackageFixture, _ *verifierSet) {
			_ = os.WriteFile(filepath.Join(f.options.CandidateRoot, "objects", "agentmemory-linux-amd64-deb.deb"), []byte("changed"), 0o600)
		},
		"native evidence": func(f *hostPackageFixture, _ *verifierSet) {
			_ = os.WriteFile(filepath.Join(f.options.CandidateRoot, "evidence", "agentmemory-linux-amd64-deb.sigstore.json"), []byte("changed"), 0o600)
		},
		"trust factory": func(_ *hostPackageFixture, v *verifierSet) { v.factoryErr = errors.New("trust") },
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newHostPackageFixture(t, "gemini", "linux", "amd64", ".zip")
			verifiers := &verifierSet{}
			mutate(fixture, verifiers)
			if err := AssembleHostPackage(context.Background(), fixture.options, verifiers.factory); err == nil {
				t.Fatal("substitution was accepted")
			}
			if _, err := os.Lstat(fixture.options.Output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed package was published: %v", err)
			}
		})
	}
}

func TestPF001HostPackageRejectsCapabilitiesPathsAndCancellation(t *testing.T) {
	t.Parallel()
	fixture := newHostPackageFixture(t, "claude", "darwin", "amd64", ".mcpb")
	//lint:ignore SA1012 The command boundary must reject an adversarial nil context.
	if err := AssembleHostPackage(nil, fixture.options, (&verifierSet{}).factory); err == nil { //nolint:staticcheck // Boundary fixture; owner=release expiry=2027-07-15.
		t.Fatal("nil context accepted")
	}
	if err := AssembleHostPackage(context.Background(), fixture.options, nil); err == nil {
		t.Fatal("nil factory accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := AssembleHostPackage(cancelled, fixture.options, (&verifierSet{}).factory); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
	for name, mutate := range map[string]func(*PackageOptions){
		"root":             func(value *PackageOptions) { value.CandidateRoot = "" },
		"host":             func(value *PackageOptions) { value.Host = "future" },
		"cell":             func(value *PackageOptions) { value.Architecture = "386" },
		"output extension": func(value *PackageOptions) { value.Output += ".zip" },
		"split output":     func(value *PackageOptions) { value.RecordOutput = filepath.Join(t.TempDir(), "record.json") },
		"same output":      func(value *PackageOptions) { value.RecordOutput = value.Output },
		"existing output":  func(value *PackageOptions) { _ = os.WriteFile(value.Output, []byte("exists"), 0o600) },
	} {
		value := newHostPackageFixture(t, "claude", "darwin", "amd64", ".mcpb")
		mutate(&value.options)
		if err := AssembleHostPackage(context.Background(), value.options, (&verifierSet{}).factory); err == nil {
			t.Fatalf("%s invalid options accepted", name)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"positional"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run(positional)=%d", code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), nil, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "Host package assembly failed") {
		t.Fatalf("run(invalid)=%d stderr=%q", code, stderr.String())
	}
}

func TestPF001HostArchiveHelpersFailClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.WriteFile(source, []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest, size, err := digestRegular(source, 64)
	if err != nil {
		t.Fatal(err)
	}
	if err := copyVerifiedEntry(io.Discard, archiveEntry{}); err == nil {
		t.Fatal("empty archive entry accepted")
	}
	entry := archiveEntry{path: source, digest: digest, size: size + 1, maximum: 64, verifyRead: true}
	if err := copyVerifiedEntry(io.Discard, entry); err == nil {
		t.Fatal("changed source accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := writeArchive(cancelled, filepath.Join(root, "cancelled.zip"), []archiveEntry{{name: "x", content: []byte("x")}}, time.Unix(1_784_073_600, 0)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled archive error=%v", err)
	}
	if _, err := readRegular(filepath.Join(root, "missing"), 1); err == nil {
		t.Fatal("missing input accepted")
	}
}

type signatureVerifierStub struct {
	calls, failCall int
	err             error
}

func (v *signatureVerifierStub) VerifyArtifactSignature(_ context.Context, digest releaseinventory.Digest, bundle []byte) error {
	v.calls++
	if v.err != nil || v.failCall == v.calls || digest.IsZero() || len(bundle) == 0 {
		if v.err != nil {
			return v.err
		}
		return errors.New("signature")
	}
	return nil
}

type verifierSet struct {
	publication signatureVerifierStub
	object      signatureVerifierStub
	factoryErr  error
}

func (v *verifierSet) factory(encoded string) (artifactSignatureVerifier, artifactSignatureVerifier, error) {
	if raw, err := base64.StdEncoding.DecodeString(encoded); err != nil || string(raw) != "trust" {
		return nil, nil, errors.New("encoded trust")
	}
	if v.factoryErr != nil {
		return nil, nil, v.factoryErr
	}
	return &v.publication, &v.object, nil
}

type hostPackageFixture struct {
	options    PackageOptions
	executable string
}

func newHostPackageFixture(t testing.TB, host, operatingSystem, architecture, extension string) *hostPackageFixture {
	t.Helper()
	root := t.TempDir()
	candidate := filepath.Join(root, "candidate")
	if err := os.MkdirAll(filepath.Join(candidate, "objects"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(candidate, "evidence"), 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(path string, raw []byte) string {
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	artifacts := publicationArtifacts(t, candidate, write)
	publication, err := releasepublication.NewPublication(releasepublication.PublicationInput{
		SchemaVersion: 1, ReleaseID: "agentmemory-1.2.3", Version: "1.2.3", BuildID: "build-17",
		SourceCommit: strings.Repeat("a", 40), BuildTimestamp: time.Unix(1_784_073_600, 0).UTC(),
		DistributionEnvelopeDigest: releaseinventory.DigestBytes([]byte("distribution")), DistributionEnvelopeSize: 12,
		ReleaseTrustDigest: releaseinventory.DigestBytes([]byte("release-trust")), ReleaseTrustSize: 13,
		Artifacts: artifacts,
	})
	if err != nil {
		t.Fatal(err)
	}
	publicationRaw, err := releasepublication.EncodeV1(publication)
	if err != nil {
		t.Fatal(err)
	}
	executable := "agentmemory-bootstrap"
	if operatingSystem == "windows" {
		executable += ".exe"
	}
	output := filepath.Join(root, "agentmemory-"+host+"-"+operatingSystem+"-"+architecture+extension)
	return &hostPackageFixture{
		executable: executable,
		options: PackageOptions{
			CandidateRoot:       candidate,
			Publication:         write(filepath.Join(root, "publication.json"), publicationRaw),
			PublicationSigstore: write(filepath.Join(root, "publication.sigstore.json"), []byte("publication signature")),
			Bootstrap:           write(filepath.Join(root, executable), []byte("signed bootstrap "+operatingSystem+" "+architecture)),
			BootstrapSigstore:   write(filepath.Join(root, "bootstrap.sigstore.json"), []byte("bootstrap signature")),
			TrustDocument:       write(filepath.Join(root, "release-trust.json"), []byte("trust")),
			Output:              output, RecordOutput: output + ".record.json", Host: host,
			OperatingSystem: operatingSystem, Architecture: architecture, Version: "1.2.3",
			SourceCommit: strings.Repeat("a", 40), SourceEpoch: 1_784_073_600,
		},
	}
}

func publicationArtifacts(t testing.TB, root string, write func(string, []byte) string) []releasepublication.ArtifactInput {
	t.Helper()
	type cell struct {
		id, os, arch, ext string
		format            releasepublication.Format
		policy            releasepublication.NativePublisherPolicy
	}
	cells := []cell{
		{"agentmemory-darwin-amd64-pkg", "darwin", "amd64", "pkg", releasepublication.FormatPKG, releasepublication.PublisherPolicyAppleNotarized},
		{"agentmemory-darwin-arm64-pkg", "darwin", "arm64", "pkg", releasepublication.FormatPKG, releasepublication.PublisherPolicyAppleNotarized},
		{"agentmemory-linux-amd64-deb", "linux", "amd64", "deb", releasepublication.FormatDEB, releasepublication.PublisherPolicyLinuxPackage},
		{"agentmemory-linux-amd64-rpm", "linux", "amd64", "rpm", releasepublication.FormatRPM, releasepublication.PublisherPolicyLinuxPackage},
		{"agentmemory-linux-arm64-deb", "linux", "arm64", "deb", releasepublication.FormatDEB, releasepublication.PublisherPolicyLinuxPackage},
		{"agentmemory-linux-arm64-rpm", "linux", "arm64", "rpm", releasepublication.FormatRPM, releasepublication.PublisherPolicyLinuxPackage},
		{"agentmemory-windows-amd64-msi", "windows", "amd64", "msi", releasepublication.FormatMSI, releasepublication.PublisherPolicyMicrosoftAuthenticode},
	}
	artifacts := make([]releasepublication.ArtifactInput, 0, 8)
	for _, cell := range cells {
		object := []byte("object:" + cell.id)
		signature := []byte("signature:" + cell.id)
		write(filepath.Join(root, "objects", cell.id+"."+cell.ext), object)
		write(filepath.Join(root, "evidence", cell.id+".sigstore.json"), signature)
		artifacts = append(artifacts, releasepublication.ArtifactInput{
			ID: cell.id, Kind: releasepublication.ArtifactKindNativePackage, OperatingSystem: cell.os,
			Architecture: cell.arch, Format: cell.format, FileName: cell.id + "." + cell.ext,
			MediaType: "application/octet-stream", Digest: releaseinventory.DigestBytes(object), Size: uint64(len(object)),
			CycloneDXSBOMDigest:   releaseinventory.DigestBytes([]byte("cyclonedx:" + cell.id)),
			ProvenanceDigest:      releaseinventory.DigestBytes([]byte("provenance:" + cell.id)),
			SignatureBundleDigest: releaseinventory.DigestBytes(signature), NativePublisherPolicy: cell.policy,
		})
	}
	id := "agentmemory-offline-bundle"
	artifacts = append(artifacts, releasepublication.ArtifactInput{
		ID: id, Kind: releasepublication.ArtifactKindOfflineBundle, Format: releasepublication.FormatTarZstd,
		FileName: id + ".tar.zst", MediaType: "application/octet-stream",
		Digest: releaseinventory.DigestBytes([]byte("offline")), Size: 7,
		CycloneDXSBOMDigest:   releaseinventory.DigestBytes([]byte("cyclonedx:" + id)),
		ProvenanceDigest:      releaseinventory.DigestBytes([]byte("provenance:" + id)),
		SignatureBundleDigest: releaseinventory.DigestBytes([]byte("signature:" + id)),
		NativePublisherPolicy: releasepublication.PublisherPolicyManifestOnly,
	})
	return artifacts
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
