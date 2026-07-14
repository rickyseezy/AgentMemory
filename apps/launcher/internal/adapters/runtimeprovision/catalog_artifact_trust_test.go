package runtimeprovision

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
)

func TestCatalogLinuxArtifactVerifierReadsAndBindsEveryExactCASObject(t *testing.T) {
	plan, content := trustReaderPlan(t)
	reader := &verifiedFinalReaderStub{content: content}
	verifier := &CatalogLinuxArtifactVerifier{reader: reader}
	digest, resources, err := verifier.readAndBindLinuxArtifacts(context.Background(), plan)
	if err != nil || digest.IsZero() {
		t.Fatalf("readAndBindLinuxArtifacts() = %s, %v", digest, err)
	}
	if !bytes.Equal(resources["repo-docker-stable-signing_key"], content["repo-docker-stable-signing_key"]) ||
		len(resources) != 1 || reader.opens != len(plan.Artifacts()) {
		t.Fatalf("resources=%v opens=%d", resources, reader.opens)
	}
	if artifact, present := linuxArtifactByID(plan, "docker-ce"); !present || artifact.ID() != "docker-ce" {
		t.Fatal("exact package descriptor was not found")
	}
	if _, present := linuxArtifactByID(plan, "missing"); present {
		t.Fatal("missing package descriptor was found")
	}
}

func TestCatalogLinuxArtifactVerifierMapsCASBoundaryFailures(t *testing.T) {
	plan, content := trustReaderPlan(t)
	tests := []struct {
		name   string
		reader *verifiedFinalReaderStub
		want   error
	}{
		{name: "missing", reader: &verifiedFinalReaderStub{openErr: artifactapp.ErrArtifactNotFound}, want: runtimeport.ErrLinuxArtifactUnavailable},
		{name: "store", reader: &verifiedFinalReaderStub{openErr: artifactapp.ErrStoreOperation}, want: runtimeport.ErrLinuxArtifactUnavailable},
		{name: "private open", reader: &verifiedFinalReaderStub{openErr: errors.New("private")}, want: runtimeport.ErrLinuxArtifactIntegrity},
		{name: "short", reader: &verifiedFinalReaderStub{content: map[string][]byte{
			"repo-docker-stable-signing_key": content["repo-docker-stable-signing_key"][:2], "docker-ce": content["docker-ce"],
		}}, want: runtimeport.ErrLinuxArtifactIntegrity},
		{name: "long", reader: &verifiedFinalReaderStub{content: map[string][]byte{
			"repo-docker-stable-signing_key": append(append([]byte(nil), content["repo-docker-stable-signing_key"]...), 'x'), "docker-ce": content["docker-ce"],
		}}, want: runtimeport.ErrLinuxArtifactIntegrity},
		{name: "read", reader: &verifiedFinalReaderStub{content: content, readErr: errors.New("read")}, want: runtimeport.ErrLinuxArtifactIntegrity},
		{name: "close", reader: &verifiedFinalReaderStub{content: content, closeErr: errors.New("close")}, want: runtimeport.ErrLinuxArtifactIntegrity},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier := &CatalogLinuxArtifactVerifier{reader: test.reader}
			_, _, err := verifier.readAndBindLinuxArtifacts(context.Background(), plan)
			if !errors.Is(err, test.want) {
				t.Fatalf("readAndBindLinuxArtifacts() error = %v, want %v", err, test.want)
			}
		})
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := mapLinuxArtifactReadError(cancelled, errors.New("private")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled read error = %v", err)
	}
}

func TestCatalogLinuxArtifactVerifierRejectsUnverifiedCompositionAndMapsArchitectures(t *testing.T) {
	reader := &verifiedFinalReaderStub{}
	clock := &fakeClock{}
	if _, err := NewCatalogLinuxArtifactVerifier(runtimecatalogapp.VerifiedCatalog{}, reader, clock); err == nil {
		t.Fatal("unverified APT catalog was accepted")
	}
	if _, err := NewCatalogLinuxArtifactVerifierWithRPMKeys(
		runtimecatalogapp.VerifiedCatalog{}, reader, clock, (*rpmSignatureVerifierStub)(nil),
	); err == nil {
		t.Fatal("unverified DNF catalog or typed-nil RPM verifier was accepted")
	}
	tests := []struct {
		manager      runtimecatalog.LinuxPackageManager
		architecture runtimecatalog.Architecture
		want         string
		valid        bool
	}{
		{runtimecatalog.LinuxPackageManagerAPT, runtimecatalog.ArchitectureX8664, "amd64", true},
		{runtimecatalog.LinuxPackageManagerAPT, runtimecatalog.ArchitectureARM64, "arm64", true},
		{runtimecatalog.LinuxPackageManagerDNF, runtimecatalog.ArchitectureX8664, "x86_64", true},
		{runtimecatalog.LinuxPackageManagerDNF, runtimecatalog.ArchitectureARM64, "aarch64", true},
		{runtimecatalog.LinuxPackageManager("other"), runtimecatalog.ArchitectureX8664, "x86_64", false},
		{runtimecatalog.LinuxPackageManagerAPT, runtimecatalog.Architecture("other"), "", false},
	}
	for _, test := range tests {
		actual, valid := nativeLinuxPackageArchitecture(test.manager, test.architecture)
		if actual != test.want || valid != test.valid {
			t.Fatalf("nativeLinuxPackageArchitecture(%q,%q)=(%q,%t)", test.manager, test.architecture, actual, valid)
		}
	}
	if id := linuxRepositoryArtifactID(runtimecatalog.LinuxRepository{}, runtimecatalog.LinuxRepositoryArtifactSigningKey); id != "repo--signing_key" {
		t.Fatalf("zero repository ID = %q", id)
	}
	if packages := linuxPackagesForRepository(nil, "docker-stable"); len(packages) != 0 {
		t.Fatal("empty package set produced packages")
	}
}

type verifiedFinalReaderStub struct {
	content  map[string][]byte
	openErr  error
	readErr  error
	closeErr error
	opens    int
}

func (r *verifiedFinalReaderStub) OpenFinal(
	_ context.Context,
	artifact artifactacquisition.Artifact,
) (io.ReadCloser, error) {
	r.opens++
	if r.openErr != nil {
		return nil, r.openErr
	}
	return &trustReadCloser{
		Reader: bytes.NewReader(r.content[artifact.ID()]), readErr: r.readErr, closeErr: r.closeErr,
	}, nil
}

type trustReadCloser struct {
	*bytes.Reader
	readErr  error
	closeErr error
}

func (r *trustReadCloser) Read(target []byte) (int, error) {
	if r.readErr != nil {
		return 0, r.readErr
	}
	return r.Reader.Read(target)
}

func (r *trustReadCloser) Close() error { return r.closeErr }

type rpmSignatureVerifierStub struct{}

func (*rpmSignatureVerifierStub) VerifyRPMPackage(
	context.Context,
	[]byte,
	string,
	artifactacquisition.Artifact,
	io.Reader,
) error {
	return nil
}

func trustReaderPlan(t testing.TB) (artifactacquisition.Plan, map[string][]byte) {
	t.Helper()
	content := map[string][]byte{
		"repo-docker-stable-signing_key": []byte("key"),
		"docker-ce":                      []byte("package"),
	}
	artifacts := make([]artifactacquisition.ArtifactInput, 0, len(content))
	for _, id := range []string{"repo-docker-stable-signing_key", "docker-ce"} {
		digest := releaseinventory.DigestBytes(content[id])
		artifacts = append(artifacts, artifactacquisition.ArtifactInput{
			ID: id, Digest: digest, Size: uint64(len(content[id])), Sources: []string{"https://example.test/" + id},
			Chunks: []artifactacquisition.ChunkInput{{Offset: 0, Size: uint64(len(content[id])), Digest: digest}},
		})
	}
	download := uint64(len(content["repo-docker-stable-signing_key"]) + len(content["docker-ce"]))
	plan, err := artifactacquisition.NewPlan(artifactacquisition.PlanInput{
		PlanDigest: releaseinventory.DigestBytes([]byte("catalog")), Artifacts: artifacts,
		Totals: artifactacquisition.TotalsInput{
			DownloadBytes: download, RollbackHeadroomBytes: 1, SafetyHeadroomBytes: 1, RequiredBytes: download + 2,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan, content
}
