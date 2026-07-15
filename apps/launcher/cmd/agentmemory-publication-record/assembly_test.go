package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releasepublication"
)

func TestPF001PublicationAssemblerHashesClosedCandidateTree(t *testing.T) {
	t.Parallel()
	fixture := newCandidateFixture(t)
	if err := AssemblePublication(context.Background(), fixture.options, compilePublication); err != nil {
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
	if err != nil || info.Mode().Perm() != 0o600 || info.ModTime().Unix() != fixture.options.SourceEpoch {
		t.Fatalf("output info=%+v error=%v", info, err)
	}
	if publication.ReleaseID() != fixture.options.ReleaseID || publication.Version() != fixture.options.Version ||
		publication.BuildID() != fixture.options.BuildID || publication.SourceCommit() != fixture.options.SourceCommit ||
		len(publication.Artifacts()) != len(candidateArtifacts) {
		t.Fatalf("publication=%+v", publication)
	}
	distribution, err := os.ReadFile(filepath.Join(fixture.options.CandidateRoot, distributionEnvelopeName))
	if err != nil || !publication.DistributionEnvelopeDigest().Equal(digestBytes(distribution)) ||
		publication.DistributionEnvelopeSize() != uint64(len(distribution)) {
		t.Fatalf("distribution binding error=%v", err)
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
			if err := AssemblePublication(context.Background(), fixture.options, compilePublication); err == nil {
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
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := AssemblePublication(cancelled, fixture.options, compilePublication); !errors.Is(err, context.Canceled) {
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
			if err := AssemblePublication(context.Background(), candidate.options, compilePublication); err == nil {
				t.Fatal("AssemblePublication() error=nil")
			}
		})
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

type candidateFixture struct {
	options PublicationOptions
}

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
