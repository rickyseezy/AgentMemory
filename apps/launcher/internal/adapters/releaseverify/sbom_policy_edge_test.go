package releaseverifyadapter

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001CycloneDXProfileRejectsEveryStructuralAmbiguity(t *testing.T) {
	t.Parallel()
	subject := evidenceSubject(t, "schema", []byte("subject bytes"), releaseinventory.ResourceKindSchema)
	var base cycloneDXDocument
	if err := json.Unmarshal(validCycloneDXBytes(t, subject), &base); err != nil {
		t.Fatal(err)
	}
	component := cycloneDXComponent{
		BOMRef: "dependency", Hashes: []cycloneDXHash{{Algorithm: "SHA-256", Content: releaseinventory.DigestBytes([]byte("dependency")).Hex()}},
		Name: "dependency", PURL: "pkg:generic/dependency@1.0.0", Type: "library", Version: "1.0.0",
	}
	tests := []struct {
		name   string
		mutate func(*cycloneDXDocument)
		want   error
	}{
		{name: "format", mutate: func(value *cycloneDXDocument) { value.BOMFormat = "Other" }, want: errEvidenceContent},
		{name: "spec", mutate: func(value *cycloneDXDocument) { value.SpecVersion = "1.5" }, want: errEvidenceContent},
		{name: "version", mutate: func(value *cycloneDXDocument) { value.Version = 0 }, want: errEvidenceContent},
		{name: "serial", mutate: func(value *cycloneDXDocument) { value.SerialNumber = "uuid" }, want: errEvidenceContent},
		{name: "time", mutate: func(value *cycloneDXDocument) { value.Metadata.Timestamp = "2026-07-13T12:00:00+04:00" }, want: errEvidenceContent},
		{name: "subject", mutate: func(value *cycloneDXDocument) { value.Metadata.Component.Name = "foreign" }, want: errEvidenceContent},
		{name: "invalid component", mutate: func(value *cycloneDXDocument) { value.Components = []cycloneDXComponent{{}} }, want: errEvidenceContent},
		{name: "subject repeated", mutate: func(value *cycloneDXDocument) {
			repeated := component
			repeated.BOMRef = subject.ID()
			value.Components = []cycloneDXComponent{repeated}
		}, want: errEvidenceContent},
		{name: "duplicate", mutate: func(value *cycloneDXDocument) { value.Components = []cycloneDXComponent{component, component} }, want: errEvidenceContent},
		{name: "ordering", mutate: func(value *cycloneDXDocument) {
			second := component
			second.BOMRef = "alpha"
			second.Name = "alpha"
			value.Components = []cycloneDXComponent{component, second}
		}, want: errEvidenceNonCanonical},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := base
			test.mutate(&candidate)
			if err := verifyCycloneDX(mustJSON(t, candidate), subject); !errors.Is(err, test.want) {
				t.Fatalf("verifyCycloneDX() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestPF001CycloneDXComponentGrammarIsClosed(t *testing.T) {
	t.Parallel()
	valid := cycloneDXComponent{
		BOMRef: "component", Hashes: []cycloneDXHash{{Algorithm: "SHA-256", Content: strings.Repeat("a", 64)}},
		Name: "component", PURL: "pkg:generic/component@1", Type: "library", Version: "1",
	}
	for _, mutate := range []func(*cycloneDXComponent){
		func(value *cycloneDXComponent) { value.BOMRef = "" },
		func(value *cycloneDXComponent) { value.Name = strings.Repeat("x", 257) },
		func(value *cycloneDXComponent) { value.Version = "" },
		func(value *cycloneDXComponent) { value.Hashes = nil },
		func(value *cycloneDXComponent) { value.PURL = "https://example.invalid" },
		func(value *cycloneDXComponent) { value.Type = "unknown" },
		func(value *cycloneDXComponent) { value.Hashes[0].Algorithm = "SHA256" },
		func(value *cycloneDXComponent) { value.Hashes[0].Content = "bad" },
	} {
		candidate := valid
		candidate.Hashes = append([]cycloneDXHash(nil), valid.Hashes...)
		mutate(&candidate)
		if validCycloneDXComponent(candidate) {
			t.Fatalf("invalid component accepted: %#v", candidate)
		}
	}
}

func TestPF001SPDXProfileAndPackageGrammarRejectAmbiguity(t *testing.T) {
	t.Parallel()
	subject := evidenceSubject(t, "core", []byte("subject bytes"), releaseinventory.ResourceKindComposeBundle)
	var base spdxDocument
	if err := json.Unmarshal(validSPDXBytes(t, subject), &base); err != nil {
		t.Fatal(err)
	}
	second := base.Packages[0]
	second.SPDXID = "SPDXRef-z-dependency"
	second.Name = "dependency"
	tests := []struct {
		name   string
		mutate func(*spdxDocument)
		want   error
	}{
		{name: "version", mutate: func(value *spdxDocument) { value.SPDXVersion = "SPDX-2.2" }, want: errEvidenceContent},
		{name: "license", mutate: func(value *spdxDocument) { value.DataLicense = "MIT" }, want: errEvidenceContent},
		{name: "document id", mutate: func(value *spdxDocument) { value.SPDXID = "SPDXRef-other" }, want: errEvidenceContent},
		{name: "namespace", mutate: func(value *spdxDocument) { value.DocumentNamespace = "https://example.invalid" }, want: errEvidenceContent},
		{name: "describes", mutate: func(value *spdxDocument) { value.DocumentDescribes = nil }, want: errEvidenceContent},
		{name: "time", mutate: func(value *spdxDocument) { value.CreationInfo.Created = "yesterday" }, want: errEvidenceContent},
		{name: "creators", mutate: func(value *spdxDocument) { value.CreationInfo.Creators = nil }, want: errEvidenceContent},
		{name: "duplicate creators", mutate: func(value *spdxDocument) { value.CreationInfo.Creators = []string{"Tool: release", "Tool: release"} }, want: errEvidenceContent},
		{name: "packages", mutate: func(value *spdxDocument) { value.Packages = nil }, want: errEvidenceContent},
		{name: "invalid package", mutate: func(value *spdxDocument) { value.Packages = []spdxPackage{{}} }, want: errEvidenceContent},
		{name: "duplicate", mutate: func(value *spdxDocument) { value.Packages = []spdxPackage{second, second} }, want: errEvidenceContent},
		{name: "ordering", mutate: func(value *spdxDocument) {
			first := second
			first.SPDXID = "SPDXRef-z"
			later := second
			later.SPDXID = "SPDXRef-a"
			value.Packages = []spdxPackage{first, later}
		}, want: errEvidenceNonCanonical},
		{name: "no subject", mutate: func(value *spdxDocument) { value.Packages = []spdxPackage{second} }, want: errEvidenceContent},
		{name: "subject digest", mutate: func(value *spdxDocument) { value.Packages[0].Checksums[0].ChecksumValue = strings.Repeat("b", 64) }, want: errEvidenceContent},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := base
			candidate.Packages = append([]spdxPackage(nil), base.Packages...)
			candidate.Packages[0].Checksums = append([]spdxChecksum(nil), base.Packages[0].Checksums...)
			test.mutate(&candidate)
			if err := verifySPDX(mustJSON(t, candidate), subject); !errors.Is(err, test.want) {
				t.Fatalf("verifySPDX() error = %v, want %v", err, test.want)
			}
		})
	}

	valid := base.Packages[0]
	for _, mutate := range []func(*spdxPackage){
		func(value *spdxPackage) { value.SPDXID = "foreign" },
		func(value *spdxPackage) { value.Name = "" },
		func(value *spdxPackage) { value.Checksums = nil },
		func(value *spdxPackage) { value.Checksums = append(value.Checksums, value.Checksums[0]) },
		func(value *spdxPackage) { value.Checksums[0].Algorithm = "" },
		func(value *spdxPackage) { value.Checksums[0].ChecksumValue = "bad" },
	} {
		candidate := valid
		candidate.Checksums = append([]spdxChecksum(nil), valid.Checksums...)
		mutate(&candidate)
		if validSPDXPackage(candidate) {
			t.Fatalf("invalid SPDX package accepted: %#v", candidate)
		}
	}
}

func TestPF001ReleaseEvidenceSetAndLockedDependencyGrammarIsClosed(t *testing.T) {
	t.Parallel()
	digestA := strings.Repeat("a", 64)
	digestB := strings.Repeat("b", 64)
	valid := []slsaDependency{
		{URI: "pkg:generic/a@sha256:" + digestA, Digest: map[string]string{"sha256": digestA}},
		{URI: "pkg:generic/b@sha256:" + digestB, Digest: map[string]string{"sha256": digestB}},
	}
	if !validLockedDependencies(valid) || !exactUniqueStrings([]string{"a", "b"}, true) {
		t.Fatal("canonical evidence collections were rejected")
	}
	for _, dependencies := range [][]slsaDependency{
		nil,
		{{URI: "", Digest: map[string]string{"sha256": digestA}}},
		{{URI: "pkg:generic/a@sha256:" + digestA, Digest: nil}},
		{{URI: "pkg:generic/a@sha256:" + digestA, Digest: map[string]string{"sha512": digestA}}},
		{{URI: "pkg:generic/a@sha256:bad", Digest: map[string]string{"sha256": "bad"}}},
		{valid[1], valid[0]},
	} {
		if validLockedDependencies(dependencies) {
			t.Fatalf("invalid dependency set accepted: %#v", dependencies)
		}
	}
	for _, values := range [][]string{{""}, {"a", "a"}, {"b", "a"}} {
		if exactUniqueStrings(values, true) {
			t.Fatalf("ambiguous string set accepted: %#v", values)
		}
	}
	if !exactUniqueStrings([]string{"b", "a"}, false) {
		t.Fatal("explicitly unordered unique set was rejected")
	}
}
