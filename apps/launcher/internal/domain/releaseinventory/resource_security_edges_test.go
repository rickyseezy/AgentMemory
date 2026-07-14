package releaseinventory

import (
	"strings"
	"testing"
	"time"
)

func TestReleaseResourceRejectsHostPathAndOCIParserAttackCorpus(t *testing.T) {
	t.Parallel()

	invalidHosts := []string{
		"", ".releases.example", "releases.example.", "releases..example",
		"-releases.example", "releases-.example", "RELEASES.example",
		"releases_example", strings.Repeat("a", 254),
	}
	for _, host := range invalidHosts {
		if validSourceHost(host) {
			t.Fatalf("validSourceHost(%q) accepted an unsafe host", host)
		}
	}
	if !validSourceHost("releases.agentmemory.dev") {
		t.Fatal("valid HTTPS release host was rejected")
	}

	invalidPaths := []string{
		"", "/artifact", "artifact/", "artifact//weights", "artifact/./weights",
		"artifact/../weights", "artifact/weights?q=latest", "artifact/weights%2fother",
	}
	for _, path := range invalidPaths {
		if validSourcePath(path) {
			t.Fatalf("validSourcePath(%q) accepted an unsafe path", path)
		}
	}
	if !validSourcePath("v1/models/qwen3_weights-0.6.bin") {
		t.Fatal("valid immutable release path was rejected")
	}

	digest := digestText("oci-edge")
	suffix := "@sha256:" + digest.Hex()
	invalidOCI := []string{
		"repository" + suffix,
		"registry.example:5000/agentmemory/core" + suffix,
		"registry.example//agentmemory/core" + suffix,
		"registry.example/agentmemory/../core" + suffix,
		"/registry.example/agentmemory/core" + suffix,
		"registry.example/agentmemory/core/" + suffix,
		"Registry.example/agentmemory/core" + suffix,
		"registry.example/agentmemory/core:latest",
		"registry.example/agentmemory/core" + suffix + "@extra",
	}
	for _, reference := range invalidOCI {
		if validOCIReference(reference, digest) {
			t.Fatalf("validOCIReference(%q) accepted mutable/ambiguous authority", reference)
		}
	}
	if !validOCIReference("registry.example/agentmemory/core"+suffix, digest) {
		t.Fatal("valid immutable OCI reference was rejected")
	}
}

func TestReleaseResourceQualificationRejectsExpiredOrCrossKindEvidence(t *testing.T) {
	t.Parallel()

	policy := digestText("policy")
	tests := []struct {
		name  string
		input ResourceInput
	}{
		{name: "license missing policy", input: ResourceInput{Kind: ResourceKindLicense, QualificationResult: QualificationResultPassed}},
		{name: "license wrong result", input: ResourceInput{Kind: ResourceKindLicense, PolicySnapshotDigest: policy, QualificationResult: "waived"}},
		{name: "license expiry forbidden", input: ResourceInput{Kind: ResourceKindLicense, PolicySnapshotDigest: policy, QualificationResult: QualificationResultPassed, QualificationExpiresAt: time.Now().UTC()}},
		{name: "vulnerability missing expiry", input: ResourceInput{Kind: ResourceKindVulnerabilityReport, PolicySnapshotDigest: policy, QualificationResult: QualificationResultPassed}},
		{name: "vulnerability pre epoch", input: ResourceInput{Kind: ResourceKindVulnerabilityReport, PolicySnapshotDigest: policy, QualificationResult: QualificationResultPassed, QualificationExpiresAt: time.Unix(-1, 0).UTC()}},
		{name: "vulnerability unsafe integer", input: ResourceInput{Kind: ResourceKindVulnerabilityReport, PolicySnapshotDigest: policy, QualificationResult: QualificationResultPassed, QualificationExpiresAt: time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)}},
		{name: "non policy qualification", input: ResourceInput{Kind: ResourceKindCycloneDXSBOM, PolicySnapshotDigest: policy}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := validateQualification(test.input); err == nil {
				t.Fatal("validateQualification() accepted invalid policy evidence")
			}
		})
	}

	if expiresAt, err := validateQualification(ResourceInput{
		Kind: ResourceKindVulnerabilityReport, PolicySnapshotDigest: policy,
		QualificationResult:    QualificationResultPassed,
		QualificationExpiresAt: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}); err != nil || expiresAt <= 0 {
		t.Fatalf("valid vulnerability qualification = %d, %v", expiresAt, err)
	}
	if expiresAt, err := validateQualification(ResourceInput{
		Kind: ResourceKindLicense, PolicySnapshotDigest: policy,
		QualificationResult: QualificationResultPassed,
	}); err != nil || expiresAt != 0 {
		t.Fatalf("valid license qualification = %d, %v", expiresAt, err)
	}
	if expiresAt, err := validateQualification(ResourceInput{Kind: ResourceKindCycloneDXSBOM}); err != nil || expiresAt != 0 {
		t.Fatalf("valid non-policy evidence = %d, %v", expiresAt, err)
	}
}

func TestReleaseResourceClosedVocabularyAndExpiryAccessors(t *testing.T) {
	t.Parallel()

	if ResourceKind("future").Valid() || ResourceKind("future").IsEvidence() ||
		LocalProviderRole("future").Valid() {
		t.Fatal("unknown release vocabulary was accepted")
	}
	if !(Resource{}).QualificationExpiresAt().IsZero() {
		t.Fatal("zero resource unexpectedly became qualified")
	}
}
