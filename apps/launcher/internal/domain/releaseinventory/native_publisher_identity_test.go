package releaseinventory

import "testing"

func TestPF001NativePublisherIdentityAcceptsPlatformCertificateVocabulary(t *testing.T) {
	t.Parallel()
	platform, err := NewPlatform("darwin", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	input := fixtureSubjectInput(
		"launcher-darwin-arm64",
		ResourceKindLauncher,
		platform,
		digestText("launcher"),
		8,
	)
	input.CycloneDXSBOMResourceID = "launcher-cyclonedx"
	input.SPDXSBOMResourceID = "launcher-spdx"
	input.ProvenanceResourceID = "launcher-provenance"
	input.LicenseResourceID = "launcher-license"
	input.VulnerabilityResourceID = "launcher-vulnerability"
	input.NativePublisherIdentity = "teamid:AB12CD34EF"
	if _, err := NewResource(input); err != nil {
		t.Fatalf("platform identity rejected: %v", err)
	}
	for _, invalid := range []string{"", " teamid:AB12CD34EF", "teamid:AB12 CD34EF", "teamid:\nAB12CD34EF"} {
		candidate := input
		candidate.NativePublisherIdentity = invalid
		if _, err := NewResource(candidate); err == nil {
			t.Fatalf("invalid publisher identity %q accepted", invalid)
		}
	}
}
