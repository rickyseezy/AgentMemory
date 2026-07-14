package releaseinventory

import "testing"

func TestCompatibilityRequiresCanonicalOrderedStableVersionRanges(t *testing.T) {
	t.Parallel()

	versionRange, err := NewVersionRange(VersionRangeInput{Minimum: "1.2.3", Maximum: "2.0.0"})
	if err != nil || !versionRange.Contains("1.9.0") || versionRange.Contains("2.0.1") {
		t.Fatalf("NewVersionRange() = %v/%v", versionRange, err)
	}
	for _, input := range []VersionRangeInput{
		{Minimum: "1.0", Maximum: "2.0.0"},
		{Minimum: "01.0.0", Maximum: "2.0.0"},
		{Minimum: "1.0.0-beta", Maximum: "2.0.0"},
		{Minimum: "2.0.0", Maximum: "1.0.0"},
	} {
		if _, err := NewVersionRange(input); err == nil {
			t.Fatalf("NewVersionRange(%+v) accepted invalid range", input)
		}
	}
	compatibility, err := NewCompatibility(CompatibilityInput{
		Launcher: versionRange, CoreAPI: versionRange, MCP: versionRange,
		Provider: versionRange, Schema: versionRange, Compose: versionRange,
		SQLite: versionRange, Neo4j: versionRange, RuntimeCatalog: versionRange,
	})
	if err != nil || !compatibility.Valid() || compatibility.Compose().Minimum() != "1.2.3" ||
		compatibility.RuntimeCatalog().Maximum() != "2.0.0" {
		t.Fatalf("NewCompatibility() = %v/%v", compatibility, err)
	}
	if _, err := NewCompatibility(CompatibilityInput{Launcher: versionRange}); err == nil {
		t.Fatal("NewCompatibility() accepted an incomplete matrix")
	}
}

func TestReleaseHistoryRequiresExactPriorDigestAndGeneration(t *testing.T) {
	t.Parallel()

	priorDigest := DigestBytes([]byte("prior manifest"))
	history, err := NewReleaseHistory(
		[]PriorReleaseInput{{
			ReleaseID: "agentmemory-0.9.0", ManifestDigest: priorDigest,
			MinimumDataGeneration: 4, MaximumDataGeneration: 5,
		}},
		[]RollbackReleaseInput{{
			ReleaseID: "agentmemory-0.9.0", ManifestDigest: priorDigest, DataGeneration: 5,
		}},
	)
	if err != nil || len(history.PriorReleases()) != 1 || len(history.RollbackReleases()) != 1 ||
		history.PriorReleases()[0].ReleaseID() != "agentmemory-0.9.0" ||
		!history.PriorReleases()[0].ManifestDigest().Equal(priorDigest) ||
		history.PriorReleases()[0].MinimumDataGeneration() != 4 ||
		history.PriorReleases()[0].MaximumDataGeneration() != 5 ||
		history.RollbackReleases()[0].ReleaseID() != "agentmemory-0.9.0" ||
		!history.RollbackReleases()[0].ManifestDigest().Equal(priorDigest) ||
		history.RollbackReleases()[0].DataGeneration() != 5 {
		t.Fatalf("NewReleaseHistory() = %v/%v", history, err)
	}
	tests := []struct {
		name     string
		prior    []PriorReleaseInput
		rollback []RollbackReleaseInput
	}{
		{
			name: "unknown rollback",
			rollback: []RollbackReleaseInput{{
				ReleaseID: "agentmemory-0.9.0", ManifestDigest: priorDigest, DataGeneration: 5,
			}},
		},
		{
			name: "digest mismatch",
			prior: []PriorReleaseInput{{
				ReleaseID: "agentmemory-0.9.0", ManifestDigest: priorDigest,
				MinimumDataGeneration: 4, MaximumDataGeneration: 5,
			}},
			rollback: []RollbackReleaseInput{{
				ReleaseID: "agentmemory-0.9.0", ManifestDigest: DigestBytes([]byte("other")), DataGeneration: 5,
			}},
		},
		{
			name: "generation mismatch",
			prior: []PriorReleaseInput{{
				ReleaseID: "agentmemory-0.9.0", ManifestDigest: priorDigest,
				MinimumDataGeneration: 4, MaximumDataGeneration: 5,
			}},
			rollback: []RollbackReleaseInput{{
				ReleaseID: "agentmemory-0.9.0", ManifestDigest: priorDigest, DataGeneration: 6,
			}},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewReleaseHistory(test.prior, test.rollback); err == nil {
				t.Fatal("NewReleaseHistory() accepted an ambiguous rollback binding")
			}
		})
	}
}

func TestReleaseChannelVocabularyIsClosed(t *testing.T) {
	t.Parallel()

	if !ReleaseChannelStable.Valid() || ReleaseChannel("production-ish").Valid() {
		t.Fatal("release channel vocabulary is not closed")
	}
}
