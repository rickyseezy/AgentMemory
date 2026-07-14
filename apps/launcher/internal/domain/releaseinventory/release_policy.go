package releaseinventory

import (
	"errors"
	"sort"
	"strconv"
	"strings"
)

const maximumReleaseHistoryEntries = 256

// ReleaseChannel is the anti-rollback and promotion namespace.
type ReleaseChannel string

// Closed release channels understood by schema v1.
const (
	ReleaseChannelStable      ReleaseChannel = "stable"
	ReleaseChannelCandidate   ReleaseChannel = "candidate"
	ReleaseChannelBeta        ReleaseChannel = "beta"
	ReleaseChannelNightly     ReleaseChannel = "nightly"
	ReleaseChannelDevelopment ReleaseChannel = "development"
)

// Valid reports whether the release channel is understood by schema v1.
func (c ReleaseChannel) Valid() bool {
	return c == ReleaseChannelStable || c == ReleaseChannelCandidate ||
		c == ReleaseChannelBeta || c == ReleaseChannelNightly ||
		c == ReleaseChannelDevelopment
}

// VersionRangeInput is an inclusive stable semantic-version compatibility range.
type VersionRangeInput struct {
	Minimum string
	Maximum string
}

// VersionRange is an immutable inclusive compatibility range. Production
// manifests intentionally prohibit prerelease and build metadata versions.
type VersionRange struct {
	minimum       string
	maximum       string
	minimumParsed [3]uint32
	maximumParsed [3]uint32
}

// NewVersionRange validates a stable major.minor.patch range.
func NewVersionRange(input VersionRangeInput) (VersionRange, error) {
	minimum, err := parseStableSemanticVersion(input.Minimum)
	if err != nil {
		return VersionRange{}, errors.New("minimum compatibility version is invalid")
	}
	maximum, err := parseStableSemanticVersion(input.Maximum)
	if err != nil || compareSemanticVersion(minimum, maximum) > 0 {
		return VersionRange{}, errors.New("maximum compatibility version is invalid")
	}
	return VersionRange{
		minimum: input.Minimum, maximum: input.Maximum,
		minimumParsed: minimum, maximumParsed: maximum,
	}, nil
}

// Minimum returns the oldest compatible version.
func (r VersionRange) Minimum() string { return r.minimum }

// Maximum returns the newest compatible version.
func (r VersionRange) Maximum() string { return r.maximum }

// Contains reports whether an exact stable semantic version is compatible.
func (r VersionRange) Contains(version string) bool {
	parsed, err := parseStableSemanticVersion(version)
	return err == nil && compareSemanticVersion(r.minimumParsed, parsed) <= 0 &&
		compareSemanticVersion(parsed, r.maximumParsed) <= 0
}

// Valid reports whether the version range can authorize a compatibility decision.
func (r VersionRange) Valid() bool {
	validated, err := NewVersionRange(VersionRangeInput{Minimum: r.minimum, Maximum: r.maximum})
	return err == nil && validated.minimumParsed == r.minimumParsed && validated.maximumParsed == r.maximumParsed
}

func parseStableSemanticVersion(value string) ([3]uint32, error) {
	var parsed [3]uint32
	parts := strings.Split(value, ".")
	if len(parts) != len(parsed) {
		return parsed, errors.New("semantic version must contain three numeric components")
	}
	for index, part := range parts {
		if part == "" || len(part) > 1 && part[0] == '0' {
			return [3]uint32{}, errors.New("semantic version component is not canonical")
		}
		component, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return [3]uint32{}, errors.New("semantic version component is invalid")
		}
		parsed[index] = uint32(component)
	}
	return parsed, nil
}

func compareSemanticVersion(left [3]uint32, right [3]uint32) int {
	for index := range left {
		if left[index] < right[index] {
			return -1
		}
		if left[index] > right[index] {
			return 1
		}
	}
	return 0
}

// CompatibilityInput contains every ADR-016 execution compatibility boundary.
type CompatibilityInput struct {
	Launcher       VersionRange
	CoreAPI        VersionRange
	MCP            VersionRange
	Provider       VersionRange
	Schema         VersionRange
	Compose        VersionRange
	SQLite         VersionRange
	Neo4j          VersionRange
	RuntimeCatalog VersionRange
}

// Compatibility is the complete immutable release compatibility matrix.
type Compatibility struct {
	launcher       VersionRange
	coreAPI        VersionRange
	mcp            VersionRange
	provider       VersionRange
	schema         VersionRange
	compose        VersionRange
	sqlite         VersionRange
	neo4j          VersionRange
	runtimeCatalog VersionRange
}

// NewCompatibility rejects a matrix with any unspecified component.
func NewCompatibility(input CompatibilityInput) (Compatibility, error) {
	ranges := []VersionRange{
		input.Launcher, input.CoreAPI, input.MCP, input.Provider, input.Schema,
		input.Compose, input.SQLite, input.Neo4j, input.RuntimeCatalog,
	}
	for _, versionRange := range ranges {
		if !versionRange.Valid() {
			return Compatibility{}, errors.New("release compatibility matrix is incomplete")
		}
	}
	return Compatibility{
		launcher: input.Launcher, coreAPI: input.CoreAPI, mcp: input.MCP,
		provider: input.Provider, schema: input.Schema, compose: input.Compose,
		sqlite: input.SQLite, neo4j: input.Neo4j, runtimeCatalog: input.RuntimeCatalog,
	}, nil
}

// Valid reports whether every compatibility component is usable.
func (c Compatibility) Valid() bool {
	_, err := NewCompatibility(CompatibilityInput{
		Launcher: c.launcher, CoreAPI: c.coreAPI, MCP: c.mcp, Provider: c.provider,
		Schema: c.schema, Compose: c.compose, SQLite: c.sqlite, Neo4j: c.neo4j,
		RuntimeCatalog: c.runtimeCatalog,
	})
	return err == nil
}

// Launcher returns the native launcher compatibility range.
func (c Compatibility) Launcher() VersionRange { return c.launcher }

// CoreAPI returns the core API compatibility range.
func (c Compatibility) CoreAPI() VersionRange { return c.coreAPI }

// MCP returns the MCP protocol compatibility range.
func (c Compatibility) MCP() VersionRange { return c.mcp }

// Provider returns the provider protocol compatibility range.
func (c Compatibility) Provider() VersionRange { return c.provider }

// Schema returns the canonical schema compatibility range.
func (c Compatibility) Schema() VersionRange { return c.schema }

// Compose returns the Compose implementation compatibility range.
func (c Compatibility) Compose() VersionRange { return c.compose }

// SQLite returns the SQLite compatibility range.
func (c Compatibility) SQLite() VersionRange { return c.sqlite }

// Neo4j returns the Neo4j compatibility range.
func (c Compatibility) Neo4j() VersionRange { return c.neo4j }

// RuntimeCatalog returns the runtime-prerequisite catalog compatibility range.
func (c Compatibility) RuntimeCatalog() VersionRange { return c.runtimeCatalog }

// PriorReleaseInput declares an exact source release and compatible data generations.
type PriorReleaseInput struct {
	ReleaseID             string
	ManifestDigest        Digest
	MinimumDataGeneration uint64
	MaximumDataGeneration uint64
}

// PriorRelease is one exact direct-upgrade source release.
type PriorRelease struct {
	releaseID             string
	manifestDigest        Digest
	minimumDataGeneration uint64
	maximumDataGeneration uint64
}

// ReleaseID returns the prior release identity.
func (r PriorRelease) ReleaseID() string { return r.releaseID }

// ManifestDigest returns the exact prior signed-manifest digest.
func (r PriorRelease) ManifestDigest() Digest { return r.manifestDigest }

// MinimumDataGeneration returns the oldest compatible data generation.
func (r PriorRelease) MinimumDataGeneration() uint64 { return r.minimumDataGeneration }

// MaximumDataGeneration returns the newest compatible data generation.
func (r PriorRelease) MaximumDataGeneration() uint64 { return r.maximumDataGeneration }

// RollbackReleaseInput declares an exact journal-selectable rollback target.
type RollbackReleaseInput struct {
	ReleaseID      string
	ManifestDigest Digest
	DataGeneration uint64
}

// RollbackRelease is one exact release and compatible preserved generation.
type RollbackRelease struct {
	releaseID      string
	manifestDigest Digest
	dataGeneration uint64
}

// ReleaseID returns the rollback release identity.
func (r RollbackRelease) ReleaseID() string { return r.releaseID }

// ManifestDigest returns the exact rollback manifest digest.
func (r RollbackRelease) ManifestDigest() Digest { return r.manifestDigest }

// DataGeneration returns the exact preserved generation required for rollback.
func (r RollbackRelease) DataGeneration() uint64 { return r.dataGeneration }

// ReleaseHistory binds direct-upgrade and exact rollback decisions.
type ReleaseHistory struct {
	prior    []PriorRelease
	rollback []RollbackRelease
}

// NewReleaseHistory validates exact release, digest, and data-generation bindings.
func NewReleaseHistory(
	priorInputs []PriorReleaseInput,
	rollbackInputs []RollbackReleaseInput,
) (ReleaseHistory, error) {
	if len(priorInputs) > maximumReleaseHistoryEntries || len(rollbackInputs) > maximumReleaseHistoryEntries {
		return ReleaseHistory{}, errors.New("release history size is invalid")
	}
	prior := make([]PriorRelease, 0, len(priorInputs))
	priorByID := make(map[string]PriorRelease, len(priorInputs))
	for _, input := range priorInputs {
		if !validIdentifier(input.ReleaseID) || input.ManifestDigest.IsZero() ||
			checkedSafeJSONInteger(input.MinimumDataGeneration, "minimum data generation") != nil ||
			checkedSafeJSONInteger(input.MaximumDataGeneration, "maximum data generation") != nil ||
			input.MinimumDataGeneration > input.MaximumDataGeneration {
			return ReleaseHistory{}, errors.New("prior release compatibility is invalid")
		}
		if _, duplicate := priorByID[input.ReleaseID]; duplicate {
			return ReleaseHistory{}, errors.New("prior release compatibility contains a duplicate")
		}
		entry := PriorRelease{
			releaseID: input.ReleaseID, manifestDigest: input.ManifestDigest,
			minimumDataGeneration: input.MinimumDataGeneration,
			maximumDataGeneration: input.MaximumDataGeneration,
		}
		prior = append(prior, entry)
		priorByID[input.ReleaseID] = entry
	}
	rollback := make([]RollbackRelease, 0, len(rollbackInputs))
	rollbackByID := make(map[string]struct{}, len(rollbackInputs))
	for _, input := range rollbackInputs {
		compatible, exists := priorByID[input.ReleaseID]
		if !exists || input.ManifestDigest.IsZero() || !input.ManifestDigest.Equal(compatible.manifestDigest) ||
			input.DataGeneration < compatible.minimumDataGeneration ||
			input.DataGeneration > compatible.maximumDataGeneration {
			return ReleaseHistory{}, errors.New("rollback release is not an exact compatible prior release")
		}
		if _, duplicate := rollbackByID[input.ReleaseID]; duplicate {
			return ReleaseHistory{}, errors.New("rollback release set contains a duplicate")
		}
		rollback = append(rollback, RollbackRelease{
			releaseID: input.ReleaseID, manifestDigest: input.ManifestDigest,
			dataGeneration: input.DataGeneration,
		})
		rollbackByID[input.ReleaseID] = struct{}{}
	}
	sort.Slice(prior, func(left int, right int) bool { return prior[left].releaseID < prior[right].releaseID })
	sort.Slice(rollback, func(left int, right int) bool { return rollback[left].releaseID < rollback[right].releaseID })
	return ReleaseHistory{prior: prior, rollback: rollback}, nil
}

// PriorReleases returns a copy of exact direct-upgrade sources.
func (h ReleaseHistory) PriorReleases() []PriorRelease {
	return append([]PriorRelease(nil), h.prior...)
}

// RollbackReleases returns a copy of exact journal-selectable rollback targets.
func (h ReleaseHistory) RollbackReleases() []RollbackRelease {
	return append([]RollbackRelease(nil), h.rollback...)
}
