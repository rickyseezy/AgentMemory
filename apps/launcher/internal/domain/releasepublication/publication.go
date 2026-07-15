package releasepublication

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

var requiredNativeCells = map[string]struct{}{
	"darwin/amd64/pkg": {}, "darwin/arm64/pkg": {},
	"linux/amd64/deb": {}, "linux/amd64/rpm": {},
	"linux/arm64/deb": {}, "linux/arm64/rpm": {},
	"windows/amd64/msi": {},
}

// PublicationInput is copied into an immutable Publication.
type PublicationInput struct {
	SchemaVersion              uint16
	ReleaseID                  string
	Version                    string
	BuildID                    string
	SourceCommit               string
	BuildTimestamp             time.Time
	DistributionEnvelopeDigest releaseinventory.Digest
	DistributionEnvelopeSize   uint64
	ReleaseTrustDigest         releaseinventory.Digest
	ReleaseTrustSize           uint64
	Artifacts                  []ArtifactInput
}

// Publication is the closed exact-object promotion authority.
type Publication struct {
	schemaVersion              uint16
	releaseID                  string
	version                    string
	buildID                    string
	sourceCommit               string
	buildTimestamp             int64
	distributionEnvelopeDigest releaseinventory.Digest
	distributionEnvelopeSize   uint64
	releaseTrustDigest         releaseinventory.Digest
	releaseTrustSize           uint64
	artifacts                  []Artifact
	canonical                  []byte
}

// NewPublication validates the certified matrix and calculates canonical JSON.
func NewPublication(input PublicationInput) (Publication, error) {
	if input.SchemaVersion != SupportedSchemaMajor || !validIdentifier(input.ReleaseID) ||
		!validIdentifier(input.BuildID) || !validSemanticVersion(input.Version) ||
		!validSourceCommit(input.SourceCommit) || input.BuildTimestamp.IsZero() ||
		input.BuildTimestamp.Unix() <= 0 || input.BuildTimestamp.Nanosecond() != 0 ||
		input.DistributionEnvelopeDigest.IsZero() || input.DistributionEnvelopeSize == 0 ||
		input.DistributionEnvelopeSize > maxSafeJSONInteger || input.ReleaseTrustDigest.IsZero() ||
		input.ReleaseTrustSize == 0 || input.ReleaseTrustSize > maxSafeJSONInteger ||
		len(input.Artifacts) != len(requiredNativeCells)+1 {
		return Publication{}, errors.New("publication identity or inventory is invalid")
	}
	artifacts := make([]Artifact, 0, len(input.Artifacts))
	identifiers := make(map[string]struct{}, len(input.Artifacts))
	if input.DistributionEnvelopeDigest.Equal(input.ReleaseTrustDigest) {
		return Publication{}, errors.New("publication authority objects alias one digest")
	}
	digests := map[string]struct{}{
		input.DistributionEnvelopeDigest.Hex(): {}, input.ReleaseTrustDigest.Hex(): {},
	}
	cells := make(map[string]struct{}, len(requiredNativeCells))
	offlineBundles := 0
	for _, artifactInput := range input.Artifacts {
		artifact, err := newArtifact(artifactInput)
		if err != nil {
			return Publication{}, err
		}
		if _, exists := identifiers[artifact.ID()]; exists {
			return Publication{}, errors.New("publication contains a duplicate artifact ID")
		}
		identifiers[artifact.ID()] = struct{}{}
		for _, digest := range []releaseinventory.Digest{
			artifact.Digest(), artifact.CycloneDXSBOMDigest(), artifact.ProvenanceDigest(), artifact.SignatureBundleDigest(),
		} {
			if _, exists := digests[digest.Hex()]; exists {
				return Publication{}, errors.New("publication aliases exact object or evidence digests")
			}
			digests[digest.Hex()] = struct{}{}
		}
		if artifact.Kind() == ArtifactKindNativePackage {
			cell := artifact.OperatingSystem() + "/" + artifact.Architecture() + "/" + string(artifact.Format())
			if _, exists := cells[cell]; exists {
				return Publication{}, errors.New("publication contains a duplicate native package cell")
			}
			cells[cell] = struct{}{}
		} else {
			offlineBundles++
		}
		artifacts = append(artifacts, artifact)
	}
	if offlineBundles != 1 || len(cells) != len(requiredNativeCells) {
		return Publication{}, errors.New("publication certified matrix is incomplete")
	}
	for cell := range requiredNativeCells {
		if _, exists := cells[cell]; !exists {
			return Publication{}, errors.New("publication certified matrix is incomplete")
		}
	}
	sort.Slice(artifacts, func(left, right int) bool { return artifacts[left].ID() < artifacts[right].ID() })
	publication := Publication{
		schemaVersion: input.SchemaVersion, releaseID: input.ReleaseID, version: input.Version,
		buildID: input.BuildID, sourceCommit: input.SourceCommit, buildTimestamp: input.BuildTimestamp.Unix(),
		distributionEnvelopeDigest: input.DistributionEnvelopeDigest,
		distributionEnvelopeSize:   input.DistributionEnvelopeSize,
		releaseTrustDigest:         input.ReleaseTrustDigest, releaseTrustSize: input.ReleaseTrustSize,
		artifacts: artifacts,
	}
	canonical, err := publication.encodeCanonical()
	if err != nil {
		return Publication{}, err
	}
	publication.canonical = canonical
	return publication, nil
}

func validSemanticVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 1 && part[0] == '0' {
			return false
		}
		for _, character := range part {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func validSourceCommit(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return strings.Trim(value, "0") != ""
}

func (p Publication) encodeCanonical() ([]byte, error) {
	artifacts := make([]canonicalArtifact, 0, len(p.artifacts))
	for _, artifact := range p.artifacts {
		artifacts = append(artifacts, canonicalArtifactFrom(artifact))
	}
	document := canonicalPublication{
		Artifacts: artifacts, BuildID: p.buildID, BuildTimestamp: p.buildTimestamp,
		DistributionEnvelopeSHA256: p.distributionEnvelopeDigest.Hex(),
		DistributionEnvelopeSize:   p.distributionEnvelopeSize, ReleaseID: p.releaseID,
		ReleaseTrustSHA256: p.releaseTrustDigest.Hex(), ReleaseTrustSize: p.releaseTrustSize,
		SchemaVersion: p.schemaVersion, SourceCommit: p.sourceCommit, Version: p.version,
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return nil, errors.New("encode publication record")
	}
	return bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), nil
}

// SchemaVersion returns the understood publication major.
func (p Publication) SchemaVersion() uint16 { return p.schemaVersion }

// ReleaseID returns the manifest-bound release identifier.
func (p Publication) ReleaseID() string { return p.releaseID }

// Version returns the stable product semantic version.
func (p Publication) Version() string { return p.version }

// BuildID returns the qualified candidate-build identifier.
func (p Publication) BuildID() string { return p.buildID }

// SourceCommit returns the exact clean source revision.
func (p Publication) SourceCommit() string { return p.sourceCommit }

// BuildTimestamp returns the canonical source build time.
func (p Publication) BuildTimestamp() time.Time {
	return time.Unix(p.buildTimestamp, 0).UTC()
}

// DistributionEnvelopeDigest returns the packaged inner authority digest.
func (p Publication) DistributionEnvelopeDigest() releaseinventory.Digest {
	return p.distributionEnvelopeDigest
}

// DistributionEnvelopeSize returns the packaged inner authority byte length.
func (p Publication) DistributionEnvelopeSize() uint64 { return p.distributionEnvelopeSize }

// ReleaseTrustDigest returns the native binaries' embedded public authority digest.
func (p Publication) ReleaseTrustDigest() releaseinventory.Digest { return p.releaseTrustDigest }

// ReleaseTrustSize returns the embedded public authority byte length.
func (p Publication) ReleaseTrustSize() uint64 { return p.releaseTrustSize }

// Artifacts returns an independently copied canonical artifact inventory.
func (p Publication) Artifacts() []Artifact { return append([]Artifact(nil), p.artifacts...) }

// NativePackage returns the single signed native installer authorized for an
// exact certified operating-system, architecture, and package-format cell.
// It never falls back across cells or returns the all-platform offline bundle.
func (p Publication) NativePackage(
	operatingSystem string,
	architecture string,
	format Format,
) (Artifact, error) {
	if len(p.canonical) == 0 || operatingSystem == "" || architecture == "" || format == "" {
		return Artifact{}, errors.New("native publication selection is invalid")
	}
	for _, artifact := range p.artifacts {
		if artifact.Kind() == ArtifactKindNativePackage &&
			artifact.OperatingSystem() == operatingSystem &&
			artifact.Architecture() == architecture && artifact.Format() == format {
			return artifact, nil
		}
	}
	return Artifact{}, errors.New("native publication cell is unsupported")
}

// Canonical returns the exact bytes signed for promotion.
func (p Publication) Canonical() []byte { return append([]byte(nil), p.canonical...) }
