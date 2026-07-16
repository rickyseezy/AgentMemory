// Package releasefixture builds a small, valid release authority for command
// integration tests. It intentionally uses the same public constructors as a
// release producer so command tests exercise the production codecs end to end.
package releasefixture

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

// FixedIdentity is the canonical identity shared by release command fixtures.
const (
	ReleaseID    = "agentmemory-1.0.0"
	Version      = "1.0.0"
	BuildID      = "build-20260701-1"
	SourceCommit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	SourceEpoch  = int64(1_782_860_400)
)

// SignedEnvelope returns a canonical key-ID envelope over CanonicalManifest.
func SignedEnvelope() ([]byte, error) {
	manifestRaw, err := CanonicalManifest()
	if err != nil {
		return nil, err
	}
	manifest, err := releaseinventory.DecodeManifestV1(manifestRaw)
	if err != nil {
		return nil, fmt.Errorf("decode fixture manifest: %w", err)
	}
	signed, err := releaseinventory.NewSignedManifest(manifest, releaseinventory.SignatureBundleInput{
		SchemaVersion:       releaseinventory.SupportedSignatureBundleSchemaMajor,
		TrustMode:           releaseinventory.SignatureTrustModeKeyID,
		TrustRootID:         "release-root-2026",
		Signature:           bytes.Repeat([]byte{0x42}, releaseinventory.ManifestSignatureSize),
		RevocationSet:       []byte("fixture-revocations"),
		TrustedTimeEvidence: []byte("fixture-trusted-time"),
	})
	if err != nil {
		return nil, fmt.Errorf("sign fixture manifest: %w", err)
	}
	envelope, err := releaseinventory.EncodeSignedManifestV1(signed)
	if err != nil {
		return nil, fmt.Errorf("encode fixture envelope: %w", err)
	}
	return envelope, nil
}

// CanonicalManifest returns a valid canonical manifest containing one Linux
// image, its OCI index, and the complete evidence set for both subjects.
func CanonicalManifest() ([]byte, error) {
	platform, err := releaseinventory.NewPlatform("linux", "amd64")
	if err != nil {
		return nil, fmt.Errorf("create fixture platform: %w", err)
	}
	imageDigest := releaseinventory.DigestBytes([]byte("fixture-image"))
	indexDigest := releaseinventory.DigestBytes([]byte("fixture-index"))
	image := subjectInput("image", releaseinventory.ResourceKindOCIImage, platform, imageDigest)
	image.OCIIndexDigest = indexDigest
	image.OCIIndexResourceID = "image-index"
	index := subjectInput("image-index", releaseinventory.ResourceKindOCIIndex, releaseinventory.Platform{}, indexDigest)
	resources, err := subjectResources(image)
	if err != nil {
		return nil, err
	}
	indexResources, err := subjectResources(index)
	if err != nil {
		return nil, err
	}
	resources = append(resources, indexResources...)

	protocol, err := releaseinventory.NewProtocolRange(1, 3)
	if err != nil {
		return nil, fmt.Errorf("create fixture protocol: %w", err)
	}
	versionRange, err := releaseinventory.NewVersionRange(releaseinventory.VersionRangeInput{
		Minimum: "1.0.0", Maximum: "1.0.0",
	})
	if err != nil {
		return nil, fmt.Errorf("create fixture version range: %w", err)
	}
	compatibility, err := releaseinventory.NewCompatibility(releaseinventory.CompatibilityInput{
		Launcher: versionRange, CoreAPI: versionRange, MCP: versionRange,
		Provider: versionRange, Schema: versionRange, Compose: versionRange,
		SQLite: versionRange, Neo4j: versionRange, RuntimeCatalog: versionRange,
	})
	if err != nil {
		return nil, fmt.Errorf("create fixture compatibility: %w", err)
	}
	trust, err := releaseinventory.NewTrustPolicy(
		releaseinventory.SignatureTrustModeKeyID,
		"release-root-2026",
		releaseinventory.DigestBytes([]byte("fixture-revocations")),
		"",
	)
	if err != nil {
		return nil, fmt.Errorf("create fixture trust: %w", err)
	}
	history, err := releaseinventory.NewReleaseHistory(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create fixture history: %w", err)
	}
	topology, err := releaseinventory.NewDockerTopology(fixtureTopology())
	if err != nil {
		return nil, fmt.Errorf("create fixture topology: %w", err)
	}
	manifest, err := releaseinventory.NewManifest(releaseinventory.ManifestInput{
		SchemaVersion: 1,
		ReleaseID:     ReleaseID,
		Version:       Version,
		BuildID:       BuildID,
		SourceCommit:  strings.Repeat("a", len(SourceCommit)),
		BuildTimestamp: time.Date(
			2026, time.June, 30, 23, 0, 0, 0, time.UTC,
		),
		Channel:                   releaseinventory.ReleaseChannelStable,
		Sequence:                  42,
		DataGeneration:            6,
		ValidFrom:                 time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC),
		ValidUntil:                time.Date(2027, time.July, 1, 0, 0, 0, 0, time.UTC),
		Protocol:                  protocol,
		Compatibility:             compatibility,
		TrustPolicy:               trust,
		ReleaseHistory:            history,
		LicensePolicyDigest:       releaseinventory.DigestBytes([]byte("license-policy")),
		VulnerabilityPolicyDigest: releaseinventory.DigestBytes([]byte("vulnerability-policy")),
		DockerTopology:            topology,
		Resources:                 resources,
	})
	if err != nil {
		return nil, fmt.Errorf("create fixture manifest: %w", err)
	}
	return manifest.CanonicalBytes(), nil
}

func subjectInput(
	id string,
	kind releaseinventory.ResourceKind,
	platform releaseinventory.Platform,
	digest releaseinventory.Digest,
) releaseinventory.ResourceInput {
	source := "registry.example/agentmemory/" + id + "@sha256:" + digest.Hex()
	return releaseinventory.ResourceInput{
		ID: id, Kind: kind, Purpose: purpose(kind), MediaType: mediaType(kind), Platform: platform,
		Digest: digest, Size: uint64(len(id)), SourceRef: source, SourceAllowlist: []string{source},
		CycloneDXSBOMResourceID: id + "-cyclonedx",
		SPDXSBOMResourceID:      id + "-spdx",
		ProvenanceResourceID:    id + "-provenance",
		LicenseResourceID:       id + "-licenses",
		VulnerabilityResourceID: id + "-vulnerabilities",
	}
}

func subjectResources(input releaseinventory.ResourceInput) ([]releaseinventory.Resource, error) {
	subject, err := releaseinventory.NewResource(input)
	if err != nil {
		return nil, fmt.Errorf("create fixture subject %q: %w", input.ID, err)
	}
	result := []releaseinventory.Resource{subject}
	for _, kind := range []releaseinventory.ResourceKind{
		releaseinventory.ResourceKindCycloneDXSBOM,
		releaseinventory.ResourceKindSPDXSBOM,
		releaseinventory.ResourceKindProvenance,
		releaseinventory.ResourceKindLicense,
		releaseinventory.ResourceKindVulnerabilityReport,
	} {
		id := evidenceID(input.ID, kind)
		digest := releaseinventory.DigestBytes([]byte(id))
		source := "bundle://" + id
		evidenceInput := releaseinventory.ResourceInput{
			ID: id, Kind: kind, Purpose: purpose(kind), MediaType: mediaType(kind),
			Digest: digest, Size: uint64(len(id)), SourceRef: source, SourceAllowlist: []string{source},
			SubjectResourceID: input.ID, SubjectDigest: input.Digest,
		}
		if kind == releaseinventory.ResourceKindLicense {
			evidenceInput.PolicySnapshotDigest = releaseinventory.DigestBytes([]byte("license-policy"))
			evidenceInput.QualificationResult = releaseinventory.QualificationResultPassed
		}
		if kind == releaseinventory.ResourceKindVulnerabilityReport {
			evidenceInput.PolicySnapshotDigest = releaseinventory.DigestBytes([]byte("vulnerability-policy"))
			evidenceInput.QualificationResult = releaseinventory.QualificationResultPassed
			evidenceInput.QualificationExpiresAt = time.Date(2027, time.August, 1, 0, 0, 0, 0, time.UTC)
		}
		evidence, evidenceErr := releaseinventory.NewResource(evidenceInput)
		if evidenceErr != nil {
			return nil, fmt.Errorf("create fixture evidence %q: %w", id, evidenceErr)
		}
		result = append(result, evidence)
	}
	return result, nil
}

func evidenceID(subject string, kind releaseinventory.ResourceKind) string {
	switch kind { //nolint:exhaustive // Only evidence kinds have fixture evidence identifiers.
	case releaseinventory.ResourceKindCycloneDXSBOM:
		return subject + "-cyclonedx"
	case releaseinventory.ResourceKindSPDXSBOM:
		return subject + "-spdx"
	case releaseinventory.ResourceKindProvenance:
		return subject + "-provenance"
	case releaseinventory.ResourceKindLicense:
		return subject + "-licenses"
	case releaseinventory.ResourceKindVulnerabilityReport:
		return subject + "-vulnerabilities"
	default:
		return ""
	}
}

func purpose(kind releaseinventory.ResourceKind) releaseinventory.ResourcePurpose {
	switch kind { //nolint:exhaustive // Unsupported fixture kinds intentionally have no evidence purpose.
	case releaseinventory.ResourceKindOCIImage:
		return releaseinventory.ResourcePurposeOCIPlatformManifest
	case releaseinventory.ResourceKindOCIIndex:
		return releaseinventory.ResourcePurposeOCIIndex
	case releaseinventory.ResourceKindCycloneDXSBOM:
		return releaseinventory.ResourcePurposeCycloneDXSBOM
	case releaseinventory.ResourceKindSPDXSBOM:
		return releaseinventory.ResourcePurposeSPDXSBOM
	case releaseinventory.ResourceKindProvenance:
		return releaseinventory.ResourcePurposeSLSAProvenance
	case releaseinventory.ResourceKindLicense:
		return releaseinventory.ResourcePurposeLicenseEvaluation
	case releaseinventory.ResourceKindVulnerabilityReport:
		return releaseinventory.ResourcePurposeVulnerabilityReport
	default:
		return ""
	}
}

func mediaType(kind releaseinventory.ResourceKind) string {
	switch kind { //nolint:exhaustive // Unsupported fixture kinds intentionally have no evidence media type.
	case releaseinventory.ResourceKindOCIImage:
		return releaseinventory.MediaTypeOCIManifest
	case releaseinventory.ResourceKindOCIIndex:
		return releaseinventory.MediaTypeOCIIndex
	case releaseinventory.ResourceKindCycloneDXSBOM:
		return releaseinventory.MediaTypeCycloneDX
	case releaseinventory.ResourceKindSPDXSBOM:
		return releaseinventory.MediaTypeSPDX
	case releaseinventory.ResourceKindProvenance:
		return releaseinventory.MediaTypeSLSAProvenance
	case releaseinventory.ResourceKindLicense:
		return releaseinventory.MediaTypeLicenseEvaluation
	case releaseinventory.ResourceKindVulnerabilityReport:
		return releaseinventory.MediaTypeVulnerabilityEvaluation
	default:
		return ""
	}
}

func fixtureTopology() releaseinventory.DockerTopologyInput {
	labels := []releaseinventory.TopologyLabelInput{{Key: "com.agentmemory.managed", Value: "true"}}
	return releaseinventory.DockerTopologyInput{
		Profiles: []string{"default"},
		Networks: []releaseinventory.DockerNetworkInput{{ID: "internal", Internal: true, Labels: labels}},
		Volumes:  []releaseinventory.DockerVolumeInput{{ID: "core-data", Purpose: "canonical-data", Labels: labels}},
		HealthProbes: []releaseinventory.HealthProbeInput{{
			ID: "core-ready", Kind: releaseinventory.HealthProbeKindHTTP, HTTPPath: "/ready", Port: 8080,
			IntervalSeconds: 10, TimeoutSeconds: 3, Retries: 5,
		}},
		Services: []releaseinventory.DockerServiceInput{{
			ID: "core", ImageResourceIDs: []string{"image"}, Profiles: []string{"default"},
			NetworkIDs: []string{"internal"},
			VolumeMounts: []releaseinventory.VolumeMountInput{{
				VolumeID: "core-data", Target: "/var/lib/agentmemory",
			}},
			HealthProbeID: "core-ready", UserID: 1000, GroupID: 1000,
			ReadOnlyRootFilesystem: true, NoNewPrivileges: true,
			PublishedPorts: []releaseinventory.PortBindingInput{{
				Host: "127.0.0.1", HostPort: 38765, ContainerPort: 8080,
			}},
			Labels: labels,
		}},
	}
}
