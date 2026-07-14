package releaseinventory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const maximumRawManifestBytes = 16 * 1024 * 1024

const maximumManifestJSONDepth = 64

var (
	// ErrManifestMalformed means the raw document is not one bounded JSON object.
	ErrManifestMalformed = errors.New("release manifest JSON is malformed")
	// ErrManifestDuplicateKey means an object repeats a key at any depth.
	ErrManifestDuplicateKey = errors.New("release manifest contains a duplicate JSON key")
	// ErrManifestUnknownField means schema v1 does not understand an input field.
	ErrManifestUnknownField = errors.New("release manifest contains an unknown field")
	// ErrManifestNonCanonical means the input bytes are not the exact canonical encoding.
	ErrManifestNonCanonical = errors.New("release manifest JSON is not canonical")
	// ErrManifestUnsupportedSchema means the declared major is not supported.
	ErrManifestUnsupportedSchema = errors.New("release manifest schema major is unsupported")
	// ErrManifestIntegrity means understood fields disagree or violate signed policy.
	ErrManifestIntegrity = errors.New("release manifest integrity validation failed")
)

// DecodeManifestV1 parses only exact canonical schema-v1 bytes and reconstructs
// the immutable execution authority. It never normalizes untrusted input before
// deciding whether the signed representation is acceptable.
func DecodeManifestV1(raw []byte) (Manifest, error) {
	if len(raw) == 0 || len(raw) > maximumRawManifestBytes {
		return Manifest{}, ErrManifestMalformed
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return Manifest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document canonicalManifest
	if err := decoder.Decode(&document); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return Manifest{}, fmt.Errorf("%w", ErrManifestUnknownField)
		}
		return Manifest{}, fmt.Errorf("%w", ErrManifestMalformed)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Manifest{}, ErrManifestMalformed
	}
	if document.SchemaVersion != SupportedManifestSchemaMajor {
		return Manifest{}, ErrManifestUnsupportedSchema
	}
	input, err := manifestInputFromCanonical(document)
	if err != nil {
		return Manifest{}, fmt.Errorf("%w", ErrManifestIntegrity)
	}
	manifest, err := NewManifest(input)
	if err != nil {
		return Manifest{}, fmt.Errorf("%w", ErrManifestIntegrity)
	}
	if !bytes.Equal(raw, manifest.CanonicalBytes()) {
		return Manifest{}, ErrManifestNonCanonical
	}
	return manifest, nil
}

// EncodeManifestV1 returns a copy of the exact canonical schema-v1 bytes.
func EncodeManifestV1(manifest Manifest) ([]byte, error) {
	if manifest.SchemaVersion() != SupportedManifestSchemaMajor || len(manifest.canonical) == 0 {
		return nil, ErrManifestUnsupportedSchema
	}
	return manifest.CanonicalBytes(), nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return ErrManifestMalformed
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, 0); err != nil {
		return err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return ErrManifestMalformed
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder, depth uint32) error {
	if depth > maximumManifestJSONDepth {
		return ErrManifestMalformed
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrManifestMalformed
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return ErrManifestMalformed
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrManifestMalformed
			}
			if _, duplicate := seen[key]; duplicate {
				return ErrManifestDuplicateKey
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return ErrManifestMalformed
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrManifestMalformed
		}
	default:
		return ErrManifestMalformed
	}
	return nil
}

func manifestInputFromCanonical(document canonicalManifest) (ManifestInput, error) {
	protocol, err := NewProtocolRange(document.Protocol.Minimum, document.Protocol.Maximum)
	if err != nil {
		return ManifestInput{}, err
	}
	compatibility, err := compatibilityFromCanonical(document.Compatibility)
	if err != nil {
		return ManifestInput{}, err
	}
	revocationDigest, err := ParseDigest(document.TrustPolicy.RevocationSetDigest)
	if err != nil {
		return ManifestInput{}, err
	}
	trustPolicy, err := NewTrustPolicyWithRuntimeRoot(
		SignatureTrustMode(document.TrustPolicy.Mode),
		document.TrustPolicy.TrustRootID,
		document.TrustPolicy.RuntimeTrustRootID,
		revocationDigest,
		document.TrustPolicy.TransparencyLogID,
	)
	if err != nil {
		return ManifestInput{}, err
	}
	history, err := historyFromCanonical(document.PriorReleases, document.RollbackReleases)
	if err != nil {
		return ManifestInput{}, err
	}
	topology, err := topologyFromCanonical(document.DockerTopology)
	if err != nil {
		return ManifestInput{}, err
	}
	resources, err := resourcesFromCanonical(document.Resources)
	if err != nil {
		return ManifestInput{}, err
	}
	licensePolicyDigest, err := ParseDigest(document.LicensePolicyDigest)
	if err != nil {
		return ManifestInput{}, err
	}
	vulnerabilityPolicyDigest, err := ParseDigest(document.VulnerabilityPolicyDigest)
	if err != nil {
		return ManifestInput{}, err
	}
	return ManifestInput{
		SchemaVersion: document.SchemaVersion, ReleaseID: document.ReleaseID,
		Version: document.Version, BuildID: document.BuildID, SourceCommit: document.SourceCommit,
		BuildTimestamp: time.UnixMicro(document.BuildTimestamp).UTC(), Channel: ReleaseChannel(document.Channel),
		Sequence: document.Sequence, DataGeneration: document.DataGeneration,
		ValidFrom: time.UnixMicro(document.ValidFrom).UTC(), ValidUntil: time.UnixMicro(document.ValidUntil).UTC(),
		Protocol: protocol, Compatibility: compatibility, TrustPolicy: trustPolicy,
		ReleaseHistory: history, LicensePolicyDigest: licensePolicyDigest,
		VulnerabilityPolicyDigest: vulnerabilityPolicyDigest, DockerTopology: topology,
		Resources: resources,
	}, nil
}

func compatibilityFromCanonical(document canonicalCompatibility) (Compatibility, error) {
	compose, err := versionRangeFromCanonical(document.Compose)
	if err != nil {
		return Compatibility{}, err
	}
	coreAPI, err := versionRangeFromCanonical(document.CoreAPI)
	if err != nil {
		return Compatibility{}, err
	}
	launcher, err := versionRangeFromCanonical(document.Launcher)
	if err != nil {
		return Compatibility{}, err
	}
	mcp, err := versionRangeFromCanonical(document.MCP)
	if err != nil {
		return Compatibility{}, err
	}
	neo4j, err := versionRangeFromCanonical(document.Neo4j)
	if err != nil {
		return Compatibility{}, err
	}
	provider, err := versionRangeFromCanonical(document.Provider)
	if err != nil {
		return Compatibility{}, err
	}
	runtimeCatalog, err := versionRangeFromCanonical(document.RuntimeCatalog)
	if err != nil {
		return Compatibility{}, err
	}
	schema, err := versionRangeFromCanonical(document.Schema)
	if err != nil {
		return Compatibility{}, err
	}
	sqlite, err := versionRangeFromCanonical(document.SQLite)
	if err != nil {
		return Compatibility{}, err
	}
	return NewCompatibility(CompatibilityInput{
		Launcher: launcher, CoreAPI: coreAPI, MCP: mcp, Provider: provider,
		Schema: schema, Compose: compose, SQLite: sqlite, Neo4j: neo4j,
		RuntimeCatalog: runtimeCatalog,
	})
}

func versionRangeFromCanonical(document canonicalVersionRange) (VersionRange, error) {
	return NewVersionRange(VersionRangeInput{Minimum: document.Minimum, Maximum: document.Maximum})
}

func historyFromCanonical(
	priorDocuments []canonicalPriorRelease,
	rollbackDocuments []canonicalRollbackRelease,
) (ReleaseHistory, error) {
	prior := make([]PriorReleaseInput, 0, len(priorDocuments))
	for _, document := range priorDocuments {
		digest, err := ParseDigest(document.ManifestDigest)
		if err != nil {
			return ReleaseHistory{}, err
		}
		prior = append(prior, PriorReleaseInput{
			ReleaseID: document.ReleaseID, ManifestDigest: digest,
			MinimumDataGeneration: document.MinimumDataGeneration,
			MaximumDataGeneration: document.MaximumDataGeneration,
		})
	}
	rollback := make([]RollbackReleaseInput, 0, len(rollbackDocuments))
	for _, document := range rollbackDocuments {
		digest, err := ParseDigest(document.ManifestDigest)
		if err != nil {
			return ReleaseHistory{}, err
		}
		rollback = append(rollback, RollbackReleaseInput{
			ReleaseID: document.ReleaseID, ManifestDigest: digest,
			DataGeneration: document.DataGeneration,
		})
	}
	return NewReleaseHistory(prior, rollback)
}

func topologyFromCanonical(document canonicalDockerTopology) (DockerTopology, error) {
	networks := make([]DockerNetworkInput, 0, len(document.Networks))
	for _, network := range document.Networks {
		networks = append(networks, DockerNetworkInput{
			ID: network.ID, Internal: network.Internal, Labels: labelsFromCanonical(network.Labels),
		})
	}
	volumes := make([]DockerVolumeInput, 0, len(document.Volumes))
	for _, volume := range document.Volumes {
		volumes = append(volumes, DockerVolumeInput{
			ID: volume.ID, Purpose: volume.Purpose, Labels: labelsFromCanonical(volume.Labels),
		})
	}
	probes := make([]HealthProbeInput, 0, len(document.HealthProbes))
	for _, probe := range document.HealthProbes {
		probes = append(probes, HealthProbeInput{
			ID: probe.ID, Kind: HealthProbeKind(probe.Kind), HTTPPath: probe.HTTPPath,
			Arguments: append([]string(nil), probe.Arguments...), IntervalSeconds: probe.IntervalSeconds,
			Port: probe.Port, TimeoutSeconds: probe.TimeoutSeconds, Retries: probe.Retries,
		})
	}
	services := make([]DockerServiceInput, 0, len(document.Services))
	for _, service := range document.Services {
		services = append(services, DockerServiceInput{
			ID: service.ID, ImageResourceIDs: append([]string(nil), service.ImageResourceIDs...),
			Profiles: append([]string(nil), service.Profiles...), NetworkIDs: append([]string(nil), service.NetworkIDs...),
			VolumeMounts: volumeMountsFromCanonical(service.VolumeMounts), HealthProbeID: service.HealthProbeID,
			UserID: service.UserID, GroupID: service.GroupID, Privileged: service.Privileged,
			ReadOnlyRootFilesystem: service.ReadOnlyRootFilesystem, NoNewPrivileges: service.NoNewPrivileges,
			Capabilities:   append([]string(nil), service.Capabilities...),
			PublishedPorts: portBindingsFromCanonical(service.PublishedPorts),
			Labels:         labelsFromCanonical(service.Labels),
		})
	}
	return NewDockerTopology(DockerTopologyInput{
		Profiles: append([]string(nil), document.Profiles...), Networks: networks,
		Volumes: volumes, HealthProbes: probes, Services: services,
	})
}

func labelsFromCanonical(documents []canonicalTopologyLabel) []TopologyLabelInput {
	result := make([]TopologyLabelInput, 0, len(documents))
	for _, document := range documents {
		result = append(result, TopologyLabelInput(document))
	}
	return result
}

func volumeMountsFromCanonical(documents []canonicalVolumeMount) []VolumeMountInput {
	result := make([]VolumeMountInput, 0, len(documents))
	for _, document := range documents {
		result = append(result, VolumeMountInput{
			VolumeID: document.VolumeID, Target: document.Target, ReadOnly: document.ReadOnly,
		})
	}
	return result
}

func portBindingsFromCanonical(documents []canonicalPortBinding) []PortBindingInput {
	result := make([]PortBindingInput, 0, len(documents))
	for _, document := range documents {
		result = append(result, PortBindingInput{
			Host: document.Host, HostPort: document.HostPort, ContainerPort: document.ContainerPort,
		})
	}
	return result
}

func resourcesFromCanonical(documents []canonicalResource) ([]Resource, error) {
	resources := make([]Resource, 0, len(documents))
	for _, document := range documents {
		resource, err := resourceFromCanonical(document)
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}
	return resources, nil
}

func resourceFromCanonical(document canonicalResource) (Resource, error) {
	digest, err := ParseDigest(document.Digest)
	if err != nil {
		return Resource{}, err
	}
	ociIndexDigest, err := parseOptionalDigest(document.OCIIndexDigest)
	if err != nil {
		return Resource{}, err
	}
	policySnapshotDigest, err := parseOptionalDigest(document.PolicySnapshotDigest)
	if err != nil {
		return Resource{}, err
	}
	subjectDigest, err := parseOptionalDigest(document.SubjectDigest)
	if err != nil {
		return Resource{}, err
	}
	expandedDigest, err := parseOptionalDigest(document.ExpandedTarget.Digest)
	if err != nil {
		return Resource{}, err
	}
	platform := Platform{}
	if document.Platform.OS != "" || document.Platform.Architecture != "" {
		platform, err = NewPlatform(document.Platform.OS, document.Platform.Architecture)
		if err != nil {
			return Resource{}, err
		}
	}
	qualificationExpiry := time.Time{}
	if document.QualificationExpiresAt != 0 {
		qualificationExpiry = time.UnixMicro(document.QualificationExpiresAt).UTC()
	}
	return NewResource(ResourceInput{
		ID: document.ID, Kind: ResourceKind(document.Kind), Purpose: ResourcePurpose(document.Purpose),
		MediaType: document.MediaType, ProviderRole: LocalProviderRole(document.ProviderRole), Platform: platform,
		Digest: digest, OCIIndexDigest: ociIndexDigest, OCIIndexResourceID: document.OCIIndexResourceID,
		Size: document.Size, SourceRef: document.SourceRef,
		SourceAllowlist:         append([]string(nil), document.SourceAllowlist...),
		CycloneDXSBOMResourceID: document.CycloneDXSBOMResourceID,
		SPDXSBOMResourceID:      document.SPDXSBOMResourceID,
		ProvenanceResourceID:    document.ProvenanceResourceID, LicenseResourceID: document.LicenseResourceID,
		VulnerabilityResourceID: document.VulnerabilityResourceID,
		NativePublisherIdentity: document.NativePublisherIdentity,
		NativePublisherPolicyID: document.NativePublisherPolicyID,
		SubjectResourceID:       document.SubjectResourceID, SubjectDigest: subjectDigest,
		PolicySnapshotDigest:   policySnapshotDigest,
		QualificationResult:    QualificationResult(document.QualificationResult),
		QualificationExpiresAt: qualificationExpiry,
		ExpandedTarget: ReleaseExpandedTargetInput{
			Kind: ExpandedTargetKind(document.ExpandedTarget.Kind), StorageID: document.ExpandedTarget.StorageID,
			Digest: expandedDigest, Bytes: document.ExpandedTarget.Bytes,
		},
	})
}

func parseOptionalDigest(value string) (Digest, error) {
	if value == "" {
		return Digest{}, nil
	}
	return ParseDigest(value)
}
