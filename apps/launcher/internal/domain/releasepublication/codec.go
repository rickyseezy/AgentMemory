package releasepublication

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

const (
	maximumPublicationBytes = 4 * 1024 * 1024
	maximumJSONDepth        = 16
)

type canonicalArtifact struct {
	Architecture          string `json:"architecture"`
	CycloneDXSBOMSHA256   string `json:"cyclonedx_sbom_sha256"`
	FileName              string `json:"file_name"`
	Format                string `json:"format"`
	ID                    string `json:"id"`
	Kind                  string `json:"kind"`
	MediaType             string `json:"media_type"`
	NativePublisherPolicy string `json:"native_publisher_policy"`
	OperatingSystem       string `json:"operating_system"`
	ProvenanceSHA256      string `json:"provenance_sha256"`
	SHA256                string `json:"sha256"`
	SignatureBundleSHA256 string `json:"signature_bundle_sha256"`
	Size                  uint64 `json:"size"`
}

type canonicalPublication struct {
	Artifacts                  []canonicalArtifact `json:"artifacts"`
	BuildID                    string              `json:"build_id"`
	BuildTimestamp             int64               `json:"build_timestamp"`
	DistributionEnvelopeSHA256 string              `json:"distribution_envelope_sha256"`
	DistributionEnvelopeSize   uint64              `json:"distribution_envelope_size"`
	ReleaseID                  string              `json:"release_id"`
	SchemaVersion              uint16              `json:"schema_version"`
	SourceCommit               string              `json:"source_commit"`
	Version                    string              `json:"version"`
}

func canonicalArtifactFrom(artifact Artifact) canonicalArtifact {
	return canonicalArtifact{
		Architecture: artifact.Architecture(), CycloneDXSBOMSHA256: artifact.CycloneDXSBOMDigest().Hex(),
		FileName: artifact.FileName(), Format: string(artifact.Format()), ID: artifact.ID(),
		Kind: string(artifact.Kind()), MediaType: artifact.MediaType(),
		NativePublisherPolicy: string(artifact.NativePublisherPolicy()), OperatingSystem: artifact.OperatingSystem(),
		ProvenanceSHA256: artifact.ProvenanceDigest().Hex(), SHA256: artifact.Digest().Hex(),
		SignatureBundleSHA256: artifact.SignatureBundleDigest().Hex(), Size: artifact.Size(),
	}
}

// EncodeV1 returns the exact canonical bytes signed by the release authority.
func EncodeV1(publication Publication) ([]byte, error) {
	if publication.SchemaVersion() != SupportedSchemaMajor || len(publication.canonical) == 0 {
		return nil, errors.New("publication schema is unsupported")
	}
	return publication.Canonical(), nil
}

// DecodeV1 accepts only the exact canonical closed schema.
func DecodeV1(raw []byte) (Publication, error) {
	if len(raw) == 0 || len(raw) > maximumPublicationBytes || rejectDuplicateKeys(raw) != nil {
		return Publication{}, errors.New("publication JSON is malformed")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document canonicalPublication
	if err := decoder.Decode(&document); err != nil {
		return Publication{}, errors.New("publication JSON is malformed or open")
	}
	if err := requireEOF(decoder); err != nil {
		return Publication{}, err
	}
	distribution, err := releaseinventory.ParseDigest(document.DistributionEnvelopeSHA256)
	if err != nil {
		return Publication{}, errors.New("publication distribution digest is invalid")
	}
	inputs := make([]ArtifactInput, 0, len(document.Artifacts))
	for _, artifact := range document.Artifacts {
		digest, digestErr := releaseinventory.ParseDigest(artifact.SHA256)
		cycloneDX, cycloneDXErr := releaseinventory.ParseDigest(artifact.CycloneDXSBOMSHA256)
		provenance, provenanceErr := releaseinventory.ParseDigest(artifact.ProvenanceSHA256)
		signature, signatureErr := releaseinventory.ParseDigest(artifact.SignatureBundleSHA256)
		if digestErr != nil || cycloneDXErr != nil || provenanceErr != nil || signatureErr != nil {
			return Publication{}, errors.New("publication artifact digest is invalid")
		}
		inputs = append(inputs, ArtifactInput{
			ID: artifact.ID, Kind: ArtifactKind(artifact.Kind), OperatingSystem: artifact.OperatingSystem,
			Architecture: artifact.Architecture, Format: Format(artifact.Format), FileName: artifact.FileName,
			MediaType: artifact.MediaType, Digest: digest, Size: artifact.Size,
			CycloneDXSBOMDigest: cycloneDX, ProvenanceDigest: provenance,
			SignatureBundleDigest: signature, NativePublisherPolicy: NativePublisherPolicy(artifact.NativePublisherPolicy),
		})
	}
	publication, err := NewPublication(PublicationInput{
		SchemaVersion: document.SchemaVersion, ReleaseID: document.ReleaseID, Version: document.Version,
		BuildID: document.BuildID, SourceCommit: document.SourceCommit,
		BuildTimestamp:             time.Unix(document.BuildTimestamp, 0).UTC(),
		DistributionEnvelopeDigest: distribution, DistributionEnvelopeSize: document.DistributionEnvelopeSize,
		Artifacts: inputs,
	})
	if err != nil || !bytes.Equal(raw, publication.canonical) {
		return Publication{}, errors.New("publication JSON is non-canonical or invalid")
	}
	return publication, nil
}

func rejectDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanValue(decoder, 0); err != nil {
		return err
	}
	return requireEOF(decoder)
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	}
	return errors.New("publication JSON has trailing input")
}

func scanValue(decoder *json.Decoder, depth uint32) error {
	if depth > maximumJSONDepth {
		return errors.New("publication JSON nesting is excessive")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			key, ok := keyToken.(string)
			if keyErr != nil || !ok {
				return errors.New("publication JSON object is malformed")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("publication JSON contains duplicate keys")
			}
			seen[key] = struct{}{}
			if err := scanValue(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := scanValue(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("publication JSON delimiter is invalid")
	}
	closing, err := decoder.Token()
	if err != nil || delimiter == '{' && closing != json.Delim('}') ||
		delimiter == '[' && closing != json.Delim(']') {
		return errors.New("publication JSON composite is incomplete")
	}
	return nil
}
