package runtimecatalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// DecodeManifestV1 accepts only exact canonical schema-v1 JSON and reconstructs immutable authority.
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
	if document.SchemaVersion != SupportedSchemaVersion {
		return Manifest{}, ErrManifestUnsupportedSchema
	}
	input, err := inputFromCanonical(document)
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

// EncodeManifestV1 returns a copy of exact canonical schema-v1 bytes.
func EncodeManifestV1(manifest Manifest) ([]byte, error) {
	if !manifest.Valid() {
		return nil, ErrManifestIntegrity
	}
	return manifest.CanonicalBytes(), nil
}

func inputFromCanonical(document canonicalManifest) (ManifestInput, error) {
	artifactDigest, err := ParseDigest(document.Artifact.SHA256)
	if err != nil {
		return ManifestInput{}, err
	}
	termsDigest, err := ParseDigest(document.Terms.Digest)
	if err != nil {
		return ManifestInput{}, err
	}
	components := make([]RuntimeComponentInput, 0, len(document.Runtime.Components))
	for _, component := range document.Runtime.Components {
		components = append(components, RuntimeComponentInput(component))
	}
	sources := make([]OfficialSourceInput, 0, len(document.Artifact.Sources))
	for _, source := range document.Artifact.Sources {
		sources = append(sources, OfficialSourceInput{
			Scheme: source.Scheme, Host: source.Host, PathPrefix: source.PathPrefix,
		})
	}
	arguments := make([]ArgumentTemplateInput, 0, len(document.Install.Arguments))
	for _, argument := range document.Install.Arguments {
		arguments = append(arguments, ArgumentTemplateInput(argument))
	}
	prerequisites := make([]PrerequisiteInput, 0, len(document.Prerequisites))
	for _, prerequisite := range document.Prerequisites {
		prerequisites = append(prerequisites, PrerequisiteInput{
			Operation: prerequisite.Operation, FeatureID: prerequisite.FeatureID,
			PackageIDs:   append([]string(nil), prerequisite.PackageIDs...),
			RepositoryID: prerequisite.RepositoryID, ServiceID: prerequisite.ServiceID,
			SubordinateIDCount: prerequisite.SubordinateIDCount,
		})
	}
	return ManifestInput{
		SchemaVersion: document.SchemaVersion, CatalogID: document.CatalogID,
		CatalogSequence: document.CatalogSequence, SigningKeyID: document.SigningKeyID,
		SupportExpiresAt: time.UnixMicro(document.SupportExpiresAt).UTC(),
		Platform: PlatformPolicyInput{
			OperatingSystem: document.Platform.OperatingSystem,
			Architecture:    document.Platform.Architecture,
			Edition:         document.Platform.Edition, Distribution: document.Platform.Distribution,
			MinimumOSVersion: document.Platform.MinimumOSVersion,
			MaximumOSVersion: document.Platform.MaximumOSVersion,
			MinimumBuild:     document.Platform.MinimumBuild, MaximumBuild: document.Platform.MaximumBuild,
			MinimumCPUCores:        document.Platform.MinimumCPUCores,
			MinimumMemoryBytes:     document.Platform.MinimumMemoryBytes,
			MinimumFreeDiskBytes:   document.Platform.MinimumFreeDiskBytes,
			VirtualizationRequired: document.Platform.VirtualizationRequired,
		},
		Runtime: RuntimePolicyInput{
			Product: document.Runtime.Product, Channel: document.Runtime.Channel,
			Version: document.Runtime.Version, ComposeVersion: document.Runtime.ComposeVersion,
			Components: components,
		},
		Artifact: ArtifactPolicyInput{
			DownloadBytes: document.Artifact.DownloadBytes,
			ExpandedBytes: document.Artifact.ExpandedBytes,
			ReserveBytes:  document.Artifact.ReserveBytes, SHA256: artifactDigest,
			Sources: sources, ProxyMode: document.Artifact.ProxyMode,
			OfflinePolicy:           document.Artifact.OfflinePolicy,
			RedistributionPermitted: document.Artifact.RedistributionPermitted,
			Publisher: PublisherPolicyInput{
				Verification:       document.Artifact.Publisher.Verification,
				Identity:           document.Artifact.Publisher.Identity,
				SigningKeyIdentity: document.Artifact.Publisher.SigningKeyIdentity,
				PackageIdentity:    document.Artifact.Publisher.PackageIdentity,
			},
		},
		Install: InstallerPolicyInput{
			Executable: document.Install.Executable, Arguments: arguments,
			RebootExitCodes:   append([]uint32(nil), document.Install.RebootExitCodes...),
			ServiceIdentity:   document.Install.ServiceIdentity,
			RollbackStrategy:  document.Install.RollbackStrategy,
			OwnershipChanges:  append([]string(nil), document.Install.OwnershipChanges...),
			VendorUIMandatory: document.Install.VendorUIMandatory,
		},
		Prerequisites:    prerequisites,
		CapabilityProbes: append([]CapabilityProbe(nil), document.CapabilityProbes...),
		Terms: TermsPolicyInput{
			ID: document.Terms.ID, Version: document.Terms.Version,
			URL: OfficialSourceInput{
				Scheme: document.Terms.URL.Scheme, Host: document.Terms.URL.Host,
				PathPrefix: document.Terms.URL.PathPrefix,
			},
			Digest: termsDigest, Presentation: document.Terms.Presentation,
		},
	}, nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, 0); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
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
			keyToken, keyError := decoder.Token()
			if keyError != nil {
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
			if valueError := scanJSONValue(decoder, depth+1); valueError != nil {
				return valueError
			}
		}
		closing, closingError := decoder.Token()
		if closingError != nil || closing != json.Delim('}') {
			return ErrManifestMalformed
		}
	case '[':
		for decoder.More() {
			if valueError := scanJSONValue(decoder, depth+1); valueError != nil {
				return valueError
			}
		}
		closing, closingError := decoder.Token()
		if closingError != nil || closing != json.Delim(']') {
			return ErrManifestMalformed
		}
	default:
		return ErrManifestMalformed
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return ErrManifestMalformed
}
