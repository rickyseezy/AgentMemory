package launcher

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"

	releaseverifyadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

const (
	nativeReleaseTrustSchemaVersion = uint16(1)
	maximumNativeReleaseTrustBytes  = 128 * 1024
)

// embeddedNativeReleaseTrustBase64 is populated by the reproducible native
// release build. It contains public verification policy only. An ordinary
// source build deliberately has no release authority and fails closed.
var embeddedNativeReleaseTrustBase64 string

type nativeReleaseTrustDocument struct {
	SchemaVersion uint16                      `json:"schemaVersion"`
	ManifestKeys  map[string]string           `json:"manifestKeys"`
	Offline       nativeOfflineTrustDocument  `json:"offline"`
	Provenance    nativeProvenanceDocument    `json:"provenance"`
	Qualification nativeQualificationDocument `json:"qualification"`
	Publishers    map[string][]string         `json:"nativePublishers"`
}

type nativeOfflineTrustDocument struct {
	TrustDomain              string            `json:"trustDomain"`
	RevocationAuthorities    map[string]string `json:"revocationAuthorities"`
	TimeAuthorities          map[string]string `json:"timeAuthorities"`
	MaximumFutureSkewSeconds uint16            `json:"maximumFutureSkewSeconds"`
}

type nativeProvenanceDocument struct {
	BuildIdentities []releaseverifyadapter.ProvenanceBuildIdentity `json:"buildIdentities"`
	RecipeDigests   []string                                       `json:"recipeDigests"`
}

type nativeQualificationDocument struct {
	PublicKeys                 map[string]string `json:"publicKeys"`
	LicensePolicySigners       map[string]string `json:"licensePolicySigners"`
	VulnerabilityPolicySigners map[string]string `json:"vulnerabilityPolicySigners"`
}

func loadEmbeddedNativeReleaseTrust() (nativeReleaseTrustMaterial, error) {
	return decodeNativeReleaseTrust(embeddedNativeReleaseTrustBase64)
}

func decodeNativeReleaseTrust(encoded string) (nativeReleaseTrustMaterial, error) {
	if encoded == "" || len(encoded) > base64.StdEncoding.EncodedLen(maximumNativeReleaseTrustBytes) {
		return nativeReleaseTrustMaterial{}, errNativeInstallerIntegrity
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != encoded || len(raw) == 0 ||
		len(raw) > maximumNativeReleaseTrustBytes || rejectDuplicateNativeTrustKeys(raw) != nil {
		return nativeReleaseTrustMaterial{}, errNativeInstallerIntegrity
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document nativeReleaseTrustDocument
	if err := decoder.Decode(&document); err != nil {
		return nativeReleaseTrustMaterial{}, errNativeInstallerIntegrity
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) || token != nil ||
		document.SchemaVersion != nativeReleaseTrustSchemaVersion {
		return nativeReleaseTrustMaterial{}, errNativeInstallerIntegrity
	}
	manifestKeys, err := decodeNativeReleaseKeys(document.ManifestKeys)
	if err != nil {
		return nativeReleaseTrustMaterial{}, errNativeInstallerIntegrity
	}
	revocationKeys, err := decodeNativeReleaseKeys(document.Offline.RevocationAuthorities)
	if err != nil {
		return nativeReleaseTrustMaterial{}, errNativeInstallerIntegrity
	}
	timeKeys, err := decodeNativeReleaseKeys(document.Offline.TimeAuthorities)
	if err != nil {
		return nativeReleaseTrustMaterial{}, errNativeInstallerIntegrity
	}
	qualificationKeys, err := decodeNativeReleaseKeys(document.Qualification.PublicKeys)
	if err != nil {
		return nativeReleaseTrustMaterial{}, errNativeInstallerIntegrity
	}
	recipes, err := decodeNativeReleaseDigests(document.Provenance.RecipeDigests)
	if err != nil {
		return nativeReleaseTrustMaterial{}, errNativeInstallerIntegrity
	}
	license, err := decodeNativeReleaseSignerBindings(document.Qualification.LicensePolicySigners)
	if err != nil {
		return nativeReleaseTrustMaterial{}, errNativeInstallerIntegrity
	}
	vulnerabilities, err := decodeNativeReleaseSignerBindings(
		document.Qualification.VulnerabilityPolicySigners,
	)
	if err != nil || document.Offline.MaximumFutureSkewSeconds > 600 {
		return nativeReleaseTrustMaterial{}, errNativeInstallerIntegrity
	}
	trust := nativeReleaseTrustMaterial{
		ManifestKeys: manifestKeys,
		Offline: releaseverifyadapter.OfflineTrustPolicyInput{
			TrustDomain:           document.Offline.TrustDomain,
			RevocationAuthorities: revocationKeys, TimeAuthorities: timeKeys,
			MaximumFutureSkew: time.Duration(document.Offline.MaximumFutureSkewSeconds) * time.Second,
		},
		Provenance: releaseverifyadapter.ProvenanceTrustPolicyInput{
			BuildIdentities: append([]releaseverifyadapter.ProvenanceBuildIdentity(nil), document.Provenance.BuildIdentities...),
			RecipeDigests:   recipes,
		},
		Qualification: releaseverifyadapter.QualificationTrustPolicyInput{
			PublicKeys: qualificationKeys, LicensePolicySigners: license,
			VulnerabilityPolicySigners: vulnerabilities,
		},
		Publishers: copyNativePublisherPolicy(document.Publishers),
	}
	// Reuse every production policy constructor here. A syntactically valid
	// document cannot become release authority unless all semantic allowlists
	// are complete, closed, and mutually bound.
	if _, err := releaseverifyadapter.NewEd25519KeyIDVerifier(trust.ManifestKeys); err != nil {
		return nativeReleaseTrustMaterial{}, errNativeInstallerIntegrity
	}
	if _, err := releaseverifyadapter.NewOfflineTrustPolicy(trust.Offline); err != nil {
		return nativeReleaseTrustMaterial{}, errNativeInstallerIntegrity
	}
	if _, err := releaseverifyadapter.NewProvenanceTrustPolicy(trust.Provenance); err != nil {
		return nativeReleaseTrustMaterial{}, errNativeInstallerIntegrity
	}
	if _, err := releaseverifyadapter.NewQualificationTrustPolicy(trust.Qualification); err != nil {
		return nativeReleaseTrustMaterial{}, errNativeInstallerIntegrity
	}
	if _, err := releaseverifyadapter.NewNativePublisherPolicyVerifier(trust.Publishers); err != nil {
		return nativeReleaseTrustMaterial{}, errNativeInstallerIntegrity
	}
	return trust, nil
}

func copyNativePublisherPolicy(
	values map[string][]string,
) releaseverifyadapter.NativePublisherPolicyInput {
	result := make(releaseverifyadapter.NativePublisherPolicyInput, len(values))
	for policyID, identities := range values {
		result[policyID] = append([]string(nil), identities...)
	}
	return result
}

func decodeNativeReleaseKeys(values map[string]string) (map[string]ed25519.PublicKey, error) {
	if len(values) == 0 {
		return nil, errNativeInstallerIntegrity
	}
	result := make(map[string]ed25519.PublicKey, len(values))
	for keyID, encoded := range values {
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if keyID == "" || err != nil || base64.StdEncoding.EncodeToString(decoded) != encoded ||
			len(decoded) != ed25519.PublicKeySize {
			return nil, errNativeInstallerIntegrity
		}
		result[keyID] = append(ed25519.PublicKey(nil), decoded...)
	}
	return result, nil
}

func decodeNativeReleaseDigests(values []string) ([]releaseinventory.Digest, error) {
	if len(values) == 0 {
		return nil, errNativeInstallerIntegrity
	}
	result := make([]releaseinventory.Digest, 0, len(values))
	seen := make(map[releaseinventory.Digest]struct{}, len(values))
	for _, value := range values {
		digest, err := releaseinventory.ParseDigest(value)
		if err != nil {
			return nil, errNativeInstallerIntegrity
		}
		if _, duplicate := seen[digest]; duplicate {
			return nil, errNativeInstallerIntegrity
		}
		seen[digest] = struct{}{}
		result = append(result, digest)
	}
	return result, nil
}

func decodeNativeReleaseSignerBindings(values map[string]string) (map[releaseinventory.Digest]string, error) {
	if len(values) == 0 {
		return nil, errNativeInstallerIntegrity
	}
	result := make(map[releaseinventory.Digest]string, len(values))
	for value, signer := range values {
		digest, err := releaseinventory.ParseDigest(value)
		if err != nil || signer == "" {
			return nil, errNativeInstallerIntegrity
		}
		result[digest] = signer
	}
	return result, nil
}

func rejectDuplicateNativeTrustKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := walkNativeTrustJSON(decoder); err != nil {
		return err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return errNativeInstallerIntegrity
	}
	return nil
}

func walkNativeTrustJSON(decoder *json.Decoder) error {
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
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return errNativeInstallerIntegrity
			}
			if _, duplicate := seen[key]; duplicate {
				return errNativeInstallerIntegrity
			}
			seen[key] = struct{}{}
			if err := walkNativeTrustJSON(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errNativeInstallerIntegrity
		}
	case '[':
		for decoder.More() {
			if err := walkNativeTrustJSON(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errNativeInstallerIntegrity
		}
	default:
		return errNativeInstallerIntegrity
	}
	return nil
}
