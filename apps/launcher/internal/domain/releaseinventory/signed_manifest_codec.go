package releaseinventory

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const maximumSignedManifestEnvelopeBytes = 32 * 1024 * 1024

// canonicalSignedManifest is the separately addressable product-manifest
// envelope used by the outer distribution catalog. Lexical field order keeps
// encoding deterministic for this closed schema.
type canonicalSignedManifest struct {
	Manifest            string `json:"manifest"`
	RevocationSet       string `json:"revocation_set"`
	SchemaVersion       uint16 `json:"schema_version"`
	Signature           string `json:"signature"`
	SigstoreBundle      string `json:"sigstore_bundle"`
	TrustedTimeEvidence string `json:"trusted_time_evidence"`
	TrustMode           string `json:"trust_mode"`
	TrustRootID         string `json:"trust_root_id"`
}

// EncodeSignedManifestV1 produces the exact bytes that a distribution-catalog
// resource hashes. The inner manifest remains independently signed.
func EncodeSignedManifestV1(signed SignedManifest) ([]byte, error) {
	manifest, err := EncodeManifestV1(signed.Manifest())
	if err != nil || signed.SignatureBundleSchemaVersion() != SupportedSignatureBundleSchemaMajor ||
		len(signed.RevocationSet()) == 0 ||
		len(signed.TrustedTimeEvidence()) == 0 ||
		(signed.TrustMode() != SignatureTrustModeKeyID && signed.TrustMode() != SignatureTrustModeCertificateTransparency) ||
		signed.TrustRootID() == "" ||
		(signed.TrustMode() == SignatureTrustModeKeyID && len(signed.Signature()) != ManifestSignatureSize) ||
		(signed.TrustMode() == SignatureTrustModeCertificateTransparency && len(signed.SigstoreBundle()) == 0) {
		return nil, ErrManifestIntegrity
	}
	document := canonicalSignedManifest{
		Manifest:            base64.StdEncoding.EncodeToString(manifest),
		RevocationSet:       base64.StdEncoding.EncodeToString(signed.RevocationSet()),
		SchemaVersion:       signed.SignatureBundleSchemaVersion(),
		Signature:           base64.StdEncoding.EncodeToString(signed.Signature()),
		SigstoreBundle:      base64.StdEncoding.EncodeToString(signed.SigstoreBundle()),
		TrustedTimeEvidence: base64.StdEncoding.EncodeToString(signed.TrustedTimeEvidence()),
		TrustMode:           string(signed.TrustMode()), TrustRootID: signed.TrustRootID(),
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return nil, ErrManifestIntegrity
	}
	encoded := bytes.TrimSuffix(output.Bytes(), []byte{'\n'})
	if len(encoded) == 0 || len(encoded) > maximumSignedManifestEnvelopeBytes {
		return nil, ErrManifestIntegrity
	}
	return append([]byte(nil), encoded...), nil
}

// DecodeSignedManifestV1 accepts only the exact canonical envelope. It never
// normalizes bytes before deciding whether the distribution resource matched.
func DecodeSignedManifestV1(raw []byte) (SignedManifest, error) {
	if len(raw) == 0 || len(raw) > maximumSignedManifestEnvelopeBytes {
		return SignedManifest{}, ErrManifestMalformed
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return SignedManifest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document canonicalSignedManifest
	if err := decoder.Decode(&document); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return SignedManifest{}, ErrManifestUnknownField
		}
		return SignedManifest{}, ErrManifestMalformed
	}
	if err := requireJSONEOF(decoder); err != nil {
		return SignedManifest{}, ErrManifestMalformed
	}
	if document.SchemaVersion != SupportedSignatureBundleSchemaMajor {
		return SignedManifest{}, ErrManifestUnsupportedSchema
	}
	manifestRaw, err := strictEnvelopeBase64(document.Manifest)
	if err != nil {
		return SignedManifest{}, ErrManifestIntegrity
	}
	manifest, err := DecodeManifestV1(manifestRaw)
	if err != nil {
		return SignedManifest{}, fmt.Errorf("%w: embedded product manifest", ErrManifestIntegrity)
	}
	signature, err := optionalEnvelopeBase64(document.Signature)
	if err != nil {
		return SignedManifest{}, ErrManifestIntegrity
	}
	sigstore, err := optionalEnvelopeBase64(document.SigstoreBundle)
	if err != nil {
		return SignedManifest{}, ErrManifestIntegrity
	}
	revocations, err := strictEnvelopeBase64(document.RevocationSet)
	if err != nil {
		return SignedManifest{}, ErrManifestIntegrity
	}
	trustedTime, err := strictEnvelopeBase64(document.TrustedTimeEvidence)
	if err != nil {
		return SignedManifest{}, ErrManifestIntegrity
	}
	signed, err := NewSignedManifest(manifest, SignatureBundleInput{
		SchemaVersion: document.SchemaVersion, TrustMode: SignatureTrustMode(document.TrustMode),
		TrustRootID: document.TrustRootID, Signature: signature, SigstoreBundle: sigstore,
		RevocationSet: revocations, TrustedTimeEvidence: trustedTime,
	})
	if err != nil {
		return SignedManifest{}, ErrManifestIntegrity
	}
	canonical, err := EncodeSignedManifestV1(signed)
	if err != nil || !bytes.Equal(raw, canonical) {
		return SignedManifest{}, ErrManifestNonCanonical
	}
	return signed, nil
}

func strictEnvelopeBase64(value string) ([]byte, error) {
	if value == "" {
		return nil, errors.New("signed manifest field is empty")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) == 0 || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("signed manifest field is not canonical base64")
	}
	return decoded, nil
}

func optionalEnvelopeBase64(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	return strictEnvelopeBase64(value)
}
