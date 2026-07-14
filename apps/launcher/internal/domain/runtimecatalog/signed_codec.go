package runtimecatalog

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	signedManifestSchemaVersion = uint16(1)
	maximumSignedManifestBytes  = maximumRawManifestBytes + 32*1024
)

type canonicalSignedManifest struct {
	SchemaVersion uint16          `json:"schema_version"`
	Manifest      json.RawMessage `json:"manifest"`
	SigningKeyID  string          `json:"signing_key_id"`
	Signature     string          `json:"signature"`
}

// EncodeSignedManifestV1 returns the canonical release-resource envelope for
// one runtime catalog manifest and its detached signature. The resource digest
// covers this complete envelope; Manifest.Digest continues to cover only the
// exact bytes authenticated by the detached signature.
func EncodeSignedManifestV1(signed SignedManifest) ([]byte, error) {
	if !signed.Valid() {
		return nil, ErrManifestIntegrity
	}
	document := canonicalSignedManifest{
		SchemaVersion: signedManifestSchemaVersion,
		Manifest:      json.RawMessage(signed.Manifest().CanonicalBytes()),
		SigningKeyID:  signed.SigningKeyID(),
		Signature:     base64.StdEncoding.EncodeToString(signed.Signature()),
	}
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumSignedManifestBytes {
		return nil, ErrManifestIntegrity
	}
	return encoded, nil
}

// DecodeSignedManifestV1 accepts only the exact canonical envelope. It
// validates transport shape and manifest/signature binding but intentionally
// leaves cryptographic verification to runtimecatalogapp.
func DecodeSignedManifestV1(raw []byte) (SignedManifest, error) {
	if len(raw) == 0 || len(raw) > maximumSignedManifestBytes {
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
			return SignedManifest{}, fmt.Errorf("%w", ErrManifestUnknownField)
		}
		return SignedManifest{}, fmt.Errorf("%w", ErrManifestMalformed)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return SignedManifest{}, ErrManifestMalformed
	}
	if document.SchemaVersion != signedManifestSchemaVersion {
		return SignedManifest{}, ErrManifestUnsupportedSchema
	}
	manifest, err := DecodeManifestV1(document.Manifest)
	if err != nil {
		return SignedManifest{}, err
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(document.Signature)
	if err != nil || base64.StdEncoding.EncodeToString(signature) != document.Signature {
		return SignedManifest{}, ErrManifestIntegrity
	}
	signed, err := NewSignedManifest(manifest, document.SigningKeyID, signature)
	if err != nil {
		return SignedManifest{}, ErrManifestIntegrity
	}
	canonical, err := EncodeSignedManifestV1(signed)
	if err != nil || !bytes.Equal(canonical, raw) {
		return SignedManifest{}, ErrManifestNonCanonical
	}
	return signed, nil
}
