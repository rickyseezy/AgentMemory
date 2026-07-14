package runtimecatalog

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestDecodeManifestV1RoundTripsOnlyExactCanonicalBytes(t *testing.T) {
	t.Parallel()

	want := mustManifest(t, validManifestInput(t))
	if !bytes.Contains(want.CanonicalBytes(), []byte(`"catalog_sequence":42`)) ||
		bytes.Contains(want.CanonicalBytes(), []byte(`,"sequence":`)) {
		t.Fatal("canonical wire contract does not use explicit catalog_sequence")
	}
	decoded, err := DecodeManifestV1(want.CanonicalBytes())
	if err != nil {
		t.Fatalf("DecodeManifestV1() error = %v", err)
	}
	if !decoded.Digest().Equal(want.Digest()) || !bytes.Equal(decoded.CanonicalBytes(), want.CanonicalBytes()) {
		t.Fatal("decoded manifest changed canonical identity")
	}
	encoded, err := EncodeManifestV1(decoded)
	if err != nil {
		t.Fatalf("EncodeManifestV1() error = %v", err)
	}
	if !bytes.Equal(encoded, want.CanonicalBytes()) {
		t.Fatal("EncodeManifestV1() changed bytes")
	}
}

func TestDecodeManifestV1RejectsMalformedDuplicateUnknownUnsupportedAndNonCanonicalJSON(t *testing.T) {
	t.Parallel()

	canonical := mustManifest(t, validManifestInput(t)).CanonicalBytes()
	tests := []struct {
		name string
		raw  []byte
		want error
	}{
		{name: "empty", raw: nil, want: ErrManifestMalformed},
		{name: "trailing document", raw: append(append([]byte(nil), canonical...), []byte("{}")...), want: ErrManifestMalformed},
		{name: "duplicate nested key", raw: []byte(`{"artifact":{"download_bytes":1,"download_bytes":2}}`), want: ErrManifestDuplicateKey},
		{name: "unknown top-level", raw: insertBeforeClosingObject(canonical, `,"unknown":true`), want: ErrManifestUnknownField},
		{name: "unknown nested", raw: bytes.Replace(canonical, []byte(`"artifact":{`), []byte(`"artifact":{"unknown":true,`), 1), want: ErrManifestUnknownField},
		{name: "unsupported schema", raw: bytes.Replace(canonical, []byte(`"schema_version":1`), []byte(`"schema_version":2`), 1), want: ErrManifestUnsupportedSchema},
		{name: "whitespace", raw: append([]byte(" "), canonical...), want: ErrManifestNonCanonical},
		{name: "different key order", raw: moveCatalogIDBeforeArtifact(canonical), want: ErrManifestNonCanonical},
		{name: "oversize", raw: bytes.Repeat([]byte(" "), maximumRawManifestBytes+1), want: ErrManifestMalformed},
		{name: "excess depth", raw: []byte(strings.Repeat("[", maximumManifestJSONDepth+2) + "0" + strings.Repeat("]", maximumManifestJSONDepth+2)), want: ErrManifestMalformed},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := DecodeManifestV1(test.raw)
			if !errors.Is(err, test.want) {
				t.Fatalf("DecodeManifestV1() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestSignedManifestBindsDetachedSignatureAndDeclaredKey(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, validManifestInput(t))
	signed, err := NewSignedManifest(manifest, manifest.SigningKeyID(), []byte("detached-signature"))
	if err != nil {
		t.Fatalf("NewSignedManifest() error = %v", err)
	}
	if !signed.Manifest().Digest().Equal(manifest.Digest()) || signed.SigningKeyID() != manifest.SigningKeyID() {
		t.Fatal("signed manifest projection is incomplete")
	}
	if !signed.Valid() || (SignedManifest{}).Valid() {
		t.Fatal("signed manifest validity did not preserve its envelope authority")
	}
	signature := signed.Signature()
	signature[0] = 'x'
	if string(signed.Signature()) != "detached-signature" {
		t.Fatal("signature leaked mutable storage")
	}
	if _, err := NewSignedManifest(manifest, "wrong-key", []byte("signature")); !errors.Is(err, ErrManifestIntegrity) {
		t.Fatalf("key mismatch error = %v", err)
	}
	if _, err := NewSignedManifest(manifest, manifest.SigningKeyID(), nil); !errors.Is(err, ErrManifestIntegrity) {
		t.Fatalf("empty signature error = %v", err)
	}
	if _, err := NewSignedManifest(manifest, manifest.SigningKeyID(), make([]byte, 16*1024+1)); !errors.Is(err, ErrManifestIntegrity) {
		t.Fatalf("oversized signature error = %v", err)
	}
	if _, err := EncodeManifestV1(Manifest{}); !errors.Is(err, ErrManifestIntegrity) {
		t.Fatalf("invalid encode error = %v", err)
	}
}

func TestRuntimeCatalogDigestParserRejectsEveryNonCanonicalRepresentation(t *testing.T) {
	t.Parallel()

	valid := DigestBytes([]byte("catalog authority"))
	parsed, err := ParseDigest(valid.Hex())
	if err != nil || !parsed.Equal(valid) || parsed.IsZero() {
		t.Fatalf("ParseDigest(valid) = %s, %v", parsed.Hex(), err)
	}
	for name, value := range map[string]string{
		"short":     "abcd",
		"uppercase": strings.ToUpper(valid.Hex()),
		"nonhex":    strings.Repeat("g", 64),
		"zero":      strings.Repeat("0", 64),
	} {
		if _, err := ParseDigest(value); err == nil {
			t.Fatalf("ParseDigest() accepted %s representation", name)
		}
	}
}

func TestRuntimeCatalogClosedValuePredicatesRejectUnknownValues(t *testing.T) {
	t.Parallel()

	if ComponentName("unknown_component").valid() || ArgumentKind("unknown_argument").valid() ||
		CapabilityProbe("unknown_capability").valid() {
		t.Fatal("closed runtime catalog vocabulary accepted an unknown value")
	}
}

func insertBeforeClosingObject(raw []byte, suffix string) []byte {
	result := append([]byte(nil), raw[:len(raw)-1]...)
	result = append(result, suffix...)
	return append(result, '}')
}

func moveCatalogIDBeforeArtifact(raw []byte) []byte {
	text := string(raw)
	needle := `,"catalog_id":"docker-desktop-macos-arm64"`
	text = strings.Replace(text, needle, "", 1)
	return []byte(`{"catalog_id":"docker-desktop-macos-arm64",` + strings.TrimPrefix(text, "{"))
}
