package runtimecatalog

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestSignedManifestCodecRoundTripsCanonicalDetachedSignatureEnvelope(t *testing.T) {
	t.Parallel()
	manifest := mustManifest(t, validManifestInput(t))
	signature := bytes.Repeat([]byte{0x5a}, 64)
	signed, err := NewSignedManifest(manifest, manifest.SigningKeyID(), signature)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeSignedManifestV1(signed)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSignedManifestV1(encoded)
	if err != nil || !decoded.Valid() || !decoded.Manifest().Digest().Equal(manifest.Digest()) ||
		!bytes.Equal(decoded.Signature(), signature) || decoded.SigningKeyID() != manifest.SigningKeyID() {
		t.Fatalf("decoded=%+v error=%v", decoded, err)
	}
	encodedAgain, err := EncodeSignedManifestV1(decoded)
	if err != nil || !bytes.Equal(encodedAgain, encoded) {
		t.Fatalf("second encoding differs: error=%v", err)
	}
}

func TestSignedManifestCodecRejectsAmbiguousMalformedAndUnboundEnvelopes(t *testing.T) {
	t.Parallel()
	manifest := mustManifest(t, validManifestInput(t))
	signed, err := NewSignedManifest(manifest, manifest.SigningKeyID(), []byte("signature"))
	if err != nil {
		t.Fatal(err)
	}
	valid, err := EncodeSignedManifestV1(signed)
	if err != nil {
		t.Fatal(err)
	}
	manifestText := string(manifest.CanonicalBytes())
	wrongKey := strings.Replace(string(valid), manifest.SigningKeyID(), "foreign-runtime-root", 1)
	badBase64 := strings.Replace(string(valid), base64.StdEncoding.EncodeToString([]byte("signature")), "%%%", 1)
	for name, candidate := range map[string][]byte{
		"empty":         nil,
		"trailing":      append(append([]byte(nil), valid...), '\n'),
		"duplicate":     []byte(strings.Replace(string(valid), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)),
		"unknown":       []byte(strings.Replace(string(valid), `"schema_version":1`, `"schema_version":1,"future":true`, 1)),
		"schema":        []byte(strings.Replace(string(valid), `"schema_version":1`, `"schema_version":2`, 1)),
		"wrong key":     []byte(wrongKey),
		"bad signature": []byte(badBase64),
		"noncanonical":  []byte(strings.Replace(string(valid), `"manifest":`+manifestText, `"manifest": `+manifestText, 1)),
	} {
		if decoded, decodeError := DecodeSignedManifestV1(candidate); decodeError == nil || decoded.Valid() {
			t.Fatalf("%s accepted: decoded=%+v error=%v", name, decoded, decodeError)
		}
	}
	if _, err := EncodeSignedManifestV1(SignedManifest{}); !errors.Is(err, ErrManifestIntegrity) {
		t.Fatalf("invalid encode error=%v", err)
	}
}
