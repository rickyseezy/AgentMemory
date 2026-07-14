package releaseinventory

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestPF001SignedProductManifestEnvelopeRoundTripsExactAuthority(t *testing.T) {
	t.Parallel()
	signed := signedEnvelopeFixture(t, SignatureTrustModeKeyID)
	encoded, err := EncodeSignedManifestV1(signed)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSignedManifestV1(encoded)
	if err != nil {
		t.Fatal(err)
	}
	encodedAgain, err := EncodeSignedManifestV1(decoded)
	if err != nil || !bytes.Equal(encoded, encodedAgain) ||
		!decoded.Manifest().Digest().Equal(signed.Manifest().Digest()) ||
		!bytes.Equal(decoded.Signature(), signed.Signature()) ||
		!bytes.Equal(decoded.RevocationSet(), signed.RevocationSet()) ||
		!bytes.Equal(decoded.TrustedTimeEvidence(), signed.TrustedTimeEvidence()) {
		t.Fatal("signed product-manifest envelope lost canonical authority")
	}
	encoded[0] = 'X'
	if bytes.Equal(encoded, encodedAgain) {
		t.Fatal("encoder aliased returned bytes")
	}

	certificate := signedEnvelopeFixture(t, SignatureTrustModeCertificateTransparency)
	certificateRaw, err := EncodeSignedManifestV1(certificate)
	if err != nil {
		t.Fatal(err)
	}
	certificateDecoded, err := DecodeSignedManifestV1(certificateRaw)
	if err != nil || len(certificateDecoded.Signature()) != 0 || len(certificateDecoded.SigstoreBundle()) == 0 {
		t.Fatal("certificate-transparency envelope lost its exclusive signature evidence")
	}
}

func TestPF001SignedProductManifestEnvelopeRejectsAmbiguityAndSubstitution(t *testing.T) {
	t.Parallel()
	valid, err := EncodeSignedManifestV1(signedEnvelopeFixture(t, SignatureTrustModeKeyID))
	if err != nil {
		t.Fatal(err)
	}
	var document canonicalSignedManifest
	if err := json.Unmarshal(valid, &document); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*canonicalSignedManifest){
		"manifest":     func(value *canonicalSignedManifest) { value.Manifest = "!" },
		"revocations":  func(value *canonicalSignedManifest) { value.RevocationSet = "" },
		"schema":       func(value *canonicalSignedManifest) { value.SchemaVersion-- },
		"signature":    func(value *canonicalSignedManifest) { value.Signature = "!" },
		"sigstore":     func(value *canonicalSignedManifest) { value.SigstoreBundle = "YQ" },
		"trusted time": func(value *canonicalSignedManifest) { value.TrustedTimeEvidence = "" },
		"trust mode":   func(value *canonicalSignedManifest) { value.TrustMode = "future" },
		"trust root":   func(value *canonicalSignedManifest) { value.TrustRootID = "" },
	}
	for name, mutate := range mutations {
		candidate := document
		mutate(&candidate)
		raw, marshalError := json.Marshal(candidate)
		if marshalError != nil {
			t.Fatal(marshalError)
		}
		if _, decodeError := DecodeSignedManifestV1(raw); decodeError == nil {
			t.Fatalf("%s mutation was accepted", name)
		}
	}
	unknown := bytes.Replace(valid, []byte(`{"manifest"`), []byte(`{"future":1,"manifest"`), 1)
	if _, err := DecodeSignedManifestV1(unknown); !errors.Is(err, ErrManifestUnknownField) {
		t.Fatalf("unknown field error=%v", err)
	}
	duplicate := bytes.Replace(valid, []byte(`{"manifest":`), []byte(`{"manifest":"eA==","manifest":`), 1)
	if _, err := DecodeSignedManifestV1(duplicate); !errors.Is(err, ErrManifestDuplicateKey) {
		t.Fatalf("duplicate field error=%v", err)
	}
	if _, err := DecodeSignedManifestV1(append(append([]byte(nil), valid...), ' ')); !errors.Is(err, ErrManifestNonCanonical) {
		t.Fatalf("noncanonical whitespace error=%v", err)
	}
	for _, raw := range [][]byte{nil, []byte("null"), []byte("{}"), []byte("{}{}"), bytes.Repeat([]byte{'x'}, maximumSignedManifestEnvelopeBytes+1)} {
		if _, err := DecodeSignedManifestV1(raw); err == nil {
			t.Fatalf("invalid envelope of length %d was accepted", len(raw))
		}
	}
}

func TestPF001SignedProductManifestEnvelopeHelpersRejectNonCanonicalBase64(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"", "!", "YQ", "YQ===", strings.Repeat("A", 3)} {
		if _, err := strictEnvelopeBase64(value); err == nil {
			t.Fatalf("strictEnvelopeBase64(%q) accepted", value)
		}
	}
	if value, err := strictEnvelopeBase64("YQ=="); err != nil || string(value) != "a" {
		t.Fatalf("canonical base64=%q,%v", value, err)
	}
	if value, err := optionalEnvelopeBase64(""); err != nil || value != nil {
		t.Fatalf("optional empty=%q,%v", value, err)
	}
	if _, err := EncodeSignedManifestV1(SignedManifest{}); !errors.Is(err, ErrManifestIntegrity) {
		t.Fatalf("zero signed manifest error=%v", err)
	}
}

func signedEnvelopeFixture(t testing.TB, mode SignatureTrustMode) SignedManifest {
	t.Helper()
	manifest := mustManifest(t, completeResources(t, mustPlatform(t, "linux", "amd64")))
	input := SignatureBundleInput{
		SchemaVersion: SupportedSignatureBundleSchemaMajor, TrustMode: mode,
		TrustRootID: "release-root-2026", RevocationSet: []byte("signed revocation set"),
		TrustedTimeEvidence: []byte("trusted time evidence"),
	}
	if mode == SignatureTrustModeKeyID {
		input.Signature = bytes.Repeat([]byte{0x5a}, ManifestSignatureSize)
	} else {
		input.SigstoreBundle = []byte("offline sigstore bundle")
	}
	signed, err := NewSignedManifest(manifest, input)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}
