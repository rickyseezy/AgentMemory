package runtimecatalog

import (
	"bytes"
	"testing"
)

func FuzzDecodeManifestV1(f *testing.F) {
	manifest := mustManifest(f, validManifestInput(f))
	f.Add(manifest.CanonicalBytes())
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"schema_version":1,"schema_version":1}`))
	f.Add([]byte{0xff, 0xfe, 0xfd})

	f.Fuzz(func(t *testing.T, raw []byte) {
		decoded, err := DecodeManifestV1(raw)
		if err != nil {
			return
		}
		encoded, err := EncodeManifestV1(decoded)
		if err != nil {
			t.Fatalf("EncodeManifestV1(decoded) error = %v", err)
		}
		if !bytes.Equal(raw, encoded) {
			t.Fatalf("accepted bytes were not canonical")
		}
		decodedAgain, err := DecodeManifestV1(encoded)
		if err != nil || !decodedAgain.Digest().Equal(decoded.Digest()) {
			t.Fatalf("canonical decode is not deterministic: err=%v", err)
		}
	})
}
