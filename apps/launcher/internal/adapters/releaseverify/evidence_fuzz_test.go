package releaseverifyadapter

import (
	"bytes"
	"encoding/json"
	"testing"
)

// FuzzReleaseEvidenceCanonicalParsers proves every security-document parser is
// bounded, panic-free, duplicate/unknown-field closed, and stable under exact
// canonical re-encoding.
func FuzzReleaseEvidenceCanonicalParsers(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"schemaVersion":1}`))
	f.Add([]byte(`{"payload":{},"signature":{}}`))
	f.Add(bytes.Repeat([]byte{'['}, maximumEvidenceJSONDepth+2))

	f.Fuzz(func(t *testing.T, raw []byte) {
		destinations := []any{
			&cycloneDXDocument{},
			&spdxDocument{},
			&slsaStatement{},
			&ociIndexDocument{},
			&qualificationEnvelope{},
			&revocationEnvelope{},
			&trustedTimeEnvelope{},
		}
		for _, destination := range destinations {
			if err := decodeCanonicalJSON(raw, destination); err != nil {
				continue
			}
			canonical, err := json.Marshal(destination)
			if err != nil {
				t.Fatalf("accepted evidence no longer marshals: %v", err)
			}
			if !bytes.Equal(raw, canonical) {
				t.Fatal("accepted evidence was not stable under canonical re-encoding")
			}
		}
	})
}
