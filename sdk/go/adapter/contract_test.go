package adapter

import "testing"

func TestPF003DecodeAndEchoExactProbe(t *testing.T) {
	t.Parallel()
	request, err := DecodeProbeRequest([]byte(`{"capabilities":["agent.event.capture"],"challenge":"challenge-1","kind":"agent","manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","package_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","protocol":"1.0","schema_version":1}`))
	if err != nil {
		t.Fatal(err)
	}
	response := request.Response()
	if response.Challenge != request.Challenge || response.PackageDigest != request.PackageDigest || response.Status != "passed" {
		t.Fatal("probe identity was not preserved")
	}
}

func TestPF003RejectsDuplicateUnknownAndNoncanonicalProbe(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		`{"schema_version":1,"schema_version":1}`,
		`{"unknown":true}`,
		`{"capabilities":["z","a"],"challenge":"challenge-1","kind":"agent","manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","package_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","protocol":"1.0","schema_version":1}`,
	} {
		if _, err := DecodeProbeRequest([]byte(value)); err == nil {
			t.Fatalf("invalid probe accepted: %s", value)
		}
	}
}
