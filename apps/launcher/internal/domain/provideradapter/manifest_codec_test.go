package provideradapter

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestPRO002ExternalManifestCodecIsStrictAndCannotCarryCompose(t *testing.T) {
	t.Parallel()
	raw := manifestJSON(t)
	manifest, err := ParseManifestJSON(raw)
	if err != nil || manifest.AdapterID() != "python-reference" || !manifest.Supports(OperationCancel) {
		t.Fatalf("parse = %#v %v", manifest, err)
	}
	tests := [][]byte{
		nil,
		[]byte(`[]`),
		[]byte(strings.Replace(string(raw), `"adapter_id":"python-reference"`, `"adapter_id":"python-reference","adapter_id":"substitution"`, 1)),
		[]byte(strings.Replace(string(raw), `"evidence":`, `"compose":{"services":{"x":{"privileged":true}}},"evidence":`, 1)),
		[]byte(strings.Replace(string(raw), `"host_network":false`, `"host_network":true`, 1)),
		[]byte(strings.Replace(string(raw), `@sha256:`, `:latest#sha256:`, 1)),
		[]byte(strings.Replace(string(raw), `"schema_version":1`, `"schema_version":2`, 1)),
	}
	for _, invalid := range tests {
		if _, err := ParseManifestJSON(invalid); !errors.Is(err, ErrInvalidManifest) {
			t.Fatalf("unsafe manifest accepted: %s %v", invalid, err)
		}
	}
}

func FuzzPRO002ManifestCodecNeverPanicsOrAcceptsUnboundedInput(f *testing.F) {
	f.Add(manifestJSON(f))
	f.Add([]byte(`{"compose":{"privileged":true}}`))
	f.Fuzz(func(_ *testing.T, raw []byte) {
		if len(raw) > maximumManifestBytes+1 {
			raw = raw[:maximumManifestBytes+1]
		}
		_, _ = ParseManifestJSON(raw)
	})
}

func manifestJSON(t testing.TB) []byte {
	t.Helper()
	input := validManifestInput()
	document := map[string]any{
		"schema_version": 1, "adapter_id": input.AdapterID, "image": input.Image, "image_digest": input.ImageDigest.Hex(),
		"protocol": map[string]any{"minimum": 1, "maximum": 1}, "transport": input.Transport, "operations": input.Operations,
		"permissions": map[string]any{"gateway_access": false, "host_network": false, "publish_port": false, "docker_socket": false, "project_mount": false, "writable_mount": false, "additional_secrets": false, "direct_egress": false, "privileged": false},
		"limits":      map[string]any{"cpus_milli": input.Limits.CPUsMilli, "memory_bytes": input.Limits.MemoryBytes, "pids": input.Limits.PIDs, "timeout_milliseconds": input.Limits.TimeoutMilliseconds, "scratch_bytes": input.Limits.ScratchBytes},
		"evidence":    map[string]any{"signature_bundle": input.Evidence.SignatureBundle.Hex(), "cyclonedx_sbom": input.Evidence.CycloneDXSBOM.Hex(), "spdx_sbom": input.Evidence.SPDXSBOM.Hex(), "provenance": input.Evidence.Provenance.Hex(), "license": input.Evidence.License.Hex(), "vulnerability": input.Evidence.Vulnerability.Hex()},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
