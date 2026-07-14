package releaseinventory

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRawManifestV1RoundTripsOnlyExactCanonicalBytes(t *testing.T) {
	t.Parallel()

	want := mustManifest(t, completeResources(t, mustPlatform(t, "linux", "amd64")))
	raw, err := EncodeManifestV1(want)
	if err != nil {
		t.Fatalf("EncodeManifestV1() error = %v", err)
	}
	got, err := DecodeManifestV1(raw)
	if err != nil {
		t.Fatalf("DecodeManifestV1() error = %v", err)
	}
	if !got.Digest().Equal(want.Digest()) || !bytes.Equal(got.CanonicalBytes(), raw) ||
		got.BuildID() != want.BuildID() || got.Channel() != ReleaseChannelStable ||
		got.DataGeneration() != want.DataGeneration() ||
		len(got.DockerTopology().Services()) != 1 || !got.Compatibility().Launcher().Contains("1.0.0") {
		t.Fatal("raw manifest round trip lost signed execution authority")
	}
	raw[0] ^= 0xff
	if bytes.Equal(raw, got.CanonicalBytes()) {
		t.Fatal("raw manifest encoder exposed mutable canonical storage")
	}
	if _, err := EncodeManifestV1(Manifest{}); !errors.Is(err, ErrManifestUnsupportedSchema) {
		t.Fatalf("EncodeManifestV1(zero) error = %v", err)
	}
}

func TestRawManifestV1RejectsAmbiguousUnknownAndNoncanonicalJSON(t *testing.T) {
	t.Parallel()

	canonical := mustManifest(t, completeResources(t, mustPlatform(t, "linux", "amd64"))).CanonicalBytes()
	tests := []struct {
		name    string
		mutate  func([]byte) []byte
		wantErr error
	}{
		{
			name: "duplicate top-level key",
			mutate: func(raw []byte) []byte {
				return bytes.Replace(raw, []byte(`{"build_id":`), []byte(`{"build_id":"duplicate","build_id":`), 1)
			},
			wantErr: ErrManifestDuplicateKey,
		},
		{
			name: "duplicate nested key",
			mutate: func(raw []byte) []byte {
				return bytes.Replace(raw, []byte(`{"cyclonedx_sbom_resource_id":`), []byte(`{"id":"duplicate","cyclonedx_sbom_resource_id":`), 1)
			},
			wantErr: ErrManifestDuplicateKey,
		},
		{
			name: "unknown top-level security field",
			mutate: func(raw []byte) []byte {
				return append([]byte(`{"allow_insecure":true,`), raw[1:]...)
			},
			wantErr: ErrManifestUnknownField,
		},
		{
			name: "unknown nested permission field",
			mutate: func(raw []byte) []byte {
				return bytes.Replace(raw, []byte(`{"capabilities":`), []byte(`{"allow_host_mount":true,"capabilities":`), 1)
			},
			wantErr: ErrManifestUnknownField,
		},
		{
			name:    "leading whitespace",
			mutate:  func(raw []byte) []byte { return append([]byte{' '}, raw...) },
			wantErr: ErrManifestNonCanonical,
		},
		{
			name: "excessive JSON depth",
			mutate: func([]byte) []byte {
				return []byte(strings.Repeat("[", maximumManifestJSONDepth+2) + "0" +
					strings.Repeat("]", maximumManifestJSONDepth+2))
			},
			wantErr: ErrManifestMalformed,
		},
		{
			name: "trailing JSON value",
			mutate: func(raw []byte) []byte {
				return append(raw, []byte(`{}`)...)
			},
			wantErr: ErrManifestMalformed,
		},
		{
			name: "unsupported major",
			mutate: func(raw []byte) []byte {
				return bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":2`), 1)
			},
			wantErr: ErrManifestUnsupportedSchema,
		},
		{
			name: "missing required identity",
			mutate: func(raw []byte) []byte {
				prefix := []byte(`{"build_id":"build-20260701-1",`)
				return bytes.Replace(raw, prefix, []byte{'{'}, 1)
			},
			wantErr: ErrManifestIntegrity,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := DecodeManifestV1(test.mutate(append([]byte(nil), canonical...)))
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("DecodeManifestV1() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestRawManifestV1RejectsMutableSourceAndCrossSubjectEvidence(t *testing.T) {
	t.Parallel()

	canonical := string(mustManifest(t, completeResources(t, mustPlatform(t, "linux", "amd64"))).CanonicalBytes())
	imageMarker := `registry.example/agentmemory/image@sha256:`
	start := strings.Index(canonical, imageMarker)
	if start < 0 {
		t.Fatal("canonical fixture omitted image source")
	}
	end := start + len(imageMarker) + 64
	immutableSource := canonical[start:end]
	mutableSource := "registry.example/agentmemory/image:latest"
	mutable := strings.ReplaceAll(canonical, immutableSource, mutableSource)
	if _, err := DecodeManifestV1([]byte(mutable)); !errors.Is(err, ErrManifestIntegrity) {
		t.Fatalf("mutable source error = %v, want integrity failure", err)
	}

	crossBound := strings.Replace(
		canonical,
		`"subject_resource_id":"launcher"`,
		`"subject_resource_id":"compose"`,
		1,
	)
	if crossBound == canonical {
		t.Fatal("canonical fixture omitted evidence subject binding")
	}
	if _, err := DecodeManifestV1([]byte(crossBound)); !errors.Is(err, ErrManifestIntegrity) {
		t.Fatalf("cross-subject error = %v, want integrity failure", err)
	}
}

func TestRawManifestV1PreservesExactPriorAndRollbackBindings(t *testing.T) {
	t.Parallel()

	resources := completeResources(t, mustPlatform(t, "linux", "amd64"))
	input := validManifestInput(resources)
	priorDigest := DigestBytes([]byte("prior manifest"))
	history, err := NewReleaseHistory(
		[]PriorReleaseInput{{
			ReleaseID: "agentmemory-0.9.0", ManifestDigest: priorDigest,
			MinimumDataGeneration: 4, MaximumDataGeneration: 5,
		}},
		[]RollbackReleaseInput{{
			ReleaseID: "agentmemory-0.9.0", ManifestDigest: priorDigest, DataGeneration: 5,
		}},
	)
	if err != nil {
		t.Fatalf("NewReleaseHistory() error = %v", err)
	}
	input.ReleaseHistory = history
	want, err := NewManifest(input)
	if err != nil {
		t.Fatalf("NewManifest() error = %v", err)
	}
	got, err := DecodeManifestV1(want.CanonicalBytes())
	if err != nil {
		t.Fatalf("DecodeManifestV1() error = %v", err)
	}
	gotHistory := got.ReleaseHistory()
	if len(gotHistory.PriorReleases()) != 1 || len(gotHistory.RollbackReleases()) != 1 ||
		!gotHistory.PriorReleases()[0].ManifestDigest().Equal(priorDigest) ||
		gotHistory.RollbackReleases()[0].DataGeneration() != 5 {
		t.Fatal("raw decoder lost exact release-history authority")
	}
}
