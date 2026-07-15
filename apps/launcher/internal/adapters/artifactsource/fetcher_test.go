package artifactsource

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001CompositeArtifactFetcherRoutesOnlyExactSignedSchemes(t *testing.T) {
	t.Parallel()
	https := &sourceFetcher{value: []byte("abc")}
	bundle := &sourceFetcher{value: []byte("abc")}
	fetcher, err := New(https, bundle)
	if err != nil {
		t.Fatal(err)
	}
	artifact, chunk := sourceFixture(t)
	for _, source := range artifact.Sources() {
		value, err := fetcher.Fetch(context.Background(), artifact, source, chunk)
		if err != nil || string(value) != "abc" {
			t.Fatalf("Fetch(%q)=(%q,%v)", source, value, err)
		}
	}
	if https.calls != 1 || bundle.calls != 1 {
		t.Fatalf("routes https=%d bundle=%d", https.calls, bundle.calls)
	}
	if _, err := fetcher.Fetch(context.Background(), artifact, "https://evil.example/file", chunk); !errors.Is(err, artifactapp.ErrFetchIntegrity) {
		t.Fatalf("unsigned source error=%v", err)
	}
	if https.calls != 1 || bundle.calls != 1 {
		t.Fatal("unauthorized source reached a delegate")
	}
}

func TestPF001CompositeArtifactFetcherRequiresBothCapabilities(t *testing.T) {
	t.Parallel()
	valid := &sourceFetcher{}
	if _, err := New(nil, valid); err == nil {
		t.Fatal("nil HTTPS fetcher accepted")
	}
	if _, err := New(valid, nil); err == nil {
		t.Fatal("nil bundle fetcher accepted")
	}
	var typedNil *sourceFetcher
	if _, err := New(typedNil, valid); err == nil {
		t.Fatal("typed-nil HTTPS fetcher accepted")
	}
	fetcher, _ := New(valid, valid)
	artifact, chunk := sourceFixture(t)
	var absent context.Context
	if _, err := fetcher.Fetch(absent, artifact, artifact.Sources()[0], chunk); !errors.Is(err, artifactapp.ErrFetchIntegrity) {
		t.Fatalf("nil context error=%v", err)
	}
}

type sourceFetcher struct {
	value []byte
	err   error
	calls int
}

func (f *sourceFetcher) Fetch(
	_ context.Context,
	_ artifactacquisition.Artifact,
	_ string,
	_ artifactacquisition.Chunk,
) ([]byte, error) {
	f.calls++
	return append([]byte(nil), f.value...), f.err
}

func sourceFixture(t *testing.T) (artifactacquisition.Artifact, artifactacquisition.Chunk) {
	t.Helper()
	plan, err := artifactacquisition.NewPlan(artifactacquisition.PlanInput{
		PlanDigest: releaseinventory.DigestBytes([]byte("plan")),
		ProxyMode:  artifactacquisition.ProxyModeSystem,
		Artifacts: []artifactacquisition.ArtifactInput{{
			ID: "artifact", Digest: releaseinventory.DigestBytes([]byte("abc")), Size: 3,
			Sources: []string{"https://release.example/artifact", "bundle://release/artifact"},
			Chunks:  []artifactacquisition.ChunkInput{{Offset: 0, Size: 3, Digest: releaseinventory.DigestBytes([]byte("abc"))}},
		}},
		Totals: artifactacquisition.TotalsInput{DownloadBytes: 3, RollbackHeadroomBytes: 1, SafetyHeadroomBytes: 1, RequiredBytes: 5},
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact := plan.Artifacts()[0]
	return artifact, artifact.Chunks()[0]
}
