//go:build darwin || linux || windows

package artifactfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
)

func TestPF001RetainedBundleReadsOnlyTheFixedBoundedDistributionEnvelope(t *testing.T) {
	t.Parallel()
	root := resolvedTempDir(t)
	bootstrap := filepath.Join(root, "bootstrap")
	makeSecureTestDirectory(t, bootstrap)
	path := filepath.Join(bootstrap, "distribution-manifest.json")
	want := []byte(`{"manifest":"separately signed"}`)
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	fetcher, err := NewBundleFetcher(root)
	if err != nil {
		t.Fatal(err)
	}
	value, err := fetcher.ReadDistributionEnvelope(t.Context())
	if err != nil || string(value) != string(want) {
		t.Fatalf("envelope=%q error=%v", value, err)
	}
	value[0] ^= 0xff
	again, err := fetcher.ReadDistributionEnvelope(t.Context())
	if err != nil || string(again) != string(want) {
		t.Fatalf("caller mutated retained bytes: envelope=%q error=%v", again, err)
	}

	//lint:ignore SA1012 Deliberate absent-context security boundary.
	if _, err := fetcher.ReadDistributionEnvelope(nil); !errors.Is(err, artifactapp.ErrFetchIntegrity) { //nolint:staticcheck
		t.Fatalf("nil context error=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fetcher.ReadDistributionEnvelope(cancelled); !errors.Is(err, context.Canceled) ||
		!errors.Is(err, artifactapp.ErrFetchUnavailable) {
		t.Fatalf("cancelled error=%v", err)
	}
	if err := fetcher.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := fetcher.ReadDistributionEnvelope(t.Context()); !errors.Is(err, artifactapp.ErrFetchIntegrity) {
		t.Fatalf("closed fetcher error=%v", err)
	}
}

func TestPF001RetainedBundleRejectsMissingEmptyOversizedAndLinkedEnvelopes(t *testing.T) {
	t.Parallel()
	t.Run("missing", func(t *testing.T) {
		root := resolvedTempDir(t)
		makeSecureTestDirectory(t, filepath.Join(root, "bootstrap"))
		fetcher, err := NewBundleFetcher(root)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = fetcher.Close() }()
		if _, err := fetcher.ReadDistributionEnvelope(t.Context()); !errors.Is(err, artifactapp.ErrFetchUnavailable) {
			t.Fatalf("missing envelope error=%v", err)
		}
	})
	for _, test := range []struct {
		name string
		size int64
	}{
		{name: "empty", size: 0},
		{name: "oversized", size: maximumDistributionEnvelopeBytes + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := resolvedTempDir(t)
			bootstrap := filepath.Join(root, "bootstrap")
			makeSecureTestDirectory(t, bootstrap)
			file, err := os.OpenFile( //nolint:gosec // Exact test-owned retained-bundle path.
				filepath.Join(bootstrap, "distribution-manifest.json"), os.O_CREATE|os.O_WRONLY, 0o600,
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := file.Truncate(test.size); err != nil {
				_ = file.Close()
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			fetcher, err := NewBundleFetcher(root)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = fetcher.Close() }()
			if _, err := fetcher.ReadDistributionEnvelope(t.Context()); !errors.Is(err, artifactapp.ErrFetchIntegrity) {
				t.Fatalf("%s envelope error=%v", test.name, err)
			}
		})
	}

	if os.PathSeparator == '/' {
		t.Run("symlink", func(t *testing.T) {
			root := resolvedTempDir(t)
			bootstrap := filepath.Join(root, "bootstrap")
			makeSecureTestDirectory(t, bootstrap)
			target := filepath.Join(root, "foreign.json")
			if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(bootstrap, "distribution-manifest.json")); err != nil {
				t.Skipf("symlink fixture unavailable: %v", err)
			}
			fetcher, err := NewBundleFetcher(root)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = fetcher.Close() }()
			if _, err := fetcher.ReadDistributionEnvelope(t.Context()); !errors.Is(err, artifactapp.ErrFetchIntegrity) {
				t.Fatalf("linked envelope error=%v", err)
			}
		})
	}
}
