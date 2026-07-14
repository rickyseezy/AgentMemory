//go:build darwin || linux

package artifactfs

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001ArtifactFSVerifiedReaderConsumesExactRetainedDescriptor(t *testing.T) {
	t.Parallel()
	store, artifact, root := finalizedReaderArtifact(t)
	reader, err := store.OpenFinal(context.Background(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	contents, err := io.ReadAll(reader)
	if err != nil || string(contents) != "abcdef" {
		t.Fatalf("ReadAll()=(%q,%v)", contents, err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("idempotent Close() error = %v", err)
	}
	if _, err := reader.Read(make([]byte, 1)); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("read after close error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(artifact.ContentKey()))); err != nil {
		t.Fatalf("verified object disappeared: %v", err)
	}
}

func TestPF001ArtifactFSVerifiedReaderRejectsPartialReadAndPostOpenMutation(t *testing.T) {
	t.Parallel()
	t.Run("partial", func(t *testing.T) {
		store, artifact, _ := finalizedReaderArtifact(t)
		reader, err := store.OpenFinal(context.Background(), artifact)
		if err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 2)
		if count, readErr := reader.Read(buffer); readErr != nil || count != len(buffer) {
			t.Fatalf("Read()=(%d,%v)", count, readErr)
		}
		if err := reader.Close(); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
			t.Fatalf("partial Close() error = %v", err)
		}
	})
	t.Run("mutation", func(t *testing.T) {
		store, artifact, root := finalizedReaderArtifact(t)
		reader, err := store.OpenFinal(context.Background(), artifact)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, filepath.FromSlash(artifact.ContentKey()))
		file, err := os.OpenFile(path, os.O_WRONLY, 0) // #nosec G304 -- exact test-owned CAS path.
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteAt([]byte("X"), 0); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, reader); err != nil && !errors.Is(err, artifactapp.ErrStoreIntegrity) {
			t.Fatalf("Copy() error = %v", err)
		}
		if err := reader.Close(); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
			t.Fatalf("mutated Close() error = %v", err)
		}
	})
}

func TestPF001ArtifactFSVerifiedReaderFailsClosedForInvalidAuthority(t *testing.T) {
	t.Parallel()
	store, artifact, _ := finalizedReaderArtifact(t)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.OpenFinal(cancelled, artifact); !errors.Is(err, context.Canceled) ||
		!errors.Is(err, artifactapp.ErrStoreOperation) {
		t.Fatalf("cancelled OpenFinal() error = %v", err)
	}
	if _, err := store.OpenFinal(hostileNilFinalReaderContext(), artifact); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("nil-context OpenFinal() error = %v", err)
	}
	if _, err := store.OpenFinal(context.Background(), artifactacquisition.Artifact{}); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("invalid-artifact OpenFinal() error = %v", err)
	}
	var nilStore *Store
	if _, err := nilStore.OpenFinal(context.Background(), artifact); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("nil-store OpenFinal() error = %v", err)
	}
	var nilReader *verifiedFinalReader
	if err := nilReader.Close(); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("nil-reader Close() error = %v", err)
	}
}

func finalizedReaderArtifact(t *testing.T) (*Store, artifactacquisition.Artifact, string) {
	t.Helper()
	root := resolvedTempDir(t)
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	aggregate, artifact, authorization := fsConsumedArtifact(t, store, "verified-reader")
	for index, chunk := range artifact.Chunks() {
		value := [][]byte{[]byte("abc"), []byte("def")}[index]
		if err := store.WriteChunk(context.Background(), authorization, chunk, value); err != nil {
			t.Fatal(err)
		}
		if _, err := aggregate.MarkChunkVerified(artifact, chunk, releaseinventory.DigestBytes(value)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Finalize(context.Background(), authorization, artifact); err != nil {
		t.Fatal(err)
	}
	return store, artifact, root
}

func hostileNilFinalReaderContext() context.Context { return nil }
