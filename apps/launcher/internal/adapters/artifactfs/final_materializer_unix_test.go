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
)

func TestPF006VerifiedCASMaterializerPublishesPrivateInstallerIdempotently(t *testing.T) {
	root := resolvedTempDir(t)
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	_, artifact, authorization := fsConsumedArtifact(t, store, "desktop-materialize")
	for index, chunk := range artifact.Chunks() {
		value := [][]byte{[]byte("abc"), []byte("def")}[index]
		if err := store.WriteChunk(context.Background(), authorization, chunk, value); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Finalize(context.Background(), authorization, artifact); err != nil {
		t.Fatal(err)
	}
	boundary := filepath.Join(root, "desktop-cache")
	target := filepath.Join(boundary, "runtime", artifact.Digest().Hex(), "Docker.dmg")
	if err := ensurePrivateMaterializationDirectory(context.Background(), boundary, filepath.Dir(target)); err != nil {
		t.Fatalf("ensurePrivateMaterializationDirectory() error=%v", err)
	}
	reader, err := store.OpenFinal(context.Background(), artifact)
	if err != nil {
		t.Fatalf("OpenFinal() error=%v", err)
	}
	if value, readError := io.ReadAll(reader); readError != nil || string(value) != "abcdef" {
		_ = reader.Close()
		t.Fatalf("verified CAS read=%q error=%v", value, readError)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("verified CAS close error=%v", err)
	}
	if err := store.MaterializeFinal(context.Background(), artifact, boundary, target); err != nil {
		t.Fatalf("MaterializeFinal() error=%v", err)
	}
	value, err := os.ReadFile(target) // #nosec G304 -- exact test-owned materialization path.
	info, statError := os.Lstat(target)
	if err != nil || statError != nil || string(value) != "abcdef" || info.Mode().Perm() != 0o600 {
		t.Fatalf("materialized value=%q info=%+v read=%v stat=%v", value, info, err, statError)
	}
	if err := store.MaterializeFinal(context.Background(), artifact, boundary, target); err != nil {
		t.Fatalf("idempotent MaterializeFinal() error=%v", err)
	}
	if err := os.WriteFile(target, []byte("abcdeg"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.MaterializeFinal(context.Background(), artifact, boundary, target); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("tampered target error=%v", err)
	}
}

func TestPF006VerifiedCASMaterializerRejectsUnsafeTargetAndCancellation(t *testing.T) {
	root := resolvedTempDir(t)
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	_, artifact, authorization := fsConsumedArtifact(t, store, "desktop-materialize-edges")
	for index, chunk := range artifact.Chunks() {
		value := [][]byte{[]byte("abc"), []byte("def")}[index]
		if err := store.WriteChunk(context.Background(), authorization, chunk, value); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Finalize(context.Background(), authorization, artifact); err != nil {
		t.Fatal(err)
	}
	boundary := filepath.Join(root, "desktop-cache")
	if err := store.MaterializeFinal(
		context.Background(), artifact, boundary, filepath.Join(root, "outside", "Docker.dmg"),
	); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("outside-boundary error=%v", err)
	}
	outside := resolvedTempDir(t)
	if err := os.Symlink(outside, boundary); err != nil {
		t.Fatal(err)
	}
	if err := store.MaterializeFinal(
		context.Background(), artifact, boundary, filepath.Join(boundary, "runtime", "Docker.dmg"),
	); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("linked-boundary error=%v", err)
	}
	if err := os.Remove(boundary); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.MaterializeFinal(
		cancelled, artifact, boundary, filepath.Join(boundary, "runtime", "Docker.dmg"),
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
}
