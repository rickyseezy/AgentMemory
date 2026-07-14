//go:build darwin || linux

package installplanfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
)

func TestRepositoryRejectsSymlinkAndNonPrivateRoot(t *testing.T) {
	t.Parallel()
	parent := filesystemTestDirectory(t)
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(context.Background(), link); !errors.Is(err, installplanapp.ErrPlanIntegrity) {
		t.Fatalf("symlink root error = %v", err)
	}
	public := filepath.Join(parent, "public")
	if err := os.Mkdir(public, 0o755); err != nil { //nolint:gosec // Deliberately creates a non-private rejection fixture.
		t.Fatal(err)
	}
	if _, err := NewRepository(context.Background(), public); !errors.Is(err, installplanapp.ErrPlanIntegrity) {
		t.Fatalf("public root error = %v", err)
	}
}

func TestUnixStoreRejectsUnsafeObjectsAndImmutableConflict(t *testing.T) {
	t.Parallel()
	root := filepath.Join(filesystemTestDirectory(t), "raw-plans")
	opened, err := openPlatformStore(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	store := opened.(*unixStore)
	defer func() { _ = store.close() }()
	if err := store.save(context.Background(), "raw.json", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if raw, err := store.load(context.Background(), "raw.json"); err != nil || string(raw) != "first" {
		t.Fatalf("raw load = %q/%v", raw, err)
	}
	if err := store.save(context.Background(), "raw.json", []byte("second")); !errors.Is(err, errImmutableConflict) {
		t.Fatalf("immutable conflict = %v", err)
	}
	if err := store.save(context.Background(), "../escape", []byte("value")); err == nil {
		t.Fatal("raw store accepted traversal")
	}
	if err := store.save(context.Background(), "empty", nil); err == nil {
		t.Fatal("raw store accepted empty bytes")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.save(cancelled, "cancelled", []byte("value")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled save = %v", err)
	}
	if _, err := store.load(cancelled, "raw.json"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled load = %v", err)
	}
	if _, err := store.load(context.Background(), "../escape"); err == nil {
		t.Fatal("raw load accepted traversal")
	}
	if err := os.Symlink(filepath.Join(root, "raw.json"), filepath.Join(root, "link.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.load(context.Background(), "link.json"); err == nil {
		t.Fatal("raw load followed a symlink")
	}
	if err := os.Mkdir(filepath.Join(root, "directory.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := store.load(context.Background(), "directory.json"); err == nil {
		t.Fatal("raw load accepted a directory")
	}
	if err := os.WriteFile(filepath.Join(root, "empty.json"), nil, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := store.load(context.Background(), "empty.json"); err == nil {
		t.Fatal("raw load accepted an empty file")
	}
}

func TestUnixStoreRejectsWritableAncestorAndInvalidComponent(t *testing.T) {
	t.Parallel()
	parent := filesystemTestDirectory(t)
	writable := filepath.Join(parent, "writable")
	if err := os.Mkdir(writable, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o777); err != nil { //nolint:gosec // Deliberately creates an unsafe-ancestor rejection fixture.
		t.Fatal(err)
	}
	if _, err := openPlatformStore(context.Background(), filepath.Join(writable, "plans")); err == nil {
		t.Fatal("world-writable ancestor was accepted")
	}
	if _, err := openOrCreatePrivateDirectory(parent+string(filepath.Separator)+".."+string(filepath.Separator)+"escape", 0); err == nil {
		t.Fatal("parent traversal component was accepted")
	}
	var nilStore *unixStore
	if err := nilStore.close(); err != nil {
		t.Fatal(err)
	}
}
