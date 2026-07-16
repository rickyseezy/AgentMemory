//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestPF001NativeStageRejectsSpecialFilesystemEntries(t *testing.T) {
	t.Parallel()
	source := t.TempDir()
	if err := os.MkdirAll(filepath.Join(source, "bootstrap"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(source, "bootstrap", "distribution-manifest.json"), []byte("manifest"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(source, "special"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyBundleTree(source, filepath.Join(t.TempDir(), "copy"), 0o700, 0o600, time.Unix(1, 0)); err == nil || err.Error() != "bundle contains a special entry" {
		t.Fatalf("copyBundleTree(special) error=%v", err)
	}

	stage := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(stage, "special"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := normalizePackageDirectories(stage, time.Unix(1, 0)); err == nil || err.Error() != "package stage contains a special entry" {
		t.Fatalf("normalizePackageDirectories(special) error=%v", err)
	}
}
