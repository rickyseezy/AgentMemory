//go:build !windows

package main

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestPF001LinuxReleaseRejectsSpecialFilesystemEntries(t *testing.T) {
	t.Parallel()
	source := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(source, "special"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyBundle(source, filepath.Join(t.TempDir(), "copy"), time.Unix(1, 0)); err == nil || err.Error() != `bundle entry "special" is not regular` {
		t.Fatalf("copyBundle(special) error=%v", err)
	}

	stage := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(stage, "special"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := normalizeDirectoryTree(stage, time.Unix(1, 0)); err == nil || err.Error() != "staging tree contains a special entry" {
		t.Fatalf("normalizeDirectoryTree(special) error=%v", err)
	}
}
