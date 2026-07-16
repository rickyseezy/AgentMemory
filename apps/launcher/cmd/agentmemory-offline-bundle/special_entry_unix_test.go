//go:build !windows

package main

import (
	"path/filepath"
	"syscall"
	"testing"
)

func TestPF001OfflineBundleRejectsSpecialFilesystemEntries(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(root, "special"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rejectUninventoriedBundleEntries(root, map[string]bundleResource{"special": {path: "special"}}); err == nil || err.Error() != "staging tree contains a special entry" {
		t.Fatalf("rejectUninventoriedBundleEntries(special) error=%v", err)
	}
}
