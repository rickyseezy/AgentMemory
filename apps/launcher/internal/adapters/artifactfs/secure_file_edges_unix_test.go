//go:build darwin || linux

package artifactfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"golang.org/x/sys/unix"
)

func TestPF001SecureDescriptorPrimitivesRejectInvalidPathsAndIdentitySwaps(t *testing.T) {
	t.Parallel()
	var absent *secureFile
	absent.close()
	if absent.verifyPathIdentity() == nil || absent.verifyExactSize(0) == nil || absent.syncDirectory() == nil {
		t.Fatal("nil secure descriptor accepted")
	}
	for _, path := range []string{"", "relative", "/"} {
		if directory, err := openSecureDirectory(path); err == nil {
			_ = directory.Close()
			t.Fatalf("invalid directory path accepted: %q", path)
		}
	}
	root := resolvedTempDir(t)
	if err := syncDirectory(root); err != nil {
		t.Fatalf("sync protected directory: %v", err)
	}
	filePath := filepath.Join(root, "ordinary")
	if err := os.WriteFile(filePath, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	if directory, err := openSecureDirectory(filePath); err == nil {
		_ = directory.Close()
		t.Fatal("regular file opened as a directory")
	}
	if _, _, err := openSecureLeaf(root, "../escape", false); err == nil {
		t.Fatal("unsafe leaf accepted")
	}
	if _, _, err := openSecureLeaf(filepath.Join(root, "missing"), "leaf", false); err == nil {
		t.Fatal("missing parent accepted")
	}
	if _, _, err := openSecureLeaf(root, "missing", false); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing leaf error=%v", err)
	}
	opened, created, err := openSecureLeaf(root, "created", true)
	if err != nil || !created || opened.verifyExactSize(0) != nil || opened.syncDirectory() != nil {
		t.Fatalf("created descriptor=(%+v,%t,%v)", opened, created, err)
	}
	opened.close()
	replayed, created, err := openSecureLeaf(root, "created", true)
	if err != nil || created {
		t.Fatalf("replayed descriptor=(%+v,%t,%v)", replayed, created, err)
	}
	if err := os.Rename(filepath.Join(root, "created"), filepath.Join(root, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "created"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replayed.verifyPathIdentity(); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("leaf identity swap error=%v", err)
	}
	replayed.close()

	identity, err := captureDirectoryIdentity(root)
	if err != nil || !directoryIdentityMatches(root, identity) || directoryIdentityMatches(root, "") ||
		directoryIdentityMatches(root, "other") || directoryIdentityMatches(filepath.Join(root, "missing"), identity) {
		t.Fatalf("directory identity=%q err=%v", identity, err)
	}
}

func TestPF001SecureRemovalPrimitivesPreserveUnsafeAndUnrelatedObjects(t *testing.T) {
	t.Parallel()
	root := resolvedTempDir(t)
	if err := removeSecureLeaf(root, "missing", 1); err != nil {
		t.Fatal(err)
	}
	exact := filepath.Join(root, "exact")
	if err := os.WriteFile(exact, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeSecureLeaf(root, "exact", 2); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("wrong-size exact removal error=%v", err)
	}
	if err := removeSecureLeaf(root, "exact", 3); err != nil {
		t.Fatal(err)
	}
	bounded := filepath.Join(root, "bounded")
	if err := os.WriteFile(bounded, []byte("ab"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeSecureLeafAtMost(root, "bounded", 1); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("oversize bounded removal error=%v", err)
	}
	if err := removeSecureLeafAtMost(root, "bounded", 2); err != nil {
		t.Fatal(err)
	}
	if err := removeSecureLeafAtMost(root, "bounded", 2); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	link := filepath.Join(root, "linked")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, link); err != nil {
		t.Fatal(err)
	}
	if err := removeSecureLeafAtMost(root, "linked", 4); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("hard-link removal error=%v", err)
	}
	if value, err := os.ReadFile(target); err != nil || string(value) != "keep" { // #nosec G304 -- test-owned path.
		t.Fatalf("hard-link target=%q err=%v", value, err)
	}
}

func TestPF001SecureDirectoryStatPolicyIsClosed(t *testing.T) {
	t.Parallel()
	effective, valid := effectiveUserID()
	if !valid {
		t.Fatal("effective user ID unavailable")
	}
	validFinal := unix.Stat_t{Mode: unix.S_IFDIR | 0o700, Uid: effective}
	validAncestor := unix.Stat_t{Mode: unix.S_IFDIR | 0o755, Uid: effective}
	stickyRoot := unix.Stat_t{Mode: unix.S_IFDIR | unix.S_ISVTX | 0o777, Uid: 0}
	if !safeControlledDirectoryStat(&validFinal, true) || !safeControlledDirectoryStat(&validAncestor, false) ||
		!safeControlledDirectoryStat(&stickyRoot, false) {
		t.Fatal("valid directory policy rejected")
	}
	invalid := []struct {
		stat  *unix.Stat_t
		final bool
	}{
		{nil, true},
		{&unix.Stat_t{Mode: unix.S_IFREG | 0o600, Uid: effective}, true},
		{&unix.Stat_t{Mode: unix.S_IFDIR | 0o700, Uid: effective + 1}, true},
		{&unix.Stat_t{Mode: unix.S_IFDIR | 0o755, Uid: effective}, true},
		{&unix.Stat_t{Mode: unix.S_IFDIR | 0o777, Uid: 0}, false},
	}
	for index, test := range invalid {
		if safeControlledDirectoryStat(test.stat, test.final) {
			t.Fatalf("invalid directory policy %d accepted", index)
		}
	}
	if safeDirectoryInfo(nil) {
		t.Fatal("nil directory information accepted")
	}
	root := resolvedTempDir(t)
	info, err := os.Lstat(root)
	if err != nil || !safeDirectoryInfo(info) {
		t.Fatalf("valid directory info=%+v err=%v", info, err)
	}
}

func TestPF001SecureDirectoryAndStoreIdentityHelpersFailClosed(t *testing.T) {
	t.Parallel()
	if store, err := newStoreWithReservationAttestor(
		resolvedTempDir(t),
		func(*os.File) (bool, error) { return false, errors.New("attestation failed") },
	); !errors.Is(err, artifactapp.ErrStoreIntegrity) || store != nil {
		t.Fatalf("failed reservation attestation store=%+v error=%v", store, err)
	}

	if duplicate, err := duplicateSecureDirectory(nil); err == nil || duplicate != nil {
		t.Fatalf("nil directory duplicate=%+v error=%v", duplicate, err)
	}
	root := resolvedTempDir(t)
	ordinaryPath := filepath.Join(root, "ordinary-file")
	if err := os.WriteFile(ordinaryPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // G304: test-created exact child path exercises regular-file descriptor rejection.
	ordinary, err := os.Open(ordinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeError := ordinary.Close(); closeError != nil {
			t.Errorf("close ordinary fixture: %v", closeError)
		}
	})
	if duplicate, err := duplicateSecureDirectory(ordinary); err == nil || duplicate != nil {
		t.Fatalf("regular-file duplicate=%+v error=%v", duplicate, err)
	}
	directory, err := openSecureDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeError := directory.Close(); closeError != nil {
			t.Errorf("close directory fixture: %v", closeError)
		}
	})
	duplicate, err := duplicateSecureDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := duplicate.Close(); err != nil {
		t.Fatal(err)
	}

	if child, err := openSecureChildDirectoryAt(nil, "child", true); err == nil || child != nil {
		t.Fatalf("nil-parent child=%+v error=%v", child, err)
	}
	if child, err := openSecureChildDirectoryAt(directory, "../escape", true); err == nil || child != nil {
		t.Fatalf("unsafe-leaf child=%+v error=%v", child, err)
	}
	if child, err := openSecureChildDirectoryAt(directory, "missing", false); !errors.Is(err, os.ErrNotExist) || child != nil {
		t.Fatalf("missing child=%+v error=%v", child, err)
	}
	child, err := openSecureChildDirectoryAt(directory, "child", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Close(); err != nil {
		t.Fatal(err)
	}

	var identity [32]byte
	identity[0] = 1
	if value, err := boundFilesystemIdentity("", directory, identity); err == nil || value != "" {
		t.Fatalf("empty filesystem binding=%q error=%v", value, err)
	}
	if value, err := boundFilesystemIdentity("local", nil, identity); err == nil || value != "" {
		t.Fatalf("nil-root binding=%q error=%v", value, err)
	}
	if value, err := boundFilesystemIdentity("local", directory, [32]byte{}); err == nil || value != "" {
		t.Fatalf("zero-marker binding=%q error=%v", value, err)
	}
	if value, err := boundFilesystemIdentity("local", directory, identity); err != nil || value == "" {
		t.Fatalf("valid binding=%q error=%v", value, err)
	}

	zeroMarker, created, err := openSecureLeaf(root, storeIdentityLeaf, true)
	if err != nil || !created {
		t.Fatalf("zero marker open created=%t error=%v", created, err)
	}
	if written, err := zeroMarker.file.Write(make([]byte, 32)); err != nil || written != 32 {
		zeroMarker.close()
		t.Fatalf("zero marker write=%d error=%v", written, err)
	}
	if opened, _, err := readStoreIdentity(zeroMarker); !errors.Is(err, artifactapp.ErrStoreIntegrity) || opened != nil {
		t.Fatalf("zero store marker opened=%+v error=%v", opened, err)
	}

	shortRoot := resolvedTempDir(t)
	shortMarker, created, err := openSecureLeaf(shortRoot, storeIdentityLeaf, true)
	if err != nil || !created {
		t.Fatalf("short marker open created=%t error=%v", created, err)
	}
	if written, err := shortMarker.file.Write([]byte{1}); err != nil || written != 1 {
		shortMarker.close()
		t.Fatalf("short marker write=%d error=%v", written, err)
	}
	if opened, _, err := readStoreIdentity(shortMarker); !errors.Is(err, artifactapp.ErrStoreIntegrity) || opened != nil {
		t.Fatalf("short store marker opened=%+v error=%v", opened, err)
	}
}
