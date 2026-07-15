//go:build darwin || linux

package artifactfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"golang.org/x/sys/unix"
)

func TestPF001InstalledBundleAcceptsOnlyPrivateOrRootReadOnlyAuthority(t *testing.T) {
	t.Parallel()
	effective, valid := effectiveUserID()
	if !valid {
		t.Fatal("effective user ID unavailable")
	}
	if !safeInstalledBundleDirectoryStat(&unix.Stat_t{Mode: unix.S_IFDIR | 0o755, Uid: 0}) ||
		safeInstalledBundleDirectoryStat(&unix.Stat_t{Mode: unix.S_IFDIR | 0o775, Uid: 0}) ||
		!safeInstalledBundleFileValues(unix.S_IFREG|0o644, 0, 1, bundleAccessInstalledReadOnly) ||
		safeInstalledBundleFileValues(unix.S_IFREG|0o664, 0, 1, bundleAccessInstalledReadOnly) ||
		safeInstalledBundleFileValues(unix.S_IFREG|0o644, 0, 2, bundleAccessInstalledReadOnly) {
		t.Fatal("root-installed Unix authority policy changed")
	}
	if effective != 0 {
		if !safeInstalledBundleDirectoryStat(&unix.Stat_t{Mode: unix.S_IFDIR | 0o700, Uid: effective}) ||
			!safeInstalledBundleFileValues(unix.S_IFREG|0o600, effective, 1, bundleAccessInstalledReadOnly) ||
			safeInstalledBundleFileValues(unix.S_IFREG|0o640, effective, 1, bundleAccessInstalledReadOnly) {
			t.Fatal("private invoking-user Unix authority policy changed")
		}
	}
}

func TestPF001InstalledBundleFailsClosedForInvalidPolicyPathsAndModes(t *testing.T) {
	t.Parallel()
	if safeInstalledBundleDirectoryStat(nil) ||
		safeBundleDirectoryDescriptor(nil, bundleAccessInstalledReadOnly) ||
		safeBundleFileStat(nil, bundleAccessInstalledReadOnly) {
		t.Fatal("absent installed authority accepted")
	}
	if _, err := openBundleDirectory("relative", bundleAccessInstalledReadOnly); err == nil {
		t.Fatal("relative installed root accepted")
	}
	if _, err := duplicateBundleDirectory(nil, bundleAccessInstalledReadOnly); err == nil {
		t.Fatal("absent installed descriptor duplicated")
	}
	if _, err := openBundleChildDirectoryAt(nil, "child", bundleAccessInstalledReadOnly); err == nil {
		t.Fatal("absent installed parent accepted")
	}
	if _, err := openBundleReadLeafAt(nil, "file", bundleAccessInstalledReadOnly); err == nil {
		t.Fatal("absent installed leaf parent accepted")
	}
	root := filepath.Join(t.TempDir(), "bundle")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewInstalledBundleFetcher(resolved); !errors.Is(err, artifactapp.ErrFetchIntegrity) {
		t.Fatalf("unsafe installed mode error=%v", err)
	}
	if _, err := newBundleFetcher(resolved, bundleAccessPolicy(99)); !errors.Is(err, artifactapp.ErrFetchIntegrity) {
		t.Fatalf("unknown bundle policy error=%v", err)
	}
	symlinkRoot := filepath.Join(t.TempDir(), "bundle")
	directoryMode := os.FileMode(0o700)
	if os.Geteuid() == 0 {
		directoryMode = 0o755
	}
	if err := os.Mkdir(symlinkRoot, directoryMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(symlinkRoot, "bootstrap")); err != nil {
		t.Fatal(err)
	}
	symlinkRoot, err = filepath.EvalSymlinks(symlinkRoot)
	if err != nil {
		t.Fatal(err)
	}
	fetcher, err := NewInstalledBundleFetcher(symlinkRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fetcher.Close() }()
	if _, err := fetcher.ReadDistributionEnvelope(context.Background()); !errors.Is(err, artifactapp.ErrFetchIntegrity) {
		t.Fatalf("linked installed child error=%v", err)
	}
}

func TestPF001InstalledBundleRetainsAndReadsExactProtectedTree(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "bundle")
	directoryMode := os.FileMode(0o700)
	fileMode := os.FileMode(0o600)
	if os.Geteuid() == 0 {
		directoryMode = 0o755
		fileMode = 0o644
	}
	if err := os.Mkdir(root, directoryMode); err != nil {
		t.Fatal(err)
	}
	bootstrap := filepath.Join(root, "bootstrap")
	if err := os.Mkdir(bootstrap, directoryMode); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(bootstrap, "distribution-manifest.json")
	if err := os.WriteFile(manifest, []byte(`{"signed":true}`), fileMode); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	fetcher, err := NewInstalledBundleFetcher(resolved)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fetcher.Close() })
	raw, err := fetcher.ReadDistributionEnvelope(context.Background())
	if err != nil || string(raw) != `{"signed":true}` {
		t.Fatalf("manifest=%q error=%v", raw, err)
	}
	if fetcher.accessPolicy != bundleAccessInstalledReadOnly {
		t.Fatal("installed bundle lost its distinct retained authority")
	}
	if err := os.Chmod(manifest, 0o640); err != nil { // #nosec G302 -- deliberately unsafe mode exercises rejection.
		t.Fatal(err)
	}
	if _, err := fetcher.ReadDistributionEnvelope(context.Background()); !errors.Is(err, artifactapp.ErrFetchIntegrity) {
		t.Fatalf("mutated installed manifest mode error=%v", err)
	}
	if err := os.Chmod(manifest, fileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bootstrap, 0o750); err != nil { // #nosec G302 -- deliberately unsafe mode exercises rejection.
		t.Fatal(err)
	}
	if _, err := fetcher.ReadDistributionEnvelope(context.Background()); !errors.Is(err, artifactapp.ErrFetchIntegrity) {
		t.Fatalf("mutated installed directory mode error=%v", err)
	}
}
