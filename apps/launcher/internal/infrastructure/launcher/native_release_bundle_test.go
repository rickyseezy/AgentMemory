package launcher

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPF001DefaultNativeReleaseBundleRootUsesOnlyTheRunningExecutable(t *testing.T) {
	t.Parallel()
	root, err := defaultNativeReleaseBundleRoot()
	if runtime.GOOS == "darwin" {
		// A Go test binary is not packaged under a signed .app/Contents/MacOS
		// boundary, so production resolution must fail closed on this host.
		if root != "" || !errors.Is(err, errNativeInstallerIntegrity) {
			t.Fatalf("unbundled macOS test executable resolved to (%q,%v)", root, err)
		}
		return
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "windows" {
		if err != nil || !filepath.IsAbs(root) || filepath.Base(root) != "bundle" ||
			filepath.Base(filepath.Dir(root)) != "resources" {
			t.Fatalf("default native bundle root=(%q,%v)", root, err)
		}
		return
	}
	if root != "" || !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("unsupported host resolved to (%q,%v)", root, err)
	}
}

func TestPF001NativeReleaseBundleRootIsFixedToTheResolvedSignedExecutable(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	executable := filepath.Join(root, "AgentMemory", "bin", "agentmemory")
	if err := os.MkdirAll(filepath.Dir(executable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("signed launcher fixture"), 0o700); err != nil { // #nosec G306 -- executable fixture.
		t.Fatal(err)
	}
	canonicalExecutable, err := filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveNativeReleaseBundleRoot(func() (string, error) { return executable, nil }, "linux")
	if err != nil || resolved != filepath.Join(filepath.Dir(canonicalExecutable), "resources", "bundle") {
		t.Fatalf("linux root=%q error=%v", resolved, err)
	}
	link := filepath.Join(root, "agentmemory-link")
	if err := os.Symlink(executable, link); err != nil {
		t.Logf("host cannot create a symlink fixture: %v", err)
	} else {
		linked, linkError := resolveNativeReleaseBundleRoot(func() (string, error) { return link, nil }, "linux")
		if linkError != nil || linked != resolved {
			t.Fatalf("linked root=%q error=%v", linked, linkError)
		}
	}

	macExecutable := filepath.Join(root, "AgentMemory.app", "Contents", "MacOS", "AgentMemory")
	if err := os.MkdirAll(filepath.Dir(macExecutable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(macExecutable, []byte("signed app fixture"), 0o700); err != nil { // #nosec G306 -- executable fixture.
		t.Fatal(err)
	}
	canonicalMacExecutable, err := filepath.EvalSymlinks(macExecutable)
	if err != nil {
		t.Fatal(err)
	}
	macRoot, err := resolveNativeReleaseBundleRoot(func() (string, error) { return macExecutable, nil }, "darwin")
	if err != nil || macRoot != filepath.Join(filepath.Dir(filepath.Dir(canonicalMacExecutable)), "Resources", "bundle") {
		t.Fatalf("macOS root=%q error=%v", macRoot, err)
	}
}

func TestPF001NativeReleaseBundleRootRejectsAmbientAndMalformedAuthority(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	directory := filepath.Join(root, "directory")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(root, "missing")
	executable := filepath.Join(root, "agentmemory")
	if err := os.WriteFile(executable, []byte("signed launcher fixture"), 0o700); err != nil { // #nosec G306 -- executable fixture.
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		resolver nativeExecutablePathResolver
		os       string
	}{
		"nil resolver":   {},
		"resolver error": {resolver: func() (string, error) { return "", errors.New("private") }, os: "linux"},
		"empty":          {resolver: func() (string, error) { return "", nil }, os: "linux"},
		"relative":       {resolver: func() (string, error) { return "agentmemory", nil }, os: "linux"},
		"unclean": {resolver: func() (string, error) {
			return root + string(os.PathSeparator) + "missing" + string(os.PathSeparator) + ".." +
				string(os.PathSeparator) + "agentmemory", nil
		}, os: "linux"},
		"missing":        {resolver: func() (string, error) { return missing, nil }, os: "linux"},
		"directory":      {resolver: func() (string, error) { return directory, nil }, os: "linux"},
		"unsupported OS": {resolver: func() (string, error) { return executable, nil }, os: "plan9"},
		"unbundled macOS": {
			resolver: func() (string, error) { return executable, nil }, os: "darwin",
		},
	} {
		if resolved, err := resolveNativeReleaseBundleRoot(test.resolver, test.os); resolved != "" ||
			!errors.Is(err, errNativeInstallerIntegrity) {
			t.Fatalf("%s resolve=(%q,%v)", name, resolved, err)
		}
	}
}
