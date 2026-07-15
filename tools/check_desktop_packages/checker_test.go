package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRepositoryDesktopPackageContracts(t *testing.T) {
	root := repositoryRoot(t)
	if violations := Check(Options{RepositoryRoot: root}); len(violations) != 0 {
		t.Fatalf("Check() violations=%v", violations)
	}
}

func TestDesktopPackageContractsRejectEverySecuritySubstitution(t *testing.T) {
	root := copyDesktopPackageFixture(t)
	mutations := map[string]struct {
		path string
		old  string
		new  string
	}{
		"mac identifier": {
			path: darwinDistributionPath,
			old:  `id="com.rickyseezy.agentmemory"`,
			new:  `id="com.example.other"`,
		},
		"mac domain": {
			path: darwinDistributionPath,
			old:  `enable_currentUserHome="false"`,
			new:  `enable_currentUserHome="true"`,
		},
		"mac helper mode": {
			path: darwinPostinstallPath,
			old:  `/usr/bin/install -d -m 0755 -o root -g wheel "/Library/Application Support/AgentMemory/runtime-helper"`,
			new:  `/usr/bin/install -d -m 0777 -o root -g wheel "/Library/Application Support/AgentMemory/runtime-helper"`,
		},
		"mac signing": {
			path: darwinSignScriptPath,
			old:  `--options runtime --timestamp --sign "${application_identity}"`,
			new:  `--sign -`,
		},
		"mac notarization": {
			path: darwinBuildScriptPath,
			old:  `notarytool submit "${package}" --keychain-profile "${notary_profile}" --wait`,
			new:  `echo notarization-skipped`,
		},
		"windows scope": {
			path: windowsPackagePath,
			old:  `Scope="perMachine"`,
			new:  `Scope="perUser"`,
		},
		"windows payload": {
			path: windowsPackagePath,
			old:  `!(bindpath.Payload)\**`,
			new:  `C:\untrusted\**`,
		},
		"windows custom action": {
			path: windowsPackagePath,
			old:  `<MajorUpgrade`,
			new:  `<CustomAction Id="RunAmbientCommand" ExeCommand="cmd.exe"/><MajorUpgrade`,
		},
	}
	for name, mutation := range mutations {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(root, filepath.FromSlash(mutation.path))
			// #nosec G304 -- path is selected from the closed mutation table above and rooted in a test fixture.
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			changed := strings.Replace(string(content), mutation.old, mutation.new, 1)
			if changed == string(content) {
				t.Fatalf("mutation did not apply to %s", mutation.path)
			}
			mode := packageContractFiles()[mutation.path]
			if err := os.WriteFile(path, []byte(changed), mode); err != nil { // #nosec G703 -- closed test-owned path.
				t.Fatal(err)
			}
			if violations := Check(Options{RepositoryRoot: root}); len(violations) == 0 {
				t.Fatal("unsafe package mutation was accepted")
			}
			if err := os.WriteFile(path, content, mode); err != nil { // #nosec G703 -- closed test-owned path.
				t.Fatal(err)
			}
		})
	}
}

func TestDesktopPackageCheckerRejectsLinksModesAndInvocationErrors(t *testing.T) {
	root := copyDesktopPackageFixture(t)
	script := filepath.Join(root, filepath.FromSlash(darwinBuildScriptPath))
	if err := os.Remove(script); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("README.md", script); err != nil {
		if mkdirErr := os.Mkdir(script, 0o700); mkdirErr != nil {
			t.Fatal(mkdirErr)
		}
	}
	postinstall := filepath.Join(root, filepath.FromSlash(darwinPostinstallPath))
	if runtime.GOOS == "windows" {
		if err := os.WriteFile(postinstall, []byte("tampered\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	} else if err := os.Chmod(postinstall, 0o600); err != nil {
		t.Fatal(err)
	}
	if violations := Check(Options{RepositoryRoot: root}); len(violations) != 2 {
		t.Fatalf("violations=%v, want link and mode errors", violations)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-root", t.TempDir()}, &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "Desktop package check failed") {
		t.Fatalf("run(missing)=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"unexpected"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run(positional)=%d", code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"-root", repositoryRoot(t)}, &stdout, &stderr); code != 0 ||
		stdout.String() != "Desktop package check passed\n" || stderr.Len() != 0 {
		t.Fatalf("run(valid)=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func repositoryRoot(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func copyDesktopPackageFixture(t testing.TB) string {
	t.Helper()
	root := t.TempDir()
	for path, mode := range packageContractFiles() {
		content, err := os.ReadFile(filepath.Join(repositoryRoot(t), filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, content, mode); err != nil { // #nosec G703 -- closed test-owned path.
			t.Fatal(err)
		}
	}
	return root
}
