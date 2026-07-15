package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRepositoryLinuxPackageContract(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	if violations := Check(Options{RepositoryRoot: root}); len(violations) != 0 {
		t.Fatalf("Check() violations = %v, want none", violations)
	}
}

func TestValidatePolicyRejectsBroaderAuthorization(t *testing.T) {
	content := readRepositoryFile(t, policyPath)
	for name, mutation := range map[string]func(string) string{
		"unbound helper": func(value string) string {
			return strings.Replace(value, helperPath, "/usr/bin/env", 1)
		},
		"retained authorization": func(value string) string {
			return strings.Replace(value, "<allow_active>auth_admin</allow_active>", "<allow_active>auth_admin_keep</allow_active>", 1)
		},
		"extra action": func(value string) string {
			return strings.Replace(value, "</policyconfig>", "<action id=\"unexpected\"/></policyconfig>", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validatePolicy([]byte(mutation(string(content)))); err == nil {
				t.Fatal("validatePolicy() error = nil, want rejection")
			}
		})
	}
}

func TestValidatePackageConfigRejectsBundleModeFlattening(t *testing.T) {
	content := readRepositoryFile(t, packageConfigPath)
	mutated := strings.Replace(string(content), "    type: tree\n    expand: true\n", "    type: tree\n    expand: true\n    file_info:\n      mode: 0644\n      owner: root\n      group: root\n", 1)
	if err := validatePackageConfig([]byte(mutated)); err == nil {
		t.Fatal("validatePackageConfig() error = nil, want rejection")
	}
}

func TestValidatePackageConfigRejectsUnknownField(t *testing.T) {
	content := append(readRepositoryFile(t, packageConfigPath), []byte("unexpected: true\n")...)
	if err := validatePackageConfig(content); err == nil {
		t.Fatal("validatePackageConfig() error = nil, want rejection")
	}
}

func TestValidatePackageConfigRejectsEveryClosedContractSubstitution(t *testing.T) {
	content := string(readRepositoryFile(t, packageConfigPath))
	mutations := map[string][2]string{
		"identity":   {"name: agentmemory", "name: other"},
		"maintainer": {"maintainer: AgentMemory Authors <rickyseezy@users.noreply.github.com>", "maintainer: \"\""},
		"umask":      {"umask: 0o022", "umask: 0o077"},
		"script":     {"postinstall: packaging/linux/scripts/postinstall.sh", "postinstall: unexpected.sh"},
		"rpm":        {"compression: zstd:19", "compression: gzip"},
		"deb":        {"compression: xz", "compression: gzip"},
		"dependency": {"      - pkexec", "      - sudo"},
		"payload":    {"dst: /usr/bin/agentmemory", "dst: /usr/bin/other"},
	}
	for name, replacement := range mutations {
		t.Run(name, func(t *testing.T) {
			mutated := strings.Replace(content, replacement[0], replacement[1], 1)
			if mutated == content {
				t.Fatalf("mutation %q did not apply", name)
			}
			if err := validatePackageConfig([]byte(mutated)); err == nil {
				t.Fatal("validatePackageConfig() error = nil, want rejection")
			}
		})
	}
}

func TestValidateTmpfilesRejectsBroaderWritableState(t *testing.T) {
	content := readRepositoryFile(t, tmpfilesPath)
	mutated := bytes.Replace(content, []byte("0755 root root"), []byte("0777 root root"), 1)
	if err := validateTmpfiles(mutated); err == nil {
		t.Fatal("validateTmpfiles() error = nil, want rejection")
	}
}

func TestCheckRejectsSymlinkAndNonExecutableScript(t *testing.T) {
	root := copyPackageFixture(t)
	postinstall := filepath.Join(root, filepath.FromSlash(postinstallPath))
	if err := os.Remove(postinstall); err != nil {
		t.Fatalf("remove postinstall: %v", err)
	}
	if err := os.Symlink("preremove.sh", postinstall); err != nil {
		t.Fatalf("symlink postinstall: %v", err)
	}
	if err := os.Chmod(filepath.Join(root, filepath.FromSlash(preremovePath)), 0o600); err != nil {
		t.Fatalf("chmod preremove: %v", err)
	}

	violations := Check(Options{RepositoryRoot: root})
	if len(violations) != 2 ||
		!strings.Contains(violations[0].Error()+violations[1].Error(), "must be a regular file") ||
		!strings.Contains(violations[0].Error()+violations[1].Error(), "mode is 0600") {
		t.Fatalf("Check() violations = %v, want symlink and mode violations", violations)
	}
}

func TestRunReportsViolationsAndInvalidInvocation(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := run([]string{"-root", t.TempDir()}, &stdout, &stderr); code != 1 {
		t.Fatalf("run(missing) = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "Linux package check failed") {
		t.Fatalf("run(missing) stderr = %q", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"unexpected"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run(positional) = %d, want 2", code)
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"-unknown"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run(flag error) = %d, want 2", code)
	}

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"-root", root}, &stdout, &stderr); code != 0 ||
		stdout.String() != "Linux package check passed\n" || stderr.Len() != 0 {
		t.Fatalf("run(valid) = %d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func readRepositoryFile(t *testing.T, relative string) []byte {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	// #nosec G304 -- the test helper accepts only package paths declared by this test file.
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	return content
}

func copyPackageFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, relative := range []string{packageConfigPath, policyPath, tmpfilesPath, postinstallPath, preremovePath} {
		content := readRepositoryFile(t, relative)
		target := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatalf("mkdir fixture: %v", err)
		}
		mode := os.FileMode(0o644)
		if relative == postinstallPath || relative == preremovePath {
			mode = 0o755
		}
		if err := os.WriteFile(target, content, mode); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
	}
	return root
}
