package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunPassesCompletePackageAndFileGates(t *testing.T) {
	t.Parallel()

	root := newRunFixture(t, 1)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run([]string{
		"-root", root,
		"-profile", "build/coverage.out",
		"-package", "80",
		"-changed", "0",
	}, &stdout, &stderr)
	if exitCode != 0 || stdout.String() != "launcher coverage gates passed\n" || stderr.Len() != 0 {
		t.Fatalf("run() = %d, stdout=%q stderr=%q", exitCode, stdout.String(), stderr.String())
	}
}

func TestRunFailsPackageAndMissingFileGates(t *testing.T) {
	t.Parallel()

	t.Run("undercovered package", func(t *testing.T) {
		t.Parallel()
		root := newRunFixture(t, 0)
		var stderr bytes.Buffer
		exitCode := run([]string{"-root", root, "-profile", "build/coverage.out", "-changed", "0"}, io.Discard, &stderr)
		if exitCode != 1 || !strings.Contains(stderr.String(), "coverage 0.00% is below 80.00%") {
			t.Fatalf("run() = %d, stderr=%q", exitCode, stderr.String())
		}
	})

	t.Run("missing executable file", func(t *testing.T) {
		t.Parallel()
		root := newRunFixture(t, 1)
		writeCoverageFixture(t, root, "apps/launcher/sample/omitted.go", `package sample

func Omitted() int {
	return 2
}
`)
		var stderr bytes.Buffer
		exitCode := run([]string{"-root", root, "-profile", "build/coverage.out", "-changed", "0"}, io.Discard, &stderr)
		if exitCode != 1 || !strings.Contains(stderr.String(), "coverage missing executable production file apps/launcher/sample/omitted.go") {
			t.Fatalf("run() = %d, stderr=%q", exitCode, stderr.String())
		}
	})
}

func TestRunValidatesInvocation(t *testing.T) {
	t.Parallel()

	tests := map[string][]string{
		"unknown flag":        {"-unknown"},
		"positional argument": {"unexpected"},
		"negative threshold":  {"-package", "-1"},
		"oversized threshold": {"-changed", "101"},
		"unsafe base":         {"-base", "--upload-pack=evil"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var stderr bytes.Buffer
			if exitCode := run(args, io.Discard, &stderr); exitCode != 2 {
				t.Fatalf("run() = %d, want 2; stderr=%q", exitCode, stderr.String())
			}
		})
	}
}

func TestRunReportsRuntimeInputFailures(t *testing.T) {
	t.Parallel()

	t.Run("missing repository", func(t *testing.T) {
		t.Parallel()
		var stderr bytes.Buffer
		exitCode := run([]string{"-root", filepath.Join(t.TempDir(), "missing"), "-changed", "0"}, io.Discard, &stderr)
		if exitCode != 1 || !strings.Contains(stderr.String(), "read root go.mod") {
			t.Fatalf("run() = %d, stderr=%q", exitCode, stderr.String())
		}
	})

	t.Run("invalid module", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		writeCoverageFixture(t, root, "go.mod", "go 1.26.5\n")
		var stderr bytes.Buffer
		exitCode := run([]string{"-root", root, "-changed", "0"}, io.Discard, &stderr)
		if exitCode != 1 || !strings.Contains(stderr.String(), "no module directive") {
			t.Fatalf("run() = %d, stderr=%q", exitCode, stderr.String())
		}
	})

	t.Run("missing profile", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		writeCoverageFixture(t, root, "go.mod", "module example.com/fixture\n")
		var stderr bytes.Buffer
		exitCode := run([]string{"-root", root, "-profile", "missing.out", "-changed", "0"}, io.Discard, &stderr)
		if exitCode != 1 || !strings.Contains(stderr.String(), "open coverage profile") {
			t.Fatalf("run() = %d, stderr=%q", exitCode, stderr.String())
		}
	})

	t.Run("missing launcher inventory", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		writeCoverageFixture(t, root, "go.mod", "module example.com/fixture\n")
		writeCoverageFixture(t, root, "coverage.out", "mode: atomic\n")
		var stderr bytes.Buffer
		exitCode := run([]string{"-root", root, "-profile", "coverage.out", "-changed", "0"}, io.Discard, &stderr)
		if exitCode != 1 || !strings.Contains(stderr.String(), "inspect launcher source") {
			t.Fatalf("run() = %d, stderr=%q", exitCode, stderr.String())
		}
	})
}

func TestRunEnforcesChangedStatementCoverageFromGit(t *testing.T) {
	root, baseCommit := newChangedGitFixture(t)

	writeChangedProfile(t, root, 0)
	var failed bytes.Buffer
	exitCode := run([]string{
		"-root", root,
		"-profile", "build/coverage.out",
		"-base", baseCommit,
		"-package", "0",
		"-changed", "80",
	}, io.Discard, &failed)
	if exitCode != 1 || !strings.Contains(failed.String(), "changed launcher coverage 0.00% is below 80.00%") {
		t.Fatalf("uncovered changed run = %d, stderr=%q", exitCode, failed.String())
	}

	writeChangedProfile(t, root, 1)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode = run([]string{
		"-root", root,
		"-profile", "build/coverage.out",
		"-base", baseCommit,
		"-package", "0",
		"-changed", "80",
	}, &stdout, &stderr)
	if exitCode != 0 || stderr.Len() != 0 {
		t.Fatalf("covered changed run = %d, stdout=%q stderr=%q", exitCode, stdout.String(), stderr.String())
	}
}

func TestRunReportsGitFailure(t *testing.T) {
	t.Parallel()

	root := newRunFixture(t, 1)
	var stderr bytes.Buffer
	exitCode := run([]string{
		"-root", root,
		"-profile", "build/coverage.out",
		"-base", "origin/main",
	}, io.Discard, &stderr)
	if exitCode != 1 || !strings.Contains(stderr.String(), "read changed launcher lines from Git") {
		t.Fatalf("run() = %d, stderr=%q", exitCode, stderr.String())
	}
}

func TestRunHandlesWriterFailures(t *testing.T) {
	t.Parallel()

	root := newRunFixture(t, 1)
	if exitCode := run([]string{"-root", root, "-profile", "build/coverage.out", "-changed", "0"}, failingWriter{}, io.Discard); exitCode != 1 {
		t.Fatalf("success-output writer failure exit = %d, want 1", exitCode)
	}
	if exitCode := run([]string{"unexpected"}, io.Discard, failingWriter{}); exitCode != 1 {
		t.Fatalf("invocation-output writer failure exit = %d, want 1", exitCode)
	}
}

func TestReadRootModulePath(t *testing.T) {
	t.Parallel()

	t.Run("quoted module", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		writeCoverageFixture(t, root, "go.mod", "module \"example.com/fixture\"\n")
		modulePath, err := readRootModulePath(root)
		if err != nil || modulePath != "example.com/fixture" {
			t.Fatalf("readRootModulePath() = %q, %v", modulePath, err)
		}
	})

	for _, modulePath := range []string{"", "../escape", "/absolute"} {
		modulePath := modulePath
		t.Run(fmt.Sprintf("invalid_%q", modulePath), func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeCoverageFixture(t, root, "go.mod", "module \""+modulePath+"\"\n")
			if _, err := readRootModulePath(root); err == nil {
				t.Fatal("readRootModulePath() error = nil")
			}
		})
	}
}

func TestReadProfileSizeAndPathRules(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	profilePath := filepath.Join(root, "coverage.out")
	writeCoverageFixture(t, root, "coverage.out", "mode: atomic\nfile.go:1.1,1.2 1 1\n")
	if _, err := readProfileWithLimit(root, profilePath, "example.com/module", 1024); err != nil {
		t.Fatalf("readProfileWithLimit() error = %v", err)
	}
	if _, err := readProfileWithLimit(root, profilePath, "example.com/module", 8); err == nil || !strings.Contains(err.Error(), "exceeds 8 bytes") {
		t.Fatalf("oversized profile error = %v", err)
	}
	if _, err := readProfileWithLimit(root, profilePath, "example.com/module", 0); err == nil {
		t.Fatal("zero profile limit error = nil")
	}
}

func TestMaximumProfileSizeSupportsFullAtomicCoverpkgMatrix(t *testing.T) {
	t.Parallel()

	const requiredHeadroom = 512 << 20
	if maximumProfileBytes < requiredHeadroom {
		t.Fatalf("maximumProfileBytes = %d, want at least %d", maximumProfileBytes, requiredHeadroom)
	}
	if maximumProfileBytes > 1<<30 {
		t.Fatalf("maximumProfileBytes = %d, want a bounded limit no larger than 1 GiB", maximumProfileBytes)
	}
}

func TestPathEscapesRoot(t *testing.T) {
	t.Parallel()

	tests := map[string]bool{
		"example.com/module": false,
		"../escape":          true,
		"/absolute":          true,
		".":                  true,
	}
	for value, expected := range tests {
		if actual := pathEscapesRoot(value); actual != expected {
			t.Errorf("pathEscapesRoot(%q) = %t, want %t", value, actual, expected)
		}
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("injected writer failure") }

func newRunFixture(t *testing.T, count uint64) string {
	t.Helper()
	root := t.TempDir()
	writeCoverageFixture(t, root, "go.mod", "module example.com/fixture\n\ngo 1.26.5\n")
	writeCoverageFixture(t, root, "apps/launcher/sample/code.go", `package sample

func Execute() int {
	return 1
}
`)
	profile := fmt.Sprintf(`mode: atomic
example.com/fixture/apps/launcher/sample/code.go:3.1,5.2 1 %d
`, count)
	writeCoverageFixture(t, root, "build/coverage.out", profile)
	return root
}

func newChangedGitFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	writeCoverageFixture(t, root, "go.mod", "module example.com/fixture\n\ngo 1.26.5\n")
	writeCoverageFixture(t, root, "apps/launcher/sample/code.go", `package sample

func Existing() int {
	return 1
}
`)
	runGit(t, root, "init", "--initial-branch=main")
	runGit(t, root, "config", "user.name", "Coverage Test")
	runGit(t, root, "config", "user.email", "coverage@example.invalid")
	runGit(t, root, "add", "go.mod", "apps/launcher/sample/code.go")
	runGit(t, root, "commit", "-m", "base")
	baseCommit := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))
	writeCoverageFixture(t, root, "apps/launcher/sample/code.go", `package sample

func Existing() int {
	return 1
}

func Changed() int {
	return 2
}
`)
	runGit(t, root, "add", "apps/launcher/sample/code.go")
	runGit(t, root, "commit", "-m", "change")
	return root, baseCommit
}

func writeChangedProfile(t *testing.T, root string, changedCount uint64) {
	t.Helper()
	profile := fmt.Sprintf(`mode: atomic
example.com/fixture/apps/launcher/sample/code.go:3.1,5.2 1 1
example.com/fixture/apps/launcher/sample/code.go:7.1,9.2 1 %d
`, changedCount)
	writeCoverageFixture(t, root, "build/coverage.out", profile)
}

func runGit(t *testing.T, directory string, arguments ...string) string {
	t.Helper()
	//nolint:gosec // G204: executable is fixed and arguments are test-owned constants/temporary paths; owner=quality, expiry=2027-07-13.
	command := exec.CommandContext(context.Background(), "git", arguments...)
	command.Dir = directory
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", arguments, err, output)
	}
	return string(output)
}
