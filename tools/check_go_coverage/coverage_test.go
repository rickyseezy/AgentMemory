package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseProfileAggregatesStatementBlocksByFileAndPackage(t *testing.T) {
	t.Parallel()

	profile, err := parseProfile(strings.NewReader(`mode: atomic
github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install/phase.go:10.1,20.2 8 1
github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install/phase.go:22.1,24.2 2 0
github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp/application.go:10.1,15.2 5 2
`), "github.com/rickyseezy/AgentMemory")
	if err != nil {
		t.Fatalf("parseProfile() error = %v", err)
	}
	if len(profile.Blocks) != 3 {
		t.Fatalf("blocks = %d, want 3", len(profile.Blocks))
	}
	if got := profile.Blocks[0].File; got != "apps/launcher/internal/domain/install/phase.go" {
		t.Fatalf("first file = %q", got)
	}
	if !profile.Blocks[0].Covered() || profile.Blocks[1].Covered() {
		t.Fatal("covered state was not derived from execution count")
	}
}

func TestParseProfileCoalescesCrossPackageCoverageBlocks(t *testing.T) {
	t.Parallel()

	profile, err := parseProfile(strings.NewReader(`mode: atomic
example.com/module/apps/launcher/a/a.go:1.1,2.2 3 0
example.com/module/apps/launcher/a/a.go:1.1,2.2 3 7
example.com/module/apps/launcher/a/a.go:3.1,4.2 2 0
`), "example.com/module")
	if err != nil {
		t.Fatal(err)
	}
	if len(profile.Blocks) != 2 || !profile.Blocks[0].Covered() || profile.Blocks[0].Count != 1 {
		t.Fatalf("coalesced profile=%+v", profile.Blocks)
	}
	result := evaluatePackages(profile, map[string]struct{}{"apps/launcher/a": {}}, 50)
	if len(result) != 1 || result[0].Statements != 5 || result[0].Covered != 3 || !result[0].Passed {
		t.Fatalf("coalesced package result=%+v", result)
	}
	if _, err := parseProfile(strings.NewReader(`mode: atomic
example.com/module/apps/launcher/a/a.go:1.1,2.2 3 0
example.com/module/apps/launcher/a/a.go:1.1,2.2 4 1
`), "example.com/module"); err == nil {
		t.Fatal("duplicate block with changed statement count was accepted")
	}
}

func TestParseProfileRejectsMalformedOrUnsafeInput(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"empty profile":           "",
		"missing mode":            "file.go:1.1,2.1 1 1\n",
		"unsupported mode":        "mode: unknown\nfile.go:1.1,2.1 1 1\n",
		"empty block line":        "mode: atomic\n\n",
		"malformed block":         "mode: atomic\nnot-a-block\n",
		"malformed location":      "mode: atomic\n:1.1,2.1 1 1\n",
		"unsafe path":             "mode: atomic\n/absolute.go:1.1,2.1 1 1\n",
		"malformed span":          "mode: atomic\nfile.go:1.1 1 1\n",
		"malformed start":         "mode: atomic\nfile.go:start,2.1 1 1\n",
		"malformed end":           "mode: atomic\nfile.go:1.1,end 1 1\n",
		"zero position":           "mode: atomic\nfile.go:0.1,2.1 1 1\n",
		"invalid statements":      "mode: atomic\nfile.go:1.1,2.1 many 1\n",
		"invalid execution count": "mode: atomic\nfile.go:1.1,2.1 1 many\n",
		"backwards line span":     "mode: atomic\nfile.go:3.1,2.1 1 1\n",
		"backwards column span":   "mode: atomic\nfile.go:2.4,2.3 1 1\n",
	}
	for name, input := range tests {
		name := name
		input := input
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseProfile(strings.NewReader(input), "example.com/module"); err == nil {
				t.Fatal("parseProfile() error = nil")
			}
		})
	}
}

func TestZeroStatementCoverageBlocksAreAcceptedAndIgnored(t *testing.T) {
	t.Parallel()

	profile, err := parseProfile(strings.NewReader("mode: atomic\napps/launcher/a/a.go:1.1,1.1 0 7\n"), "example.com/module")
	if err != nil {
		t.Fatalf("parseProfile() error = %v", err)
	}
	results := evaluatePackages(profile, map[string]struct{}{"apps/launcher/a": {}}, 80)
	if len(results) != 1 || !results[0].Missing || results[0].Statements != 0 {
		t.Fatalf("package results = %+v", results)
	}
	if missing := missingProfileFiles(profile, map[string]struct{}{"apps/launcher/a/a.go": {}}); len(missing) != 1 {
		t.Fatalf("missing files = %v", missing)
	}
	changed := evaluateChanged(profile, changedLines{"apps/launcher/a/a.go": {{Start: 1, End: 1}}}, 90)
	if !changed.Passed || changed.Statements != 0 {
		t.Fatalf("changed result = %+v", changed)
	}
}

func TestProfileAndDiffReadersPropagateReadFailure(t *testing.T) {
	t.Parallel()

	injected := errors.New("injected read failure")
	if _, err := parseProfile(failingReader{err: injected}, "example.com/module"); !errors.Is(err, injected) {
		t.Fatalf("parseProfile() error = %v", err)
	}
	if _, err := parseChangedLines(failingReader{err: injected}); !errors.Is(err, injected) {
		t.Fatalf("parseChangedLines() error = %v", err)
	}
}

func TestEvaluatePackageThresholdReportsEveryUndercoveredPackage(t *testing.T) {
	t.Parallel()

	profile := coverageProfile{Blocks: []coverageBlock{
		{File: "apps/launcher/a/a.go", StartLine: 1, EndLine: 2, Statements: 8, Count: 1},
		{File: "apps/launcher/a/a.go", StartLine: 3, EndLine: 4, Statements: 2, Count: 0},
		{File: "apps/launcher/b/b.go", StartLine: 1, EndLine: 4, Statements: 10, Count: 0},
		{File: "tools/not-launcher.go", StartLine: 1, EndLine: 2, Statements: 100, Count: 1},
		{File: "apps/launcher/unexpected/code.go", StartLine: 1, EndLine: 2, Statements: 100, Count: 1},
	}}
	expected := map[string]struct{}{
		"apps/launcher/a": {},
		"apps/launcher/b": {},
		"apps/launcher/c": {},
	}

	results := evaluatePackages(profile, expected, 80)
	if len(results) != 3 {
		t.Fatalf("results = %d, want 3", len(results))
	}
	assertPackageResult(t, results[0], "apps/launcher/a", 80, true)
	assertPackageResult(t, results[1], "apps/launcher/b", 0, false)
	if results[2].Package != "apps/launcher/c" || !results[2].Missing {
		t.Fatalf("missing result = %+v", results[2])
	}
}

func TestEvaluateChangedWithNoExecutableIntersectionPasses(t *testing.T) {
	t.Parallel()

	result := evaluateChanged(
		coverageProfile{Blocks: []coverageBlock{{File: "apps/launcher/a.go", StartLine: 1, EndLine: 2, Statements: 1, Count: 0}}},
		changedLines{"apps/launcher/a.go": {{Start: 10, End: 12}}},
		90,
	)
	if !result.Passed || result.Percent != 100 || result.Statements != 0 {
		t.Fatalf("changed result = %+v", result)
	}
}

func TestParseChangedLinesAndEvaluateChangedThreshold(t *testing.T) {
	t.Parallel()

	changed, err := parseChangedLines(strings.NewReader(`diff --git a/apps/launcher/a/a.go b/apps/launcher/a/a.go
--- a/apps/launcher/a/a.go
+++ b/apps/launcher/a/a.go
@@ -10,2 +10,3 @@
+one
+two
+three
diff --git a/apps/launcher/b/b.go b/apps/launcher/b/b.go
--- /dev/null
+++ b/apps/launcher/b/b.go
@@ -0,0 +1,2 @@
+one
+two
`))
	if err != nil {
		t.Fatalf("parseChangedLines() error = %v", err)
	}
	if !changed.Contains("apps/launcher/a/a.go", 10) || !changed.Contains("apps/launcher/a/a.go", 12) {
		t.Fatal("first hunk lines were not recorded")
	}
	if changed.Contains("apps/launcher/a/a.go", 13) {
		t.Fatal("line outside hunk was recorded")
	}

	profile := coverageProfile{Blocks: []coverageBlock{
		{File: "apps/launcher/a/a.go", StartLine: 9, EndLine: 10, Statements: 2, Count: 1},
		{File: "apps/launcher/a/a.go", StartLine: 11, EndLine: 12, Statements: 3, Count: 0},
		{File: "apps/launcher/b/b.go", StartLine: 1, EndLine: 2, Statements: 5, Count: 1},
	}}
	result := evaluateChanged(profile, changed, 90)
	if result.Statements != 10 || result.Covered != 7 || result.Percent != 70 || result.Passed {
		t.Fatalf("changed result = %+v, want 7/10 (70%%) failure", result)
	}
}

func TestParseChangedLinesRejectsMalformedHunk(t *testing.T) {
	t.Parallel()

	_, err := parseChangedLines(strings.NewReader("+++ b/apps/launcher/a/a.go\n@@ malformed @@\n"))
	if err == nil {
		t.Fatal("parseChangedLines() error = nil")
	}
}

func TestParseChangedLinesAcceptsBoundedGeneratedAssetLine(t *testing.T) {
	t.Parallel()

	input := "+++ b/apps/launcher/generated.go\n@@ -0,0 +1 @@\n+" +
		strings.Repeat("x", 128<<10) + "\n"
	changed, err := parseChangedLines(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseChangedLines() error = %v", err)
	}
	if !changed.Contains("apps/launcher/generated.go", 1) {
		t.Fatal("generated source line was not recorded")
	}
}

func TestParseChangedLinesHandlesDeletionAndZeroLengthHunks(t *testing.T) {
	t.Parallel()

	changed, err := parseChangedLines(strings.NewReader(`diff --git a/apps/launcher/deleted.go b/apps/launcher/deleted.go
--- a/apps/launcher/deleted.go
+++ /dev/null
@@ -1,2 +0,0 @@
diff --git a/apps/launcher/kept.go b/apps/launcher/kept.go
--- a/apps/launcher/kept.go
+++ b/apps/launcher/kept.go
@@ -3,0 +4,0 @@
`))
	if err != nil {
		t.Fatalf("parseChangedLines() error = %v", err)
	}
	if len(changed) != 0 {
		t.Fatalf("changed lines = %v, want none", changed)
	}
}

func TestParseChangedLinesRejectsUnsafeAndOverflowingInput(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"unsafe target":       "+++ b/../../escape.go\n",
		"hunk without target": "@@ -1 +1 @@\n",
		"invalid start":       "+++ b/file.go\n@@ -1 +18446744073709551616 @@\n",
		"invalid length":      "+++ b/file.go\n@@ -1 +1,18446744073709551616 @@\n",
		"zero start":          "+++ b/file.go\n@@ -1 +0,1 @@\n",
		"overflowing range":   "+++ b/file.go\n@@ -1 +18446744073709551615,2 @@\n",
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseChangedLines(strings.NewReader(input)); err == nil {
				t.Fatal("parseChangedLines() error = nil")
			}
		})
	}
}

func TestDiscoverSourceInventoryIncludesOnlyExecutableProductionFiles(t *testing.T) {
	t.Parallel()

	repository := t.TempDir()
	writeCoverageFixture(t, repository, "apps/launcher/withcode/code.go", `package withcode

func Execute() int {
	return 1
}
`)
	writeCoverageFixture(t, repository, "apps/launcher/withcode/code_test.go", `package withcode

func testOnly() { panic("not production") }
`)
	writeCoverageFixture(t, repository, "apps/launcher/constants/constants.go", `package constants

const Name = "agentmemory"
`)
	writeCoverageFixture(t, repository, "apps/launcher/empty/empty.go", `package empty

func Empty() {}
`)
	writeCoverageFixture(t, repository, "apps/launcher/ignored/_ignored.go", "this is deliberately not Go")
	writeCoverageFixture(t, repository, "apps/launcher/ignored/tagged.go", "//go:build ignore\n\nthis is deliberately not Go")
	writeCoverageFixture(t, repository, "apps/launcher/vendor/ignored.go", "this is deliberately not Go")
	writeCoverageFixture(t, repository, "apps/launcher/.hidden/ignored.go", "this is deliberately not Go")

	inventory, err := discoverSourceInventory(repository)
	if err != nil {
		t.Fatalf("discoverSourceInventory() error = %v", err)
	}
	if _, found := inventory.Packages["apps/launcher/withcode"]; !found {
		t.Fatal("executable production package was not discovered")
	}
	if _, found := inventory.Packages["apps/launcher/constants"]; found {
		t.Fatal("statement-free package must not create an impossible coverage gate")
	}
	if _, found := inventory.Packages["apps/launcher/empty"]; found {
		t.Fatal("empty-function package must not create an impossible coverage gate")
	}
	if _, found := inventory.Files["apps/launcher/withcode/code.go"]; !found {
		t.Fatal("executable production file was not discovered")
	}
	if _, found := inventory.Files["apps/launcher/withcode/code_test.go"]; found {
		t.Fatal("test file was included in production inventory")
	}
}

func TestDiscoverSourceInventoryRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	t.Run("launcher path is a file", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		writeCoverageFixture(t, root, "apps/launcher", "not a directory")
		if _, err := discoverSourceInventory(root); err == nil {
			t.Fatal("discoverSourceInventory() error = nil")
		}
	})

	t.Run("active source has invalid syntax", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		writeCoverageFixture(t, root, "apps/launcher/broken/broken.go", "package broken\nfunc Broken(")
		if _, err := discoverSourceInventory(root); err == nil {
			t.Fatal("discoverSourceInventory() error = nil")
		}
	})

	t.Run("malformed build constraint", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		writeCoverageFixture(t, root, "apps/launcher/broken/tag.go", "//go:build (\n\npackage broken")
		if _, err := discoverSourceInventory(root); err == nil {
			t.Fatal("discoverSourceInventory() error = nil")
		}
	})

	t.Run("source symlink", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "target.go")
		if err := os.WriteFile(target, []byte("package sample\nfunc Run() {}"), 0o600); err != nil {
			t.Fatalf("write target: %v", err)
		}
		directory := filepath.Join(root, "apps", "launcher", "sample")
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatalf("create source directory: %v", err)
		}
		if err := os.Symlink(target, filepath.Join(directory, "linked.go")); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		if _, err := discoverSourceInventory(root); err == nil {
			t.Fatal("discoverSourceInventory() error = nil")
		}
	})
}

type failingReader struct {
	err error
}

func (reader failingReader) Read([]byte) (int, error) { return 0, reader.err }

var _ io.Reader = failingReader{}

func TestMissingProfileFilesReportsOmittedProductionCode(t *testing.T) {
	t.Parallel()

	profile := coverageProfile{Blocks: []coverageBlock{{
		File:       "apps/launcher/a/covered.go",
		StartLine:  1,
		EndLine:    2,
		Statements: 1,
		Count:      1,
	}}}
	expected := map[string]struct{}{
		"apps/launcher/a/covered.go": {},
		"apps/launcher/a/omitted.go": {},
	}
	missing := missingProfileFiles(profile, expected)
	if len(missing) != 1 || missing[0] != "apps/launcher/a/omitted.go" {
		t.Fatalf("missing files = %v", missing)
	}
}

func assertPackageResult(t *testing.T, result packageCoverage, name string, percent float64, passed bool) {
	t.Helper()
	if result.Package != name || result.Percent != percent || result.Passed != passed {
		t.Fatalf("package result = %+v, want package=%s percent=%.1f passed=%t", result, name, percent, passed)
	}
}

func writeCoverageFixture(t *testing.T, root string, relativePath string, contents string) {
	t.Helper()
	file := filepath.Join(root, filepath.FromSlash(relativePath))
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	if err := os.WriteFile(file, []byte(contents), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}
