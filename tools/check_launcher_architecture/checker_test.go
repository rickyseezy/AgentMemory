package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckAllowsDomainStandardLibraryAndDomainImports(t *testing.T) {
	repository := newFixture(t)
	writeGoFile(t, repository, "apps/launcher/internal/domain/install/operation.go", `package install

import (
	"fmt"
	"time"
	"example.com/agentmemory/apps/launcher/internal/domain/value"
)
`)

	violations, err := Check(Options{RepositoryRoot: repository})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("Check() violations = %v, want none", violations)
	}
}

func TestCheckRejectsDomainDependenciesOutsideItsLayer(t *testing.T) {
	repository := newFixture(t)
	writeGoFile(t, repository, "apps/launcher/internal/domain/install/operation.go", `package install

import (
	"example.com/agentmemory/apps/launcher/internal/application/install"
	"example.com/agentmemory/apps/launcher/internal/adapters/filesystem"
	"github.com/google/uuid"
)
`)

	violations, err := Check(Options{RepositoryRoot: repository})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	assertImportViolations(t, violations, map[string]string{
		"example.com/agentmemory/apps/launcher/internal/application/install": "domain-dependency",
		"example.com/agentmemory/apps/launcher/internal/adapters/filesystem": "inward-adapter",
		"github.com/google/uuid": "domain-dependency",
	})
}

func TestCheckRejectsForbiddenApplicationDependencies(t *testing.T) {
	repository := newFixture(t)
	writeGoFile(t, repository, "apps/launcher/internal/application/install/install.go", `package install

import (
	"io/fs"
	"net"
	"os/exec"
	"net/http/httptest"
	"path/filepath"
	"syscall"
	"unsafe"
	"github.com/docker/docker/client"
	"example.com/agentmemory/apps/launcher/internal/adapters/dockercli"
	"example.com/agentmemory/apps/launcher/internal/infrastructure/configuration"
)
`)

	violations, err := Check(Options{RepositoryRoot: repository})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	assertImportViolations(t, violations, map[string]string{
		"io/fs":                           "forbidden-import",
		"net":                             "forbidden-import",
		"os/exec":                         "forbidden-import",
		"net/http/httptest":               "forbidden-import",
		"path/filepath":                   "forbidden-import",
		"syscall":                         "forbidden-import",
		"unsafe":                          "forbidden-import",
		"github.com/docker/docker/client": "docker-sdk",
		"example.com/agentmemory/apps/launcher/internal/adapters/dockercli":           "inward-adapter",
		"example.com/agentmemory/apps/launcher/internal/infrastructure/configuration": "inward-infrastructure",
	})
}

func TestCheckRejectsUnreviewedStandardLibraryCapabilities(t *testing.T) {
	repository := newFixture(t)
	writeGoFile(t, repository, "apps/launcher/internal/application/install/install.go", `package install

import (
	"crypto/rand"
	"database/sql"
	"io/ioutil"
	"runtime"
)
`)

	violations, err := Check(Options{RepositoryRoot: repository})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	assertImportViolations(t, violations, map[string]string{
		"crypto/rand":  "inward-stdlib-capability",
		"database/sql": "inward-stdlib-capability",
		"io/ioutil":    "inward-stdlib-capability",
		"runtime":      "inward-stdlib-capability",
	})
}

func TestAllowedInwardStandardLibraryIsExplicit(t *testing.T) {
	t.Parallel()
	for _, importPath := range []string{"context", "crypto/sha256", "encoding/json", "errors", "fmt", "io", "testing", "time"} {
		if !isAllowedInwardStandardLibrary(importPath) {
			t.Errorf("reviewed import %q was rejected", importPath)
		}
	}
	for _, importPath := range []string{"", "crypto/rand", "database/sql", "io/fs", "io/ioutil", "os", "runtime"} {
		if isAllowedInwardStandardLibrary(importPath) {
			t.Errorf("capability import %q was accepted", importPath)
		}
	}
}

func TestCheckAllowsApplicationInwardDependencies(t *testing.T) {
	repository := newFixture(t)
	writeGoFile(t, repository, "apps/launcher/internal/application/install/install.go", `package install

import (
	"context"
	"example.com/agentmemory/apps/launcher/internal/application/ports"
	"example.com/agentmemory/apps/launcher/internal/contracts"
	"example.com/agentmemory/apps/launcher/internal/domain/install"
)
`)

	violations, err := Check(Options{RepositoryRoot: repository})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("Check() violations = %v, want none", violations)
	}
}

func TestCheckUsesLauncherModuleDirectiveForLayerClassification(t *testing.T) {
	repository := newFixture(t)
	writeGoFile(t, repository, "apps/launcher/go.mod", "module example.com/launcher\n\ngo 1.26\n")
	writeGoFile(t, repository, "apps/launcher/internal/application/install/install.go", `package install

import "example.com/launcher/internal/adapters/dockercli"
`)

	violations, err := Check(Options{RepositoryRoot: repository})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	assertImportViolations(t, violations, map[string]string{
		"example.com/launcher/internal/adapters/dockercli": "inward-adapter",
	})
}

func TestCheckRejectsApplicationExternalDependency(t *testing.T) {
	repository := newFixture(t)
	writeGoFile(t, repository, "apps/launcher/internal/application/install/install.go", `package install

import "github.com/google/uuid"
`)

	violations, err := Check(Options{RepositoryRoot: repository})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	assertImportViolations(t, violations, map[string]string{
		"github.com/google/uuid": "application-dependency",
	})
}

func TestCheckAppliesForbiddenImportRulesToDomain(t *testing.T) {
	repository := newFixture(t)
	writeGoFile(t, repository, "apps/launcher/internal/domain/install/operation.go", `package install

import "net/http"
`)

	violations, err := Check(Options{RepositoryRoot: repository})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	assertImportViolations(t, violations, map[string]string{"net/http": "forbidden-import"})
}

func TestCheckIgnoresTestFilesByDefaultAndCanCheckThemExplicitly(t *testing.T) {
	repository := newFixture(t)
	writeGoFile(t, repository, "apps/launcher/internal/application/install/install_test.go", `package install

import "os/exec"
`)

	violations, err := Check(Options{RepositoryRoot: repository})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("default Check() violations = %v, want none", violations)
	}

	violations, err = Check(Options{RepositoryRoot: repository, IncludeTests: true})
	if err != nil {
		t.Fatalf("Check(IncludeTests) error = %v", err)
	}
	assertImportViolations(t, violations, map[string]string{"os/exec": "forbidden-import"})
}

func TestRunPrintsActionableDiagnosticsAndReturnsNonzero(t *testing.T) {
	repository := newFixture(t)
	writeGoFile(t, repository, "apps/launcher/internal/application/install/install.go", `package install

import "os/exec"
`)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run([]string{"-root", repository}, &stdout, &stderr)
	if exitCode != 1 {
		t.Fatalf("run() exit code = %d, want 1", exitCode)
	}
	if stdout.Len() != 0 {
		t.Fatalf("run() stdout = %q, want empty", stdout.String())
	}
	wantParts := []string{
		"apps/launcher/internal/application/install/install.go:3:",
		"application",
		`imports "os/exec"`,
		"forbidden-import",
	}
	for _, part := range wantParts {
		if !strings.Contains(stderr.String(), part) {
			t.Errorf("run() stderr = %q, want substring %q", stderr.String(), part)
		}
	}
}

func TestRunReturnsTwoForInvalidInvocation(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run([]string{"-unknown"}, &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("run() exit code = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("run() stderr = %q, want flag parsing diagnostic", stderr.String())
	}
}

func TestRunReturnsTwoForUnexpectedPositionalArgument(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run([]string{"unexpected"}, &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("run() exit code = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "unexpected positional arguments") {
		t.Fatalf("run() stderr = %q, want positional argument diagnostic", stderr.String())
	}
}

func TestRunReportsSuccessfulCheck(t *testing.T) {
	repository := newFixture(t)
	writeGoFile(t, repository, "apps/launcher/internal/domain/install/operation.go", "package install\n")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run([]string{"-root", repository}, &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if stdout.String() != "launcher architecture check passed\n" {
		t.Fatalf("run() stdout = %q, want success message", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("run() stderr = %q, want empty", stderr.String())
	}
}

func TestRunReportsScannerFailure(t *testing.T) {
	repository := t.TempDir()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run([]string{"-root", repository}, &stdout, &stderr)
	if exitCode != 1 {
		t.Fatalf("run() exit code = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr.String(), "inspect launcher path") {
		t.Fatalf("run() stderr = %q, want launcher path diagnostic", stderr.String())
	}
}

func TestCheckReportsMalformedGoFileWithItsPath(t *testing.T) {
	repository := newFixture(t)
	writeGoFile(t, repository, "apps/launcher/internal/domain/install/broken.go", "package install\nimport (\n")

	_, err := Check(Options{RepositoryRoot: repository})
	if err == nil {
		t.Fatal("Check() error = nil, want parse error")
	}
	if !strings.Contains(err.Error(), "apps/launcher/internal/domain/install/broken.go") {
		t.Fatalf("Check() error = %q, want repository-relative file path", err)
	}
}

func TestCheckValidatesLauncherPathAndModule(t *testing.T) {
	t.Run("launcher path is a file", func(t *testing.T) {
		repository := t.TempDir()
		writeGoFile(t, repository, "launcher.go", "package launcher\n")
		_, err := Check(Options{RepositoryRoot: repository, LauncherPath: "launcher.go"})
		if err == nil || !strings.Contains(err.Error(), "is not a directory") {
			t.Fatalf("Check() error = %v, want not-a-directory diagnostic", err)
		}
	})

	t.Run("module directive is missing", func(t *testing.T) {
		repository := newFixture(t)
		writeGoFile(t, repository, "apps/launcher/go.mod", "go 1.26\n")
		_, err := Check(Options{RepositoryRoot: repository})
		if err == nil || !strings.Contains(err.Error(), "missing module directive") {
			t.Fatalf("Check() error = %v, want module diagnostic", err)
		}
	})

	t.Run("absolute custom launcher path", func(t *testing.T) {
		repository := t.TempDir()
		launcher := filepath.Join(repository, "custom-launcher")
		writeGoFile(t, launcher, "internal/domain/value/value.go", "package value\n")
		violations, err := Check(Options{RepositoryRoot: repository, LauncherPath: launcher})
		if err != nil {
			t.Fatalf("Check() error = %v", err)
		}
		if len(violations) != 0 {
			t.Fatalf("Check() violations = %v, want none", violations)
		}
	})
}

func TestCheckSkipsTestsOuterLayersAndIgnoredDirectories(t *testing.T) {
	repository := newFixture(t)
	writeGoFile(t, repository, "apps/launcher/internal/adapters/dockercli/client.go", "package dockercli\nimport \"os/exec\"\n")
	writeGoFile(t, repository, "apps/launcher/cmd/agentmemory/main.go", "package main\nimport \"net/http\"\n")
	writeGoFile(t, repository, "apps/launcher/vendor/broken.go", "not go")
	writeGoFile(t, repository, "apps/launcher/.generated/broken.go", "not go")

	violations, err := Check(Options{RepositoryRoot: repository})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("Check() violations = %v, want none", violations)
	}
}

func TestLayerAndPathHelpersHandleUnknownAndExternalPaths(t *testing.T) {
	if got := sourceLayerForFile("/launcher", "/other/file.go"); got != layerUnknown {
		t.Fatalf("sourceLayerForFile() = %q, want unknown", got)
	}
	if got := sourceLayerForFile("/launcher", "/launcher/main.go"); got != layerUnknown {
		t.Fatalf("sourceLayerForFile(root file) = %q, want unknown", got)
	}
	if got := importedLauncherLayer("example.com/external/pkg", "example.com/launcher"); got != layerUnknown {
		t.Fatalf("importedLauncherLayer() = %q, want unknown", got)
	}
	if got := parseLayer("other"); got != layerUnknown {
		t.Fatalf("parseLayer() = %q, want unknown", got)
	}
	if isStandardLibrary("") || isStandardLibrary("C") {
		t.Fatal("empty and C imports must not be classified as standard library")
	}
	outside := displayPath("/repository", "/elsewhere/file.go")
	if outside != "/elsewhere/file.go" {
		t.Fatalf("displayPath() = %q, want absolute outside path", outside)
	}
}

func newFixture(t *testing.T) string {
	t.Helper()
	repository := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repository, "apps", "launcher"), 0o700); err != nil {
		t.Fatalf("create fixture launcher: %v", err)
	}
	return repository
}

func writeGoFile(t *testing.T, repository string, relativePath string, content string) {
	t.Helper()
	path := filepath.Join(repository, filepath.FromSlash(relativePath))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture file: %v", err)
	}
}

func assertImportViolations(t *testing.T, violations []Violation, want map[string]string) {
	t.Helper()
	got := make(map[string]string, len(violations))
	for _, violation := range violations {
		got[violation.ImportPath] = violation.Rule
	}
	if len(got) != len(want) {
		t.Fatalf("violation count = %d (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for importPath, rule := range want {
		if got[importPath] != rule {
			t.Errorf("violation for %q = %q, want %q", importPath, got[importPath], rule)
		}
	}
}
