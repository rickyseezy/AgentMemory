// Package main implements the AgentMemory launcher architecture policy check.
package main

import (
	"fmt"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const defaultLauncherPath = "apps/launcher"

type layer string

const (
	layerUnknown        layer = "unknown"
	layerDomain         layer = "domain"
	layerApplication    layer = "application"
	layerAdapters       layer = "adapters"
	layerInfrastructure layer = "infrastructure"
	layerContracts      layer = "contracts"
)

// Options controls which launcher source tree is inspected.
type Options struct {
	RepositoryRoot string
	LauncherPath   string
	IncludeTests   bool
}

// Violation describes one forbidden dependency at its import declaration.
type Violation struct {
	File       string
	Line       int
	Column     int
	Layer      string
	ImportPath string
	Rule       string
	Reason     string
}

func (v Violation) String() string {
	return fmt.Sprintf(
		"%s:%d:%d: [%s] %s imports %q: %s",
		v.File,
		v.Line,
		v.Column,
		v.Rule,
		v.Layer,
		v.ImportPath,
		v.Reason,
	)
}

// Check inspects production Go imports in the launcher and returns every
// Clean Architecture dependency violation in deterministic source order.
func Check(options Options) ([]Violation, error) {
	repositoryRoot := options.RepositoryRoot
	if repositoryRoot == "" {
		repositoryRoot = "."
	}
	repositoryRoot, err := filepath.Abs(repositoryRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve repository root: %w", err)
	}

	launcherPath := options.LauncherPath
	if launcherPath == "" {
		launcherPath = defaultLauncherPath
	}
	launcherRoot := launcherPath
	if !filepath.IsAbs(launcherRoot) {
		launcherRoot = filepath.Join(repositoryRoot, filepath.FromSlash(launcherPath))
	}
	launcherRoot, err = filepath.Abs(launcherRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve launcher path: %w", err)
	}
	info, err := os.Stat(launcherRoot)
	if err != nil {
		return nil, fmt.Errorf("inspect launcher path %q: %w", displayPath(repositoryRoot, launcherRoot), err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("launcher path %q is not a directory", displayPath(repositoryRoot, launcherRoot))
	}

	modulePath, err := readModulePath(filepath.Join(launcherRoot, "go.mod"))
	if err != nil {
		return nil, err
	}

	violations := make([]Violation, 0)
	err = filepath.WalkDir(launcherRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk %q: %w", displayPath(repositoryRoot, path), walkErr)
		}
		if entry.IsDir() {
			if path != launcherRoot && isIgnoredDirectory(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(entry.Name()) != ".go" {
			return nil
		}
		if strings.HasSuffix(entry.Name(), "_test.go") && !options.IncludeTests {
			return nil
		}

		sourceLayer := sourceLayerForFile(launcherRoot, path)
		if sourceLayer != layerDomain && sourceLayer != layerApplication {
			return nil
		}
		fileViolations, checkErr := checkFile(repositoryRoot, path, sourceLayer, modulePath)
		if checkErr != nil {
			return checkErr
		}
		violations = append(violations, fileViolations...)
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(violations, func(i int, j int) bool {
		left := violations[i]
		right := violations[j]
		if left.File != right.File {
			return left.File < right.File
		}
		if left.Line != right.Line {
			return left.Line < right.Line
		}
		if left.Column != right.Column {
			return left.Column < right.Column
		}
		return left.ImportPath < right.ImportPath
	})
	return violations, nil
}

func checkFile(
	repositoryRoot string,
	path string,
	sourceLayer layer,
	modulePath string,
) ([]Violation, error) {
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, path, nil, parser.ImportsOnly)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", displayPath(repositoryRoot, path), err)
	}

	violations := make([]Violation, 0)
	for _, imported := range parsed.Imports {
		importPath, unquoteErr := strconv.Unquote(imported.Path.Value)
		if unquoteErr != nil {
			position := fileSet.Position(imported.Path.Pos())
			return nil, fmt.Errorf(
				"parse import at %s:%d:%d: %w",
				displayPath(repositoryRoot, path),
				position.Line,
				position.Column,
				unquoteErr,
			)
		}
		rule, reason := dependencyViolation(sourceLayer, importPath, modulePath)
		if rule == "" {
			continue
		}
		position := fileSet.Position(imported.Path.Pos())
		violations = append(violations, Violation{
			File:       displayPath(repositoryRoot, path),
			Line:       position.Line,
			Column:     position.Column,
			Layer:      string(sourceLayer),
			ImportPath: importPath,
			Rule:       rule,
			Reason:     reason,
		})
	}
	return violations, nil
}

func dependencyViolation(sourceLayer layer, importPath string, modulePath string) (string, string) {
	if isForbiddenInwardImport(importPath) {
		return "forbidden-import", "inward launcher layers may not import host filesystem, process, network, syscall, or unsafe packages"
	}
	if isStandardLibrary(importPath) && !isAllowedInwardStandardLibrary(importPath) {
		return "inward-stdlib-capability", "inward launcher layers may import only the reviewed capability-free standard-library allowlist"
	}
	if isDockerSDK(importPath) {
		return "docker-sdk", "Docker implementations belong behind an outbound adapter"
	}

	targetLayer := importedLauncherLayer(importPath, modulePath)
	if targetLayer == layerAdapters {
		return "inward-adapter", "an inward layer may not import an adapter"
	}
	if targetLayer == layerInfrastructure {
		return "inward-infrastructure", "an inward layer may not import infrastructure"
	}

	switch sourceLayer {
	case layerDomain:
		if targetLayer == layerDomain || isStandardLibrary(importPath) {
			return "", ""
		}
		return "domain-dependency", "domain may import only the standard library and launcher domain packages"
	case layerApplication:
		if targetLayer == layerDomain || targetLayer == layerApplication || targetLayer == layerContracts || isStandardLibrary(importPath) {
			return "", ""
		}
		return "application-dependency", "application may import only the standard library and inward launcher packages"
	case layerUnknown, layerAdapters, layerInfrastructure, layerContracts:
		return "", ""
	}
	return "", ""
}

// isAllowedInwardStandardLibrary is intentionally an allowlist rather than a
// growing blacklist. New standard-library dependencies in domain/application
// code therefore require an explicit architecture review instead of silently
// introducing ambient clocks, entropy, persistence, host inspection, dynamic
// loading, or another side-effecting capability.
func isAllowedInwardStandardLibrary(importPath string) bool {
	allowed := map[string]struct{}{
		"bytes":           {},
		"cmp":             {},
		"context":         {},
		"crypto/hmac":     {},
		"crypto/sha256":   {},
		"encoding":        {},
		"encoding/base64": {},
		"encoding/binary": {},
		"encoding/hex":    {},
		"encoding/json":   {},
		"errors":          {},
		"fmt":             {},
		"hash":            {},
		"hash/fnv":        {},
		"io":              {},
		"maps":            {},
		"math":            {},
		"math/bits":       {},
		"reflect":         {},
		"regexp":          {},
		"slices":          {},
		"sort":            {},
		"strconv":         {},
		"strings":         {},
		"sync":            {},
		"testing":         {},
		"time":            {},
		"unicode":         {},
		"unicode/utf8":    {},
	}
	_, ok := allowed[importPath]
	return ok
}

func sourceLayerForFile(launcherRoot string, path string) layer {
	relative, err := filepath.Rel(launcherRoot, path)
	if err != nil {
		return layerUnknown
	}
	parts := strings.Split(filepath.ToSlash(relative), "/")
	if len(parts) < 2 || parts[0] != "internal" {
		return layerUnknown
	}
	return parseLayer(parts[1])
}

func importedLauncherLayer(importPath string, modulePath string) layer {
	if modulePath != "" {
		prefix := strings.TrimSuffix(modulePath, "/") + "/internal/"
		if strings.HasPrefix(importPath, prefix) {
			return parseFirstPathPart(strings.TrimPrefix(importPath, prefix))
		}
	}

	normalized := "/" + strings.TrimPrefix(importPath, "/")
	const marker = "/apps/launcher/internal/"
	markerIndex := strings.Index(normalized, marker)
	if markerIndex == -1 {
		return layerUnknown
	}
	return parseFirstPathPart(normalized[markerIndex+len(marker):])
}

func parseFirstPathPart(path string) layer {
	part, _, _ := strings.Cut(path, "/")
	return parseLayer(part)
}

func parseLayer(name string) layer {
	switch name {
	case string(layerDomain):
		return layerDomain
	case string(layerApplication):
		return layerApplication
	case string(layerAdapters):
		return layerAdapters
	case string(layerInfrastructure):
		return layerInfrastructure
	case string(layerContracts):
		return layerContracts
	default:
		return layerUnknown
	}
}

func isForbiddenInwardImport(importPath string) bool {
	forbiddenPrefixes := [...]string{
		"io/fs",
		"net",
		"os",
		"path/filepath",
		"syscall",
		"unsafe",
	}
	for _, prefix := range forbiddenPrefixes {
		if importPath == prefix || strings.HasPrefix(importPath, prefix+"/") {
			return true
		}
	}
	return false
}

func isDockerSDK(importPath string) bool {
	prefixes := []string{
		"github.com/compose-spec/compose-go",
		"github.com/docker/cli",
		"github.com/docker/compose",
		"github.com/docker/docker",
		"github.com/moby/moby",
	}
	for _, prefix := range prefixes {
		if importPath == prefix || strings.HasPrefix(importPath, prefix+"/") {
			return true
		}
	}
	return false
}

func isStandardLibrary(importPath string) bool {
	if importPath == "C" || importPath == "" {
		return false
	}
	pkg, err := build.Default.Import(importPath, "", build.FindOnly)
	return err == nil && pkg.Goroot
}

func readModulePath(path string) (string, error) {
	// path is constructed from the validated launcher root, never from a source
	// file import or an untrusted manifest.
	//nolint:gosec // G304: repository quality tooling must read this exact go.mod path; owner=quality, expiry=2027-07-13.
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read launcher module: %w", err)
	}
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "module" {
			return strings.Trim(fields[1], `"`), nil
		}
	}
	return "", fmt.Errorf("read launcher module %q: missing module directive", filepath.ToSlash(path))
}

func isIgnoredDirectory(name string) bool {
	return name == ".git" || name == "vendor" || strings.HasPrefix(name, ".")
}

func displayPath(repositoryRoot string, path string) string {
	relative, err := filepath.Rel(repositoryRoot, path)
	if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return filepath.ToSlash(relative)
	}
	return filepath.ToSlash(path)
}
