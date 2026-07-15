package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	defaultPackageThreshold = 80
	defaultChangedThreshold = 80
	// Atomic -coverpkg profiles repeat the launcher block inventory for each
	// package under test. Keep reads bounded while leaving production growth
	// headroom above the current full launcher matrix.
	maximumProfileBytes = 512 << 20
)

var safeGitRefPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("check_go_coverage", flag.ContinueOnError)
	flags.SetOutput(stderr)
	profilePath := flags.String("profile", "build/go-cover.out", "Go coverage profile path")
	repositoryRoot := flags.String("root", ".", "repository root")
	baseRef := flags.String("base", "origin/main", "trusted Git base ref for changed-code coverage")
	packageThreshold := flags.Float64("package", defaultPackageThreshold, "minimum statement coverage for every launcher package")
	changedThreshold := flags.Float64("changed", defaultChangedThreshold, "minimum statement coverage for changed launcher code")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		return writeInvocationError(stderr, "unexpected positional arguments: %v", flags.Args())
	}
	if !validThreshold(*packageThreshold) || !validThreshold(*changedThreshold) {
		return writeInvocationError(stderr, "coverage thresholds must be between 0 and 100")
	}
	if *changedThreshold > 0 && !safeGitRefPattern.MatchString(*baseRef) {
		return writeInvocationError(stderr, "base ref contains unsupported characters")
	}

	root, err := filepath.Abs(*repositoryRoot)
	if err != nil {
		_ = writeLine(stderr, "resolve repository root: %v", err)
		return 1
	}
	modulePath, err := readRootModulePath(root)
	if err != nil {
		_ = writeLine(stderr, "%v", err)
		return 1
	}
	profile, err := readProfile(root, *profilePath, modulePath)
	if err != nil {
		_ = writeLine(stderr, "%v", err)
		return 1
	}
	inventory, err := discoverSourceInventory(root)
	if err != nil {
		_ = writeLine(stderr, "%v", err)
		return 1
	}

	failed := false
	missingFiles := missingProfileFiles(profile, inventory.Files)
	for _, file := range missingFiles {
		if !writeLine(stderr, "coverage missing executable production file %s", file) {
			return 1
		}
		failed = true
	}
	for _, result := range evaluatePackages(profile, inventory.Packages, *packageThreshold) {
		if result.Passed {
			continue
		}
		if result.Missing {
			if !writeLine(stderr, "coverage missing launcher package %s", result.Package) {
				return 1
			}
		} else if !writeLine(
			stderr,
			"launcher package %s coverage %.2f%% is below %.2f%% (%d/%d statements)",
			result.Package,
			result.Percent,
			*packageThreshold,
			result.Covered,
			result.Statements,
		) {
			return 1
		}
		failed = true
	}

	if *changedThreshold > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		changed, diffErr := changedLauncherLines(ctx, root, *baseRef)
		if diffErr != nil {
			_ = writeLine(stderr, "%v", diffErr)
			return 1
		}
		changedResult := evaluateChanged(profile, changed, *changedThreshold)
		if !changedResult.Passed {
			if !writeLine(
				stderr,
				"changed launcher coverage %.2f%% is below %.2f%% (%d/%d statements)",
				changedResult.Percent,
				*changedThreshold,
				changedResult.Covered,
				changedResult.Statements,
			) {
				return 1
			}
			failed = true
		}
	}
	if failed {
		return 1
	}
	if !writeLine(stdout, "launcher coverage gates passed") {
		return 1
	}
	return 0
}

func validThreshold(value float64) bool {
	return value >= 0 && value <= 100
}

func readRootModulePath(root string) (string, error) {
	path := filepath.Join(root, "go.mod")
	// path is an exact child of the already-resolved repository root.
	//nolint:gosec // G304: quality tooling must read the repository go.mod; owner=quality, expiry=2027-07-13.
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read root go.mod: %w", err)
	}
	for _, line := range strings.Split(string(contents), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "module" {
			modulePath := strings.Trim(fields[1], `"`)
			if modulePath == "" || pathEscapesRoot(modulePath) {
				return "", errors.New("root go.mod has an invalid module directive")
			}
			return modulePath, nil
		}
	}
	return "", errors.New("root go.mod has no module directive")
}

func readProfile(root string, configuredPath string, modulePath string) (coverageProfile, error) {
	return readProfileWithLimit(root, configuredPath, modulePath, maximumProfileBytes)
}

func readProfileWithLimit(
	root string,
	configuredPath string,
	modulePath string,
	maximumBytes int64,
) (coverageProfile, error) {
	if maximumBytes <= 0 {
		return coverageProfile{}, errors.New("coverage profile size limit must be positive")
	}
	profilePath := configuredPath
	if !filepath.IsAbs(profilePath) {
		profilePath = filepath.Join(root, profilePath)
	}
	profilePath = filepath.Clean(profilePath)
	file, err := os.Open(profilePath)
	if err != nil {
		return coverageProfile{}, fmt.Errorf("open coverage profile: %w", err)
	}
	limited := &io.LimitedReader{R: file, N: maximumBytes + 1}
	profile, parseErr := parseProfile(limited, modulePath)
	closeErr := file.Close()
	if limited.N == 0 {
		return coverageProfile{}, fmt.Errorf("coverage profile exceeds %d bytes", maximumBytes)
	}
	if parseErr != nil {
		return coverageProfile{}, parseErr
	}
	if closeErr != nil {
		return coverageProfile{}, fmt.Errorf("close coverage profile: %w", closeErr)
	}
	return profile, nil
}

func pathEscapesRoot(value string) bool {
	normalized := filepath.ToSlash(value)
	cleaned := filepath.ToSlash(filepath.Clean(value))
	return cleaned != normalized || cleaned == "." || cleaned == ".." ||
		strings.HasPrefix(cleaned, "../") || pathIsAbsolute(value)
}

func pathIsAbsolute(value string) bool {
	return filepath.IsAbs(value) || strings.HasPrefix(value, "/")
}

func changedLauncherLines(ctx context.Context, root string, baseRef string) (changedLines, error) {
	// baseRef is restricted by safeGitRefPattern and passed as one argv value;
	// neither it nor root is interpreted by a shell.
	//nolint:gosec // G204: fixed executable/argv with a validated ref and repository path; owner=quality, expiry=2027-07-13.
	command := exec.CommandContext(
		ctx,
		"git",
		"diff",
		"--unified=0",
		"--no-ext-diff",
		"--no-renames",
		baseRef+"...HEAD",
		"--",
		strings.TrimSuffix(launcherPathPrefix, "/"),
	)
	command.Dir = root
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("read changed launcher lines from Git: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	changed, err := parseChangedLines(&stdout)
	if err != nil {
		return nil, err
	}
	return changed, nil
}

func writeInvocationError(writer io.Writer, format string, values ...any) int {
	if !writeLine(writer, format, values...) {
		return 1
	}
	return 2
}

func writeLine(writer io.Writer, format string, values ...any) bool {
	_, err := fmt.Fprintf(writer, format+"\n", values...)
	return err == nil
}
