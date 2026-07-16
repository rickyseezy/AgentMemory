package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Go statement coverage cannot attribute execution to constant declarations.
// TestPF001NativeBuildStaticAuthorityIsExact asserts every release value.
const (
	// mutator-disable-next-line *
	requiredGoVersion = "go1.26.5"
	// mutator-disable-next-line *
	maximumTrustDocumentBytes = 128 * 1024
	// mutator-disable-next-line *
	maximumNativeBinaryBytes = 512 * 1024 * 1024
	// mutator-disable-next-line *
	nativeBuildMetadataName = "unsigned-build.json"
	// mutator-disable-next-line *
	releaseTrustVariable = "github.com/rickyseezy/AgentMemory/apps/launcher/internal/infrastructure/launcher.embeddedNativeReleaseTrustBase64"
)

// BuildOptions contains every caller-controlled native build input.
type BuildOptions struct {
	RepositoryRoot  string
	TrustDocument   string
	Output          string
	OperatingSystem string
	Architecture    string
	SourceEpoch     int64
}

// Command is one closed release-engineering process invocation.
type Command struct {
	Name string
	Args []string
	Dir  string
	Env  map[string]string
}

// CommandRunner isolates Git and Go from the deterministic build policy.
type CommandRunner interface {
	Run(context.Context, Command) ([]byte, error)
}

type trustValidator func(string) error

type buildOperations interface {
	MkdirTemp(string, string) (string, error)
	Mkdir(string, os.FileMode) error
	RemoveAll(string) error
	WriteBuildMetadata(string, nativeBuildMetadata, time.Time) error
	NormalizeDirectory(string, time.Time) error
	Rename(string, string) error
}

type systemBuildOperations struct{}

func (systemBuildOperations) MkdirTemp(parent string, pattern string) (string, error) {
	return os.MkdirTemp(parent, pattern)
}

func (systemBuildOperations) Mkdir(path string, mode os.FileMode) error { return os.Mkdir(path, mode) }

func (systemBuildOperations) RemoveAll(path string) error { return os.RemoveAll(path) }

func (systemBuildOperations) WriteBuildMetadata(
	path string,
	metadata nativeBuildMetadata,
	epoch time.Time,
) error {
	return writeBuildMetadata(path, metadata, epoch)
}

func (systemBuildOperations) NormalizeDirectory(root string, epoch time.Time) error {
	return normalizeDirectory(root, epoch)
}

func (systemBuildOperations) Rename(oldPath string, newPath string) error {
	return os.Rename(oldPath, newPath)
}

type nativeBuildArtifact struct {
	Name    string `json:"name"`
	Package string `json:"package"`
	SHA256  string `json:"sha256"`
	Size    uint64 `json:"size"`
}

type nativeBuildMetadata struct {
	SchemaVersion   int                   `json:"schema_version"`
	SourceCommit    string                `json:"source_commit"`
	GoVersion       string                `json:"go_version"`
	OperatingSystem string                `json:"operating_system"`
	Architecture    string                `json:"architecture"`
	SourceEpoch     int64                 `json:"source_epoch"`
	Artifacts       []nativeBuildArtifact `json:"artifacts"`
}

type resolvedBuildOptions struct {
	BuildOptions
	cgoEnabled string
}

// Build compiles each native entry point twice under the exact same closed
// environment, rejects any byte difference, and atomically publishes only the
// first proven-reproducible output plus canonical unsigned provenance.
func Build(
	ctx context.Context,
	options BuildOptions,
	runner CommandRunner,
	validateTrust trustValidator,
) error {
	return buildWithOperations(ctx, options, runner, validateTrust, systemBuildOperations{})
}

func buildWithOperations(
	ctx context.Context,
	options BuildOptions,
	runner CommandRunner,
	validateTrust trustValidator,
	operations buildOperations,
) error {
	if ctx == nil || runner == nil || validateTrust == nil || operations == nil {
		return errors.New("native build capabilities are incomplete")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	resolved, err := resolveBuildOptions(options)
	if err != nil {
		return err
	}
	trust, err := readBoundedRegularFile(resolved.TrustDocument, maximumTrustDocumentBytes)
	if err != nil {
		return fmt.Errorf("read release trust: %w", err)
	}
	encodedTrust := base64.StdEncoding.EncodeToString(trust)
	// Clearing the transient public-authority bytes is a defense-in-depth memory-hygiene action;
	// it has no observable functional outcome that a mutation test can assert.
	// mutator-disable-next-line statement/remove
	clear(trust)
	if err := validateTrust(encodedTrust); err != nil {
		return errors.New("release trust is not accepted by the production decoder")
	}
	commit, err := cleanSourceCommit(ctx, runner, resolved.RepositoryRoot)
	if err != nil {
		return err
	}
	if err := requireToolchain(ctx, runner, resolved.RepositoryRoot); err != nil {
		return err
	}
	parent := filepath.Dir(resolved.Output)
	temporary, err := operations.MkdirTemp(parent, ".agentmemory-native-build-")
	if err != nil {
		return fmt.Errorf("create private native build root: %w", err)
	}
	defer func() { _ = operations.RemoveAll(temporary) }()
	firstRoot := filepath.Join(temporary, ".first")
	secondRoot := filepath.Join(temporary, ".second")
	for _, path := range []string{firstRoot, secondRoot} {
		if err := operations.Mkdir(path, 0o700); err != nil {
			return fmt.Errorf("create reproducibility pass: %w", err)
		}
	}
	epoch := time.Unix(resolved.SourceEpoch, 0).UTC()
	artifacts := make([]nativeBuildArtifact, 0, 3)
	for _, specification := range []struct {
		name        string
		packagePath string
	}{
		{name: executableName("agentmemory", resolved.OperatingSystem), packagePath: "./apps/launcher/cmd/agentmemory"},
		{name: executableName("agentmemory-bootstrap", resolved.OperatingSystem), packagePath: "./apps/launcher/cmd/agentmemory-bootstrap"},
		{name: executableName("agentmemory-runtime-helper", resolved.OperatingSystem), packagePath: "./apps/launcher/cmd/agentmemory-runtime-helper"},
	} {
		artifact, err := buildReproducibleBinary(
			ctx, runner, resolved, encodedTrust, firstRoot, secondRoot,
			temporary, specification.name, specification.packagePath, epoch,
		)
		if err != nil {
			return fmt.Errorf("build %s: %w", specification.name, err)
		}
		artifacts = append(artifacts, artifact)
	}
	if err := operations.RemoveAll(firstRoot); err != nil {
		return fmt.Errorf("remove first comparison root: %w", err)
	}
	if err := operations.RemoveAll(secondRoot); err != nil {
		return fmt.Errorf("remove second comparison root: %w", err)
	}
	metadata := nativeBuildMetadata{
		SchemaVersion: 1, SourceCommit: commit, GoVersion: requiredGoVersion,
		OperatingSystem: resolved.OperatingSystem, Architecture: resolved.Architecture,
		SourceEpoch: resolved.SourceEpoch, Artifacts: artifacts,
	}
	if err := operations.WriteBuildMetadata(filepath.Join(temporary, nativeBuildMetadataName), metadata, epoch); err != nil {
		return fmt.Errorf("write native build metadata: %w", err)
	}
	if err := operations.NormalizeDirectory(temporary, epoch); err != nil {
		return fmt.Errorf("normalize native build root: %w", err)
	}
	if err := operations.Rename(temporary, resolved.Output); err != nil {
		return fmt.Errorf("publish native build: %w", err)
	}
	return nil
}

func resolveBuildOptions(options BuildOptions) (resolvedBuildOptions, error) {
	return resolveBuildOptionsForRuntime(options, runtime.GOOS, runtime.GOARCH)
}

func resolveBuildOptionsForRuntime(
	options BuildOptions,
	runnerOperatingSystem string,
	runnerArchitecture string,
) (resolvedBuildOptions, error) {
	absRoot, err := filepath.Abs(options.RepositoryRoot)
	if err != nil {
		return resolvedBuildOptions{}, fmt.Errorf("resolve repository root: %w", err)
	}
	absRoot, err = filepath.EvalSymlinks(absRoot)
	if err != nil {
		return resolvedBuildOptions{}, fmt.Errorf("resolve repository root links: %w", err)
	}
	info, err := os.Lstat(absRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return resolvedBuildOptions{}, errors.New("repository root is not a directory")
	}
	if options.OperatingSystem != "linux" && options.OperatingSystem != "windows" && options.OperatingSystem != "darwin" {
		return resolvedBuildOptions{}, errors.New("operating system must be linux, windows, or darwin")
	}
	if options.Architecture != "amd64" && options.Architecture != "arm64" {
		return resolvedBuildOptions{}, errors.New("architecture must be amd64 or arm64")
	}
	if options.SourceEpoch <= 0 {
		return resolvedBuildOptions{}, errors.New("source date epoch must be positive")
	}
	if options.OperatingSystem == "darwin" &&
		(runnerOperatingSystem != "darwin" || runnerArchitecture != options.Architecture) {
		return resolvedBuildOptions{}, errors.New("darwin CGO release builds require an exact native runner")
	}
	resolved := resolvedBuildOptions{BuildOptions: options, cgoEnabled: "0"}
	resolved.RepositoryRoot = absRoot
	if options.OperatingSystem == "darwin" {
		resolved.cgoEnabled = "1"
	}
	for name, value := range map[string]*string{
		"trust document": &resolved.TrustDocument,
		"output":         &resolved.Output,
	} {
		if *value == "" {
			return resolvedBuildOptions{}, fmt.Errorf("%s is required", name)
		}
		if !filepath.IsAbs(*value) {
			*value = filepath.Join(absRoot, *value)
		}
		*value = filepath.Clean(*value)
	}
	if _, err := os.Lstat(resolved.Output); err == nil {
		return resolvedBuildOptions{}, errors.New("output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return resolvedBuildOptions{}, fmt.Errorf("inspect output: %w", err)
	}
	parentInfo, err := os.Lstat(filepath.Dir(resolved.Output))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return resolvedBuildOptions{}, errors.New("output parent must be an existing non-symlink directory")
	}
	return resolved, nil
}

func cleanSourceCommit(ctx context.Context, runner CommandRunner, root string) (string, error) {
	status, err := runner.Run(ctx, Command{
		Name: "git", Args: []string{"status", "--porcelain=v1", "--untracked-files=all"}, Dir: root,
	})
	if err != nil {
		return "", errors.New("verify clean source revision failed")
	}
	if len(status) != 0 {
		return "", errors.New("source revision is dirty")
	}
	raw, err := runner.Run(ctx, Command{Name: "git", Args: []string{"rev-parse", "HEAD"}, Dir: root})
	commit := strings.TrimSpace(string(raw))
	if err != nil || !validSourceCommit(commit) {
		return "", errors.New("resolve exact source revision failed")
	}
	return commit, nil
}

func validSourceCommit(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func requireToolchain(ctx context.Context, runner CommandRunner, root string) error {
	raw, err := runner.Run(ctx, Command{Name: "go", Args: []string{"version"}, Dir: root})
	fields := strings.Fields(string(raw))
	if err != nil || len(fields) != 4 || fields[0] != "go" || fields[1] != "version" || fields[2] != requiredGoVersion {
		return fmt.Errorf("release build requires exact Go toolchain %s", requiredGoVersion)
	}
	return nil
}

func buildReproducibleBinary(
	ctx context.Context,
	runner CommandRunner,
	options resolvedBuildOptions,
	encodedTrust string,
	firstRoot string,
	secondRoot string,
	outputRoot string,
	name string,
	packagePath string,
	epoch time.Time,
) (nativeBuildArtifact, error) {
	paths := []string{filepath.Join(firstRoot, name), filepath.Join(secondRoot, name)}
	for _, output := range paths {
		if err := runNativeBuild(ctx, runner, options, encodedTrust, packagePath, output); err != nil {
			return nativeBuildArtifact{}, err
		}
	}
	firstDigest, firstSize, err := regularFileDigest(paths[0])
	if err != nil {
		return nativeBuildArtifact{}, err
	}
	secondDigest, secondSize, err := regularFileDigest(paths[1])
	if err != nil || firstSize != secondSize || !bytes.Equal(firstDigest, secondDigest) {
		return nativeBuildArtifact{}, errors.New("repeated native builds are not byte-for-byte reproducible")
	}
	target := filepath.Join(outputRoot, name)
	if err := os.Rename(paths[0], target); err != nil {
		return nativeBuildArtifact{}, err
	}
	// #nosec G302 -- shipped native entry points are intentionally executable.
	if err := os.Chmod(target, 0o755); err != nil {
		return nativeBuildArtifact{}, err
	}
	if err := os.Chtimes(target, epoch, epoch); err != nil {
		return nativeBuildArtifact{}, err
	}
	return nativeBuildArtifact{
		Name: name, Package: packagePath, SHA256: hex.EncodeToString(firstDigest), Size: firstSize,
	}, nil
}

func runNativeBuild(
	ctx context.Context,
	runner CommandRunner,
	options resolvedBuildOptions,
	encodedTrust string,
	packagePath string,
	output string,
) error {
	ldflags := "-buildid= -X " + releaseTrustVariable + "=" + encodedTrust
	_, err := runner.Run(ctx, Command{
		Name: "go",
		Args: []string{
			"build", "-buildvcs=true", "-trimpath", "-ldflags", ldflags,
			"-o", output, packagePath,
		},
		Dir: options.RepositoryRoot,
		Env: map[string]string{
			"CGO_ENABLED": options.cgoEnabled, "GOARCH": options.Architecture,
			"GOOS": options.OperatingSystem, "GOENV": "off", "GOFLAGS": "-mod=readonly",
			"GOPROXY": "off", "GOTOOLCHAIN": "local", "GOWORK": "off",
		},
	})
	if err != nil {
		return errors.New("reproducible Go build failed")
	}
	return nil
}

func regularFileDigest(path string) ([]byte, uint64, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumNativeBinaryBytes {
		return nil, 0, errors.New("native build did not produce a bounded regular file")
	}
	// #nosec G304 -- path is one closed output below a private build-pass directory.
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, 0, errors.New("native build output changed while opening")
	}
	digest := sha256.New()
	read, err := io.Copy(digest, io.LimitReader(file, maximumNativeBinaryBytes+1))
	if err != nil || read != info.Size() {
		return nil, 0, errors.New("native build output changed while hashing")
	}
	return digest.Sum(nil), uint64(read), nil // #nosec G115 -- positivity and an upper bound are proven above.
}

func writeBuildMetadata(path string, metadata nativeBuildMetadata, epoch time.Time) error {
	raw, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	// #nosec G304 -- path is the fixed metadata leaf beneath the private build root.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	failed := true
	defer func() {
		_ = file.Close()
		if failed {
			_ = os.Remove(path)
		}
	}()
	if written, err := file.Write(raw); err != nil || written != len(raw) {
		return errors.New("write complete native build metadata failed")
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	// #nosec G302 -- unsigned build provenance is public release material.
	if err := os.Chmod(path, 0o644); err != nil {
		return err
	}
	if err := os.Chtimes(path, epoch, epoch); err != nil {
		return err
	}
	failed = false
	return nil
}

func executableName(base string, operatingSystem string) string {
	if operatingSystem == "windows" {
		return base + ".exe"
	}
	return base
}

func normalizeDirectory(path string, epoch time.Time) error {
	// #nosec G302 -- published native build directories are traversable release inputs.
	if err := os.Chmod(path, 0o755); err != nil {
		return err
	}
	return os.Chtimes(path, epoch, epoch)
}

func readBoundedRegularFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("input must be a bounded non-empty regular file")
	}
	// #nosec G304 -- path is an explicit release input constrained above.
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("input changed while opening")
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(content)) != info.Size() || int64(len(content)) > maximum {
		return nil, errors.New("input changed while reading")
	}
	return content, nil
}

type processRunner struct{}

func (processRunner) Run(ctx context.Context, command Command) ([]byte, error) {
	if ctx == nil || command.Dir == "" || command.Name != "git" && command.Name != "go" {
		return nil, errors.New("invalid or disallowed native build command")
	}
	process := exec.CommandContext(ctx, command.Name, command.Args...) // #nosec G204 -- executable names are closed above.
	process.Dir = command.Dir
	process.Env = closedBuildEnvironment(command.Env)
	output, err := process.CombinedOutput()
	if err != nil {
		return nil, err
	}
	return output, nil
}

func closedBuildEnvironment(values map[string]string) []string {
	allowed := map[string]string{}
	for _, name := range []string{"HOME", "PATH", "SystemRoot", "TEMP", "TMP", "TMPDIR", "USERPROFILE"} {
		if value, found := os.LookupEnv(name); found && value != "" {
			allowed[name] = value
		}
	}
	for key, value := range values {
		allowed[key] = value
	}
	keys := make([]string, 0, len(allowed))
	for key := range allowed {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+allowed[key])
	}
	return result
}
