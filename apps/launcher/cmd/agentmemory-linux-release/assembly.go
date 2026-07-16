package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/infrastructure/releasefile"
)

// Go statement coverage cannot attribute execution to constant declarations.
// TestPF001LinuxReleaseStaticLimitsAreExact asserts this security boundary.
const (
	// mutator-disable-next-line *
	maximumTrustDocumentBytes = 128 * 1024
)

// AssemblyOptions contains every caller-controlled release assembly input.
type AssemblyOptions struct {
	RepositoryRoot    string
	BundleRoot        string
	TrustDocument     string
	Output            string
	Architecture      string
	SourceEpoch       int64
	VerificationEpoch int64
}

// Command is one closed external process invocation used during assembly.
type Command struct {
	Name string
	Args []string
	Dir  string
	Env  map[string]string
}

// CommandRunner isolates Git and Go execution from deterministic file staging.
type CommandRunner interface {
	Run(context.Context, Command) ([]byte, error)
}

type trustValidator func(string) error
type bundleResolver func(context.Context, string, string, string, string, time.Time) (verifiedNativePackage, error)

type assemblyOperations interface {
	MkdirTemp(string, string) (string, error)
	CopyBundle(string, string, time.Time) error
	CopyVerifiedNativeResource(string, string, verifiedNativeResource, time.Time) error
	NormalizeDirectoryTree(string, time.Time) error
	Rename(string, string) error
	RemoveAll(string) error
}

type systemAssemblyOperations struct{}

func (systemAssemblyOperations) MkdirTemp(parent string, pattern string) (string, error) {
	return os.MkdirTemp(parent, pattern)
}

func (systemAssemblyOperations) CopyBundle(source string, target string, epoch time.Time) error {
	return copyBundle(source, target, epoch)
}

func (systemAssemblyOperations) CopyVerifiedNativeResource(
	root string,
	target string,
	resource verifiedNativeResource,
	epoch time.Time,
) error {
	return copyVerifiedNativeResource(root, target, resource, epoch)
}

func (systemAssemblyOperations) NormalizeDirectoryTree(root string, epoch time.Time) error {
	return normalizeDirectoryTree(root, epoch)
}

func (systemAssemblyOperations) Rename(oldPath string, newPath string) error {
	return os.Rename(oldPath, newPath)
}

func (systemAssemblyOperations) RemoveAll(path string) error { return os.RemoveAll(path) }

type verifiedNativeResource struct {
	resourceID string
	bundlePath string
	sha256     string
	size       uint64
}

func (r verifiedNativeResource) valid() bool {
	if r.resourceID == "" || r.bundlePath == "" || r.size == 0 || len(r.sha256) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(r.sha256)
	return err == nil
}

type verifiedNativePackage struct {
	operatingSystem string
	architecture    string
	launcher        verifiedNativeResource
	helper          verifiedNativeResource
}

func (p verifiedNativePackage) valid(operatingSystem string, architecture string) bool {
	return p.operatingSystem == operatingSystem && p.architecture == architecture &&
		p.launcher.valid() && p.helper.valid() &&
		p.launcher.resourceID != p.helper.resourceID &&
		p.launcher.bundlePath != p.helper.bundlePath && p.launcher.sha256 != p.helper.sha256
}

// Assemble validates release authority, requires a clean source revision,
// cross-builds both Linux entry points, and atomically publishes a normalized
// nFPM stage. It never creates a partially usable requested output directory.
func Assemble(
	ctx context.Context,
	options AssemblyOptions,
	runner CommandRunner,
	validateTrust trustValidator,
	resolveBundle bundleResolver,
) error {
	return assembleWithOperations(
		ctx, options, runner, validateTrust, resolveBundle, systemAssemblyOperations{},
	)
}

func assembleWithOperations(
	ctx context.Context,
	options AssemblyOptions,
	runner CommandRunner,
	validateTrust trustValidator,
	resolveBundle bundleResolver,
	operations assemblyOperations,
) error {
	if ctx == nil || runner == nil || validateTrust == nil || resolveBundle == nil || operations == nil {
		return errors.New("assembly capabilities are incomplete")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	resolved, err := resolveAssemblyOptions(options)
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
	if err := requireCleanRevision(ctx, runner, resolved.RepositoryRoot); err != nil {
		return err
	}
	epoch := time.Unix(resolved.SourceEpoch, 0).UTC()

	parent := filepath.Dir(resolved.Output)
	temporary, err := operations.MkdirTemp(parent, ".agentmemory-linux-stage-")
	if err != nil {
		return fmt.Errorf("create private staging directory: %w", err)
	}
	defer func() { _ = operations.RemoveAll(temporary) }()

	stagedBundle := filepath.Join(temporary, "bundle")
	if err := operations.CopyBundle(resolved.BundleRoot, stagedBundle, epoch); err != nil {
		return fmt.Errorf("stage release bundle: %w", err)
	}
	verifiedAt := time.Unix(resolved.VerificationEpoch, 0).UTC()
	selection, err := resolveBundle(
		ctx, stagedBundle, encodedTrust, "linux", resolved.Architecture, verifiedAt,
	)
	if err != nil || !selection.valid("linux", resolved.Architecture) {
		return errors.New("release bundle failed the production verification stack")
	}
	for _, binary := range []struct {
		name     string
		resource verifiedNativeResource
	}{
		{name: "agentmemory", resource: selection.launcher},
		{name: "agentmemory-runtime-helper", resource: selection.helper},
	} {
		if err := operations.CopyVerifiedNativeResource(
			stagedBundle, filepath.Join(temporary, binary.name), binary.resource, epoch,
		); err != nil {
			return fmt.Errorf("stage verified %s: %w", binary.name, err)
		}
	}
	if err := operations.NormalizeDirectoryTree(temporary, epoch); err != nil {
		return fmt.Errorf("normalize staging directories: %w", err)
	}
	if err := operations.Rename(temporary, resolved.Output); err != nil {
		return fmt.Errorf("publish staging directory: %w", err)
	}
	return nil
}

func resolveAssemblyOptions(options AssemblyOptions) (AssemblyOptions, error) {
	absRoot, err := filepath.Abs(options.RepositoryRoot)
	if err != nil {
		return AssemblyOptions{}, fmt.Errorf("resolve repository root: %w", err)
	}
	absRoot, err = filepath.EvalSymlinks(absRoot)
	if err != nil {
		return AssemblyOptions{}, fmt.Errorf("resolve repository root links: %w", err)
	}
	rootInfo, err := os.Lstat(absRoot)
	if !releasefile.StableDirectory(rootInfo, err) {
		return AssemblyOptions{}, errors.New("repository root is not a directory")
	}
	if options.Architecture != "amd64" && options.Architecture != "arm64" {
		return AssemblyOptions{}, errors.New("architecture must be amd64 or arm64")
	}
	if options.SourceEpoch <= 0 {
		return AssemblyOptions{}, errors.New("source date epoch must be positive")
	}
	if options.VerificationEpoch <= 0 {
		return AssemblyOptions{}, errors.New("release verification epoch must be positive")
	}

	resolved := options
	resolved.RepositoryRoot = absRoot
	for name, value := range map[string]*string{
		"bundle root":    &resolved.BundleRoot,
		"trust document": &resolved.TrustDocument,
		"output":         &resolved.Output,
	} {
		if *value == "" {
			return AssemblyOptions{}, fmt.Errorf("%s is required", name)
		}
		if !filepath.IsAbs(*value) {
			*value = filepath.Join(absRoot, *value)
		}
		*value = filepath.Clean(*value)
	}
	if _, err := os.Lstat(resolved.Output); err == nil {
		return AssemblyOptions{}, errors.New("output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return AssemblyOptions{}, fmt.Errorf("inspect output: %w", err)
	}
	parent := filepath.Dir(resolved.Output)
	parentInfo, err := os.Lstat(parent)
	if !releasefile.StableDirectory(parentInfo, err) {
		return AssemblyOptions{}, errors.New("output parent must be an existing non-symlink directory")
	}
	return resolved, nil
}

func requireCleanRevision(ctx context.Context, runner CommandRunner, root string) error {
	output, err := runner.Run(ctx, Command{
		Name: "git", Args: []string{"status", "--porcelain=v1", "--untracked-files=all"}, Dir: root,
	})
	if err != nil {
		return errors.New("verify clean source revision failed")
	}
	if len(output) != 0 {
		return errors.New("source revision is dirty")
	}
	return nil
}

func copyBundle(sourceRoot string, targetRoot string, epoch time.Time) error {
	rootInfo, err := os.Lstat(sourceRoot)
	if !releasefile.StableDirectory(rootInfo, err) {
		return errors.New("bundle root must be a non-symlink directory")
	}
	if err := os.Mkdir(targetRoot, 0o700); err != nil {
		return err
	}
	err = filepath.WalkDir(sourceRoot, func(path string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == sourceRoot {
			return nil
		}
		relative, confined := releasefile.ConfinedRelative(sourceRoot, path)
		if !confined {
			return errors.New("bundle entry escaped its root")
		}
		target := filepath.Join(targetRoot, relative)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("bundle entry %q is a symlink", filepath.ToSlash(relative))
		}
		if info.IsDir() {
			if err := os.Mkdir(target, 0o700); err != nil {
				return err
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("bundle entry %q is not regular", filepath.ToSlash(relative))
		}
		return copyRegularFile(path, target, info, epoch)
	})
	if err != nil {
		return err
	}
	manifest := filepath.Join(targetRoot, "bootstrap", "distribution-manifest.json")
	if info, err := os.Lstat(manifest); err != nil || !info.Mode().IsRegular() {
		return errors.New("bundle is missing bootstrap/distribution-manifest.json")
	}
	return nil
}

func copyRegularFile(source string, target string, expected os.FileInfo, epoch time.Time) error {
	// #nosec G304 -- source is an Lstat-verified regular entry yielded beneath the validated bundle root.
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	opened, err := input.Stat()
	if !releasefile.SameRegularFile(expected, opened, err) {
		return errors.New("bundle file changed while opening")
	}
	// #nosec G304 -- target is constructed from the private staging root and a root-confined relative path.
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	failed := true
	defer func() {
		_ = output.Close()
		if failed {
			_ = os.Remove(target)
		}
	}()
	if _, err := io.Copy(output, input); err != nil {
		return err
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	// #nosec G302 -- verification input stays owner-private until the complete production stack accepts it.
	if err := os.Chmod(target, 0o600); err != nil {
		return err
	}
	if err := os.Chtimes(target, epoch, epoch); err != nil {
		return err
	}
	failed = false
	return nil
}

func copyVerifiedNativeResource(
	bundleRoot string,
	target string,
	resource verifiedNativeResource,
	epoch time.Time,
) error {
	if !resource.valid() || strings.Contains(resource.bundlePath, `\`) ||
		strings.ContainsRune(resource.bundlePath, 0) || filepath.IsAbs(resource.bundlePath) ||
		filepath.ToSlash(filepath.Clean(filepath.FromSlash(resource.bundlePath))) != resource.bundlePath ||
		resource.bundlePath == "." || strings.HasPrefix(resource.bundlePath, "../") {
		return errors.New("native resource projection is invalid")
	}
	source := filepath.Join(bundleRoot, filepath.FromSlash(resource.bundlePath))
	if _, confined := releasefile.ConfinedRelative(bundleRoot, source); !confined {
		return errors.New("native resource escaped the retained bundle")
	}
	expected, err := os.Lstat(source)
	if !releasefile.ExactRegularSize(expected, err, resource.size) {
		return errors.New("native resource size or type does not match its verified projection")
	}
	// #nosec G304 -- source is a confined, canonical signed bundle path validated above.
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	opened, err := input.Stat()
	if !releasefile.SameRegularFile(expected, opened, err) {
		return errors.New("native resource changed while opening")
	}
	// #nosec G304 -- target is one fixed leaf beneath the private staging root.
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	failed := true
	defer func() {
		_ = output.Close()
		if failed {
			_ = os.Remove(target)
		}
	}()
	digest := sha256.New()
	written, err := io.Copy(io.MultiWriter(output, digest), input)
	if !releasefile.ExactDigestTransfer(
		written, err, resource.size, hex.EncodeToString(digest.Sum(nil)), resource.sha256, true,
	) {
		return errors.New("native resource digest does not match its verified projection")
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	// #nosec G302 -- native package entry points must be executable by the invoking desktop user.
	if err := os.Chmod(target, 0o755); err != nil {
		return err
	}
	if err := os.Chtimes(target, epoch, epoch); err != nil {
		return err
	}
	failed = false
	return nil
}

func normalizeDirectoryTree(root string, epoch time.Time) error {
	directories := make([]string, 0, 32)
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if !releasefile.StableEntry(info, err) {
			return errors.New("staging tree contains an invalid entry")
		}
		switch {
		case entry.IsDir():
			directories = append(directories, path)
		case !info.Mode().IsRegular():
			return errors.New("staging tree contains a special entry")
		default:
			relative, relativeErr := filepath.Rel(root, path)
			if relativeErr != nil {
				return relativeErr
			}
			if relative == "bundle" || strings.HasPrefix(relative, "bundle"+string(filepath.Separator)) {
				// #nosec G122,G302 -- the path is beneath the private symlink-rejected stage; verified public resources become package payloads.
				if err := os.Chmod(path, 0o644); err != nil {
					return err
				}
				// #nosec G122 -- the path is beneath the private symlink-rejected stage.
				if err := os.Chtimes(path, epoch, epoch); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		return err
	}
	for _, directory := range directories {
		if err := normalizeDirectory(directory, epoch); err != nil {
			return err
		}
	}
	return nil
}

func normalizeDirectory(path string, epoch time.Time) error {
	// #nosec G302 -- nFPM package payload directories are intentionally traversable, root-owned 0755 paths.
	if err := os.Chmod(path, 0o755); err != nil {
		return err
	}
	return os.Chtimes(path, epoch, epoch)
}

func readBoundedRegularFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if !releasefile.BoundedRegular(info, err, maximum) {
		return nil, errors.New("input must be a bounded non-empty regular file")
	}
	// #nosec G304 -- path is an explicit release input already constrained by Lstat and size checks.
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if !releasefile.SameRegularFile(info, opened, err) {
		return nil, errors.New("input changed while opening")
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if !releasefile.StableContent(len(content), err, info.Size(), maximum) {
		return nil, errors.New("input changed while reading")
	}
	return content, nil
}

type processRunner struct{}

func (processRunner) Run(ctx context.Context, command Command) ([]byte, error) {
	if ctx == nil || command.Name == "" || command.Dir == "" {
		return nil, errors.New("invalid release command")
	}
	if command.Name != "git" {
		return nil, errors.New("release command is not allowlisted")
	}
	// #nosec G204 -- executable names are allowlisted above and every argument is constructed by this command.
	process := exec.CommandContext(ctx, command.Name, command.Args...)
	process.Dir = command.Dir
	process.Env = mergedEnvironment(command.Env)
	output, err := process.CombinedOutput()
	if err != nil {
		return nil, err
	}
	return output, nil
}

func mergedEnvironment(overrides map[string]string) []string {
	values := make(map[string]string)
	for _, entry := range os.Environ() {
		key, value, found := strings.Cut(entry, "=")
		if found {
			values[key] = value
		}
	}
	for key, value := range overrides {
		values[key] = value
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+values[key])
	}
	// Windows permits mixed-case environment names inherited from the host.
	// Sorting the final wire values, rather than only the map keys, keeps the
	// command contract deterministic on every supported build host.
	sort.Strings(result)
	return result
}
