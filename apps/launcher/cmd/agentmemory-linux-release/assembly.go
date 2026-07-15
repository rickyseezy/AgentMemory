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
)

const (
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
	digest, err := hex.DecodeString(r.sha256)
	return err == nil && len(digest) == sha256.Size
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
	if ctx == nil || runner == nil || validateTrust == nil || resolveBundle == nil {
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
	if err := validateTrust(encodedTrust); err != nil {
		return errors.New("release trust is not accepted by the production decoder")
	}
	if err := requireCleanRevision(ctx, runner, resolved.RepositoryRoot); err != nil {
		return err
	}
	epoch := time.Unix(resolved.SourceEpoch, 0).UTC()

	parent := filepath.Dir(resolved.Output)
	temporary, err := os.MkdirTemp(parent, ".agentmemory-linux-stage-")
	if err != nil {
		return fmt.Errorf("create private staging directory: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(temporary)
		}
	}()

	stagedBundle := filepath.Join(temporary, "bundle")
	if err := copyBundle(resolved.BundleRoot, stagedBundle, epoch); err != nil {
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
		if err := copyVerifiedNativeResource(
			stagedBundle, filepath.Join(temporary, binary.name), binary.resource, epoch,
		); err != nil {
			return fmt.Errorf("stage verified %s: %w", binary.name, err)
		}
	}
	if err := normalizeDirectoryTree(temporary, epoch); err != nil {
		return fmt.Errorf("normalize staging directories: %w", err)
	}
	if err := os.Rename(temporary, resolved.Output); err != nil {
		return fmt.Errorf("publish staging directory: %w", err)
	}
	committed = true
	return nil
}

func resolveAssemblyOptions(options AssemblyOptions) (AssemblyOptions, error) {
	root := options.RepositoryRoot
	if root == "" {
		root = "."
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return AssemblyOptions{}, fmt.Errorf("resolve repository root: %w", err)
	}
	absRoot, err = filepath.EvalSymlinks(absRoot)
	if err != nil {
		return AssemblyOptions{}, fmt.Errorf("resolve repository root links: %w", err)
	}
	rootInfo, err := os.Lstat(absRoot)
	if err != nil || !rootInfo.IsDir() {
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
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
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
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
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
		relative, err := filepath.Rel(sourceRoot, path)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
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
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(expected, opened) {
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
	// #nosec G302 -- 0644 is the deliberate root-owned package payload mode; the source is public release material.
	if err := os.Chmod(target, 0o644); err != nil {
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
	relative, err := filepath.Rel(bundleRoot, source)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("native resource escaped the retained bundle")
	}
	expected, err := os.Lstat(source)
	if err != nil || !expected.Mode().IsRegular() || expected.Mode()&os.ModeSymlink != 0 ||
		expected.Size() <= 0 || uint64(expected.Size()) != resource.size { // #nosec G115 -- positivity is checked first.
		return errors.New("native resource size or type does not match its verified projection")
	}
	// #nosec G304 -- source is a confined, canonical signed bundle path validated above.
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	opened, err := input.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(expected, opened) {
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
	if err != nil || written <= 0 || uint64(written) != resource.size { // #nosec G115 -- positivity is checked first.
		return errors.New("native resource changed while copying")
	}
	if !strings.EqualFold(hex.EncodeToString(digest.Sum(nil)), resource.sha256) {
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
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("staging tree contains an invalid entry")
		}
		if entry.IsDir() {
			directories = append(directories, path)
		} else if !info.Mode().IsRegular() {
			return errors.New("staging tree contains a special entry")
		}
		return nil
	}); err != nil {
		return err
	}
	sort.Slice(directories, func(i, j int) bool {
		return strings.Count(directories[i], string(filepath.Separator)) >
			strings.Count(directories[j], string(filepath.Separator))
	})
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
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("input must be a bounded non-empty regular file")
	}
	// #nosec G304 -- path is an explicit release input already constrained by Lstat and size checks.
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
	return result
}
