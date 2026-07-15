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

const maximumTrustDocumentBytes = 128 * 1024

// StageOptions contains every caller-controlled desktop package input.
type StageOptions struct {
	RepositoryRoot    string
	BundleRoot        string
	TrustDocument     string
	Output            string
	OperatingSystem   string
	Architecture      string
	SourceEpoch       int64
	VerificationEpoch int64
}

// Command is one closed external process invocation.
type Command struct {
	Name string
	Args []string
	Dir  string
}

// CommandRunner isolates the clean-revision proof from deterministic staging.
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
	decoded, err := hex.DecodeString(r.sha256)
	return err == nil && len(decoded) == sha256.Size
}

type verifiedNativePackage struct {
	operatingSystem string
	architecture    string
	launcher        verifiedNativeResource
	helper          verifiedNativeResource
}

func (p verifiedNativePackage) valid(operatingSystem string, architecture string) bool {
	return p.operatingSystem == operatingSystem && p.architecture == architecture &&
		p.launcher.valid() && p.helper.valid() && p.launcher.resourceID != p.helper.resourceID &&
		p.launcher.bundlePath != p.helper.bundlePath && p.launcher.sha256 != p.helper.sha256
}

// Stage verifies one complete retained release and publishes an atomic native
// package payload containing only its exact manifest-bound desktop binaries.
func Stage(
	ctx context.Context,
	options StageOptions,
	runner CommandRunner,
	validateTrust trustValidator,
	resolveBundle bundleResolver,
) error {
	if ctx == nil || runner == nil || validateTrust == nil || resolveBundle == nil {
		return errors.New("native package staging capabilities are incomplete")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	resolved, err := resolveStageOptions(options)
	if err != nil {
		return err
	}
	trust, err := readBoundedRegularFile(resolved.TrustDocument, maximumTrustDocumentBytes)
	if err != nil {
		return fmt.Errorf("read release trust: %w", err)
	}
	encodedTrust := base64.StdEncoding.EncodeToString(trust)
	clear(trust)
	if err := validateTrust(encodedTrust); err != nil {
		return errors.New("release trust is not accepted by the production decoder")
	}
	if err := requireCleanRevision(ctx, runner, resolved.RepositoryRoot); err != nil {
		return err
	}
	epoch := time.Unix(resolved.SourceEpoch, 0).UTC()
	parent := filepath.Dir(resolved.Output)
	temporary, err := os.MkdirTemp(parent, ".agentmemory-native-package-")
	if err != nil {
		return fmt.Errorf("create private package root: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(temporary)
		}
	}()
	verificationRoot := filepath.Join(temporary, ".verification-bundle")
	if err := copyBundleTree(resolved.BundleRoot, verificationRoot, 0o700, 0o600, epoch); err != nil {
		return fmt.Errorf("retain private release bundle: %w", err)
	}
	selection, err := resolveBundle(
		ctx, verificationRoot, encodedTrust, resolved.OperatingSystem, resolved.Architecture,
		time.Unix(resolved.VerificationEpoch, 0).UTC(),
	)
	if err != nil || !selection.valid(resolved.OperatingSystem, resolved.Architecture) {
		return errors.New("release bundle failed the production verification stack")
	}
	payload := filepath.Join(temporary, "payload")
	if err := os.Mkdir(payload, 0o700); err != nil {
		return fmt.Errorf("create package payload: %w", err)
	}
	layout, err := desktopPackageLayout(resolved.OperatingSystem)
	if err != nil {
		return err
	}
	bundleTarget := filepath.Join(payload, filepath.FromSlash(layout.bundle))
	if err := os.MkdirAll(filepath.Dir(bundleTarget), 0o700); err != nil {
		return fmt.Errorf("create installed bundle parent: %w", err)
	}
	if err := copyBundleTree(verificationRoot, bundleTarget, 0o755, 0o644, epoch); err != nil {
		return fmt.Errorf("stage installed release bundle: %w", err)
	}
	for _, target := range []struct {
		path     string
		resource verifiedNativeResource
	}{
		{path: layout.launcher, resource: selection.launcher},
		{path: layout.helper, resource: selection.helper},
	} {
		absolute := filepath.Join(payload, filepath.FromSlash(target.path))
		if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
			return fmt.Errorf("create native package directory: %w", err)
		}
		if err := copyVerifiedNativeResource(verificationRoot, absolute, target.resource, epoch); err != nil {
			return fmt.Errorf("stage verified native resource: %w", err)
		}
	}
	if err := os.RemoveAll(verificationRoot); err != nil {
		return fmt.Errorf("remove private verification authority: %w", err)
	}
	if err := normalizePackageDirectories(temporary, epoch); err != nil {
		return fmt.Errorf("normalize native package directories: %w", err)
	}
	if err := os.Rename(temporary, resolved.Output); err != nil {
		return fmt.Errorf("publish native package stage: %w", err)
	}
	committed = true
	return nil
}

type packageLayout struct {
	launcher string
	helper   string
	bundle   string
}

func desktopPackageLayout(operatingSystem string) (packageLayout, error) {
	switch operatingSystem {
	case "darwin":
		return packageLayout{
			launcher: "usr/local/bin/agentmemory",
			helper:   "Library/PrivilegedHelperTools/com.rickyseezy.agentmemory.runtime-helper",
			bundle:   "Library/Application Support/AgentMemory/resources/bundle",
		}, nil
	case "windows":
		return packageLayout{
			launcher: "agentmemory.exe", helper: "bin/agentmemory-runtime-helper.exe",
			bundle: "resources/bundle",
		}, nil
	default:
		return packageLayout{}, errors.New("desktop package operating system is unsupported")
	}
}

func resolveStageOptions(options StageOptions) (StageOptions, error) {
	root := options.RepositoryRoot
	if root == "" {
		root = "."
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return StageOptions{}, fmt.Errorf("resolve repository root: %w", err)
	}
	absRoot, err = filepath.EvalSymlinks(absRoot)
	if err != nil {
		return StageOptions{}, fmt.Errorf("resolve repository root links: %w", err)
	}
	info, err := os.Lstat(absRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return StageOptions{}, errors.New("repository root is not a directory")
	}
	if options.OperatingSystem != "darwin" && options.OperatingSystem != "windows" {
		return StageOptions{}, errors.New("operating system must be darwin or windows")
	}
	if options.Architecture != "amd64" && options.Architecture != "arm64" {
		return StageOptions{}, errors.New("architecture must be amd64 or arm64")
	}
	if options.SourceEpoch <= 0 || options.VerificationEpoch <= 0 {
		return StageOptions{}, errors.New("source and verification epochs must be positive")
	}
	resolved := options
	resolved.RepositoryRoot = absRoot
	for name, value := range map[string]*string{
		"bundle root": &resolved.BundleRoot, "trust document": &resolved.TrustDocument, "output": &resolved.Output,
	} {
		if *value == "" {
			return StageOptions{}, fmt.Errorf("%s is required", name)
		}
		if !filepath.IsAbs(*value) {
			*value = filepath.Join(absRoot, *value)
		}
		*value = filepath.Clean(*value)
	}
	if _, err := os.Lstat(resolved.Output); err == nil {
		return StageOptions{}, errors.New("output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return StageOptions{}, fmt.Errorf("inspect output: %w", err)
	}
	parent, err := os.Lstat(filepath.Dir(resolved.Output))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 {
		return StageOptions{}, errors.New("output parent must be an existing non-symlink directory")
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

func copyBundleTree(
	sourceRoot string,
	targetRoot string,
	directoryMode os.FileMode,
	fileMode os.FileMode,
	epoch time.Time,
) error {
	rootInfo, err := os.Lstat(sourceRoot)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("bundle root must be a non-symlink directory")
	}
	if err := os.Mkdir(targetRoot, directoryMode); err != nil {
		return err
	}
	directories := []string{targetRoot}
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
			return errors.New("bundle contains a symbolic link")
		}
		if info.IsDir() {
			if err := os.Mkdir(target, directoryMode); err != nil {
				return err
			}
			directories = append(directories, target)
			return nil
		}
		if !info.Mode().IsRegular() {
			return errors.New("bundle contains a special entry")
		}
		return copyRegularFile(path, target, info, fileMode, epoch)
	})
	if err != nil {
		return err
	}
	manifest := filepath.Join(targetRoot, "bootstrap", "distribution-manifest.json")
	if info, err := os.Lstat(manifest); err != nil || !info.Mode().IsRegular() {
		return errors.New("bundle is missing bootstrap/distribution-manifest.json")
	}
	sort.Slice(directories, func(i, j int) bool { return len(directories[i]) > len(directories[j]) })
	for _, directory := range directories {
		if err := os.Chmod(directory, directoryMode); err != nil { // #nosec G302 -- caller supplies a closed private/public package mode.
			return err
		}
		if err := os.Chtimes(directory, epoch, epoch); err != nil {
			return err
		}
	}
	return nil
}

func copyRegularFile(
	source string,
	target string,
	expected os.FileInfo,
	mode os.FileMode,
	epoch time.Time,
) error {
	// #nosec G304 -- source is an Lstat-verified regular entry yielded beneath the explicit bundle root.
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	opened, err := input.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(expected, opened) {
		return errors.New("bundle file changed while opening")
	}
	// #nosec G304 -- target is beneath a private staging root and confined relative path.
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
	if err := os.Chmod(target, mode); err != nil { // #nosec G302 -- caller supplies a closed private/public package mode.
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
	if !resource.valid() || strings.Contains(resource.bundlePath, `\`) || strings.ContainsRune(resource.bundlePath, 0) ||
		filepath.IsAbs(resource.bundlePath) || filepath.ToSlash(filepath.Clean(filepath.FromSlash(resource.bundlePath))) != resource.bundlePath ||
		resource.bundlePath == "." || strings.HasPrefix(resource.bundlePath, "../") {
		return errors.New("native resource projection is invalid")
	}
	source := filepath.Join(bundleRoot, filepath.FromSlash(resource.bundlePath))
	expected, err := os.Lstat(source)
	if err != nil || !expected.Mode().IsRegular() || expected.Size() <= 0 || uint64(expected.Size()) != resource.size { // #nosec G115 -- positivity is checked.
		return errors.New("native resource size or type differs from its verified projection")
	}
	// #nosec G304 -- source is one canonical manifest-selected bundle path.
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	opened, err := input.Stat()
	if err != nil || !os.SameFile(expected, opened) {
		return errors.New("native resource changed while opening")
	}
	// #nosec G304 -- target is one fixed native package leaf.
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
	if err != nil || written <= 0 || uint64(written) != resource.size ||
		!strings.EqualFold(hex.EncodeToString(digest.Sum(nil)), resource.sha256) { // #nosec G115 -- positivity is checked.
		return errors.New("native resource bytes differ from their verified projection")
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	// #nosec G302 -- native installed entry points are intentionally executable.
	if err := os.Chmod(target, 0o755); err != nil {
		return err
	}
	if err := os.Chtimes(target, epoch, epoch); err != nil {
		return err
	}
	failed = false
	return nil
}

func normalizePackageDirectories(root string, epoch time.Time) error {
	directories := make([]string, 0, 32)
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("package stage contains an invalid entry")
		}
		if entry.IsDir() {
			directories = append(directories, path)
		} else if !info.Mode().IsRegular() {
			return errors.New("package stage contains a special entry")
		}
		return nil
	}); err != nil {
		return err
	}
	sort.Slice(directories, func(i, j int) bool { return len(directories[i]) > len(directories[j]) })
	for _, directory := range directories {
		// #nosec G122,G302 -- private symlink-rejected stage paths become root-owned package directories.
		if err := os.Chmod(directory, 0o755); err != nil {
			return err
		}
		// #nosec G122 -- private symlink-rejected stage path.
		if err := os.Chtimes(directory, epoch, epoch); err != nil {
			return err
		}
	}
	return nil
}

func readBoundedRegularFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("input must be a bounded non-empty regular file")
	}
	// #nosec G304 -- explicit release input constrained above.
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
	if ctx == nil || command.Name != "git" || command.Dir == "" {
		return nil, errors.New("invalid or disallowed package-stage command")
	}
	process := exec.CommandContext(ctx, command.Name, command.Args...) // #nosec G204 -- executable is closed above.
	process.Dir = command.Dir
	output, err := process.CombinedOutput()
	if err != nil {
		return nil, err
	}
	return output, nil
}
