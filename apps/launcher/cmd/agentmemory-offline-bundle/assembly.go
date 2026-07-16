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
	"strings"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/infrastructure/releasefile"
)

// Go statement coverage cannot attribute execution to constant declarations.
// TestPF001OfflineBundleStaticAuthorityIsExact asserts every release value.
const (
	// mutator-disable-next-line *
	maximumOfflineTrustBytes = 128 * 1024
	// mutator-disable-next-line *
	maximumOfflineEnvelopeBytes = 32 * 1024 * 1024
	// mutator-disable-next-line *
	distributionEnvelopePath = "bootstrap/distribution-manifest.json"
)

// AssembleOptions contains every caller-controlled retained-bundle input.
type AssembleOptions struct {
	RepositoryRoot    string
	StagingRoot       string
	SignedEnvelope    string
	TrustDocument     string
	Output            string
	SourceEpoch       int64
	VerificationEpoch int64
}

// Command is one closed source-revision observation.
type Command struct {
	Name string
	Args []string
	Dir  string
}

// CommandRunner isolates Git from deterministic bundle assembly.
type CommandRunner interface {
	Run(context.Context, Command) ([]byte, error)
}

type bundleResource struct {
	id     string
	path   string
	sha256 string
	size   uint64
}

func (r bundleResource) valid() bool {
	if r.id == "" || len(r.id) > 128 || r.path == "" || r.size == 0 || len(r.sha256) != sha256.Size*2 ||
		strings.Contains(r.path, `\`) || strings.ContainsRune(r.path, 0) || filepath.IsAbs(r.path) ||
		filepath.ToSlash(filepath.Clean(filepath.FromSlash(r.path))) != r.path || r.path == "." ||
		strings.HasPrefix(r.path, "../") || r.path == distributionEnvelopePath {
		return false
	}
	_, err := hex.DecodeString(r.sha256)
	return err == nil && strings.ToLower(r.sha256) == r.sha256
}

type bundleInventory struct {
	sourceCommit string
	resources    []bundleResource
}

func (i bundleInventory) clone() bundleInventory {
	return bundleInventory{sourceCommit: i.sourceCommit, resources: append([]bundleResource(nil), i.resources...)}
}

type envelopeDecoder func([]byte) (bundleInventory, error)
type bundleValidator func(context.Context, string, string, string, string, time.Time) error

type bundleOperations interface {
	MkdirTemp(string, string) (string, error)
	MkdirAll(string, os.FileMode) error
	CopyExactBundleResource(string, string, bundleResource, time.Time) error
	RejectUninventoriedBundleEntries(string, map[string]bundleResource) error
	WriteExactFile(string, []byte, time.Time) error
	NormalizeBundleDirectories(string, time.Time) error
	Rename(string, string) error
	RemoveAll(string) error
}

type systemBundleOperations struct{}

func (systemBundleOperations) MkdirTemp(parent string, pattern string) (string, error) {
	return os.MkdirTemp(parent, pattern)
}

func (systemBundleOperations) MkdirAll(path string, mode os.FileMode) error {
	return os.MkdirAll(path, mode)
}

func (systemBundleOperations) CopyExactBundleResource(
	root string,
	target string,
	resource bundleResource,
	epoch time.Time,
) error {
	return copyExactBundleResource(root, target, resource, epoch)
}

func (systemBundleOperations) RejectUninventoriedBundleEntries(
	root string,
	expected map[string]bundleResource,
) error {
	return rejectUninventoriedBundleEntries(root, expected)
}

func (systemBundleOperations) WriteExactFile(path string, content []byte, epoch time.Time) error {
	return writeExactFile(path, content, epoch)
}

func (systemBundleOperations) NormalizeBundleDirectories(root string, epoch time.Time) error {
	return normalizeBundleDirectories(root, epoch)
}

func (systemBundleOperations) Rename(oldPath string, newPath string) error {
	return os.Rename(oldPath, newPath)
}

func (systemBundleOperations) RemoveAll(path string) error { return os.RemoveAll(path) }

// This closed declarative matrix is asserted field-for-field by
// TestPF001OfflineBundleStaticAuthorityIsExact.
var certifiedReleaseTargets = []struct{ operatingSystem, architecture string }{
	// mutator-disable-next-line *
	{operatingSystem: "linux", architecture: "amd64"},
	// mutator-disable-next-line *
	{operatingSystem: "linux", architecture: "arm64"},
	// mutator-disable-next-line *
	{operatingSystem: "darwin", architecture: "amd64"},
	// mutator-disable-next-line *
	{operatingSystem: "darwin", architecture: "arm64"},
	// mutator-disable-next-line *
	{operatingSystem: "windows", architecture: "amd64"},
}

// Assemble publishes one private, immutable retained bundle only after its
// exact signed inventory passes production verification for every certified
// PF-001 platform. It neither signs nor rebuilds any input artifact.
func Assemble(
	ctx context.Context,
	options AssembleOptions,
	runner CommandRunner,
	decode envelopeDecoder,
	validate bundleValidator,
) error {
	return assembleWithOperations(
		ctx, options, runner, decode, validate, systemBundleOperations{},
	)
}

func assembleWithOperations(
	ctx context.Context,
	options AssembleOptions,
	runner CommandRunner,
	decode envelopeDecoder,
	validate bundleValidator,
	operations bundleOperations,
) error {
	if ctx == nil || runner == nil || decode == nil || validate == nil || operations == nil {
		return errors.New("offline bundle assembly capabilities are incomplete")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	resolved, err := resolveAssembleOptions(options)
	if err != nil {
		return err
	}
	commit, err := cleanBundleSourceCommit(ctx, runner, resolved.RepositoryRoot)
	if err != nil {
		return err
	}
	envelope, err := readBoundedRegularFile(resolved.SignedEnvelope, maximumOfflineEnvelopeBytes)
	if err != nil {
		return fmt.Errorf("read signed distribution envelope: %w", err)
	}
	inventory, err := decode(envelope)
	if err != nil || inventory.sourceCommit != commit {
		// Transient envelope clearing is memory hygiene with no observable functional outcome.
		// mutator-disable-next-line statement/remove
		clear(envelope)
		return errors.New("signed distribution inventory does not bind the clean source revision")
	}
	expected, err := validateBundleInventory(inventory)
	if err != nil {
		// mutator-disable-next-line statement/remove
		clear(envelope)
		return err
	}
	trust, err := readBoundedRegularFile(resolved.TrustDocument, maximumOfflineTrustBytes)
	if err != nil {
		// mutator-disable-next-line statement/remove
		clear(envelope)
		return fmt.Errorf("read native release trust: %w", err)
	}
	encodedTrust := base64.StdEncoding.EncodeToString(trust)
	// Clearing the transient public-authority bytes is a defense-in-depth memory-hygiene action;
	// it has no observable functional outcome that a mutation test can assert.
	// mutator-disable-next-line statement/remove
	clear(trust)

	parent := filepath.Dir(resolved.Output)
	temporary, err := operations.MkdirTemp(parent, ".agentmemory-offline-bundle-")
	if err != nil {
		// mutator-disable-next-line statement/remove
		clear(envelope)
		return fmt.Errorf("create private bundle root: %w", err)
	}
	defer func() {
		// mutator-disable-next-line statement/remove
		clear(envelope)
		_ = operations.RemoveAll(temporary)
	}()
	epoch := time.Unix(resolved.SourceEpoch, 0).UTC()
	for _, resource := range inventory.resources {
		target := filepath.Join(temporary, filepath.FromSlash(resource.path))
		if err := operations.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return fmt.Errorf("create bundle resource parent: %w", err)
		}
		if err := operations.CopyExactBundleResource(resolved.StagingRoot, target, resource, epoch); err != nil {
			return fmt.Errorf("copy resource %s: %w", resource.id, err)
		}
	}
	if err := operations.RejectUninventoriedBundleEntries(resolved.StagingRoot, expected); err != nil {
		return err
	}
	manifestTarget := filepath.Join(temporary, filepath.FromSlash(distributionEnvelopePath))
	if err := operations.MkdirAll(filepath.Dir(manifestTarget), 0o700); err != nil {
		return fmt.Errorf("create distribution envelope parent: %w", err)
	}
	if err := operations.WriteExactFile(manifestTarget, envelope, epoch); err != nil {
		return fmt.Errorf("write distribution envelope: %w", err)
	}
	if err := operations.NormalizeBundleDirectories(temporary, epoch); err != nil {
		return fmt.Errorf("normalize retained bundle: %w", err)
	}
	verifiedAt := time.Unix(resolved.VerificationEpoch, 0).UTC()
	for _, target := range certifiedReleaseTargets {
		if err := validate(ctx, temporary, encodedTrust, target.operatingSystem, target.architecture, verifiedAt); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("release verification failed for %s/%s", target.operatingSystem, target.architecture)
		}
	}
	if err := operations.Rename(temporary, resolved.Output); err != nil {
		return fmt.Errorf("publish retained offline bundle: %w", err)
	}
	return nil
}

func resolveAssembleOptions(options AssembleOptions) (AssembleOptions, error) {
	absRoot, err := filepath.Abs(options.RepositoryRoot)
	if err != nil {
		return AssembleOptions{}, fmt.Errorf("resolve repository root: %w", err)
	}
	absRoot, err = filepath.EvalSymlinks(absRoot)
	if err != nil {
		return AssembleOptions{}, fmt.Errorf("resolve repository links: %w", err)
	}
	if info, statErr := os.Lstat(absRoot); !releasefile.StableDirectory(info, statErr) {
		return AssembleOptions{}, errors.New("repository root must be a non-symlink directory")
	}
	if options.SourceEpoch <= 0 || options.VerificationEpoch <= 0 {
		return AssembleOptions{}, errors.New("source and verification epochs must be positive")
	}
	resolved := options
	resolved.RepositoryRoot = absRoot
	for name, value := range map[string]*string{
		"staging root":    &resolved.StagingRoot,
		"signed envelope": &resolved.SignedEnvelope,
		"trust document":  &resolved.TrustDocument,
		"output":          &resolved.Output,
	} {
		if *value == "" {
			return AssembleOptions{}, fmt.Errorf("%s is required", name)
		}
		if !filepath.IsAbs(*value) {
			*value = filepath.Join(absRoot, *value)
		}
		*value = filepath.Clean(*value)
	}
	stagingInfo, err := os.Lstat(resolved.StagingRoot)
	if !releasefile.StableDirectory(stagingInfo, err) {
		return AssembleOptions{}, errors.New("staging root must be a non-symlink directory")
	}
	if _, err := os.Lstat(resolved.Output); err == nil {
		return AssembleOptions{}, errors.New("output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return AssembleOptions{}, fmt.Errorf("inspect output: %w", err)
	}
	parentInfo, err := os.Lstat(filepath.Dir(resolved.Output))
	if !releasefile.StableDirectory(parentInfo, err) {
		return AssembleOptions{}, errors.New("output parent must be an existing non-symlink directory")
	}
	return resolved, nil
}

func cleanBundleSourceCommit(ctx context.Context, runner CommandRunner, root string) (string, error) {
	status, err := runner.Run(ctx, Command{
		Name: "git", Args: []string{"status", "--porcelain=v1", "--untracked-files=all"}, Dir: root,
	})
	if err != nil || len(status) != 0 {
		return "", errors.New("source revision is unavailable or dirty")
	}
	raw, err := runner.Run(ctx, Command{Name: "git", Args: []string{"rev-parse", "HEAD"}, Dir: root})
	commit := strings.TrimSpace(string(raw))
	if err != nil || !canonicalSourceCommit(commit) {
		return "", errors.New("source revision is unavailable or dirty")
	}
	return commit, nil
}

func canonicalSourceCommit(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return strings.Trim(value, "0") != ""
}

func validateBundleInventory(inventory bundleInventory) (map[string]bundleResource, error) {
	if !canonicalSourceCommit(inventory.sourceCommit) || len(inventory.resources) == 0 {
		return nil, errors.New("signed bundle inventory is incomplete")
	}
	byPath := make(map[string]bundleResource, len(inventory.resources))
	ids := make(map[string]struct{}, len(inventory.resources))
	for _, resource := range inventory.resources {
		if !resource.valid() {
			return nil, errors.New("signed bundle resource projection is invalid")
		}
		if _, duplicate := ids[resource.id]; duplicate {
			return nil, errors.New("signed bundle resource identifier is duplicated")
		}
		if _, duplicate := byPath[resource.path]; duplicate {
			return nil, errors.New("signed bundle resource path is aliased")
		}
		ids[resource.id] = struct{}{}
		byPath[resource.path] = resource
	}
	return byPath, nil
}

func copyExactBundleResource(root string, target string, resource bundleResource, epoch time.Time) error {
	source := filepath.Join(root, filepath.FromSlash(resource.path))
	info, err := os.Lstat(source)
	if !releasefile.ExactRegularSize(info, err, resource.size) {
		return errors.New("resource type or size differs from the signed inventory")
	}
	// #nosec G304 -- source is one validated signed-inventory path beneath the explicit staging root.
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	opened, err := input.Stat()
	if !releasefile.SameRegularFile(info, opened, err) {
		return errors.New("resource changed while opening")
	}
	// #nosec G304 -- target is confined to a new private output root.
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
		written, err, resource.size, hex.EncodeToString(digest.Sum(nil)), resource.sha256, false,
	) {
		return errors.New("resource bytes differ from the signed inventory")
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	if err := os.Chtimes(target, epoch, epoch); err != nil {
		return err
	}
	failed = false
	return nil
}

func rejectUninventoriedBundleEntries(root string, expected map[string]bundleResource) error {
	seen := make(map[string]struct{}, len(expected))
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(path)
		if !releasefile.StableEntry(info, err) {
			return errors.New("staging tree contains a linked or unstable entry")
		}
		if entry.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return errors.New("staging tree contains a special entry")
		}
		relative, confined := releasefile.ConfinedRelative(root, path)
		if !confined {
			return errors.New("staging entry escaped its root")
		}
		canonical := filepath.ToSlash(relative)
		if _, exists := expected[canonical]; !exists {
			return errors.New("staging tree contains an uninventoried file")
		}
		seen[canonical] = struct{}{}
		return nil
	})
	if err != nil {
		return err
	}
	if len(seen) != len(expected) {
		return errors.New("staging tree is missing an inventoried file")
	}
	return nil
}

func writeExactFile(path string, content []byte, epoch time.Time) error {
	// #nosec G304 -- path is the one fixed distribution envelope beneath a new private root.
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
	written, err := file.Write(content)
	if err != nil || written != len(content) || file.Sync() != nil || file.Close() != nil {
		return errors.New("distribution envelope publication failed")
	}
	if err := os.Chtimes(path, epoch, epoch); err != nil {
		return err
	}
	failed = false
	return nil
}

func normalizeBundleDirectories(root string, epoch time.Time) error {
	directories := make([]string, 0, 64)
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			directories = append(directories, path)
		}
		return nil
	}); err != nil {
		return err
	}
	for _, directory := range directories {
		if err := os.Chmod(directory, 0o700); err != nil { // #nosec G302 -- private retained bundle boundary.
			return err
		}
		if err := os.Chtimes(directory, epoch, epoch); err != nil {
			return err
		}
	}
	return nil
}

func readBoundedRegularFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if !releasefile.BoundedRegular(info, err, maximum) {
		return nil, errors.New("input must be a bounded non-empty regular file")
	}
	// #nosec G304 -- explicit release input bounded above.
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

func decodeProductionInventory(raw []byte) (bundleInventory, error) {
	signed, err := releaseinventory.DecodeSignedManifestV1(raw)
	if err != nil {
		return bundleInventory{}, err
	}
	manifest := signed.Manifest()
	return projectProductionInventory(manifest.SourceCommit(), manifest.Resources())
}

func projectProductionInventory(
	sourceCommit string,
	resources []releaseinventory.Resource,
) (bundleInventory, error) {
	projected := make([]bundleResource, 0, len(resources))
	for _, resource := range resources {
		path := strings.TrimPrefix(resource.SourceRef(), "bundle://")
		if path == resource.SourceRef() || path == "" {
			return bundleInventory{}, errors.New("release resource is not retained in the offline bundle")
		}
		projected = append(projected, bundleResource{
			id: resource.ID(), path: path, sha256: resource.Digest().Hex(), size: resource.Size(),
		})
	}
	return bundleInventory{sourceCommit: sourceCommit, resources: projected}, nil
}

type processRunner struct{}

func (processRunner) Run(ctx context.Context, command Command) ([]byte, error) {
	if ctx == nil || command.Name != "git" || command.Dir == "" {
		return nil, errors.New("invalid or disallowed offline-bundle command")
	}
	process := exec.CommandContext(ctx, command.Name, command.Args...) // #nosec G204 -- executable is closed above.
	process.Dir = command.Dir
	return process.CombinedOutput()
}
