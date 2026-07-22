package mcpsessionhost

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpsessionapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/mcpsession"
)

const maximumGitMetadataBytes = 4096

// FilesystemGitIdentityResolver reads only Git's documented repository locator
// files. It avoids PATH/executable discovery and never widens the workspace mount.
type FilesystemGitIdentityResolver struct{ key [pathIdentityKeyBytes]byte }

// NewFilesystemGitIdentityResolver binds repository identities to one installation key.
func NewFilesystemGitIdentityResolver(key []byte) (*FilesystemGitIdentityResolver, error) {
	if len(key) != pathIdentityKeyBytes {
		return nil, errors.New("git metadata identity key is invalid")
	}
	resolver := &FilesystemGitIdentityResolver{}
	copy(resolver.key[:], key)
	return resolver, nil
}

// Resolve supports ordinary .git directories plus linked-worktree/submodule
// `gitdir:` locators and their optional `commondir` indirection.
func (r *FilesystemGitIdentityResolver) Resolve(
	ctx context.Context,
	path mcpsessionapp.PathIdentity,
) (mcpsessionapp.GitIdentity, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || !validPathIdentity(path) {
		return mcpsessionapp.GitIdentity{}, errors.New("git metadata identity is invalid")
	}
	repositoryRoot, locator, found, err := findGitLocator(ctx, path.RealPath)
	if err != nil {
		return mcpsessionapp.GitIdentity{}, err
	}
	if !found {
		return mcpsessionapp.GitIdentity{Coverage: mcpsession.GitCoverageNone}, nil
	}
	worktreeDirectory, err := resolveGitDirectory(locator, repositoryRoot)
	if err != nil {
		return mcpsessionapp.GitIdentity{}, err
	}
	commonDirectory, err := resolveCommonDirectory(worktreeDirectory)
	if err != nil {
		return mcpsessionapp.GitIdentity{}, err
	}
	coverage := mcpsession.GitCoveragePartial
	if pathWithin(path.RealPath, repositoryRoot) && pathWithin(path.RealPath, worktreeDirectory) &&
		pathWithin(path.RealPath, commonDirectory) {
		coverage = mcpsession.GitCoverageComplete
	}
	return mcpsessionapp.GitIdentity{
		RepositoryID: r.fingerprint("agentmemory.git-repository.v1", commonDirectory),
		WorktreeID: r.fingerprint(
			"agentmemory.git-worktree.v1", commonDirectory, worktreeDirectory, path.PathFingerprint,
		),
		Coverage: coverage,
	}, nil
}

func validPathIdentity(path mcpsessionapp.PathIdentity) bool {
	_, err := mcpsession.NewWorkspaceIdentity(mcpsession.WorkspaceIdentityInput{
		LogicalPath: path.LogicalPath, RealPath: path.RealPath,
		DeviceIdentity: path.DeviceIdentity, PathFingerprint: path.PathFingerprint,
		GitCoverage: mcpsession.GitCoverageNone,
	})
	return err == nil
}

func findGitLocator(ctx context.Context, start string) (string, string, bool, error) {
	current := start
	for {
		if err := ctx.Err(); err != nil {
			return "", "", false, err
		}
		locator := filepath.Join(current, ".git")
		info, err := os.Lstat(locator)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
				return "", "", false, errors.New("git metadata locator is unsafe")
			}
			return current, locator, true, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", "", false, errors.New("git metadata locator is unavailable")
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", "", false, nil
		}
		current = parent
	}
}

func resolveGitDirectory(locator, repositoryRoot string) (string, error) {
	info, err := os.Lstat(locator)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("git metadata locator is unavailable")
	}
	if info.IsDir() {
		return stableDirectory(locator)
	}
	value, err := stableMetadataLine(locator)
	if err != nil || !strings.HasPrefix(value, "gitdir: ") {
		return "", errors.New("git metadata locator is invalid")
	}
	selected := strings.TrimPrefix(value, "gitdir: ")
	if selected == "" || strings.TrimSpace(selected) != selected || strings.ContainsAny(selected, "\x00\r\n") {
		return "", errors.New("git metadata locator is invalid")
	}
	if !filepath.IsAbs(selected) {
		selected = filepath.Join(repositoryRoot, selected)
	}
	return stableDirectory(filepath.Clean(selected))
}

func resolveCommonDirectory(gitDirectory string) (string, error) {
	locator := filepath.Join(gitDirectory, "commondir")
	info, err := os.Lstat(locator)
	if errors.Is(err, os.ErrNotExist) {
		return gitDirectory, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("git common metadata is unavailable")
	}
	value, err := stableMetadataLine(locator)
	if err != nil || value == "" || strings.TrimSpace(value) != value ||
		strings.ContainsAny(value, "\x00\r\n") {
		return "", errors.New("git common metadata is invalid")
	}
	if !filepath.IsAbs(value) {
		value = filepath.Join(gitDirectory, value)
	}
	return stableDirectory(filepath.Clean(value))
}

func stableMetadataLine(path string) (string, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		before.Size() <= 0 || before.Size() > maximumGitMetadataBytes {
		return "", errors.New("git metadata file is unsafe")
	}
	file, err := os.Open(path) // #nosec G304 -- exact discovered .git/commondir locator.
	if err != nil {
		return "", errors.New("git metadata file is unavailable")
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return "", errors.New("git metadata file identity changed")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maximumGitMetadataBytes+1))
	after, afterError := os.Lstat(path)
	if err != nil || afterError != nil || len(payload) > maximumGitMetadataBytes ||
		after.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, after) {
		return "", errors.New("git metadata file identity changed")
	}
	value, valid := parseGitLine(payload)
	if !valid {
		return "", errors.New("git metadata file is invalid")
	}
	return value, nil
}

func stableDirectory(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !filepath.IsAbs(resolved) || filepath.Clean(resolved) != resolved {
		return "", errors.New("git metadata directory is unavailable")
	}
	before, err := os.Lstat(resolved)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("git metadata directory is unsafe")
	}
	directory, err := os.Open(resolved) // #nosec G304 -- exact canonical Git metadata directory.
	if err != nil {
		return "", errors.New("git metadata directory is unavailable")
	}
	defer func() { _ = directory.Close() }()
	opened, err := directory.Stat()
	after, afterError := os.Lstat(resolved)
	if err != nil || afterError != nil || !opened.IsDir() || after.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return "", errors.New("git metadata directory identity changed")
	}
	return resolved, nil
}

func (r *FilesystemGitIdentityResolver) fingerprint(values ...string) string {
	digest := hmac.New(sha256.New, r.key[:])
	for _, value := range values {
		_, _ = digest.Write(lengthFrame(value))
	}
	return hex.EncodeToString(digest.Sum(nil))
}

var _ mcpsessionapp.GitIdentityPort = (*FilesystemGitIdentityResolver)(nil)
