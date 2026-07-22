package mcpsessionhost

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpsessionapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/mcpsession"
)

const maximumGitOutputBytes = 4096

// ErrNotGitRepository is the only dependency outcome converted to absent Git coverage.
var ErrNotGitRepository = errors.New("workspace is not a Git repository")

// GitCommandPort runs the signed Git executable with an exact working directory and argv.
type GitCommandPort interface {
	Run(context.Context, string, []string) ([]byte, error)
}

// GitIdentityResolver derives stable keyed repository/worktree identities on the host.
type GitIdentityResolver struct {
	key    [pathIdentityKeyBytes]byte
	runner GitCommandPort
}

// NewGitIdentityResolver copies the installation key and rejects partial composition.
func NewGitIdentityResolver(key []byte, runner GitCommandPort) (*GitIdentityResolver, error) {
	if len(key) != pathIdentityKeyBytes || nilGitRunner(runner) {
		return nil, errors.New("git identity authority is invalid")
	}
	resolver := &GitIdentityResolver{runner: runner}
	copy(resolver.key[:], key)
	return resolver, nil
}

// Resolve identifies Git state without mounting a parent or external worktree metadata.
func (r *GitIdentityResolver) Resolve(
	ctx context.Context,
	path mcpsessionapp.PathIdentity,
) (mcpsessionapp.GitIdentity, error) {
	if r == nil || ctx == nil || nilGitRunner(r.runner) {
		return mcpsessionapp.GitIdentity{}, errors.New("git identity authority is invalid")
	}
	if err := ctx.Err(); err != nil {
		return mcpsessionapp.GitIdentity{}, err
	}
	if _, err := mcpsession.NewWorkspaceIdentity(mcpsession.WorkspaceIdentityInput{
		LogicalPath: path.LogicalPath, RealPath: path.RealPath,
		DeviceIdentity: path.DeviceIdentity, PathFingerprint: path.PathFingerprint,
		GitCoverage: mcpsession.GitCoverageNone,
	}); err != nil {
		return mcpsessionapp.GitIdentity{}, errors.New("workspace identity is invalid")
	}
	repositoryRoot, err := r.gitPath(ctx, path.RealPath, "--show-toplevel")
	if errors.Is(err, ErrNotGitRepository) {
		return mcpsessionapp.GitIdentity{Coverage: mcpsession.GitCoverageNone}, nil
	}
	if err != nil {
		return mcpsessionapp.GitIdentity{}, errors.New("git repository identity is unavailable")
	}
	commonDirectory, err := r.gitPath(ctx, path.RealPath, "--git-common-dir")
	if err != nil {
		return mcpsessionapp.GitIdentity{}, errors.New("git repository identity is unavailable")
	}
	worktreeDirectory, err := r.gitPath(ctx, path.RealPath, "--git-dir")
	if err != nil {
		return mcpsessionapp.GitIdentity{}, errors.New("git worktree identity is unavailable")
	}
	coverage := mcpsession.GitCoveragePartial
	if pathWithin(path.RealPath, repositoryRoot) && pathWithin(path.RealPath, commonDirectory) &&
		pathWithin(path.RealPath, worktreeDirectory) {
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

func (r *GitIdentityResolver) gitPath(
	ctx context.Context,
	directory string,
	selector string,
) (string, error) {
	output, err := r.runner.Run(ctx, directory, []string{
		"rev-parse", "--path-format=absolute", selector,
	})
	if err != nil {
		return "", err
	}
	value, ok := parseGitLine(output)
	if !ok || !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return "", errors.New("git returned an invalid path")
	}
	return value, nil
}

func (r *GitIdentityResolver) fingerprint(values ...string) string {
	digest := hmac.New(sha256.New, r.key[:])
	for _, value := range values {
		_, _ = digest.Write(lengthFrame(value))
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func parseGitLine(output []byte) (string, bool) {
	if len(output) == 0 || len(output) > maximumGitOutputBytes || output[len(output)-1] != '\n' {
		return "", false
	}
	value := string(output[:len(output)-1])
	value = strings.TrimSuffix(value, "\r")
	return value, value != "" && !strings.ContainsAny(value, "\x00\r\n")
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func nilGitRunner(runner GitCommandPort) bool {
	if runner == nil {
		return true
	}
	value := reflect.ValueOf(runner)
	//nolint:exhaustive // Every non-nilable concrete kind is a valid capability.
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	case reflect.Invalid:
		return true
	default:
		return false
	}
}

var _ mcpsessionapp.GitIdentityPort = (*GitIdentityResolver)(nil)
