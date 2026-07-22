package mcpsessionhost

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpsessionapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/mcpsession"
)

func TestPF005GitResolverReportsCompleteAndPartialCoverageWithoutWideningWorkspace(t *testing.T) {
	t.Parallel()
	key := []byte(strings.Repeat("g", 32))
	repository := testGitPath("/repo")
	worktreePath := testGitPath("/worktrees/task")
	completeRunner := &gitRunner{responses: [][]byte{
		[]byte(repository + "\n"), []byte(filepath.Join(repository, ".git") + "\n"),
		[]byte(filepath.Join(repository, ".git") + "\n"),
	}}
	complete := mustGitResolver(t, key, completeRunner)
	identity, err := complete.Resolve(context.Background(), mcpsessionapp.PathIdentity{
		LogicalPath: repository, RealPath: repository, DeviceIdentity: "dev:1",
		PathFingerprint: strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatalf("Resolve(complete) error = %v", err)
	}
	if identity.Coverage != mcpsession.GitCoverageComplete || len(identity.RepositoryID) != 64 ||
		len(identity.WorktreeID) != 64 {
		t.Fatalf("complete identity = %#v", identity)
	}

	partialRunner := &gitRunner{responses: [][]byte{
		[]byte(repository + "\n"), []byte(filepath.Join(repository, ".git") + "\n"),
		[]byte(filepath.Join(repository, ".git", "worktrees", "task") + "\n"),
	}}
	partial := mustGitResolver(t, key, partialRunner)
	worktree, err := partial.Resolve(context.Background(), mcpsessionapp.PathIdentity{
		LogicalPath: worktreePath, RealPath: worktreePath, DeviceIdentity: "dev:1",
		PathFingerprint: strings.Repeat("b", 64),
	})
	if err != nil {
		t.Fatalf("Resolve(partial) error = %v", err)
	}
	if worktree.Coverage != mcpsession.GitCoveragePartial ||
		worktree.RepositoryID != identity.RepositoryID || worktree.WorktreeID == identity.WorktreeID {
		t.Fatalf("partial identity = %#v complete = %#v", worktree, identity)
	}
	if partialRunner.directories[0] != worktreePath {
		t.Fatalf("git working directory = %q", partialRunner.directories[0])
	}
	wantFirst := []string{"rev-parse", "--path-format=absolute", "--show-toplevel"}
	if !reflect.DeepEqual(partialRunner.arguments[0], wantFirst) {
		t.Fatalf("first argv = %#v", partialRunner.arguments[0])
	}
}

func testGitPath(unixPath string) string {
	if runtime.GOOS != "windows" {
		return unixPath
	}
	return `C:\` + strings.ReplaceAll(strings.TrimPrefix(unixPath, "/"), "/", `\`)
}

func TestPF005GitResolverReturnsNoneOnlyForTypedNonRepository(t *testing.T) {
	t.Parallel()
	runner := &gitRunner{errors: []error{ErrNotGitRepository}}
	resolver := mustGitResolver(t, []byte(strings.Repeat("g", 32)), runner)
	identity, err := resolver.Resolve(context.Background(), mcpsessionapp.PathIdentity{
		LogicalPath: "/workspace", RealPath: "/workspace", DeviceIdentity: "dev:1",
		PathFingerprint: strings.Repeat("a", 64),
	})
	if err != nil || identity.Coverage != mcpsession.GitCoverageNone ||
		identity.RepositoryID != "" || identity.WorktreeID != "" {
		t.Fatalf("Resolve(non-repository) identity=%#v error=%v", identity, err)
	}

	for _, response := range [][]byte{
		nil, []byte("relative\n"), []byte("/repo\nforeign\n"), []byte("/repo\x00bad\n"),
	} {
		invalid := mustGitResolver(t, []byte(strings.Repeat("g", 32)), &gitRunner{
			responses: [][]byte{response},
		})
		if _, err := invalid.Resolve(context.Background(), mcpsessionapp.PathIdentity{
			LogicalPath: "/workspace", RealPath: "/workspace", DeviceIdentity: "dev:1",
			PathFingerprint: strings.Repeat("a", 64),
		}); err == nil {
			t.Fatalf("Resolve(response=%q) error = nil", response)
		}
	}
	if _, err := NewGitIdentityResolver(nil, nil); err == nil {
		t.Fatal("NewGitIdentityResolver(nil) error = nil")
	}
}

func mustGitResolver(t testing.TB, key []byte, runner GitCommandPort) *GitIdentityResolver {
	t.Helper()
	resolver, err := NewGitIdentityResolver(key, runner)
	if err != nil {
		t.Fatalf("NewGitIdentityResolver() error = %v", err)
	}
	return resolver
}

type gitRunner struct {
	responses   [][]byte
	errors      []error
	directories []string
	arguments   [][]string
	call        int
}

func (r *gitRunner) Run(_ context.Context, directory string, arguments []string) ([]byte, error) {
	r.directories = append(r.directories, directory)
	r.arguments = append(r.arguments, append([]string(nil), arguments...))
	index := r.call
	r.call++
	if index < len(r.errors) && r.errors[index] != nil {
		return nil, r.errors[index]
	}
	if index >= len(r.responses) {
		return nil, errors.New("missing fake response")
	}
	return append([]byte(nil), r.responses[index]...), nil
}
