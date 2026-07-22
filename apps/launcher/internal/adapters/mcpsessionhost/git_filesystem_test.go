package mcpsessionhost

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpsessionapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/mcpsession"
)

func TestPF005FilesystemGitResolverFindsOrdinaryRepositoryFromSubdirectory(t *testing.T) {
	t.Parallel()
	repository := t.TempDir()
	gitDirectory := filepath.Join(repository, ".git")
	workspace := filepath.Join(repository, "src", "nested")
	mustDirectory(t, gitDirectory)
	mustDirectory(t, workspace)
	resolver := mustFilesystemGitResolver(t)

	identity, err := resolver.Resolve(t.Context(), filesystemPathIdentity(workspace, "a"))
	if err != nil {
		t.Fatal(err)
	}
	if identity.Coverage != mcpsession.GitCoveragePartial || len(identity.RepositoryID) != 64 ||
		len(identity.WorktreeID) != 64 {
		t.Fatalf("identity=%#v", identity)
	}

	rootIdentity, err := resolver.Resolve(t.Context(), filesystemPathIdentity(repository, "a"))
	if err != nil || rootIdentity.Coverage != mcpsession.GitCoverageComplete ||
		rootIdentity.RepositoryID != identity.RepositoryID {
		t.Fatalf("root identity=%#v error=%v", rootIdentity, err)
	}
}

func TestPF005FilesystemGitResolverHandlesExternalWorktreeAndSubmoduleLocators(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	common := filepath.Join(root, "main", ".git")
	worktreeGit := filepath.Join(common, "worktrees", "feature")
	workspace := filepath.Join(root, "feature")
	mustDirectory(t, common)
	mustDirectory(t, worktreeGit)
	mustDirectory(t, workspace)
	mustWrite(t, filepath.Join(workspace, ".git"), "gitdir: "+worktreeGit+"\n")
	mustWrite(t, filepath.Join(worktreeGit, "commondir"), "../..\n")
	resolver := mustFilesystemGitResolver(t)

	identity, err := resolver.Resolve(t.Context(), filesystemPathIdentity(workspace, "b"))
	if err != nil || identity.Coverage != mcpsession.GitCoveragePartial ||
		len(identity.RepositoryID) != 64 || len(identity.WorktreeID) != 64 {
		t.Fatalf("worktree identity=%#v error=%v", identity, err)
	}

	submodule := filepath.Join(root, "main", "modules", "child")
	submoduleGit := filepath.Join(common, "modules", "child")
	mustDirectory(t, submodule)
	mustDirectory(t, submoduleGit)
	mustWrite(t, filepath.Join(submodule, ".git"), "gitdir: ../../.git/modules/child\n")
	submoduleIdentity, err := resolver.Resolve(
		t.Context(), filesystemPathIdentity(submodule, "c"),
	)
	if err != nil || submoduleIdentity.Coverage != mcpsession.GitCoveragePartial ||
		submoduleIdentity.RepositoryID == identity.RepositoryID {
		t.Fatalf("submodule identity=%#v error=%v", submoduleIdentity, err)
	}
}

func TestPF005FilesystemGitResolverRejectsUnsafeMetadataAndReportsNonGit(t *testing.T) {
	t.Parallel()
	resolver := mustFilesystemGitResolver(t)
	plain := t.TempDir()
	identity, err := resolver.Resolve(t.Context(), filesystemPathIdentity(plain, "d"))
	if err != nil || identity.Coverage != mcpsession.GitCoverageNone ||
		identity.RepositoryID != "" || identity.WorktreeID != "" {
		t.Fatalf("plain identity=%#v error=%v", identity, err)
	}

	unsafe := t.TempDir()
	target := filepath.Join(unsafe, "actual")
	mustDirectory(t, target)
	if err := os.Symlink(target, filepath.Join(unsafe, ".git")); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(t.Context(), filesystemPathIdentity(unsafe, "e")); err == nil {
		t.Fatal("symlink .git locator was accepted")
	}

	broken := t.TempDir()
	mustWrite(t, filepath.Join(broken, ".git"), "gitdir: missing\n")
	if _, err := resolver.Resolve(t.Context(), filesystemPathIdentity(broken, "f")); err == nil {
		t.Fatal("missing external Git directory was accepted")
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolver.Resolve(cancelled, filesystemPathIdentity(plain, "g")); err == nil {
		t.Fatal("cancelled resolution was accepted")
	}
	if _, err := NewFilesystemGitIdentityResolver(nil); err == nil {
		t.Fatal("empty key was accepted")
	}
}

func mustFilesystemGitResolver(t testing.TB) *FilesystemGitIdentityResolver {
	t.Helper()
	resolver, err := NewFilesystemGitIdentityResolver([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}

func filesystemPathIdentity(path, seed string) mcpsessionapp.PathIdentity {
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		path = resolved
	}
	return mcpsessionapp.PathIdentity{
		LogicalPath: path, RealPath: path, DeviceIdentity: "dev:1",
		PathFingerprint: strings.Repeat(seed, 64),
	}
}

func mustDirectory(t testing.TB, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t testing.TB, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
