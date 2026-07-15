package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRepositoryReleaseWorkflowMatchesReviewedContract(t *testing.T) {
	t.Parallel()
	if violations := Check(Options{RepositoryRoot: repositoryRoot(t)}); len(violations) != 0 {
		t.Fatalf("Check() violations=%v", violations)
	}
}

func TestReleaseWorkflowCheckerRejectsEveryByteSubstitution(t *testing.T) {
	t.Parallel()
	root := copyWorkflowFixture(t)
	path := filepath.Join(root, filepath.FromSlash(releaseWorkflowPath))
	// #nosec G304 -- path is the closed workflow path under a private test root.
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, replacement := range map[string]string{
		"mutable release":  strings.Replace(string(content), ".enabled == true", ".enabled == false", 1),
		"untrusted action": strings.Replace(string(content), downloadArtifactCommit, "main", 1),
		"rebuild":          strings.Replace(string(content), "without rebuilding", "after rebuilding", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(replacement), 0o644); err != nil { // #nosec G306 -- contract mode under a private test root.
				t.Fatal(err)
			}
			if violations := Check(Options{RepositoryRoot: root}); len(violations) != 1 {
				t.Fatalf("violations=%v", violations)
			}
			if err := os.WriteFile(path, content, 0o644); err != nil { // #nosec G306,G703 -- closed contract path/mode under a private test root.
				t.Fatal(err)
			}
		})
	}
}

func TestReleaseWorkflowCheckerRejectsMissingLinksAndInvocationErrors(t *testing.T) {
	t.Parallel()
	root := copyWorkflowFixture(t)
	path := filepath.Join(root, filepath.FromSlash(releaseWorkflowPath))
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("foreign.yml", path); err != nil {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if violations := Check(Options{RepositoryRoot: root}); len(violations) != 1 {
		t.Fatalf("violations=%v", violations)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-root", t.TempDir()}, &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "Release workflow check failed") {
		t.Fatalf("run(missing)=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"positional"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run(positional)=%d", code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"-root", repositoryRoot(t)}, &stdout, &stderr); code != 0 ||
		stdout.String() != "Release workflow check passed\n" || stderr.Len() != 0 {
		t.Fatalf("run(valid)=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func repositoryRoot(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func copyWorkflowFixture(t testing.TB) string {
	t.Helper()
	root := t.TempDir()
	for workflow := range reviewedWorkflows {
		content, err := os.ReadFile(filepath.Join(repositoryRoot(t), filepath.FromSlash(workflow)))
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(root, filepath.FromSlash(workflow))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, content, 0o644); err != nil { // #nosec G306,G703 -- closed contract path/mode under a private test root.
			t.Fatal(err)
		}
	}
	return root
}
