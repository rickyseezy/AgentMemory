//go:build linux || (darwin && cgo)

package process

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

func TestPF001ArgvRunnerRejectsExecutableSwapBeforeAnyLaunch(t *testing.T) {
	t.Parallel()
	directory := filepath.Join(trustedExecutableFixtureDirectory(t), "private")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := copyCurrentTestExecutable(t, directory)
	authority := testExecutableAuthority(t, path)
	mutator := publisherVerifierFunc(func(
		context.Context,
		argvprocess.ExecutableAuthority,
		ExecutableEvidence,
	) error {
		//nolint:gosec // G304: exact test-created executable path exercises a swap attack.
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.Rename(path, path+".original"); err != nil {
			return err
		}
		//nolint:gosec // G306: executable permission is required by this isolated attack fixture.
		return os.WriteFile(path, contents, 0o700)
	})
	runner, err := NewRunner(authority, mutator)
	if err != nil {
		t.Fatal(err)
	}
	runner.testOnlyAllowMutablePath = true
	invocation, err := argvprocess.NewInvocation(path, []string{
		"-test.run=^TestPF001ArgvRunnerHelper$", "--", "emit", "must-not-run",
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(context.Background(), invocation)
	if !errors.Is(err, argvprocess.ErrInvalidInvocation) || len(result.StandardOutput) != 0 {
		t.Fatalf("swap result/error = %+v/%v", result, err)
	}
}

func TestPF001ArgvRunnerRejectsPostLaunchPathReplacement(t *testing.T) {
	t.Parallel()
	directory := filepath.Join(trustedExecutableFixtureDirectory(t), "private")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	executable := copyCurrentTestExecutable(t, directory)
	invocation, err := argvprocess.NewInvocation(executable, []string{
		"-test.run=^TestPF001ArgvRunnerHelper$", "--", "rename-path", executable,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := mustTestRunner(t, executable).Run(context.Background(), invocation)
	if !errors.Is(err, argvprocess.ErrInvalidInvocation) {
		t.Fatalf("replacement result/error = %+v/%v", result, err)
	}
	if _, statError := os.Lstat(executable); !errors.Is(statError, os.ErrNotExist) {
		t.Fatalf("fixture path was not replaced: %v", statError)
	}
}

func TestPF001ArgvRunnerRejectsWritableExecutableAncestorAndDigestMutation(t *testing.T) {
	t.Parallel()
	writableDirectory := filepath.Join(trustedExecutableFixtureDirectory(t), "writable")
	if err := os.Mkdir(writableDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	writablePath := copyCurrentTestExecutable(t, writableDirectory)
	authority := testExecutableAuthority(t, writablePath)
	if err := os.Chmod(writableDirectory, 0o777); err != nil { //nolint:gosec // G302: deliberately insecure ancestor fixture.
		t.Fatal(err)
	}
	runner, err := NewRunner(authority, testPublisherVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	runner.testOnlyAllowMutablePath = true
	invocation, _ := argvprocess.NewInvocation(writablePath, nil)
	if _, err := runner.Run(context.Background(), invocation); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
		t.Fatalf("writable ancestor error = %v", err)
	}

	privateDirectory := filepath.Join(trustedExecutableFixtureDirectory(t), "private")
	if err := os.Mkdir(privateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	mutatedPath := copyCurrentTestExecutable(t, privateDirectory)
	authority = testExecutableAuthority(t, mutatedPath)
	file, err := os.OpenFile(mutatedPath, os.O_WRONLY|os.O_APPEND, 0) // #nosec G304 -- isolated test fixture.
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("digest substitution")); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	runner, _ = NewRunner(authority, testPublisherVerifier{})
	runner.testOnlyAllowMutablePath = true
	invocation, _ = argvprocess.NewInvocation(mutatedPath, nil)
	if _, err := runner.Run(context.Background(), invocation); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
		t.Fatalf("digest substitution error = %v", err)
	}
}

func copyCurrentTestExecutable(t *testing.T, directory string) string {
	t.Helper()
	contents, err := os.ReadFile(testCurrentExecutable(t))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "runner-fixture")
	if err := os.WriteFile(path, contents, 0o700); err != nil { //nolint:gosec // G306: executable test fixture.
		t.Fatal(err)
	}
	return path
}

func trustedExecutableFixtureDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp(filepath.Dir(testCurrentExecutable(t)), "agentmemory-process-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil { //nolint:gosec // G302: executable fixture directory requires traversal.
		_ = os.RemoveAll(directory)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}
