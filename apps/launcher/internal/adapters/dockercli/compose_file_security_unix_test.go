//go:build linux || (darwin && cgo)

package dockercli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
)

func TestPF001ComposeInputSecurityRejectsPermissionsLinksAndForeignOwner(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	path := filepath.Join(directory, "input")
	if err := os.WriteFile(path, []byte("input"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	status := *info.Sys().(*syscall.Stat_t)
	if !privateUnixComposeFile(info, int64(status.Uid)) {
		t.Fatal("owner-only single-link input was rejected")
	}
	if privateUnixComposeFile(info, int64(status.Uid)+1) {
		t.Fatal("foreign owner was accepted")
	}
	//nolint:gosec // G302: deliberately makes the isolated attack fixture unsafe; owner=security expiry=2027-07-14.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	info, _ = os.Lstat(path)
	if privateUnixComposeFile(info, int64(status.Uid)) {
		t.Fatal("group/world-readable input was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "second-link")
	if err := os.Link(path, link); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	info, _ = os.Lstat(path)
	if privateUnixComposeFile(info, int64(status.Uid)) {
		t.Fatal("multiply linked input was accepted")
	}
}

func TestPF001ComposeAdapterRejectsUnsafePermissionsOnEveryInput(t *testing.T) {
	t.Parallel()

	for _, input := range []string{"compose", "environment", "secret"} {
		input := input
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			project, rendered := composeFixture(t, "private-inputs")
			path := project.ConfigurationPath()
			switch input {
			case "environment":
				path = project.EmptyEnvironmentPath()
			case "secret":
				path = filepath.Join(project.ProjectDirectory(), executionSecretName)
			}
			//nolint:gosec // G302: deliberately makes the isolated attack fixture unsafe; owner=security expiry=2027-07-14.
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
			runner := &composeRunner{outputs: []argvprocess.Result{{StandardOutput: rendered}}}
			compose, _ := NewCompose(testExecutorsForCompose(t, runner))
			if _, err := compose.VerifyConfiguration(context.Background(), project); !errors.Is(err, containerengine.ErrInvalidComposeProject) || len(runner.invocations) > 1 {
				t.Fatalf("unsafe %s error=%v calls=%d", input, err, len(runner.invocations))
			}
		})
	}
}

func TestPF001ComposeAdapterRejectsHardLinkedAuthorityFile(t *testing.T) {
	t.Parallel()

	project, rendered := composeFixture(t, "hardlink-input")
	second := filepath.Join(project.ProjectDirectory(), "second-compose-link")
	if err := os.Link(project.ConfigurationPath(), second); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	runner := &composeRunner{outputs: []argvprocess.Result{{StandardOutput: rendered}}}
	compose, _ := NewCompose(testExecutorsForCompose(t, runner))
	if _, err := compose.VerifyConfiguration(context.Background(), project); !errors.Is(err, containerengine.ErrInvalidComposeProject) || len(runner.invocations) != 0 {
		t.Fatalf("hard-linked Compose input error=%v calls=%d", err, len(runner.invocations))
	}
}

func TestPF001SealedExecutionDirectoryBlocksPathSwapDuringCompose(t *testing.T) {
	t.Parallel()

	project, rendered := composeFixture(t, "sealed-execution")
	var swapError error
	runner := &composeRunner{outputs: []argvprocess.Result{
		{StandardOutput: rendered}, {StandardOutput: []byte("ok\n")}, {},
	}}
	runner.beforeRun = func(invocation argvprocess.Invocation) {
		if len(runner.invocations) != 2 {
			return
		}
		model, err := decodeRenderedPolicy(invocation.StandardInput(), project.Name())
		if err != nil {
			swapError = err
			return
		}
		swapError = os.Remove(model.Secrets[composeplan.SecretInstallationKey].File)
	}
	compose, _ := NewCompose(testExecutorsForCompose(t, runner))
	if err := compose.RunMigrations(context.Background(), project); err != nil {
		t.Fatal(err)
	}
	if swapError == nil {
		t.Fatal("owner-only sealed execution directory permitted a concurrent path swap")
	}
}

func TestPF001ExecutionCreationStaysBoundToOpenedDirectoryAndNeverRemovesByName(t *testing.T) {
	t.Parallel()

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(root, "generation")
	if err := createPrivateExecutionDirectory(context.Background(), original); err != nil {
		t.Fatal(err)
	}
	directory, err := openPrivateExecutionDirectory(context.Background(), original)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = directory.Close() }()

	retained := filepath.Join(root, "retained-generation")
	if err := os.Rename(original, retained); err != nil {
		t.Fatal(err)
	}
	if err := createPrivateExecutionDirectory(context.Background(), original); err != nil {
		t.Fatal(err)
	}
	expectedPath := filepath.Join(original, executionSecretName)
	file, err := ensureExecutionFile(
		context.Background(), directory, executionSecretName, expectedPath, []byte("descriptor-bound"), false,
	)
	if file != nil {
		_ = file.Close()
	}
	if !errors.Is(err, containerengine.ErrInvalidComposeProject) {
		t.Fatalf("substituted ancestor error = %v", err)
	}
	if _, err := os.Lstat(expectedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("substituted named directory received a secret: %v", err)
	}
	retainedPath := filepath.Join(retained, executionSecretName)
	// #nosec G304 -- the retained test directory is isolated under t.TempDir.
	contents, err := os.ReadFile(retainedPath)
	if err != nil || string(contents) != "descriptor-bound" {
		t.Fatalf("descriptor-bound quarantine contents/error = %q/%v", contents, err)
	}
}

func TestPF001ExecutionSecretLeafIsContainerReadableBehindHostPrivateDirectory(t *testing.T) {
	t.Parallel()

	project, rendered := composeFixture(t, "secret-mode-boundary")
	execution, err := prepareBoundComposeExecution(
		context.Background(), project, rendered, validExecutionSecretValues(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer execution.authority.close()
	directoryInfo, err := os.Lstat(execution.directory)
	if err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(execution.directory, executionSecretName)
	secretInfo, err := os.Lstat(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	if directoryInfo.Mode().Perm() != 0o500 || directoryInfo.Mode().Perm()&0o077 != 0 ||
		secretInfo.Mode().Perm() != 0o400 {
		t.Fatalf(
			"host-directory/container-leaf modes = %04o/%04o",
			directoryInfo.Mode().Perm(),
			secretInfo.Mode().Perm(),
		)
	}
	if !privateComposePath(secretPath, false) {
		t.Fatal("owner-only projector input was rejected by the ordinary Compose input policy")
	}
	if !privateExecutionMaterializationPath(secretPath, false) {
		t.Fatal("guarded execution materialization rejected the exact host-isolated/container-readable mode pair")
	}
}

func TestPF001ComposeMutationRejectsWritableProjectAncestor(t *testing.T) {
	t.Parallel()

	project, rendered := composeFixture(t, "writable-ancestor")
	ancestor := filepath.Dir(project.ProjectDirectory())
	if err := os.Chmod(ancestor, 0o777); err != nil { //nolint:gosec // G302: deliberately writable ancestor attack fixture.
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(ancestor, 0o700) //nolint:gosec // G302: owner-only directory cleanup mode.
	})
	runner := &composeRunner{outputs: []argvprocess.Result{{StandardOutput: rendered}}}
	compose, _ := NewCompose(testExecutorsForCompose(t, runner))
	if err := compose.RunMigrations(context.Background(), project); !errors.Is(err, containerengine.ErrInvalidComposeProject) {
		t.Fatalf("writable ancestor mutation error = %v", err)
	}
	if len(runner.invocations) != 1 {
		t.Fatalf("writable ancestor reached mutating Docker call: %d invocations", len(runner.invocations))
	}
}
