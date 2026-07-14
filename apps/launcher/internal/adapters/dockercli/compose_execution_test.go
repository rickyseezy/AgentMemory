package dockercli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
)

func TestPF001ExecutionMaterializationRejectsUnsafeFilesAndParserInput(t *testing.T) {
	t.Parallel()

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "managed")
	if err := createPrivateExecutionDirectory(context.Background(), directory); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(directory, "empty")
	writePrivateTestFile(t, empty, nil)
	//lint:ignore SA1012 A nil context is the deliberate fail-closed boundary under test.
	//nolint:staticcheck // A nil context is the deliberate fail-closed boundary under test.
	if _, err := readPrivateExecutionFile(nil, empty, true, 1); !errors.Is(err, containerengine.ErrInvalidComposeProject) {
		t.Fatalf("nil context read error = %v", err)
	}
	if _, err := readPrivateExecutionFile(context.Background(), empty, false, 1); !errors.Is(err, containerengine.ErrInvalidComposeProject) {
		t.Fatalf("empty secret read error = %v", err)
	}
	if contents, err := readPrivateExecutionFile(context.Background(), empty, true, 1); err != nil || len(contents) != 0 {
		t.Fatalf("empty environment read = %q/%v", contents, err)
	}
	value := filepath.Join(directory, "value")
	writePrivateTestFile(t, value, []byte("ab"))
	if _, err := readPrivateExecutionFile(context.Background(), value, false, 1); !errors.Is(err, containerengine.ErrInvalidComposeProject) {
		t.Fatalf("oversized protected input error = %v", err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(value, link); err == nil {
		if _, err := readPrivateExecutionFile(context.Background(), link, false, 8); !errors.Is(err, containerengine.ErrInvalidComposeProject) {
			t.Fatalf("linked protected input error = %v", err)
		}
	}
	if err := writeComplete(nil, []byte("x")); !errors.Is(err, containerengine.ErrInvalidComposeProject) {
		t.Fatalf("nil materialization error = %v", err)
	}
	for _, malformed := range [][]byte{[]byte("{"), []byte("{} {}")} {
		if _, err := escapeComposeInterpolation(malformed); err == nil {
			t.Fatalf("malformed execution JSON %q was accepted", malformed)
		}
	}
}

func TestPF001ExecutionMaterializationReusesOnlyIdenticalNoReplaceFiles(t *testing.T) {
	t.Parallel()

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "managed")
	if err := createPrivateExecutionDirectory(context.Background(), directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "bound-secret")
	contents := []byte("bound-value")
	directoryHandle, err := openPrivateExecutionDirectory(context.Background(), directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = directoryHandle.Close() }()
	first, err := ensureExecutionFile(
		context.Background(), directoryHandle, "bound-secret", path, contents, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	second, err := ensureExecutionFile(
		context.Background(), directoryHandle, "bound-secret", path, contents, false,
	)
	if err != nil {
		t.Fatalf("identical materialization reuse: %v", err)
	}
	defer func() { _ = second.Close() }()
	third, err := ensureExecutionFile(
		context.Background(), directoryHandle, "bound-secret", path, []byte("other"), false,
	)
	if !errors.Is(err, containerengine.ErrInvalidComposeProject) {
		t.Fatalf("non-identical materialization error = %v", err)
	}
	if third != nil {
		_ = third.Close()
		t.Fatal("content-mismatched materialization returned authority")
	}
	notDirectory := filepath.Join(directory, "not-directory")
	writePrivateTestFile(t, notDirectory, []byte("x"))
	if err := errEnsureExecutionDirectory(context.Background(), notDirectory); !errors.Is(err, containerengine.ErrInvalidComposeProject) {
		t.Fatalf("file-as-directory error = %v", err)
	}
}

func TestPF001BoundExecutionFailsBeforeMutationAndCanBeReused(t *testing.T) {
	t.Parallel()

	project, rendered := composeFixture(t, "bound-reuse")
	runner := &composeRunner{outputs: []argvprocess.Result{
		{StandardOutput: rendered}, {StandardOutput: []byte("ok\n")}, {}, {},
		{StandardOutput: rendered}, {StandardOutput: []byte("ok\n")}, {}, {},
	}}
	compose, _ := NewCompose(testExecutorsForCompose(t, runner))
	if err := compose.RunMigrations(context.Background(), project); err != nil {
		t.Fatal(err)
	}
	if err := compose.RunMigrations(context.Background(), project); err != nil {
		t.Fatalf("reuse bound generation: %v", err)
	}
	if len(runner.invocations) != 8 {
		t.Fatalf("reused invocation count = %d", len(runner.invocations))
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	cancelledRunner := &composeRunner{}
	cancelledCompose, _ := NewCompose(testExecutorsForCompose(t, cancelledRunner))
	if _, err := cancelledCompose.VerifyConfiguration(cancelled, project); !errors.Is(err, context.Canceled) ||
		!errors.Is(err, containerengine.ErrComposeOperation) || len(cancelledRunner.invocations) != 0 {
		t.Fatalf("pre-cancelled verification error/calls = %v/%d", err, len(cancelledRunner.invocations))
	}
	if _, err := prepareBoundComposeExecution(cancelled, project, rendered, validExecutionSecretValues()); !errors.Is(err, context.Canceled) ||
		!errors.Is(err, containerengine.ErrComposeOperation) {
		t.Fatalf("cancelled binding error = %v", err)
	}
	//lint:ignore SA1012 A nil context is the deliberate fail-closed boundary under test.
	//nolint:staticcheck // A nil context is the deliberate fail-closed boundary under test.
	if _, err := prepareBoundComposeExecution(nil, project, rendered, validExecutionSecretValues()); !errors.Is(err, context.Canceled) ||
		!errors.Is(err, containerengine.ErrComposeOperation) {
		t.Fatalf("nil-context binding error = %v", err)
	}
	if _, err := prepareBoundComposeExecution(context.Background(), project, nil, validExecutionSecretValues()); !errors.Is(err, containerengine.ErrInvalidComposeProject) {
		t.Fatalf("empty canonical binding error = %v", err)
	}
	if _, err := prepareBoundComposeExecution(context.Background(), project, []byte("{"), validExecutionSecretValues()); !errors.Is(err, containerengine.ErrComposeConfigurationMismatch) {
		t.Fatalf("invalid canonical binding error = %v", err)
	}
	if _, err := prepareBoundComposeExecution(context.Background(), project, rendered, nil); !errors.Is(err, containerengine.ErrInvalidComposeProject) {
		t.Fatalf("empty secret binding error = %v", err)
	}
	//lint:ignore SA1012 A nil context is the deliberate fail-closed boundary under test.
	//nolint:staticcheck // A nil context is the deliberate fail-closed boundary under test.
	if err := compose.runBound(nil, project, boundComposeExecution{}, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil-context bound run error = %v", err)
	}
	oversized, err := prepareBoundComposeExecution(
		context.Background(), project, rendered, validExecutionSecretValues(),
	)
	if err != nil {
		t.Fatal(err)
	}
	oversized.configuration = []byte(strings.Repeat("x", maximumDockerJSON+1))
	if err := compose.runBound(context.Background(), project, oversized, nil); !errors.Is(err, containerengine.ErrComposeOperation) {
		t.Fatalf("oversized bound invocation error = %v", err)
	}
}

func TestPF001BoundExecutionRejectsEmptySecretAndRootCollision(t *testing.T) {
	t.Parallel()

	for _, collision := range []bool{false, true} {
		collision := collision
		t.Run(map[bool]string{false: "empty-secret", true: "root-collision"}[collision], func(t *testing.T) {
			t.Parallel()
			project, rendered := composeFixture(t, "bound-failure")
			if collision {
				writePrivateTestFile(t, filepath.Join(project.ProjectDirectory(), executionMaterializationRoot), []byte("x"))
			} else {
				secret := filepath.Join(project.ProjectDirectory(), executionSecretName)
				if err := os.Truncate(secret, 0); err != nil {
					t.Fatal(err)
				}
			}
			runner := &composeRunner{outputs: []argvprocess.Result{{StandardOutput: rendered}}}
			compose, _ := NewCompose(testExecutorsForCompose(t, runner))
			if err := compose.StartAndWait(context.Background(), project); !errors.Is(err, containerengine.ErrInvalidComposeProject) {
				t.Fatalf("bound failure error = %v", err)
			}
			wantInvocations := 0
			if collision {
				wantInvocations = 1
			}
			if len(runner.invocations) != wantInvocations {
				t.Fatalf("bound failure used %d invocations, want %d", len(runner.invocations), wantInvocations)
			}
		})
	}
}
