package dockercli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001ComposeAdapterUsesOnlyExactAddressedArgv(t *testing.T) {
	t.Parallel()

	project, rendered := composeFixture(t, "directory with spaces;$(id)")
	tests := []struct {
		name      string
		invoke    func(*Compose, containerengine.ComposeProject) error
		operation []string
	}{
		{
			name: "verify",
			invoke: func(compose *Compose, project containerengine.ComposeProject) error {
				_, err := compose.VerifyConfiguration(context.Background(), project)
				return err
			},
			operation: []string{"config", "--format", "json", "--no-env-resolution"},
		},
		{
			name: "migrate",
			invoke: func(compose *Compose, project containerengine.ComposeProject) error {
				return compose.RunMigrations(context.Background(), project)
			},
			operation: []string{"run", "--rm", "--no-deps", "--pull", "never", "--no-TTY", "--interactive=false", "migrate"},
		},
		{
			name: "start",
			invoke: func(compose *Compose, project containerengine.ComposeProject) error {
				return compose.StartAndWait(context.Background(), project)
			},
			operation: []string{
				"up", "--detach", "--wait", "--wait-timeout", "300", "--pull", "never", "--no-build",
				"core", "neo4j", "local-embedding", "local-reranker", "local-extractor",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runner := &composeRunner{outputs: []argvprocess.Result{{StandardOutput: rendered}}}
			if test.name != "verify" {
				runner.outputs = append(runner.outputs,
					argvprocess.Result{StandardOutput: []byte("ok\n")}, argvprocess.Result{})
			}
			compose, err := NewCompose(testExecutorsForCompose(t, runner))
			if err != nil {
				t.Fatal(err)
			}
			if err := test.invoke(compose, project); err != nil {
				t.Fatal(err)
			}
			wantPrefix := []string{
				"--host", "unix:///var/run/docker.sock",
				"--ansi", "never",
				"--progress", "quiet",
				"--project-name", "agentmemory_019f5f2012347abc81230123456789ab",
				"--project-directory", project.ProjectDirectory(),
				"--env-file", project.EmptyEnvironmentPath(),
				"--file", project.ConfigurationPath(),
			}
			lastInvocation := runner.invocations[len(runner.invocations)-1]
			if test.name != "verify" {
				executionDirectory := filepath.Join(
					project.ProjectDirectory(), executionMaterializationRoot, composePolicyGeneration,
				)
				wantPrefix = []string{
					"--host", "unix:///var/run/docker.sock",
					"--ansi", "never",
					"--progress", "quiet",
					"--project-name", "agentmemory_019f5f2012347abc81230123456789ab",
					"--project-directory", executionDirectory,
					"--env-file", filepath.Join(executionDirectory, executionEnvironmentName),
					"--file", "-",
				}
				if len(lastInvocation.StandardInput()) == 0 {
					t.Fatal("side effect did not receive authenticated Compose bytes on stdin")
				}
			} else if len(lastInvocation.StandardInput()) != 0 {
				t.Fatal("configuration render unexpectedly received stdin")
			}
			want := append(append([]string(nil), wantPrefix...), test.operation...)
			wantExecutable := testPlatformToolPath("/verified/docker-compose")
			if lastInvocation.Executable() != wantExecutable || !reflect.DeepEqual(lastInvocation.Arguments(), want) {
				t.Fatalf("invocation = %q %q, want %q %q", lastInvocation.Executable(), lastInvocation.Arguments(), wantExecutable, want)
			}
			wantInvocations := 3
			if test.name == "migrate" {
				wantInvocations = 4
				dependency := runner.invocations[len(runner.invocations)-2].Arguments()
				wantDependency := []string{
					"up", "--detach", "--wait", "--wait-timeout", "300", "--pull", "never", "--no-build", "neo4j",
				}
				if len(dependency) < len(wantDependency) || !reflect.DeepEqual(
					dependency[len(dependency)-len(wantDependency):], wantDependency,
				) {
					t.Fatalf("migration dependency invocation = %q", dependency)
				}
			}
			if test.name != "verify" && len(runner.invocations) != wantInvocations {
				t.Fatalf("side effect used %d invocations, want %d", len(runner.invocations), wantInvocations)
			}
		})
	}
}

func TestPF001ComposeAdapterFailsClosedBeforeSideEffects(t *testing.T) {
	t.Parallel()

	project, rendered := composeFixture(t, "release")
	tests := []struct {
		name   string
		output argvprocess.Result
		err    error
	}{
		{name: "wrong digest", output: argvprocess.Result{StandardOutput: []byte(`{"services":{"other":{}}}`)}, err: containerengine.ErrComposeConfigurationMismatch},
		{name: "invalid JSON", output: argvprocess.Result{StandardOutput: []byte(`{"services":`)}, err: containerengine.ErrComposeConfigurationMismatch},
		{name: "empty", output: argvprocess.Result{}, err: containerengine.ErrComposeConfigurationMismatch},
		{name: "truncated", output: argvprocess.Result{StandardOutput: rendered, OutputTruncated: true}, err: containerengine.ErrComposeOperation},
		{name: "nonzero", output: argvprocess.Result{StandardOutput: rendered, ExitCode: 17}, err: containerengine.ErrComposeOperation},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runner := &composeRunner{outputs: []argvprocess.Result{test.output}}
			compose, err := NewCompose(testExecutorsForCompose(t, runner))
			if err != nil {
				t.Fatal(err)
			}
			err = compose.StartAndWait(context.Background(), project)
			if !errors.Is(err, test.err) {
				t.Fatalf("StartAndWait() error = %v, want %v", err, test.err)
			}
			if len(runner.invocations) != 1 {
				t.Fatalf("configuration failure reached side effect: %d calls", len(runner.invocations))
			}
		})
	}
}

func TestPF001ComposeAdapterRejectsUnsafeManagedFiles(t *testing.T) {
	t.Parallel()

	project, rendered := composeFixture(t, "release")
	if err := os.Remove(project.EmptyEnvironmentPath()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(project.EmptyEnvironmentPath(), []byte("SECRET=value"), 0o600); err != nil {
		t.Fatal(err)
	}
	compose, _ := NewCompose(testExecutorsForCompose(
		t, &composeRunner{outputs: []argvprocess.Result{{StandardOutput: rendered}}},
	))
	if _, err := compose.VerifyConfiguration(context.Background(), project); !errors.Is(err, containerengine.ErrInvalidComposeProject) {
		t.Fatalf("non-empty environment error = %v", err)
	}

	project, rendered = composeFixture(t, "release")
	original := project.ConfigurationPath()
	target := filepath.Join(project.ProjectDirectory(), "target.yaml")
	if err := os.Rename(original, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, original); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	compose, _ = NewCompose(testExecutorsForCompose(
		t, &composeRunner{outputs: []argvprocess.Result{{StandardOutput: rendered}}},
	))
	if _, err := compose.VerifyConfiguration(context.Background(), project); !errors.Is(err, containerengine.ErrInvalidComposeProject) {
		t.Fatalf("symlink configuration error = %v", err)
	}
}

func TestPF001ComposeAdapterRejectsMissingDependenciesAndPropagatesCancellation(t *testing.T) {
	t.Parallel()

	if _, err := NewCompose(Executors{}); err == nil {
		t.Fatal("NewCompose() accepted missing signed executors")
	}

	project, rendered := composeFixture(t, "release")
	cancelled := &composeRunner{outputs: []argvprocess.Result{{StandardOutput: rendered}}, err: context.Canceled}
	compose, _ := NewCompose(testExecutorsForCompose(t, cancelled))
	_, err := compose.VerifyConfiguration(context.Background(), project)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, containerengine.ErrComposeOperation) {
		t.Fatalf("cancellation error = %v", err)
	}
}

func TestPF001ComposeProjectionCancellationStopsBeforeMigrationAndPreservesCause(t *testing.T) {
	t.Parallel()

	project, rendered := composeFixture(t, "projection-cancellation")
	runner := &composeRunner{outputs: []argvprocess.Result{{StandardOutput: rendered}}}
	runner.beforeRun = func(invocation argvprocess.Invocation) {
		arguments := invocation.Arguments()
		if len(arguments) != 0 && arguments[len(arguments)-1] == string(composeplan.ServiceSecretProjector) {
			runner.err = context.Canceled
		}
	}
	compose, err := NewCompose(testExecutorsForCompose(t, runner))
	if err != nil {
		t.Fatal(err)
	}
	err = compose.RunMigrations(context.Background(), project)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, containerengine.ErrComposeOperation) {
		t.Fatalf("projection cancellation error = %v", err)
	}
	if len(runner.invocations) != 2 {
		t.Fatalf("projection cancellation reached migration: calls=%d", len(runner.invocations))
	}
}

func composeFixture(t *testing.T, directoryName string) (containerengine.ComposeProject, []byte) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, directoryName)
	ensurePrivateTestDirectory(t, directory)
	registerExecutionMaterializationCleanup(t, directory)
	configuration := filepath.Join(directory, "compose.yaml")
	environment := filepath.Join(directory, "empty.env")
	writePrivateTestFile(t, configuration, []byte("services: {}\n"))
	writePrivateTestFile(t, environment, nil)
	secretFile := writeValidComposePolicySecrets(t, directory)
	plan, err := composeplan.NewPolicyPlan(validComposePolicyModel(secretFile))
	if err != nil {
		t.Fatal(err)
	}
	rendered := marshalRenderedFixture(t, validRenderedDocument(validComposePolicyModel(secretFile)))
	endpoint, err := containerengine.NewEndpoint("unix:///var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	project, err := containerengine.NewComposeProject(
		endpoint,
		"agentmemory_019f5f2012347abc81230123456789ab",
		directory,
		configuration,
		environment,
		releaseinventory.DigestBytes(rendered),
		plan,
		300,
	)
	if err != nil {
		t.Fatal(err)
	}
	return project, rendered
}

func registerExecutionMaterializationCleanup(t *testing.T, projectDirectory string) {
	t.Helper()
	t.Cleanup(func() {
		root := filepath.Join(projectDirectory, executionMaterializationRoot)
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info == nil {
				return os.ErrInvalid
			}
			if info.IsDir() {
				_ = os.Chmod(path, 0o700) //nolint:gosec // G302,G122: trusted test-only cleanup walk restores owner traversal.
			} else {
				_ = os.Chmod(path, 0o600) //nolint:gosec // G122: trusted test-only cleanup walk over generated files.
			}
			return nil
		})
	})
}

type composeRunner struct {
	invocations []argvprocess.Invocation
	outputs     []argvprocess.Result
	err         error
	beforeRun   func(argvprocess.Invocation)
	afterRun    func()
}

func (r *composeRunner) Run(_ context.Context, invocation argvprocess.Invocation) (argvprocess.Result, error) {
	r.invocations = append(r.invocations, invocation)
	if r.beforeRun != nil {
		r.beforeRun(invocation)
	}
	if r.afterRun != nil {
		r.afterRun()
		r.afterRun = nil
	}
	if r.err != nil {
		return argvprocess.Result{}, r.err
	}
	if len(r.outputs) == 0 {
		return argvprocess.Result{}, nil
	}
	output := r.outputs[0]
	r.outputs = r.outputs[1:]
	return output, nil
}

func TestPF001ComposeAdapterBoundsRenderedOutput(t *testing.T) {
	t.Parallel()

	project, _ := composeFixture(t, "release")
	runner := &composeRunner{outputs: []argvprocess.Result{{StandardOutput: []byte(strings.Repeat("x", maximumDockerJSON+1))}}}
	compose, _ := NewCompose(testExecutorsForCompose(t, runner))
	if _, err := compose.VerifyConfiguration(context.Background(), project); !errors.Is(err, containerengine.ErrComposeOperation) {
		t.Fatalf("oversized render error = %v", err)
	}
}

func TestPF001ComposeAdapterRejectsInvalidPathTopologyBeforeDocker(t *testing.T) {
	t.Parallel()

	validProject, rendered := composeFixture(t, "release")
	endpoint := validProject.Endpoint()
	projectName := validProject.Name()
	digest := validProject.ExpectedConfigurationDigest()
	plan := validProject.ExpectedPolicyPlan()
	outside := filepath.Join(filepath.Dir(validProject.ProjectDirectory()), "outside.yaml")
	if err := os.WriteFile(outside, []byte("services: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name          string
		directory     string
		configuration string
		environment   string
	}{
		{name: "relative paths", directory: "relative", configuration: "relative/compose.yaml", environment: "relative/empty.env"},
		{name: "configuration outside", directory: validProject.ProjectDirectory(), configuration: outside, environment: validProject.EmptyEnvironmentPath()},
		{name: "directory is file", directory: validProject.ConfigurationPath(), configuration: validProject.ConfigurationPath(), environment: validProject.EmptyEnvironmentPath()},
		{name: "configuration is directory", directory: validProject.ProjectDirectory(), configuration: validProject.ProjectDirectory(), environment: validProject.EmptyEnvironmentPath()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			project, err := containerengine.NewComposeProject(
				endpoint, projectName, test.directory, test.configuration, test.environment, digest, plan, 300,
			)
			if err != nil {
				t.Fatal(err)
			}
			runner := &composeRunner{outputs: []argvprocess.Result{{StandardOutput: rendered}}}
			compose, _ := NewCompose(testExecutorsForCompose(t, runner))
			if _, err := compose.VerifyConfiguration(context.Background(), project); !errors.Is(err, containerengine.ErrInvalidComposeProject) || len(runner.invocations) != 0 {
				t.Fatalf("VerifyConfiguration() error=%v calls=%d", err, len(runner.invocations))
			}
		})
	}
}

func TestPF001ComposeAdapterSanitizesEveryProcessBoundary(t *testing.T) {
	t.Parallel()

	project, rendered := composeFixture(t, "release")
	tests := []struct {
		name      string
		ctx       context.Context
		outputs   []argvprocess.Result
		runnerErr error
	}{
		{name: "nil context"},
		{name: "runner failure", ctx: context.Background(), runnerErr: errors.New("private stderr")},
		{name: "runner deadline", ctx: context.Background(), runnerErr: context.DeadlineExceeded},
		{name: "oversized stderr", ctx: context.Background(), outputs: []argvprocess.Result{{StandardOutput: rendered, StandardError: []byte(strings.Repeat("x", maximumDockerJSON+1))}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runner := &composeRunner{outputs: append([]argvprocess.Result(nil), test.outputs...), err: test.runnerErr}
			compose, err := NewCompose(testExecutorsForCompose(t, runner))
			if err != nil {
				t.Fatal(err)
			}
			_, err = compose.VerifyConfiguration(test.ctx, project)
			if !errors.Is(err, containerengine.ErrComposeOperation) || strings.Contains(err.Error(), "private stderr") {
				t.Fatalf("VerifyConfiguration() error = %v", err)
			}
		})
	}

	runner := &composeRunner{outputs: []argvprocess.Result{{StandardOutput: rendered}, {ExitCode: 9}}}
	compose, _ := NewCompose(testExecutorsForCompose(t, runner))
	if err := compose.RunMigrations(context.Background(), project); !errors.Is(err, containerengine.ErrComposeOperation) {
		t.Fatalf("RunMigrations() operation error = %v", err)
	}
}
