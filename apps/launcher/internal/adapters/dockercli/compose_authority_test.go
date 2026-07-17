//go:build !darwin || cgo

package dockercli

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001DeriveReleaseProjectBuildsAuthorityOnlyFromSignedSourceAndNormalizedRender(t *testing.T) {
	t.Parallel()

	directory, rendered, plan, _ := validComposePolicyFixture(t)
	addressed := policyComposeProject(t, directory, rendered, plan)
	source := composeReleaseSourceFixture(t, addressed)
	runner := &composeRunner{outputs: []argvprocess.Result{{StandardOutput: rendered}}}
	compose, err := NewCompose(testExecutorsForCompose(t, runner))
	if err != nil {
		t.Fatal(err)
	}
	project, normalized, err := compose.DeriveReleaseProject(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	model, decodeError := decodeRenderedPolicy(normalized.CanonicalBytes(), project.Name())
	if decodeError != nil || !project.ExpectedPolicyPlan().Matches(model) ||
		!project.ExpectedConfigurationDigest().Equal(releaseinventory.DigestBytes(rendered)) ||
		project.ConfigurationPath() != addressed.ConfigurationPath() || len(runner.invocations) != 1 {
		t.Fatalf("derived project/render/calls = %#v/%v/%d", project, decodeError, len(runner.invocations))
	}
	want := []string{
		"--host", addressed.Endpoint().String(), "--ansi", "never", "--progress", "quiet",
		"--project-name", addressed.Name(), "--project-directory", addressed.ProjectDirectory(),
		"--env-file", addressed.EmptyEnvironmentPath(), "--file", addressed.ConfigurationPath(),
		"config", "--format", "json", "--no-env-resolution",
	}
	if actual := runner.invocations[0].Arguments(); !equalStrings(actual, want) {
		t.Fatalf("derive argv = %q, want %q", actual, want)
	}
}

func TestPF001ReleaseOperationsDeriveAuthorityAndMutateAsOneBoundary(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		invoke    func(*Compose, context.Context, containerengine.ComposeReleaseSource) (containerengine.RenderedConfiguration, error)
		operation []string
	}{
		{
			name: "migrations",
			invoke: func(compose *Compose, ctx context.Context, source containerengine.ComposeReleaseSource) (containerengine.RenderedConfiguration, error) {
				return compose.RunReleaseMigrations(ctx, source)
			},
			operation: []string{"run", "--rm", "--no-deps", "--pull", "never", "--no-TTY", "--interactive=false", "migrate"},
		},
		{
			name: "start and wait",
			invoke: func(compose *Compose, ctx context.Context, source containerengine.ComposeReleaseSource) (containerengine.RenderedConfiguration, error) {
				return compose.StartReleaseAndWait(ctx, source)
			},
			operation: []string{
				"up", "--detach", "--wait", "--wait-timeout", "300", "--pull", "never", "--no-build",
				"core", "neo4j", "local-embedding", "local-reranker", "local-extractor",
			},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			directory, rendered, plan, _ := validComposePolicyFixture(t)
			addressed := policyComposeProject(t, directory, rendered, plan)
			source := composeReleaseSourceFixture(t, addressed)
			runner := &composeRunner{outputs: []argvprocess.Result{
				{StandardOutput: rendered}, {StandardOutput: rendered}, {StandardOutput: []byte("ok\n")}, {},
			}}
			compose, _ := NewCompose(testExecutorsForCompose(t, runner))
			normalized, err := test.invoke(compose, context.Background(), source)
			if err != nil || !normalized.Digest().Equal(releaseinventory.DigestBytes(rendered)) {
				t.Fatalf("release operation = %s/%v", normalized.Digest().Hex(), err)
			}
			wantCalls := 4
			if test.name == "migrations" {
				wantCalls = 5
			}
			if len(runner.invocations) != wantCalls {
				t.Fatalf("release operation calls = %d, want %d", len(runner.invocations), wantCalls)
			}
			projection := runner.invocations[2].Arguments()
			if projection[len(projection)-1] != string(composeplan.ServiceSecretProjector) {
				t.Fatalf("projection argv = %q", projection)
			}
			last := runner.invocations[len(runner.invocations)-1]
			actual := last.Arguments()
			if len(actual) < len(test.operation) || !equalStrings(actual[len(actual)-len(test.operation):], test.operation) ||
				len(last.StandardInput()) == 0 {
				t.Fatalf("release mutation argv/stdin = %q/%d", actual, len(last.StandardInput()))
			}
		})
	}
}

func TestPF001ReleaseOperationsNeverMutateWhenDerivationFails(t *testing.T) {
	t.Parallel()

	directory, rendered, plan, _ := validComposePolicyFixture(t)
	addressed := policyComposeProject(t, directory, rendered, plan)
	source := composeReleaseSourceFixture(t, addressed)
	runner := &composeRunner{outputs: []argvprocess.Result{{StandardOutput: []byte(`{"services":{}}`)}}}
	compose, _ := NewCompose(testExecutorsForCompose(t, runner))
	normalized, err := compose.RunReleaseMigrations(context.Background(), source)
	if !errors.Is(err, containerengine.ErrComposeConfigurationMismatch) ||
		len(normalized.CanonicalBytes()) != 0 || len(runner.invocations) != 1 {
		t.Fatalf("failed derivation result/error/calls = %q/%v/%d", normalized.CanonicalBytes(), err, len(runner.invocations))
	}
}

func TestPF001DeriveReleaseProjectFailsClosedBeforeReturningExecutionAuthority(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		mutate func(*containerengine.ComposeReleaseSource, *composeRunner, containerengine.ComposeProject, []byte)
		want   error
	}{
		{
			name: "wrong signed source digest",
			mutate: func(source *containerengine.ComposeReleaseSource, _ *composeRunner, project containerengine.ComposeProject, _ []byte) {
				identity, _ := composeplan.NewIdentity(composePolicyInstallation, composePolicyGeneration)
				*source, _ = containerengine.NewComposeReleaseSource(
					project.Endpoint(), identity, "0.1.0", project.ProjectDirectory(), project.ConfigurationPath(),
					project.EmptyEnvironmentPath(), releaseinventory.DigestBytes([]byte("other")), 300,
				)
			},
			want: containerengine.ErrInvalidComposeProject,
		},
		{
			name: "policy-invalid normalized output",
			mutate: func(_ *containerengine.ComposeReleaseSource, runner *composeRunner, _ containerengine.ComposeProject, rendered []byte) {
				runner.outputs = []argvprocess.Result{{StandardOutput: append(rendered, []byte(" ")...)}}
				runner.outputs[0].StandardOutput[0] = '['
			},
			want: containerengine.ErrComposeConfigurationMismatch,
		},
		{
			name: "source identity swapped during render",
			mutate: func(_ *containerengine.ComposeReleaseSource, runner *composeRunner, project containerengine.ComposeProject, _ []byte) {
				runner.afterRun = func() {
					if err := os.Remove(project.ConfigurationPath()); err != nil {
						t.Errorf("remove source: %v", err)
						return
					}
					writePrivateTestFile(t, project.ConfigurationPath(), []byte("services: {}\n"))
				}
			},
			want: containerengine.ErrInvalidComposeProject,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			directory, rendered, plan, _ := validComposePolicyFixture(t)
			addressed := policyComposeProject(t, directory, rendered, plan)
			source := composeReleaseSourceFixture(t, addressed)
			runner := &composeRunner{outputs: []argvprocess.Result{{StandardOutput: rendered}}}
			test.mutate(&source, runner, addressed, rendered)
			compose, _ := NewCompose(testExecutorsForCompose(t, runner))
			project, normalized, err := compose.DeriveReleaseProject(context.Background(), source)
			if !errors.Is(err, test.want) || project.Name() != "" || len(normalized.CanonicalBytes()) != 0 {
				t.Fatalf("derive error/project/render = %v/%#v/%q", err, project, normalized.CanonicalBytes())
			}
		})
	}
}

func composeReleaseSourceFixture(
	t *testing.T,
	project containerengine.ComposeProject,
) containerengine.ComposeReleaseSource {
	t.Helper()
	contents, err := os.ReadFile(project.ConfigurationPath())
	if err != nil {
		t.Fatal(err)
	}
	identity, err := composeplan.NewIdentity(composePolicyInstallation, composePolicyGeneration)
	if err != nil {
		t.Fatal(err)
	}
	source, err := containerengine.NewComposeReleaseSource(
		project.Endpoint(), identity, "0.1.0", project.ProjectDirectory(), project.ConfigurationPath(),
		project.EmptyEnvironmentPath(), releaseinventory.DigestBytes(contents), 300,
	)
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func equalStrings(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
