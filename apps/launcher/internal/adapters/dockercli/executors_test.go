package dockercli

import (
	"context"
	"crypto/sha256"
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

func TestPF001ExecutorsBindDistinctRolesToOneSignedReleaseAndRuntimePlan(t *testing.T) {
	t.Parallel()
	releaseDigest := sha256.Sum256([]byte("release-a"))
	planDigest := sha256.Sum256([]byte("plan-a"))
	docker := &testBoundRunner{
		authority: testDockerCLIAuthority(t, releaseDigest, planDigest), delegate: testNoopRunner{},
	}
	compose := &testBoundRunner{
		authority: testComposeAuthority(t, releaseDigest, planDigest), delegate: testNoopRunner{},
	}
	executors, err := NewExecutors(docker, compose)
	if err != nil || !executors.valid() {
		t.Fatalf("NewExecutors() = %+v, %v", executors, err)
	}

	tests := []struct {
		name    string
		docker  argvprocess.ExecutableAuthority
		compose argvprocess.ExecutableAuthority
	}{
		{
			name: "release substitution", docker: docker.authority,
			compose: testComposeAuthority(t, sha256.Sum256([]byte("release-b")), planDigest),
		},
		{
			name: "runtime plan substitution", docker: docker.authority,
			compose: testComposeAuthority(t, releaseDigest, sha256.Sum256([]byte("plan-b"))),
		},
		{
			name: "role substitution",
			docker: testToolAuthority(
				t, "not-docker", "/verified/not-docker", argvprocess.ExecutableRoleComposePlugin,
				releaseDigest, planDigest,
			),
			compose: compose.authority,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewExecutors(
				&testBoundRunner{authority: test.docker, delegate: testNoopRunner{}},
				&testBoundRunner{authority: test.compose, delegate: testNoopRunner{}},
			)
			if !errors.Is(err, argvprocess.ErrInvalidInvocation) {
				t.Fatalf("NewExecutors() error = %v", err)
			}
		})
	}

	// A runner cannot substitute its authority after aggregate construction.
	compose.authority = testComposeAuthority(t, releaseDigest, sha256.Sum256([]byte("plan-c")))
	if executors.valid() {
		t.Fatal("post-construction authority substitution was accepted")
	}
}

type testRunOnly interface {
	Run(context.Context, argvprocess.Invocation) (argvprocess.Result, error)
}

type testBoundRunner struct {
	authority argvprocess.ExecutableAuthority
	delegate  testRunOnly
}

func (r *testBoundRunner) ExecutableAuthority() argvprocess.ExecutableAuthority { return r.authority }

func (r *testBoundRunner) Run(
	ctx context.Context,
	invocation argvprocess.Invocation,
) (argvprocess.Result, error) {
	return r.delegate.Run(ctx, invocation)
}

type testNoopRunner struct{}

func (testNoopRunner) Run(context.Context, argvprocess.Invocation) (argvprocess.Result, error) {
	return argvprocess.Result{}, nil
}

func testExecutorsForCompose(t *testing.T, compose testRunOnly) Executors {
	t.Helper()
	return testExecutors(t, testNoopRunner{}, compose)
}

func testExecutorsForDocker(t *testing.T, docker testRunOnly) Executors {
	t.Helper()
	return testExecutors(t, docker, testNoopRunner{})
}

func testExecutors(t *testing.T, docker, compose testRunOnly) Executors {
	t.Helper()
	releaseDigest := sha256.Sum256([]byte("test-release-manifest"))
	planDigest := sha256.Sum256([]byte("test-runtime-plan"))
	dockerRunner := &testBoundRunner{delegate: docker}
	composeRunner := &testBoundRunner{delegate: compose}
	dockerRunner.authority = testDockerCLIAuthority(t, releaseDigest, planDigest)
	composeRunner.authority = testComposeAuthority(t, releaseDigest, planDigest)
	executors, err := NewExecutors(dockerRunner, composeRunner)
	if err != nil {
		t.Fatal(err)
	}
	return executors
}

func testDockerCLIAuthority(
	t *testing.T,
	releaseDigest [sha256.Size]byte,
	planDigest [sha256.Size]byte,
) argvprocess.ExecutableAuthority {
	t.Helper()
	return testToolAuthority(
		t, "docker-cli", "/verified/docker", argvprocess.ExecutableRoleDockerCLI, releaseDigest, planDigest,
	)
}

func testComposeAuthority(
	t *testing.T,
	releaseDigest [sha256.Size]byte,
	planDigest [sha256.Size]byte,
) argvprocess.ExecutableAuthority {
	t.Helper()
	return testToolAuthority(
		t, "compose-plugin", "/verified/docker-compose", argvprocess.ExecutableRoleComposePlugin,
		releaseDigest, planDigest,
	)
}

func testToolAuthority(
	t *testing.T,
	id string,
	path string,
	role argvprocess.ExecutableRole,
	releaseDigest [sha256.Size]byte,
	planDigest [sha256.Size]byte,
) argvprocess.ExecutableAuthority {
	t.Helper()
	path = testPlatformToolPath(path)
	authority, err := argvprocess.NewExecutableAuthority(argvprocess.ExecutableAuthorityInput{
		CanonicalID: id, CanonicalPath: path, SHA256: sha256.Sum256([]byte(id)),
		OwnerIdentity: "test-owner", PublisherIdentity: "test-publisher",
		PublisherPolicyID: "test-policy", ReleaseManifestDigest: releaseDigest,
		PublisherTrustDigest: sha256.Sum256([]byte("test-publisher-trust")),
		RuntimePlanDigest:    planDigest, Role: role, Platform: runtime.GOOS, Architecture: runtime.GOARCH,
	})
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func testPlatformToolPath(unixPath string) string {
	if runtime.GOOS != "windows" {
		return unixPath
	}
	return `C:\verified\` + strings.ReplaceAll(strings.TrimPrefix(unixPath, "/verified/"), "/", `\`) + ".exe"
}
