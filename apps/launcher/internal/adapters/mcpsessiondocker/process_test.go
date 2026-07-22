package mcpsessiondocker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpsessionapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

func TestPF005DockerProcessUsesOnlySignedDockerAuthorityAndExactArgv(t *testing.T) {
	t.Parallel()
	runner := &streamingRunner{authority: dockerAuthority(t, argvprocess.ExecutableRoleDockerCLI)}
	runner.result = argvprocess.Result{StandardOutput: []byte("captured")}
	process, err := NewProcess(runner)
	if err != nil {
		t.Fatal(err)
	}
	arguments := []string{"--host", "unix:///verified/docker.sock", "version", "--format", "json"}
	output, err := process.Capture(t.Context(), arguments)
	if err != nil || string(output) != "captured" {
		t.Fatalf("Capture()=%q,%v", output, err)
	}
	arguments[0] = "mutated"
	if runner.invocation.Executable() != runner.authority.CanonicalPath() ||
		runner.invocation.Arguments()[0] != "--host" {
		t.Fatalf("invocation=%q %#v", runner.invocation.Executable(), runner.invocation.Arguments())
	}

	var outputStream, diagnostics bytes.Buffer
	streams := mcpsessionapp.Streams{
		Input: strings.NewReader("MCP request"), Output: &outputStream, Diagnostics: &diagnostics,
	}
	if err := process.Stream(t.Context(), []string{"container", "start", "session"}, streams); err != nil {
		t.Fatal(err)
	}
	if runner.streams.Input() != streams.Input || runner.streams.Output() != streams.Output ||
		runner.streams.Diagnostics() != streams.Diagnostics {
		t.Fatal("stream capabilities were substituted")
	}
}

func TestPF005DockerProcessClassifiesOnlyExactContainerNotFound(t *testing.T) {
	t.Parallel()
	runner := &streamingRunner{authority: dockerAuthority(t, argvprocess.ExecutableRoleDockerCLI)}
	runner.runError = errors.New("docker exit")
	process, _ := NewProcess(runner)
	arguments := []string{
		"--host", "unix:///verified/docker.sock", "container", "rm", "--force", "--volumes", "session",
	}
	runner.result = argvprocess.Result{
		ExitCode: 1, StandardError: []byte("Error response from daemon: No such container: session\n"),
	}
	if _, err := process.Capture(t.Context(), arguments); !errors.Is(err, ErrContainerNotFound) {
		t.Fatalf("exact not-found error=%v", err)
	}
	runner.result.StandardError = []byte("permission denied\n")
	if _, err := process.Capture(t.Context(), arguments); !errors.Is(err, runner.runError) {
		t.Fatalf("foreign failure error=%v", err)
	}
	if missingContainer([]string{"short"}, runner.result) {
		t.Fatal("short argv classified as not found")
	}
}

func TestPF005DockerProcessRejectsPartialCompositionAndInvalidInvocation(t *testing.T) {
	t.Parallel()
	if _, err := NewProcess(nil); err == nil {
		t.Fatal("NewProcess(nil) error=nil")
	}
	var typedNil *streamingRunner
	if _, err := NewProcess(typedNil); err == nil {
		t.Fatal("NewProcess(typed nil) error=nil")
	}
	compose := &streamingRunner{authority: dockerAuthority(t, argvprocess.ExecutableRoleComposePlugin)}
	if _, err := NewProcess(compose); err == nil {
		t.Fatal("NewProcess(compose) error=nil")
	}
	runner := &streamingRunner{authority: dockerAuthority(t, argvprocess.ExecutableRoleDockerCLI)}
	process, _ := NewProcess(runner)
	if _, err := process.Capture(t.Context(), []string{"bad\x00arg"}); err == nil {
		t.Fatal("Capture(NUL) error=nil")
	}
	if err := process.Stream(t.Context(), []string{"version"}, mcpsessionapp.Streams{}); err == nil {
		t.Fatal("Stream(nil streams) error=nil")
	}
	if _, err := (*Process)(nil).Capture(t.Context(), nil); err == nil {
		t.Fatal("nil Process Capture error=nil")
	}
}

func TestPF005ComposeProcessUsesOnlyIndependentSignedComposeAuthority(t *testing.T) {
	t.Parallel()
	runner := &streamingRunner{authority: dockerAuthority(t, argvprocess.ExecutableRoleComposePlugin)}
	runner.result = argvprocess.Result{StandardOutput: []byte("compose-ready")}
	process, err := NewComposeProcess(runner)
	if err != nil {
		t.Fatal(err)
	}
	arguments := []string{"--host", "unix:///verified/docker.sock", "up", "--detach"}
	output, err := process.Capture(t.Context(), arguments)
	if err != nil || string(output) != "compose-ready" {
		t.Fatalf("Capture()=%q,%v", output, err)
	}
	arguments[0] = "mutated"
	if runner.invocation.Executable() != runner.authority.CanonicalPath() ||
		runner.invocation.Arguments()[0] != "--host" {
		t.Fatalf("invocation=%q %#v", runner.invocation.Executable(), runner.invocation.Arguments())
	}

	docker := &streamingRunner{authority: dockerAuthority(t, argvprocess.ExecutableRoleDockerCLI)}
	if _, err := NewComposeProcess(docker); err == nil {
		t.Fatal("Docker CLI authority accepted as Compose")
	}
	if _, err := NewComposeProcess(nil); err == nil {
		t.Fatal("nil Compose runner accepted")
	}
	if _, err := process.Capture(t.Context(), []string{"bad\x00arg"}); err == nil {
		t.Fatal("NUL argument accepted")
	}
	if _, err := (*ComposeProcess)(nil).Capture(t.Context(), nil); err == nil {
		t.Fatal("nil Compose process accepted")
	}
}

type streamingRunner struct {
	authority  argvprocess.ExecutableAuthority
	invocation argvprocess.Invocation
	streams    argvprocess.Streams
	result     argvprocess.Result
	runError   error
	streamErr  error
}

func (r *streamingRunner) ExecutableAuthority() argvprocess.ExecutableAuthority { return r.authority }

func (r *streamingRunner) Run(
	_ context.Context,
	invocation argvprocess.Invocation,
) (argvprocess.Result, error) {
	r.invocation = invocation
	return r.result, r.runError
}

func (r *streamingRunner) RunStreaming(
	_ context.Context,
	invocation argvprocess.Invocation,
	streams argvprocess.Streams,
) error {
	r.invocation = invocation
	r.streams = streams
	return r.streamErr
}

func dockerAuthority(
	t testing.TB,
	role argvprocess.ExecutableRole,
) argvprocess.ExecutableAuthority {
	t.Helper()
	path := "/verified/docker"
	if runtime.GOOS == "windows" {
		path = `C:\verified\docker.exe`
	}
	nonzero := sha256.Sum256([]byte("nonzero"))
	authority, err := argvprocess.NewExecutableAuthority(argvprocess.ExecutableAuthorityInput{
		CanonicalID: "docker", CanonicalPath: path, SHA256: nonzero, OwnerIdentity: "owner",
		PublisherIdentity: "publisher", PublisherPolicyID: "policy", PublisherTrustDigest: nonzero,
		ReleaseManifestDigest: nonzero, RuntimePlanDigest: nonzero, Role: role,
		Platform: runtime.GOOS, Architecture: runtime.GOARCH,
	})
	if err != nil {
		t.Fatalf("NewExecutableAuthority() error=%v", err)
	}
	return authority
}
