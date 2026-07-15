package agentconfigadapter

import (
	"context"
	"crypto/sha256"
	"errors"
	"runtime"
	"strings"
	"testing"

	port "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	domain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
)

const (
	verifierInstallationID = "018f0c74-7b5d-7cc1-8a2c-123456789abc"
	verifierEntryID        = "018f0c74-7b5d-7cc2-9a2c-123456789abc"
)

func TestPF001InvocationVerifierCompletesExactBootstrapHandshake(t *testing.T) {
	t.Parallel()
	runner, target := verifierFixture(t)
	verifier, err := NewInvocationVerifier(runner)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(context.Background(), target); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if runner.calls != 1 || runner.invocation.Executable() != target.Command() ||
		strings.Join(runner.invocation.Arguments(), "\x00") != strings.Join(target.Arguments(), "\x00") ||
		!strings.Contains(string(runner.invocation.StandardInput()), `"method":"initialize"`) ||
		!strings.Contains(string(runner.invocation.StandardInput()), `"method":"tools/list"`) {
		t.Fatal("verifier did not execute the exact bounded MCP exchange")
	}
}

func TestPF001InvocationVerifierRejectsTranscriptSubstitution(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"raw stdout":        "starting\n",
		"not terminated":    validVerifierOutput()[:len(validVerifierOutput())-1],
		"wrong identity":    strings.Replace(validVerifierOutput(), `"name":"agentmemory"`, `"name":"attacker"`, 1),
		"wrong version":     strings.Replace(validVerifierOutput(), `"protocolVersion":"2025-06-18"`, `"protocolVersion":"future"`, 1),
		"missing tool":      strings.Replace(validVerifierOutput(), `,{"name":"installation_cancel","inputSchema":{"type":"object"}}`, "", 1),
		"duplicate tool":    strings.Replace(validVerifierOutput(), "installation_cancel", "installation_status", 1),
		"foreign tool":      strings.Replace(validVerifierOutput(), "installation_cancel", "memory_delete", 1),
		"server error":      strings.Replace(validVerifierOutput(), `"result":{"protocolVersion"`, `"error":{"code":-1,"message":"no"},"result":{"protocolVersion"`, 1),
		"unknown envelope":  strings.Replace(validVerifierOutput(), `"jsonrpc":"2.0","id":1`, `"jsonrpc":"2.0","id":1,"foreign":true`, 1),
		"unexpected notice": strings.Replace(validVerifierOutput(), `"id":2,"result"`, `"method":"notifications/message"}\n{"jsonrpc":"2.0","id":2,"result"`, 1),
	}
	for name, output := range tests {
		output := output
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runner, target := verifierFixture(t)
			runner.result.StandardOutput = []byte(output)
			verifier, err := NewInvocationVerifier(runner)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifier.Verify(context.Background(), target); !errors.Is(err, port.ErrIntegrity) {
				t.Fatalf("Verify() error = %v, want ErrIntegrity", err)
			}
		})
	}
}

func TestPF001InvocationVerifierRejectsAuthorityAndExecutionFailures(t *testing.T) {
	t.Parallel()
	runner, target := verifierFixture(t)
	wrongRole := *runner
	wrongRole.authority = verifierAuthority(t, argvprocess.ExecutableRoleDockerCLI)
	if _, err := NewInvocationVerifier(&wrongRole); !errors.Is(err, port.ErrInvalidArgument) {
		t.Fatalf("wrong role error = %v", err)
	}
	if _, err := NewInvocationVerifier((*verifierRunner)(nil)); !errors.Is(err, port.ErrInvalidArgument) {
		t.Fatalf("typed nil error = %v", err)
	}
	verifier, err := NewInvocationVerifier(runner)
	if err != nil {
		t.Fatal(err)
	}
	wrongTarget, err := domain.NewTargetForAgent(
		domain.AgentHostCodex, verifierInstallationID, verifierEntryID,
		"/verified/other", target.LauncherDigest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(context.Background(), wrongTarget); !errors.Is(err, port.ErrInvalidArgument) {
		t.Fatalf("wrong target error = %v", err)
	}
	runner.runError = errors.New("child failed")
	if err := verifier.Verify(context.Background(), target); !errors.Is(err, port.ErrIntegrity) {
		t.Fatalf("runner failure error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifier.Verify(cancelled, target); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
}

type verifierRunner struct {
	authority  argvprocess.ExecutableAuthority
	result     argvprocess.Result
	runError   error
	calls      int
	invocation argvprocess.Invocation
}

func (r *verifierRunner) ExecutableAuthority() argvprocess.ExecutableAuthority { return r.authority }

func (r *verifierRunner) Run(_ context.Context, invocation argvprocess.Invocation) (argvprocess.Result, error) {
	r.calls++
	r.invocation = invocation
	return r.result, r.runError
}

func verifierFixture(t *testing.T) (*verifierRunner, domain.Target) {
	t.Helper()
	authority := verifierAuthority(t, argvprocess.ExecutableRoleAgentMemoryLauncher)
	target, err := domain.NewTargetForAgent(
		domain.AgentHostCodex, verifierInstallationID, verifierEntryID,
		authority.CanonicalPath(), domain.Digest(authority.SHA256()),
	)
	if err != nil {
		t.Fatal(err)
	}
	return &verifierRunner{
		authority: authority,
		result: argvprocess.Result{
			ExitCode:       0,
			StandardOutput: []byte(validVerifierOutput()),
		},
	}, target
}

func verifierAuthority(t *testing.T, role argvprocess.ExecutableRole) argvprocess.ExecutableAuthority {
	t.Helper()
	path := "/verified/agentmemory"
	if runtime.GOOS == "windows" {
		path = `C:\Verified\agentmemory.exe`
	}
	authority, err := argvprocess.NewExecutableAuthority(argvprocess.ExecutableAuthorityInput{
		CanonicalID: "agentmemory-launcher", CanonicalPath: path,
		SHA256: sha256.Sum256([]byte("launcher")), OwnerIdentity: "owner",
		PublisherIdentity: "publisher", PublisherPolicyID: "publisher-policy",
		PublisherTrustDigest:  sha256.Sum256([]byte("publisher-trust")),
		ReleaseManifestDigest: sha256.Sum256([]byte("release")),
		RuntimePlanDigest:     sha256.Sum256([]byte("runtime")),
		Role:                  role, Platform: runtime.GOOS, Architecture: runtime.GOARCH,
	})
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func validVerifierOutput() string {
	return `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":true}},"serverInfo":{"name":"agentmemory","version":"1.0.0"}}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"installation_status","inputSchema":{"type":"object"}},{"name":"installation_open_setup","inputSchema":{"type":"object"}},{"name":"installation_cancel","inputSchema":{"type":"object"}}]}}` + "\n"
}
