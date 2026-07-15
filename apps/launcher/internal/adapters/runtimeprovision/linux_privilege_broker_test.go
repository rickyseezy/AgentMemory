package runtimeprovision

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
)

func TestPF006PolkitPrivilegeBrokerUsesOnlyFixedAuthenticatedStdinContract(t *testing.T) {
	t.Parallel()
	request, receipt := privilegeTransportFixture(t)
	codec := &privilegeCodecStub{encoded: []byte(`{"schemaVersion":1}`), receipt: receipt}
	runner := &privilegeRunnerStub{
		authority: privilegeTransportAuthority(t, request.Authority()),
		result:    argvprocess.Result{StandardOutput: []byte(`{"receipt":"signed"}`)},
	}
	broker, err := NewPolkitPrivilegeBroker(runner, codec)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := broker.Execute(t.Context(), request)
	if err != nil || actual.Digest() != receipt.Digest() || codec.encodeCalls != 1 || codec.decodeCalls != 1 ||
		runner.calls != 1 || runner.invocation.Executable() != "/usr/bin/pkexec" ||
		runner.invocation.EnvironmentProfile() != argvprocess.EnvironmentProfilePrivilegeBroker ||
		string(runner.invocation.StandardInput()) != string(codec.encoded) {
		t.Fatalf("receipt=%+v error=%v calls=%d/%d/%d invocation=%+v", actual, err, codec.encodeCalls, codec.decodeCalls, runner.calls, runner.invocation)
	}
	wanted := []string{"--disable-internal-agent", "/usr/libexec/agentmemory/agentmemory-runtime-helper", "--request-stdin"}
	arguments := runner.invocation.Arguments()
	if len(arguments) != len(wanted) {
		t.Fatalf("arguments=%q", arguments)
	}
	for index := range wanted {
		if arguments[index] != wanted[index] {
			t.Fatalf("arguments=%q", arguments)
		}
	}
}

func TestPF006PolkitPrivilegeBrokerMapsNativeDecisionWithoutLeakingDiagnostics(t *testing.T) {
	t.Parallel()
	request, receipt := privilegeTransportFixture(t)
	tests := []struct {
		name   string
		result argvprocess.Result
		runErr error
		codec  *privilegeCodecStub
		want   error
	}{
		{name: "declined", result: argvprocess.Result{ExitCode: 126, StandardError: []byte("private")}, runErr: errors.New("exit"), codec: &privilegeCodecStub{encoded: []byte("x"), receipt: receipt}, want: runtimeport.ErrPrivilegeDenied},
		{name: "unavailable", result: argvprocess.Result{ExitCode: 127}, runErr: errors.New("exit"), codec: &privilegeCodecStub{encoded: []byte("x"), receipt: receipt}, want: runtimeport.ErrPrivilegeUnavailable},
		{name: "execution failure", result: argvprocess.Result{ExitCode: 1}, runErr: errors.New("exit"), codec: &privilegeCodecStub{encoded: []byte("x"), receipt: receipt}, want: runtimeport.ErrPrivilegeUnavailable},
		{name: "truncated", result: argvprocess.Result{OutputTruncated: true}, codec: &privilegeCodecStub{encoded: []byte("x"), receipt: receipt}, want: runtimeport.ErrPrivilegeIntegrity},
		{name: "stderr", result: argvprocess.Result{StandardOutput: []byte("receipt"), StandardError: []byte("private")}, codec: &privilegeCodecStub{encoded: []byte("x"), receipt: receipt}, want: runtimeport.ErrPrivilegeIntegrity},
		{name: "decode", result: argvprocess.Result{StandardOutput: []byte("receipt")}, codec: &privilegeCodecStub{encoded: []byte("x"), decodeErr: errors.New("private")}, want: runtimeport.ErrPrivilegeIntegrity},
		{name: "empty request", codec: &privilegeCodecStub{receipt: receipt}, want: runtimeport.ErrPrivilegeIntegrity},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runner := &privilegeRunnerStub{
				authority: privilegeTransportAuthority(t, request.Authority()), result: test.result, err: test.runErr,
			}
			broker, err := NewPolkitPrivilegeBroker(runner, test.codec)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := broker.Execute(t.Context(), request); !errors.Is(err, test.want) ||
				stringsContainPrivate(err) {
				t.Fatalf("error=%v want=%v", err, test.want)
			}
		})
	}
}

func TestPF006PolkitPrivilegeBrokerRejectsUnsafeConstructionAndCancellation(t *testing.T) {
	t.Parallel()
	request, receipt := privilegeTransportFixture(t)
	validRunner := &privilegeRunnerStub{authority: privilegeTransportAuthority(t, request.Authority())}
	validCodec := &privilegeCodecStub{encoded: []byte("x"), receipt: receipt}
	if broker, err := NewPolkitPrivilegeBroker(nil, validCodec); err == nil || broker != nil {
		t.Fatalf("nil runner broker=%+v error=%v", broker, err)
	}
	if broker, err := NewPolkitPrivilegeBroker(validRunner, nil); err == nil || broker != nil {
		t.Fatalf("nil codec broker=%+v error=%v", broker, err)
	}
	wrong := *validRunner
	wrong.authority = rootlessAuthority(t, request.Authority())
	if broker, err := NewPolkitPrivilegeBroker(&wrong, validCodec); err == nil || broker != nil {
		t.Fatalf("wrong runner broker=%+v error=%v", broker, err)
	}
	broker, _ := NewPolkitPrivilegeBroker(validRunner, validCodec)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := broker.Execute(cancelled, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
}

type privilegeCodecStub struct {
	encoded     []byte
	receipt     runtimeport.PrivilegeReceipt
	encodeErr   error
	decodeErr   error
	encodeCalls int
	decodeCalls int
}

func (c *privilegeCodecStub) EncodePrivilegeRequest(context.Context, runtimeport.PrivilegeRequest) ([]byte, error) {
	c.encodeCalls++
	return append([]byte(nil), c.encoded...), c.encodeErr
}

func (c *privilegeCodecStub) DecodePrivilegeReceipt([]byte) (runtimeport.PrivilegeReceipt, error) {
	c.decodeCalls++
	return c.receipt, c.decodeErr
}

type privilegeRunnerStub struct {
	authority  argvprocess.ExecutableAuthority
	result     argvprocess.Result
	err        error
	invocation argvprocess.Invocation
	calls      int
}

func (r *privilegeRunnerStub) ExecutableAuthority() argvprocess.ExecutableAuthority {
	return r.authority
}

func (r *privilegeRunnerStub) Run(_ context.Context, invocation argvprocess.Invocation) (argvprocess.Result, error) {
	r.calls++
	r.invocation = invocation
	return r.result, r.err
}

func privilegeTransportAuthority(t testing.TB, authority runtimeport.LinuxAuthority) argvprocess.ExecutableAuthority {
	t.Helper()
	executable, err := argvprocess.NewExecutableAuthority(argvprocess.ExecutableAuthorityInput{
		CanonicalID: "pkexec", CanonicalPath: authority.PrivilegeToolPath(), SHA256: authority.PrivilegeToolSHA256(),
		OwnerIdentity: "uid:0", PublisherIdentity: "package:" + authority.PrivilegeToolPackage(),
		PublisherPolicyID: "linux:package-receipt:v1", PublisherTrustDigest: authority.PrivilegeToolPackageReceiptDigest(),
		ReleaseManifestDigest: sha256.Sum256([]byte("release")), RuntimePlanDigest: authority.PlanDigest(),
		Role: argvprocess.ExecutableRolePrivilegeBroker, Platform: "linux", Architecture: authority.Architecture().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return executable
}

func privilegeTransportFixture(t *testing.T) (runtimeport.PrivilegeRequest, runtimeport.PrivilegeReceipt) {
	t.Helper()
	_, authority := adapterAuthority(t)
	now := time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC)
	nonce := runtimeport.Nonce{1, 2, 3}
	state, err := runtimeport.ExpectedPrivilegeState(authority, runtimeport.PrivilegeInstallPackages)
	if err != nil {
		t.Fatal(err)
	}
	request, err := runtimeport.NewPrivilegeRequest(runtimeport.PrivilegeRequestInput{
		OperationID: "019f5f23-transport", Attempt: 1, Operation: runtimeport.PrivilegeInstallPackages,
		Authority: authority, Nonce: nonce, IssuedAt: now, ExpiresAt: now.Add(time.Minute), ExpectedState: state,
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := (&fakePrivilegeBroker{}).Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	return request, receipt
}

func stringsContainPrivate(err error) bool {
	return err != nil && err.Error() == "private"
}
