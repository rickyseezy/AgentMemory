package hostverifyapp

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001VerifyHostAuthenticatesBeforeNativeProbeAndBindsReceipt(t *testing.T) {
	t.Parallel()
	command, observation := hostCommandFixture(t)
	signature := &signatureVerifier{}
	probe := &nativeProbe{result: mustObserved(t, observation)}
	application, err := NewApplication(Dependencies{Signature: signature, Probe: probe})
	if err != nil {
		t.Fatal(err)
	}
	verification, err := application.Verify(context.Background(), command)
	if err != nil || !verification.Certified() || verification.Failure() != hostverification.FailureNone ||
		!verification.ValidFor(command.OperationID, command.ParentPlanDigest) ||
		!verification.HostPlanDigest().Equal(command.SignedPlan.Plan().Digest()) || verification.EvidenceDigest().IsZero() ||
		signature.calls != 1 || probe.calls != 1 || !probe.last.Digest().Equal(command.SignedPlan.Plan().Digest()) {
		t.Fatalf("Verify() = %+v, %v, signature=%d probe=%d", verification, err, signature.calls, probe.calls)
	}
}

func TestPF001VerifyHostReturnsClosedExpectedRejections(t *testing.T) {
	t.Parallel()
	command, observation := hostCommandFixture(t)
	tests := []struct {
		name      string
		configure func(*hostverification.ObservationInput, *nativeProbe)
		want      hostverification.FailureReason
	}{
		{name: "native encryption", configure: func(_ *hostverification.ObservationInput, probe *nativeProbe) {
			probe.result = mustRejected(t, hostverification.FailureEncryptionUnavailable)
		}, want: hostverification.FailureEncryptionUnavailable},
		{name: "cpu policy", configure: func(input *hostverification.ObservationInput, _ *nativeProbe) {
			input.CPUCores = command.SignedPlan.Plan().MinimumCPUCores() - 1
		}, want: hostverification.FailureInsufficientCPU},
		{name: "port policy", configure: func(input *hostverification.ObservationInput, _ *nativeProbe) {
			input.AvailablePorts[0].Port++
		}, want: hostverification.FailureLoopbackPortUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := hostverification.ObservationInput{
				Platform: observation.Platform(), CPUCores: observation.CPUCores(), MemoryBytes: observation.MemoryBytes(),
				FreeDiskBytes: observation.FreeDiskBytes(), StorageTarget: observation.StorageTarget(),
				Virtualization: observation.Virtualization(), Encryption: observation.Encryption(), AvailablePorts: observation.AvailablePorts(),
			}
			probe := &nativeProbe{}
			test.configure(&input, probe)
			if !probe.result.Valid() {
				changed, err := hostverification.NewObservation(input)
				if err != nil {
					t.Fatal(err)
				}
				probe.result = mustObserved(t, changed)
			}
			application, _ := NewApplication(Dependencies{Signature: &signatureVerifier{}, Probe: probe})
			verification, err := application.Verify(context.Background(), command)
			if err != nil || verification.Certified() || verification.Failure() != test.want ||
				!verification.ValidFor(command.OperationID, command.ParentPlanDigest) || verification.EvidenceDigest().IsZero() {
				t.Fatalf("Verify() = %+v, %v", verification, err)
			}
		})
	}
}

func TestPF001VerifyHostRejectsTrustBindingAndDependencyFailures(t *testing.T) {
	t.Parallel()
	command, observation := hostCommandFixture(t)
	tests := []struct {
		name      string
		command   Command
		signature *signatureVerifier
		probe     *nativeProbe
		want      ErrorCode
		probed    bool
	}{
		{name: "zero command", command: Command{}, signature: &signatureVerifier{}, probe: &nativeProbe{}, want: ErrorCodeIntegrity},
		{name: "parent remains operation binding", command: func() Command {
			changed := command
			changed.ParentPlanDigest, _ = install.BindPlan([]byte("other parent"))
			return changed
		}(), signature: &signatureVerifier{}, probe: &nativeProbe{result: mustObserved(t, observation)}, want: "", probed: true},
		{name: "untrusted", command: command, signature: &signatureVerifier{err: ErrUntrustedSigner}, probe: &nativeProbe{}, want: ErrorCodeIntegrity},
		{name: "bad signature", command: command, signature: &signatureVerifier{err: ErrSignatureInvalid}, probe: &nativeProbe{}, want: ErrorCodeIntegrity},
		{name: "signature outage", command: command, signature: &signatureVerifier{err: errors.New("raw PKI")}, probe: &nativeProbe{}, want: ErrorCodeDependency},
		{name: "probe outage", command: command, signature: &signatureVerifier{}, probe: &nativeProbe{err: errors.New("raw syscall")}, want: ErrorCodeDependency, probed: true},
		{name: "invalid probe", command: command, signature: &signatureVerifier{}, probe: &nativeProbe{}, want: ErrorCodeIntegrity, probed: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			application, _ := NewApplication(Dependencies{Signature: test.signature, Probe: test.probe})
			verification, err := application.Verify(context.Background(), test.command)
			if test.want == "" {
				if err != nil || !verification.ValidFor(test.command.OperationID, test.command.ParentPlanDigest) {
					t.Fatalf("Verify() = %+v, %v", verification, err)
				}
				return
			}
			var typed *Error
			if !errors.As(err, &typed) || typed.Code() != test.want || typed.Error() != string(test.want) {
				t.Fatalf("Verify() error = %#v", err)
			}
			wantCalls := 0
			if test.probed {
				wantCalls = 1
			}
			if test.probe.calls != wantCalls {
				t.Fatalf("probe calls = %d, want %d", test.probe.calls, wantCalls)
			}
		})
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	application, _ := NewApplication(Dependencies{Signature: &signatureVerifier{}, Probe: &nativeProbe{result: mustObserved(t, observation)}})
	if _, err := application.Verify(cancelled, command); errorCode(err) != ErrorCodeCancelled {
		t.Fatalf("cancelled error = %#v", err)
	}
	var absentContext context.Context
	if _, err := application.Verify(absentContext, command); errorCode(err) != ErrorCodeCancelled {
		t.Fatalf("nil context error = %#v", err)
	}
}

func TestPF001VerifyHostRejectsMissingAndTypedNilCapabilities(t *testing.T) {
	t.Parallel()
	var typedSignature *signatureVerifier
	var typedProbe *nativeProbe
	for _, dependencies := range []Dependencies{
		{}, {Signature: typedSignature, Probe: &nativeProbe{}}, {Signature: &signatureVerifier{}, Probe: typedProbe},
	} {
		if _, err := NewApplication(dependencies); err == nil {
			t.Fatalf("NewApplication(%+v) succeeded", dependencies)
		}
	}
}

func hostCommandFixture(t *testing.T) (Command, hostverification.Observation) {
	t.Helper()
	parent, _ := install.BindPlan([]byte("canonical parent"))
	operationID, _ := install.NewOperationID("019f6000-1234-7abc-8123-0123456789ab")
	plan, err := hostverification.NewPlan(hostverification.Input{
		PolicyID: "host-policy-1", SigningKeyID: "host-root-1",
		Platform:        hostverification.PlatformTuple{OperatingSystem: hostverification.OperatingSystemLinux, Product: "ubuntu", Architecture: hostverification.ArchitectureAMD64, Version: "24.04", Build: "6.8.0-63-generic"},
		MinimumCPUCores: 4, MinimumMemoryBytes: 8 << 30, MinimumFreeDiskBytes: 40 << 30,
		StorageTarget: "/home/user/.agentmemory",
		RequiredPorts: []hostverification.LoopbackEndpoint{{Family: hostverification.LoopbackIPv4, Port: 4317}, {Family: hostverification.LoopbackIPv6, Port: 4318}},
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := hostverification.NewSignedPlan(plan, plan.SigningKeyID(), []byte("signature"))
	if err != nil {
		t.Fatal(err)
	}
	observation, err := hostverification.NewObservation(hostverification.ObservationInput{
		Platform: plan.Platform(), CPUCores: 8, MemoryBytes: 16 << 30, FreeDiskBytes: 100 << 30,
		StorageTarget: plan.StorageTarget(), Virtualization: hostverification.VirtualizationKVM,
		Encryption: hostverification.EncryptionDMcrypt, AvailablePorts: plan.RequiredPorts(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return Command{OperationID: operationID, ParentPlanDigest: parent, SignedPlan: signed}, observation
}

func mustObserved(t *testing.T, observation hostverification.Observation) hostverification.ProbeResult {
	t.Helper()
	result, err := hostverification.NewObservedResult(observation)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func mustRejected(t *testing.T, reason hostverification.FailureReason) hostverification.ProbeResult {
	t.Helper()
	result, err := hostverification.NewRejectedResult(reason)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

type signatureVerifier struct {
	err   error
	calls int
}

func (v *signatureVerifier) VerifyHostPlanSignature(context.Context, hostverification.SignedPlan) error {
	v.calls++
	return v.err
}

type nativeProbe struct {
	result hostverification.ProbeResult
	err    error
	calls  int
	last   hostverification.Plan
}

func (p *nativeProbe) ProbeHost(_ context.Context, plan hostverification.Plan) (hostverification.ProbeResult, error) {
	p.calls++
	p.last = plan
	return p.result, p.err
}

func errorCode(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Code()
	}
	return ""
}
