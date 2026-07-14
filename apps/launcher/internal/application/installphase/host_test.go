package installphase

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/hostverifyapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001HostPhaseBindsCertifiedEvidenceIntoParentSaga(t *testing.T) {
	t.Parallel()
	request, projection, query, verifier := hostPhaseFixture(t, hostverification.FailureNone)
	phase, err := NewHostVerificationPhase(query, verifier)
	if err != nil {
		t.Fatal(err)
	}
	output, err := phase.VerifyHost(context.Background(), request)
	if err != nil || output.Outcome() != installapp.PhaseOutcomeCompleted ||
		output.OutputDigest().IsZero() || !output.InputDigest().Equal(projection.SignedHostPlan.Plan().Digest()) ||
		output.RuntimeOwnership() != install.RuntimeOwnershipUndetermined ||
		output.NextSafeAction() != "installation.continue" {
		t.Fatalf("VerifyHost() = %+v, %v", output, err)
	}
}

func TestPF001HostPhaseMapsClosedNativeRejectionToUnsupportedHost(t *testing.T) {
	t.Parallel()
	request, _, query, verifier := hostPhaseFixture(t, hostverification.FailureEncryptionUnavailable)
	phase, _ := NewHostVerificationPhase(query, verifier)
	output, err := phase.VerifyHost(context.Background(), request)
	if err != nil || output.Outcome() != installapp.PhaseOutcomeUnsupportedHost ||
		output.NextSafeAction() != "installation.select_supported_host" {
		t.Fatalf("VerifyHost() = %+v, %v", output, err)
	}
}

func TestPF001HostPhaseRejectsCrossPlanAndUntrustedResults(t *testing.T) {
	t.Parallel()
	request, _, _, _ := hostPhaseFixture(t, hostverification.FailureNone)
	tests := []struct {
		name      string
		configure func(*HostVerificationPlan, *hostPlanQuery, *HostVerifier)
		want      ErrorCode
	}{
		{name: "query error", configure: func(_ *HostVerificationPlan, query *hostPlanQuery, _ *HostVerifier) {
			query.err = errors.New("raw repository")
		}, want: ErrorCodePlanUnavailable},
		{name: "parent mismatch", configure: func(plan *HostVerificationPlan, _ *hostPlanQuery, _ *HostVerifier) {
			plan.ParentPlanDigest, _ = install.BindPlan([]byte("other parent"))
		}, want: ErrorCodeInvalidBinding},
		{name: "ownership", configure: func(plan *HostVerificationPlan, _ *hostPlanQuery, _ *HostVerifier) {
			plan.RuntimeOwnership = install.RuntimeOwnershipReusedExternal
		}, want: ErrorCodeInvalidBinding},
		{name: "verifier error", configure: func(_ *HostVerificationPlan, _ *hostPlanQuery, verifier *HostVerifier) {
			*verifier = failingHostVerifier{err: errors.New("raw native")}
		}, want: ErrorCodeHostUnavailable},
		{name: "invalid result", configure: func(_ *HostVerificationPlan, _ *hostPlanQuery, verifier *HostVerifier) {
			*verifier = failingHostVerifier{}
		}, want: ErrorCodeInvalidBinding},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, projection, query, verifier := hostPhaseFixture(t, hostverification.FailureNone)
			var capability HostVerifier = verifier
			test.configure(&projection, query, &capability)
			query.plan = projection
			phase, _ := NewHostVerificationPhase(query, capability)
			_, err := phase.VerifyHost(context.Background(), request)
			var typed *Error
			if !errors.As(err, &typed) || typed.Code() != test.want {
				t.Fatalf("VerifyHost() error = %#v", err)
			}
		})
	}

	_, _, query, verifier := hostPhaseFixture(t, hostverification.FailureNone)
	if _, err := NewHostVerificationPhase(nil, verifier); err == nil {
		t.Fatal("nil plan query was accepted")
	}
	if _, err := NewHostVerificationPhase(query, nil); err == nil {
		t.Fatal("nil verifier was accepted")
	}
	phase, _ := NewHostVerificationPhase(query, verifier)
	if _, err := phase.VerifyHost(context.Background(), installapp.PhaseRequest{}); err == nil {
		t.Fatal("invalid request was accepted")
	}
}

func hostPhaseFixture(
	t *testing.T,
	rejection hostverification.FailureReason,
) (installapp.PhaseRequest, HostVerificationPlan, *hostPlanQuery, *hostverifyapp.Application) {
	t.Helper()
	parentBytes := []byte("canonical parent host plan")
	parent, _ := install.BindPlan(parentBytes)
	operationID, _ := install.NewOperationID("019f6001-1234-7abc-8123-0123456789ab")
	request, err := installapp.NewPhaseRequestForIntegration(operationID, parent, 1, parentBytes)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := hostverification.NewPlan(hostverification.Input{
		PolicyID: "host-policy-1", SigningKeyID: "host-root-1",
		Platform:        hostverification.PlatformTuple{OperatingSystem: hostverification.OperatingSystemLinux, Product: "ubuntu", Architecture: hostverification.ArchitectureAMD64, Version: "24.04", Build: "6.8.0-63-generic"},
		MinimumCPUCores: 4, MinimumMemoryBytes: 8 << 30, MinimumFreeDiskBytes: 40 << 30,
		StorageTarget: "/home/user/.agentmemory",
		RequiredPorts: []hostverification.LoopbackEndpoint{{Family: hostverification.LoopbackIPv4, Port: 4317}},
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := hostverification.NewSignedPlan(plan, plan.SigningKeyID(), []byte("signature"))
	if err != nil {
		t.Fatal(err)
	}
	projection := HostVerificationPlan{
		ParentPlanDigest: parent, SignedHostPlan: signed,
		RuntimeOwnership: install.RuntimeOwnershipUndetermined,
	}
	var probe hostverification.ProbeResult
	if rejection == hostverification.FailureNone {
		observation, observationError := hostverification.NewObservation(hostverification.ObservationInput{
			Platform: plan.Platform(), CPUCores: 8, MemoryBytes: 16 << 30, FreeDiskBytes: 100 << 30,
			StorageTarget: plan.StorageTarget(), Virtualization: hostverification.VirtualizationKVM,
			Encryption: hostverification.EncryptionDMcrypt, AvailablePorts: plan.RequiredPorts(),
		})
		if observationError != nil {
			t.Fatal(observationError)
		}
		probe, err = hostverification.NewObservedResult(observation)
	} else {
		probe, err = hostverification.NewRejectedResult(rejection)
	}
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := hostverifyapp.NewApplication(hostverifyapp.Dependencies{
		Signature: acceptingHostSignature{}, Probe: fixedHostProbe{result: probe},
	})
	if err != nil {
		t.Fatal(err)
	}
	return request, projection, &hostPlanQuery{plan: projection}, verifier
}

type hostPlanQuery struct {
	plan HostVerificationPlan
	err  error
}

func (q *hostPlanQuery) ResolveHostVerificationPlan(context.Context, install.PlanDigest) (HostVerificationPlan, error) {
	return q.plan, q.err
}

type acceptingHostSignature struct{}

func (acceptingHostSignature) VerifyHostPlanSignature(context.Context, hostverification.SignedPlan) error {
	return nil
}

type fixedHostProbe struct{ result hostverification.ProbeResult }

func (p fixedHostProbe) ProbeHost(context.Context, hostverification.Plan) (hostverification.ProbeResult, error) {
	return p.result, nil
}

type failingHostVerifier struct{ err error }

func (v failingHostVerifier) Verify(context.Context, hostverifyapp.Command) (hostverifyapp.Verification, error) {
	return hostverifyapp.Verification{}, v.err
}
