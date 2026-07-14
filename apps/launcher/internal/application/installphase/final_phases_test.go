package installphase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/activereleaseapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/readinessapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/readiness"
)

func TestPF001FinalPhaseAdaptersBindReadinessReceiptIntoActivation(t *testing.T) {
	t.Parallel()

	fixture := newFinalPhaseFixture(t)
	readinessPhase, err := NewReadinessPhase(fixture.readinessPlans, fixture.readiness)
	if err != nil {
		t.Fatal(err)
	}
	readinessOutput, err := readinessPhase.VerifyReadiness(context.Background(), fixture.request)
	if err != nil || readinessOutput.Outcome() != installapp.PhaseOutcomeCompleted {
		t.Fatalf("VerifyReadiness() = %+v, %v", readinessOutput, err)
	}
	if !fixture.readiness.last.PlanDigest.Equal(fixture.request.PlanDigest()) ||
		fixture.readiness.last.OperationID != fixture.request.OperationID() ||
		!fixture.readiness.receipt.Digest().Equal(readinessOutput.OutputDigest()) {
		t.Fatal("readiness phase lost the exact installation/release binding")
	}

	activationPhase, err := NewActiveReleasePhase(fixture.activationPlans, fixture.activation, fixture.capacity)
	if err != nil {
		t.Fatal(err)
	}
	activationOutput, err := activationPhase.CommitActiveRelease(context.Background(), fixture.request)
	if err != nil || activationOutput.Outcome() != installapp.PhaseOutcomeCompleted {
		t.Fatalf("CommitActiveRelease() = %+v, %v", activationOutput, err)
	}
	if fixture.capacity.transferGeneration != fixture.activationPlans.plan.GenerationID ||
		fixture.capacity.transferInstallation != fixture.activationPlans.plan.InstallationID {
		t.Fatal("activation did not transfer expanded/rollback/safety capacity ownership before Ready")
	}
	if fixture.activationPlans.operation != fixture.request.OperationID() {
		t.Fatal("activation plan query was not bound to the phase operation")
	}
	if !fixture.activation.last.ReadinessReceiptDigest.Equal(fixture.readiness.receipt.Digest()) ||
		!activationOutput.InputDigest().Equal(fixture.readiness.receipt.Digest()) ||
		!activationOutput.OutputDigest().Equal(fixture.activation.pointerDigest) {
		t.Fatal("activation phase was not authorized by the persisted readiness receipt")
	}
}

func TestPF001ReadinessPhaseKeepsActivationUnreachableOnAnyNegativeGate(t *testing.T) {
	t.Parallel()

	fixture := newFinalPhaseFixture(t)
	fixture.readiness.verification = readinessapp.NewNotReadyVerification([]readiness.Failure{{
		Probe: readiness.ProbeSemanticWriteIndexRecall,
		Code:  readiness.FailureProbeFailed,
	}})
	phase, _ := NewReadinessPhase(fixture.readinessPlans, fixture.readiness)
	output, err := phase.VerifyReadiness(context.Background(), fixture.request)
	if err != nil || output.Outcome() != installapp.PhaseOutcomeFailedRecoverable || output.NextSafeAction() != "installation.readiness_retry" {
		t.Fatalf("VerifyReadiness() = %+v, %v", output, err)
	}
}

func TestPF001FinalPhaseAdaptersRejectCrossPlanAndSanitizeBoundaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		invoke func(*finalPhaseFixture) error
	}{
		{name: "readiness plan missing", invoke: func(value *finalPhaseFixture) error {
			value.readinessPlans.err = errors.New("/private/path")
			phase, _ := NewReadinessPhase(value.readinessPlans, value.readiness)
			_, err := phase.VerifyReadiness(context.Background(), value.request)
			return err
		}},
		{name: "readiness plan mismatch", invoke: func(value *finalPhaseFixture) error {
			value.readinessPlans.plan.PlanDigest, _ = install.BindPlan([]byte("other"))
			phase, _ := NewReadinessPhase(value.readinessPlans, value.readiness)
			_, err := phase.VerifyReadiness(context.Background(), value.request)
			return err
		}},
		{name: "readiness dependency", invoke: func(value *finalPhaseFixture) error {
			value.readiness.err = errors.New("secret raw")
			phase, _ := NewReadinessPhase(value.readinessPlans, value.readiness)
			_, err := phase.VerifyReadiness(context.Background(), value.request)
			return err
		}},
		{name: "activation plan missing", invoke: func(value *finalPhaseFixture) error {
			value.activationPlans.err = errors.New("/private/path")
			phase, _ := NewActiveReleasePhase(value.activationPlans, value.activation, value.capacity)
			_, err := phase.CommitActiveRelease(context.Background(), value.request)
			return err
		}},
		{name: "activation plan mismatch", invoke: func(value *finalPhaseFixture) error {
			value.activationPlans.plan.PlanDigest, _ = install.BindPlan([]byte("other"))
			phase, _ := NewActiveReleasePhase(value.activationPlans, value.activation, value.capacity)
			_, err := phase.CommitActiveRelease(context.Background(), value.request)
			return err
		}},
		{name: "activation dependency", invoke: func(value *finalPhaseFixture) error {
			value.activation.err = errors.New("secret raw")
			phase, _ := NewActiveReleasePhase(value.activationPlans, value.activation, value.capacity)
			_, err := phase.CommitActiveRelease(context.Background(), value.request)
			return err
		}},
		{name: "activation capacity evidence", invoke: func(value *finalPhaseFixture) error {
			value.capacity.transferResult = &artifactapp.CapacityResult{Version: 1, Leases: []artifactacquisition.CapacityLeaseSnapshot{{
				LeaseID: "l-manufactured", Purpose: string(artifactacquisition.LeaseSafety), State: string(artifactacquisition.LeaseTransferred),
			}}}
			phase, _ := NewActiveReleasePhase(value.activationPlans, value.activation, value.capacity)
			_, err := phase.CommitActiveRelease(context.Background(), value.request)
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newFinalPhaseFixture(t)
			err := test.invoke(fixture)
			var typed *Error
			if !errors.As(err, &typed) || typed.Code() == "" || typed.Error() != string(typed.Code()) {
				t.Fatalf("error = %#v", err)
			}
			if containsSensitive(typed.Error()) {
				t.Fatal("raw boundary detail escaped")
			}
		})
	}
}

func TestPF001FinalPhaseAdaptersRequireEveryCapability(t *testing.T) {
	t.Parallel()

	fixture := newFinalPhaseFixture(t)
	if _, err := NewReadinessPhase(nil, fixture.readiness); err == nil {
		t.Fatal("NewReadinessPhase() accepted nil plan query")
	}
	if _, err := NewReadinessPhase(fixture.readinessPlans, nil); err == nil {
		t.Fatal("NewReadinessPhase() accepted nil verifier")
	}
	if _, err := NewActiveReleasePhase(nil, fixture.activation, fixture.capacity); err == nil {
		t.Fatal("NewActiveReleasePhase() accepted nil plan query")
	}
	if _, err := NewActiveReleasePhase(fixture.activationPlans, nil, fixture.capacity); err == nil {
		t.Fatal("NewActiveReleasePhase() accepted nil committer")
	}
	if _, err := NewActiveReleasePhase(fixture.activationPlans, fixture.activation, nil); err == nil {
		t.Fatal("NewActiveReleasePhase() accepted nil capacity coordinator")
	}
	var typedNil *readinessVerifier
	if _, err := NewReadinessPhase(fixture.readinessPlans, typedNil); err == nil {
		t.Fatal("NewReadinessPhase() accepted typed nil verifier")
	}

	invalid := installapp.PhaseRequest{}
	phase, _ := NewReadinessPhase(fixture.readinessPlans, fixture.readiness)
	if _, err := phase.VerifyReadiness(context.Background(), invalid); err == nil {
		t.Fatal("readiness phase accepted invalid request")
	}
	activation, _ := NewActiveReleasePhase(fixture.activationPlans, fixture.activation, fixture.capacity)
	if _, err := activation.CommitActiveRelease(context.Background(), invalid); err == nil {
		t.Fatal("activation phase accepted invalid request")
	}
}

type finalPhaseFixture struct {
	request         installapp.PhaseRequest
	readinessPlans  *readinessPlanQuery
	activationPlans *activationPlanQuery
	readiness       *readinessVerifier
	activation      *activationCommitter
	capacity        *artifactCapacityApplication
}

func newFinalPhaseFixture(t *testing.T) *finalPhaseFixture {
	t.Helper()
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	planDigest, _ := install.BindPlan([]byte("canonical plan"))
	request, err := installapp.NewPhaseRequestForIntegration(operationID, planDigest, 1, []byte("canonical plan"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := install.DigestBytes([]byte("manifest"))
	compose := install.DigestBytes([]byte("compose"))
	receipt := finalPhaseReceipt(t, operationID, planDigest, manifest, compose)
	readinessPlan := ReadinessPlan{
		PlanDigest: planDigest, ReleaseID: "release-v1", GenerationID: "019f5f21-5678-7def-9123-abcdef012345",
		ManifestDigest: manifest, ComposeDigest: compose, RuntimeOwnership: install.RuntimeOwnershipReusedExternal,
	}
	installationID := "019f5f20-1234-7abc-8123-0123456789ab"
	identity, _ := composeplan.NewIdentity(installationID, readinessPlan.GenerationID)
	projectionAuthority, _ := identity.SecretProjectionCapacities()
	secretProjections := make([]artifactapp.SecretProjectionCapacity, 0, len(projectionAuthority))
	for _, authority := range projectionAuthority {
		secretProjections = append(secretProjections, artifactapp.SecretProjectionCapacity{
			Name: authority.Name(), Purpose: authority.Purpose(), ReservedBytes: authority.ReservedBytes(),
		})
	}
	activationPlan := ActivationPlan{
		PlanDigest: planDigest, InstallationID: installationID,
		ReleaseID: readinessPlan.ReleaseID, GenerationID: readinessPlan.GenerationID,
		ManifestDigest: manifest, ComposeDigest: compose, ReadinessReceiptDigest: receipt.Digest(),
		RuntimeEndpoint: "unix:///var/run/docker.sock", ReleaseSequence: 7,
		ResourceInventoryVersion: 9, ResourceInventoryDigest: install.DigestBytes([]byte("inventory")),
		SecurityEpoch: 3, RuntimeOwnership: install.RuntimeOwnershipReusedExternal,
		CapacityCommand: artifactapp.CapacityCommand{OperationID: operationID.String(), ParentPlanDigest: planDigest,
			InstallationID: installationID, ReleaseID: readinessPlan.ReleaseID, GenerationID: readinessPlan.GenerationID,
			Plan: artifactPhasePlan(t), SecretProjections: secretProjections,
			HostCAS:          artifactapp.CapacityTarget{Kind: artifactapp.CapacityHostCAS, Locator: "/cas"},
			HostRelease:      artifactapp.CapacityTarget{Kind: artifactapp.CapacityHostRelease, Locator: "/releases/release-1"},
			DockerEngine:     artifactapp.CapacityTarget{Kind: artifactapp.CapacityDockerEngine, Locator: "engine"},
			DockerDataVolume: artifactapp.CapacityTarget{Kind: artifactapp.CapacityDockerDataVolume, Locator: "volume"}},
	}
	return &finalPhaseFixture{
		request:         request,
		readinessPlans:  &readinessPlanQuery{plan: readinessPlan},
		activationPlans: &activationPlanQuery{plan: activationPlan},
		readiness:       &readinessVerifier{verification: readinessapp.NewReadyVerification(receipt), receipt: receipt},
		activation: &activationCommitter{result: activereleaseapp.Result{
			Status: activereleaseapp.StatusCommitted, PointerDigest: install.DigestBytes([]byte("pointer")),
		}, pointerDigest: install.DigestBytes([]byte("pointer"))}, capacity: &artifactCapacityApplication{},
	}
}

type readinessPlanQuery struct {
	plan ReadinessPlan
	err  error
}

func (q *readinessPlanQuery) ResolveReadinessPlan(context.Context, install.PlanDigest) (ReadinessPlan, error) {
	return q.plan, q.err
}

type activationPlanQuery struct {
	plan      ActivationPlan
	err       error
	operation install.OperationID
}

func (q *activationPlanQuery) ResolveActivationPlan(_ context.Context, _ install.PlanDigest, operation install.OperationID) (ActivationPlan, error) {
	q.operation = operation
	return q.plan, q.err
}

type readinessVerifier struct {
	verification readinessapp.Verification
	receipt      readiness.Receipt
	last         readinessapp.Command
	err          error
}

func (v *readinessVerifier) Verify(_ context.Context, command readinessapp.Command) (readinessapp.Verification, error) {
	v.last = command
	return v.verification, v.err
}

type activationCommitter struct {
	result        activereleaseapp.Result
	pointerDigest install.Digest
	last          activereleaseapp.Command
	err           error
}

func (c *activationCommitter) Commit(_ context.Context, command activereleaseapp.Command) (activereleaseapp.Result, error) {
	c.last = command
	return c.result, c.err
}

func finalPhaseReceipt(
	t *testing.T,
	operationID install.OperationID,
	plan install.PlanDigest,
	manifest install.Digest,
	compose install.Digest,
) readiness.Receipt {
	t.Helper()
	return completeReceiptForInstallPhase(t, operationID, plan, "release-v1", "019f5f21-5678-7def-9123-abcdef012345", manifest, compose)
}

func completeReceiptForInstallPhase(
	t *testing.T,
	operationID install.OperationID,
	plan install.PlanDigest,
	releaseID string,
	generationID string,
	manifest install.Digest,
	compose install.Digest,
) readiness.Receipt {
	t.Helper()
	now := time.Date(2026, 7, 13, 10, 11, 12, 123456000, time.UTC)
	results := make([]readiness.Result, 0, len(readiness.RequiredProbes()))
	for _, probe := range readiness.RequiredProbes() {
		result, err := readiness.NewResult(readiness.ResultInput{
			Probe: probe, Status: readiness.StatusPassed, OperationID: operationID, PlanDigest: plan,
			ReleaseID: releaseID, GenerationID: generationID, ManifestDigest: manifest, ComposeDigest: compose,
			EvidenceDigest: install.DigestBytes([]byte(probe.String())), ObservedAt: now,
		})
		if err != nil {
			t.Fatal(err)
		}
		results = append(results, result)
	}
	receipt, failures := readiness.NewGate().Evaluate(readiness.GateInput{
		OperationID: operationID, PlanDigest: plan, ReleaseID: releaseID, GenerationID: generationID,
		ManifestDigest: manifest, ComposeDigest: compose, EvaluatedAt: now, Results: results,
	})
	if len(failures) != 0 {
		t.Fatal(failures)
	}
	return receipt
}

func containsSensitive(value string) bool {
	return value == "/private/path" || value == "secret raw"
}
