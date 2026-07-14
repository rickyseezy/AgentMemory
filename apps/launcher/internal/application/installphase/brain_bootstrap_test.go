package installphase

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/brainbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001BrainBootstrapPhaseBindsExactOwnerAndFirstBrain(t *testing.T) {
	t.Parallel()
	fixture := newBrainBootstrapPhaseFixture(t)
	phase, err := NewBrainBootstrapPhase(fixture.plans, fixture.bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	output, err := phase.BootstrapLocalBrain(context.Background(), fixture.request)
	if err != nil || output.Outcome() != installapp.PhaseOutcomeCompleted ||
		!output.InputDigest().Equal(fixture.bootstrap.last.BindingDigest()) ||
		!output.OutputDigest().Equal(fixture.bootstrap.receipt.OutputDigest()) ||
		output.RuntimeOwnership() != install.RuntimeOwnershipProvisionedByAgentMemory {
		t.Fatalf("BootstrapLocalBrain() = %#v/%v", output, err)
	}
	if fixture.bootstrap.last.OwnerPrincipalID() == "" || fixture.bootstrap.last.OwnerGrantID() == "" ||
		fixture.bootstrap.last.OwnerSubjectDigest().IsZero() || fixture.bootstrap.last.BrainName() != "local" {
		t.Fatal("bootstrap phase dropped owner or Brain authority")
	}
}

func TestPF001BrainBootstrapPhaseRejectsReplayAndSanitizesFailures(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(*brainBootstrapPhaseFixture)
		code   ErrorCode
	}{
		{name: "plan unavailable", code: ErrorCodePlanUnavailable, mutate: func(value *brainBootstrapPhaseFixture) {
			value.plans.err = errors.New("/private/plan")
		}},
		{name: "cross attempt authorization", code: ErrorCodeInvalidBinding, mutate: func(value *brainBootstrapPhaseFixture) {
			value.plans.wrongAttempt = true
		}},
		{name: "Core unavailable", code: ErrorCodeBrainBootstrapUnavailable, mutate: func(value *brainBootstrapPhaseFixture) {
			value.bootstrap.err = errors.New("secret raw")
		}},
		{name: "cross plan receipt", code: ErrorCodeInvalidBinding, mutate: func(value *brainBootstrapPhaseFixture) {
			value.bootstrap.wrongReceipt = true
		}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newBrainBootstrapPhaseFixture(t)
			test.mutate(fixture)
			phase, _ := NewBrainBootstrapPhase(fixture.plans, fixture.bootstrap)
			_, err := phase.BootstrapLocalBrain(context.Background(), fixture.request)
			var typed *Error
			if !errors.As(err, &typed) || typed.Code() != test.code || typed.Error() != string(test.code) {
				t.Fatalf("error = %#v, want %s", err, test.code)
			}
		})
	}
}

func TestPF001BrainBootstrapPhaseRequiresCapabilitiesAndValidRequest(t *testing.T) {
	t.Parallel()
	fixture := newBrainBootstrapPhaseFixture(t)
	if _, err := NewBrainBootstrapPhase(nil, fixture.bootstrap); err == nil {
		t.Fatal("constructor accepted nil plans")
	}
	if _, err := NewBrainBootstrapPhase(fixture.plans, nil); err == nil {
		t.Fatal("constructor accepted nil bootstrapper")
	}
	var typedNil *brainBootstrapper
	if _, err := NewBrainBootstrapPhase(fixture.plans, typedNil); err == nil {
		t.Fatal("constructor accepted typed nil bootstrapper")
	}
	phase, _ := NewBrainBootstrapPhase(fixture.plans, fixture.bootstrap)
	if _, err := phase.BootstrapLocalBrain(context.Background(), installapp.PhaseRequest{}); err == nil {
		t.Fatal("phase accepted invalid request")
	}
}

type brainBootstrapPhaseFixture struct {
	request   installapp.PhaseRequest
	plans     *brainBootstrapPlanQuery
	bootstrap *brainBootstrapper
}

func newBrainBootstrapPhaseFixture(t testing.TB) *brainBootstrapPhaseFixture {
	t.Helper()
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	plan, _ := install.BindPlan([]byte("canonical plan"))
	request, err := installapp.NewPhaseRequestForIntegration(operationID, plan, 3, []byte("canonical plan"))
	if err != nil {
		t.Fatal(err)
	}
	return &brainBootstrapPhaseFixture{
		request: request,
		plans: &brainBootstrapPlanQuery{input: brainbootstrap.AuthorizationInput{ //nolint:gosec // G101: path names only; no credential value is present.
			OperationID: operationID, ParentPlan: plan, Attempt: 3,
			RuntimeOwnership: install.RuntimeOwnershipProvisionedByAgentMemory,
			CoreEndpoint:     "http://127.0.0.1:9411", APICredentialPath: "/owner/.agentmemory/secrets/api-credential",
			InstallationID:     "019f5f20-1234-7abc-8123-0123456789ab",
			OwnerPrincipalID:   "019f5f24-5678-7def-9123-abcdef012348",
			OwnerGrantID:       "019f5f25-5678-7def-9123-abcdef012349",
			OwnerSubjectDigest: install.DigestBytes([]byte("owner subject")),
			BrainID:            "019f5f26-5678-7def-9123-abcdef012350", BrainName: "local",
			ReleaseDigest: install.DigestBytes([]byte("release manifest")),
			GenerationID:  "019f5f21-5678-7def-9123-abcdef012345",
		}},
		bootstrap: &brainBootstrapper{},
	}
}

type brainBootstrapPlanQuery struct {
	input        brainbootstrap.AuthorizationInput
	err          error
	wrongAttempt bool
}

func (q *brainBootstrapPlanQuery) ResolveBrainBootstrapAuthorization(
	_ context.Context,
	_ install.PlanDigest,
	_ install.OperationID,
	_ uint32,
) (brainbootstrap.Authorization, error) {
	if q.err != nil {
		return brainbootstrap.Authorization{}, q.err
	}
	input := q.input
	if q.wrongAttempt {
		input.Attempt++
	}
	return brainbootstrap.NewAuthorization(input)
}

type brainBootstrapper struct {
	last         brainbootstrap.Authorization
	receipt      brainbootstrap.Receipt
	err          error
	wrongReceipt bool
}

func (b *brainBootstrapper) BootstrapLocalBrain(
	_ context.Context,
	authorization brainbootstrap.Authorization,
) (brainbootstrap.Receipt, error) {
	b.last = authorization
	if b.err != nil {
		return brainbootstrap.Receipt{}, b.err
	}
	receiptAuthorization := authorization
	if b.wrongReceipt {
		input := brainbootstrap.AuthorizationInput{
			OperationID: authorization.OperationID(), ParentPlan: authorization.ParentPlanDigest(),
			Attempt: authorization.Attempt() + 1, RuntimeOwnership: authorization.RuntimeOwnership(),
			CoreEndpoint: authorization.CoreEndpoint(), APICredentialPath: authorization.APICredentialPath(),
			InstallationID: authorization.InstallationID(), OwnerPrincipalID: authorization.OwnerPrincipalID(),
			OwnerGrantID: authorization.OwnerGrantID(), OwnerSubjectDigest: authorization.OwnerSubjectDigest(),
			BrainID: authorization.BrainID(), BrainName: authorization.BrainName(),
			ReleaseDigest: authorization.ReleaseDigest(), GenerationID: authorization.GenerationID(),
		}
		receiptAuthorization, _ = brainbootstrap.NewAuthorization(input)
	}
	receipt, _ := brainbootstrap.NewReceiptForAdapter(receiptAuthorization, brainbootstrap.DispositionCreated)
	b.receipt = receipt
	return receipt, nil
}
