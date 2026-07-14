package installphase

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productstack"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001StackPhasesBindMigrationsAndStartupToExactParentAttempt(t *testing.T) {
	t.Parallel()
	fixture := newStackPhaseFixture(t)

	migrations, err := NewMigrationPhase(fixture.plans, fixture.stack)
	if err != nil {
		t.Fatal(err)
	}
	migrationOutput, err := migrations.RunMigrations(context.Background(), fixture.request)
	if err != nil || migrationOutput.Outcome() != installapp.PhaseOutcomeCompleted ||
		migrationOutput.RuntimeOwnership() != install.RuntimeOwnershipReusedExternal ||
		migrationOutput.VerifiedArtifactDigest().IsZero() {
		t.Fatalf("RunMigrations() = %#v/%v", migrationOutput, err)
	}
	if fixture.plans.lastOperation != productstack.OperationMigrate ||
		fixture.stack.last.Operation() != productstack.OperationMigrate ||
		!migrationOutput.InputDigest().Equal(fixture.stack.last.BindingDigest()) {
		t.Fatal("migration phase lost its operation-specific plan authority")
	}

	core, err := NewCoreGraphPhase(fixture.plans, fixture.stack)
	if err != nil {
		t.Fatal(err)
	}
	coreOutput, err := core.EnsureCoreAndGraph(context.Background(), fixture.request)
	if err != nil || coreOutput.Outcome() != installapp.PhaseOutcomeCompleted ||
		coreOutput.RuntimeOwnership() != install.RuntimeOwnershipReusedExternal ||
		!coreOutput.VerifiedArtifactDigest().Equal(fixture.stack.receipt.ConfigurationDigest()) {
		t.Fatalf("EnsureCoreAndGraph() = %#v/%v", coreOutput, err)
	}
	if fixture.plans.lastOperation != productstack.OperationStartCoreAndGraph ||
		fixture.stack.last.Operation() != productstack.OperationStartCoreAndGraph ||
		!coreOutput.OutputDigest().Equal(fixture.stack.receipt.OutputDigest()) {
		t.Fatal("Core/graph phase lost its exact stack execution receipt")
	}
}

func TestPF001StackPhasesRejectCrossPlanReceiptAndSanitizeFailures(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		mutate func(*stackPhaseFixture)
		invoke func(*stackPhaseFixture) error
		code   ErrorCode
	}{
		{
			name: "plan unavailable", code: ErrorCodePlanUnavailable,
			mutate: func(value *stackPhaseFixture) { value.plans.err = errors.New("/private/plan") },
			invoke: func(value *stackPhaseFixture) error {
				phase, _ := NewMigrationPhase(value.plans, value.stack)
				_, err := phase.RunMigrations(context.Background(), value.request)
				return err
			},
		},
		{
			name: "cross-operation authority", code: ErrorCodeInvalidBinding,
			mutate: func(value *stackPhaseFixture) { value.plans.swapOperation = true },
			invoke: func(value *stackPhaseFixture) error {
				phase, _ := NewMigrationPhase(value.plans, value.stack)
				_, err := phase.RunMigrations(context.Background(), value.request)
				return err
			},
		},
		{
			name: "stack unavailable", code: ErrorCodeStackUnavailable,
			mutate: func(value *stackPhaseFixture) { value.stack.err = errors.New("secret raw") },
			invoke: func(value *stackPhaseFixture) error {
				phase, _ := NewCoreGraphPhase(value.plans, value.stack)
				_, err := phase.EnsureCoreAndGraph(context.Background(), value.request)
				return err
			},
		},
		{
			name: "cross-attempt receipt", code: ErrorCodeInvalidBinding,
			mutate: func(value *stackPhaseFixture) { value.stack.wrongReceipt = true },
			invoke: func(value *stackPhaseFixture) error {
				phase, _ := NewCoreGraphPhase(value.plans, value.stack)
				_, err := phase.EnsureCoreAndGraph(context.Background(), value.request)
				return err
			},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newStackPhaseFixture(t)
			test.mutate(fixture)
			err := test.invoke(fixture)
			var typed *Error
			if !errors.As(err, &typed) || typed.Code() != test.code || typed.Error() != string(test.code) {
				t.Fatalf("error = %#v, want %s", err, test.code)
			}
		})
	}
}

func TestPF001StackPhasesRequireEveryCapabilityAndValidRequest(t *testing.T) {
	t.Parallel()
	fixture := newStackPhaseFixture(t)
	if _, err := NewMigrationPhase(nil, fixture.stack); err == nil {
		t.Fatal("NewMigrationPhase accepted nil plans")
	}
	if _, err := NewMigrationPhase(fixture.plans, nil); err == nil {
		t.Fatal("NewMigrationPhase accepted nil stack")
	}
	if _, err := NewCoreGraphPhase(nil, fixture.stack); err == nil {
		t.Fatal("NewCoreGraphPhase accepted nil plans")
	}
	if _, err := NewCoreGraphPhase(fixture.plans, nil); err == nil {
		t.Fatal("NewCoreGraphPhase accepted nil stack")
	}
	var typedNil *stackEnsurer
	if _, err := NewCoreGraphPhase(fixture.plans, typedNil); err == nil {
		t.Fatal("NewCoreGraphPhase accepted typed nil stack")
	}
	phase, _ := NewMigrationPhase(fixture.plans, fixture.stack)
	if _, err := phase.RunMigrations(context.Background(), installapp.PhaseRequest{}); err == nil {
		t.Fatal("RunMigrations accepted invalid request")
	}
}

type stackPhaseFixture struct {
	request installapp.PhaseRequest
	plans   *stackPlanQuery
	stack   *stackEnsurer
}

func newStackPhaseFixture(t testing.TB) *stackPhaseFixture {
	t.Helper()
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	plan, _ := install.BindPlan([]byte("canonical plan"))
	request, err := installapp.NewPhaseRequestForIntegration(operationID, plan, 2, []byte("canonical plan"))
	if err != nil {
		t.Fatal(err)
	}
	return &stackPhaseFixture{
		request: request,
		plans:   &stackPlanQuery{source: stackPhaseSource(t), ownership: install.RuntimeOwnershipReusedExternal},
		stack:   &stackEnsurer{},
	}
}

type stackPlanQuery struct {
	source        containerengine.ComposeReleaseSource
	ownership     install.RuntimeOwnership
	lastOperation productstack.Operation
	err           error
	swapOperation bool
}

func (q *stackPlanQuery) ResolveStackAuthorization(
	_ context.Context,
	plan install.PlanDigest,
	operationID install.OperationID,
	attempt uint32,
	operation productstack.Operation,
) (productstack.Authorization, error) {
	q.lastOperation = operation
	if q.err != nil {
		return productstack.Authorization{}, q.err
	}
	if q.swapOperation {
		operation = productstack.OperationStartCoreAndGraph
	}
	return productstack.NewAuthorization(operation, operationID, plan, attempt, q.ownership, q.source)
}

type stackEnsurer struct {
	last         productstack.Authorization
	receipt      productstack.Receipt
	err          error
	wrongReceipt bool
}

func (s *stackEnsurer) RunMigrations(_ context.Context, authorization productstack.Authorization) (productstack.Receipt, error) {
	return s.execute(authorization)
}

func (s *stackEnsurer) StartCoreAndGraph(_ context.Context, authorization productstack.Authorization) (productstack.Receipt, error) {
	return s.execute(authorization)
}

func (s *stackEnsurer) execute(authorization productstack.Authorization) (productstack.Receipt, error) {
	s.last = authorization
	if s.err != nil {
		return productstack.Receipt{}, s.err
	}
	receiptAuthorization := authorization
	if s.wrongReceipt {
		receiptAuthorization, _ = productstack.NewAuthorization(
			authorization.Operation(), authorization.OperationID(), authorization.ParentPlanDigest(),
			authorization.Attempt()+1, authorization.RuntimeOwnership(), authorization.Source(),
		)
	}
	receipt, _ := productstack.NewReceiptForAdapter(receiptAuthorization, install.DigestBytes([]byte("normalized compose")))
	s.receipt = receipt
	return receipt, nil
}

func stackPhaseSource(t testing.TB) containerengine.ComposeReleaseSource {
	t.Helper()
	endpoint, _ := containerengine.NewEndpoint("unix:///run/user/1000/docker.sock")
	identity, _ := composeplan.NewIdentity(
		"019f5f20-1234-7abc-8123-0123456789ab",
		"019f5f21-5678-7def-9123-abcdef012345",
	)
	source, err := containerengine.NewComposeReleaseSource(
		endpoint, identity, "1.0.0", "/owner/agentmemory/releases/v1/compose",
		"/owner/agentmemory/releases/v1/compose/compose.yaml",
		"/owner/agentmemory/releases/v1/compose/empty.env",
		releaseinventory.DigestBytes([]byte("compose source")), 180,
	)
	if err != nil {
		t.Fatal(err)
	}
	return source
}
