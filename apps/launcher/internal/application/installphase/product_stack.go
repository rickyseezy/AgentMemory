package installphase

import (
	"context"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productstack"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

// MigrationPhase is the concrete RunMigrations adapter.
type MigrationPhase struct {
	plans StackPlanQuery
	stack productstack.Ensurer
}

// NewMigrationPhase requires canonical plan resolution and the signed-source
// Docker stack use case.
func NewMigrationPhase(plans StackPlanQuery, stack productstack.Ensurer) (*MigrationPhase, error) {
	if nilPort(plans) || nilPort(stack) {
		return nil, errors.New("migration phase capabilities are required")
	}
	return &MigrationPhase{plans: plans, stack: stack}, nil
}

// RunMigrations executes only the release-bound one-shot migration service.
func (p *MigrationPhase) RunMigrations(
	ctx context.Context,
	request installapp.PhaseRequest,
) (installapp.PhaseOutput, error) {
	return executeStackPhase(
		ctx, request, p.plans, p.stack, productstack.OperationMigrate,
		"retain.migrated_generation", "migrations", "applied",
	)
}

// CoreGraphPhase is the concrete EnsureCoreAndGraph adapter.
type CoreGraphPhase struct {
	plans StackPlanQuery
	stack productstack.Ensurer
}

// NewCoreGraphPhase requires canonical plan resolution and the signed-source
// Docker stack use case.
func NewCoreGraphPhase(plans StackPlanQuery, stack productstack.Ensurer) (*CoreGraphPhase, error) {
	if nilPort(plans) || nilPort(stack) {
		return nil, errors.New("core/graph phase capabilities are required")
	}
	return &CoreGraphPhase{plans: plans, stack: stack}, nil
}

// EnsureCoreAndGraph starts the exact persistent services and requires their
// Compose health gates. It does not claim the later eleven-probe readiness gate.
func (p *CoreGraphPhase) EnsureCoreAndGraph(
	ctx context.Context,
	request installapp.PhaseRequest,
) (installapp.PhaseOutput, error) {
	return executeStackPhase(
		ctx, request, p.plans, p.stack, productstack.OperationStartCoreAndGraph,
		"retain.started_generation", "compose_health", "verified",
	)
}

func executeStackPhase(
	ctx context.Context,
	request installapp.PhaseRequest,
	plans StackPlanQuery,
	stack productstack.Ensurer,
	operation productstack.Operation,
	compensation string,
	factName string,
	factValue string,
) (installapp.PhaseOutput, error) {
	if !validRequest(request) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	authorization, err := plans.ResolveStackAuthorization(
		ctx, request.PlanDigest(), request.OperationID(), request.Attempt(), operation,
	)
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodePlanUnavailable)
	}
	if !validStackAuthorization(authorization, request, operation) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	var receipt productstack.Receipt
	if operation == productstack.OperationMigrate {
		receipt, err = stack.RunMigrations(ctx, authorization)
	} else {
		receipt, err = stack.StartCoreAndGraph(ctx, authorization)
	}
	if err != nil {
		if errors.Is(err, productstack.ErrIntegrity) {
			return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
		}
		return installapp.PhaseOutput{}, phaseError(ErrorCodeStackUnavailable)
	}
	if !receipt.ValidFor(authorization) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	return completedStackOutput(authorization, receipt, compensation, factName, factValue)
}

func completedStackOutput(
	authorization productstack.Authorization,
	receipt productstack.Receipt,
	compensationKey string,
	factName string,
	factValue string,
) (installapp.PhaseOutput, error) {
	compensation, err := install.NewCompensationBoundary(compensationKey)
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	nextAction, err := install.NewSafeAction("installation.continue")
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	fact, err := install.NewNonSecretFact(factName, factValue)
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	return installapp.NewCompletedPhaseOutput(installapp.CompletionOutput{
		InputDigest: authorization.BindingDigest(), OutputDigest: receipt.OutputDigest(),
		VerifiedArtifactDigest: receipt.ConfigurationDigest(), Facts: []install.NonSecretFact{fact},
		RuntimeOwnership: authorization.RuntimeOwnership(), CompensationBoundary: compensation,
		NextSafeAction: nextAction,
	})
}

func validStackAuthorization(
	authorization productstack.Authorization,
	request installapp.PhaseRequest,
	operation productstack.Operation,
) bool {
	return authorization.Valid() && authorization.Operation() == operation &&
		authorization.OperationID() == request.OperationID() &&
		authorization.ParentPlanDigest().Equal(request.PlanDigest()) &&
		authorization.Attempt() == request.Attempt() && authorization.RuntimeOwnership().Resolved()
}

var (
	_ installapp.MigrationPort = (*MigrationPhase)(nil)
	_ installapp.CoreGraphPort = (*CoreGraphPhase)(nil)
)
