package installphase

import (
	"context"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/brainbootstrap"
)

// BrainBootstrapPhase is the concrete BootstrapLocalBrain adapter.
type BrainBootstrapPhase struct {
	plans     BrainBootstrapPlanQuery
	bootstrap brainbootstrap.Bootstrapper
}

// NewBrainBootstrapPhase requires canonical plan resolution and the
// authenticated local Core bootstrap boundary.
func NewBrainBootstrapPhase(
	plans BrainBootstrapPlanQuery,
	bootstrap brainbootstrap.Bootstrapper,
) (*BrainBootstrapPhase, error) {
	if nilPort(plans) || nilPort(bootstrap) {
		return nil, errors.New("brain bootstrap phase capabilities are required")
	}
	return &BrainBootstrapPhase{plans: plans, bootstrap: bootstrap}, nil
}

// BootstrapLocalBrain creates or re-verifies the exact installation, owner,
// initial grant, and first Brain aggregate as one idempotent Core transaction.
func (p *BrainBootstrapPhase) BootstrapLocalBrain(
	ctx context.Context,
	request installapp.PhaseRequest,
) (installapp.PhaseOutput, error) {
	if !validRequest(request) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	authorization, err := p.plans.ResolveBrainBootstrapAuthorization(
		ctx, request.PlanDigest(), request.OperationID(), request.Attempt(),
	)
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodePlanUnavailable)
	}
	if !validBrainBootstrapAuthorization(authorization, request) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	receipt, err := p.bootstrap.BootstrapLocalBrain(ctx, authorization)
	if err != nil {
		if errors.Is(err, brainbootstrap.ErrIntegrity) {
			return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
		}
		return installapp.PhaseOutput{}, phaseError(ErrorCodeBrainBootstrapUnavailable)
	}
	if !receipt.ValidFor(authorization) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	return completedOutput(
		authorization.BindingDigest(), receipt.OutputDigest(), authorization.RuntimeOwnership(),
		"retain.initial_brain", "installation.continue", "brain_bootstrap", string(receipt.Disposition()),
	)
}

func validBrainBootstrapAuthorization(
	authorization brainbootstrap.Authorization,
	request installapp.PhaseRequest,
) bool {
	return authorization.Valid() && authorization.OperationID() == request.OperationID() &&
		authorization.ParentPlanDigest().Equal(request.PlanDigest()) &&
		authorization.Attempt() == request.Attempt() && authorization.RuntimeOwnership().Resolved()
}

var _ installapp.BrainBootstrapPort = (*BrainBootstrapPhase)(nil)
