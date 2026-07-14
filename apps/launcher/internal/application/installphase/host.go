package installphase

import (
	"context"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/hostverifyapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

// HostVerificationPhase is the concrete InstallApplication VerifyHost adapter.
type HostVerificationPhase struct {
	plans    HostVerificationPlanQuery
	verifier HostVerifier
}

// NewHostVerificationPhase requires authenticated resolution and certification.
func NewHostVerificationPhase(
	plans HostVerificationPlanQuery,
	verifier HostVerifier,
) (*HostVerificationPhase, error) {
	if nilPort(plans) || nilPort(verifier) {
		return nil, errors.New("host verification phase capabilities are required")
	}
	return &HostVerificationPhase{plans: plans, verifier: verifier}, nil
}

// VerifyHost authenticates nested policy and translates only a certified
// receipt or one expected unsupported-host result into the parent saga.
func (p *HostVerificationPhase) VerifyHost(
	ctx context.Context,
	request installapp.PhaseRequest,
) (installapp.PhaseOutput, error) {
	if !validRequest(request) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	projection, err := p.plans.ResolveHostVerificationPlan(ctx, request.PlanDigest())
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodePlanUnavailable)
	}
	if !projection.ParentPlanDigest.Equal(request.PlanDigest()) ||
		projection.RuntimeOwnership != install.RuntimeOwnershipUndetermined ||
		!projection.SignedHostPlan.Valid() {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	verification, err := p.verifier.Verify(ctx, hostverifyapp.Command{
		OperationID: request.OperationID(), ParentPlanDigest: request.PlanDigest(),
		SignedPlan: projection.SignedHostPlan,
	})
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeHostUnavailable)
	}
	if !verification.ValidFor(request.OperationID(), request.PlanDigest()) ||
		!verification.HostPlanDigest().Equal(projection.SignedHostPlan.Plan().Digest()) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	if !verification.Certified() {
		return expectedOutput(installapp.PhaseOutcomeUnsupportedHost, "installation.select_supported_host")
	}
	return completedOutput(
		projection.SignedHostPlan.Plan().Digest(), verification.EvidenceDigest(),
		projection.RuntimeOwnership, "installation.no_host_mutation", "installation.continue",
		"host_status", "certified",
	)
}

var _ installapp.HostVerificationPort = (*HostVerificationPhase)(nil)
