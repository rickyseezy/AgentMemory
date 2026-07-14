package bootstrapresolver

import (
	"context"
	"reflect"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpbootstrapapp"
	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/installplan"
)

// CanonicalPlanRepository is implemented by installplanfs.Repository.
type CanonicalPlanRepository interface {
	Load(context.Context, install.PlanDigest) (installplan.Plan, error)
}

// InstallOperationRepository is implemented by the authenticated
// filesystem.InstallOperationRepository.
type InstallOperationRepository interface {
	Load(context.Context, install.OperationID) (*install.Operation, error)
}

// PlanRepositoryAdapter narrows the immutable plan repository to resolver
// authority without leaking the full plan domain across the composition seam.
type PlanRepositoryAdapter struct{ repository CanonicalPlanRepository }

// NewPlanRepositoryAdapter rejects missing and typed-nil repositories.
func NewPlanRepositoryAdapter(repository CanonicalPlanRepository) (*PlanRepositoryAdapter, error) {
	if nilAuthority(repository) {
		return nil, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	return &PlanRepositoryAdapter{repository: repository}, nil
}

// LoadPlan authenticates the repository result against the requested digest.
func (a *PlanRepositoryAdapter) LoadPlan(
	ctx context.Context,
	digest install.PlanDigest,
) (PlanAuthority, error) {
	if a == nil || ctx == nil || digest.IsZero() || nilAuthority(a.repository) {
		return nil, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	plan, err := a.repository.Load(ctx, digest)
	if err != nil || !plan.Digest().Equal(digest) || plan.OperationID().IsZero() ||
		plan.InstallationID() == "" || !plan.AgentConfiguration().AgentHost().Valid() ||
		len(plan.CanonicalBytes()) == 0 {
		return nil, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	return planProjection{plan: plan}, nil
}

type planProjection struct{ plan installplan.Plan }

func (p planProjection) Digest() install.PlanDigest       { return p.plan.Digest() }
func (p planProjection) OperationID() install.OperationID { return p.plan.OperationID() }
func (p planProjection) InstallationID() string           { return p.plan.InstallationID() }
func (p planProjection) AgentHost() agentconfigdomain.AgentHost {
	return p.plan.AgentConfiguration().AgentHost()
}
func (p planProjection) CanonicalBytes() []byte { return p.plan.CanonicalBytes() }

// OperationAuthorityAdapter narrows the operation repository to one exact
// identity/plan verification query.
type OperationAuthorityAdapter struct{ repository InstallOperationRepository }

// NewOperationAuthorityAdapter rejects missing and typed-nil repositories.
func NewOperationAuthorityAdapter(repository InstallOperationRepository) (*OperationAuthorityAdapter, error) {
	if nilAuthority(repository) {
		return nil, mcpbootstrapapp.ErrBootstrapIntegrity
	}
	return &OperationAuthorityAdapter{repository: repository}, nil
}

// VerifyOperation authenticates the restored aggregate and exact plan binding.
func (a *OperationAuthorityAdapter) VerifyOperation(
	ctx context.Context,
	operationID install.OperationID,
	planDigest install.PlanDigest,
) error {
	if a == nil || ctx == nil || operationID.IsZero() || planDigest.IsZero() || nilAuthority(a.repository) {
		return mcpbootstrapapp.ErrBootstrapIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	operation, err := a.repository.Load(ctx, operationID)
	if err != nil || operation == nil || operation.ID() != operationID ||
		!operation.PlanDigest().Equal(planDigest) {
		return mcpbootstrapapp.ErrBootstrapIntegrity
	}
	return nil
}

func nilAuthority(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Every non-nilable concrete kind is a valid authority.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid:
		return true
	default:
		return false
	}
}

var (
	_ PlanAuthorityRepository = (*PlanRepositoryAdapter)(nil)
	_ OperationAuthority      = (*OperationAuthorityAdapter)(nil)
)
