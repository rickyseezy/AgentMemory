package artifactapp

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
)

// ExpandedTargetAuthorityResolver may return only an explicit representation
// projected from authenticated signed-plan data. Implementations must reject
// plans that omit target kind; archive semantics must never be inferred.
type ExpandedTargetAuthorityResolver interface {
	ResolveExpandedTarget(
		context.Context,
		artifactacquisition.CapacityConsumeAuthorization,
	) (artifactacquisition.ExpandedTargetAuthority, error)
}

// ExpandedTargetRepository stores an independent authenticated and
// rollback-protected lifecycle journal for each target lease.
type ExpandedTargetRepository interface {
	LoadExpandedTarget(context.Context, string) (artifactacquisition.ExpandedTargetSnapshot, error)
	SaveExpandedTarget(context.Context, uint64, artifactacquisition.ExpandedTargetSnapshot) error
}

// ExpandedTargetEngine is the explicit representation execution boundary.
// Every observation must repeat the exact source, target, pool, receipt,
// owner, and measured-byte bindings; the orchestration adapter rejects drift.
type ExpandedTargetEngine interface {
	InspectExpandedTarget(
		context.Context,
		artifactacquisition.ExpandedTargetAuthority,
		artifactacquisition.ExpandedTargetSnapshot,
	) (artifactacquisition.ExpandedTargetObservation, error)
	MaterializeExpandedTarget(
		context.Context,
		artifactacquisition.ExpandedTargetAuthority,
	) (artifactacquisition.ExpandedTargetObservation, error)
	TransferExpandedTarget(
		context.Context,
		artifactacquisition.ExpandedTargetAuthority,
		artifactacquisition.ExpandedTargetSnapshot,
		string,
	) (artifactacquisition.ExpandedTargetObservation, error)
	RetireExpandedTarget(
		context.Context,
		artifactacquisition.ExpandedTargetAuthority,
		artifactacquisition.ExpandedTargetSnapshot,
		artifactacquisition.CapacityReleaseAuthorization,
	) (artifactacquisition.ExpandedTargetObservation, error)
}
