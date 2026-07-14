package installplanapp

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/readiness"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/resourceinventory"
)

// RuntimePlanRepository durably stores one immutable authenticated authority
// for each operation and parent plan.
type RuntimePlanRepository interface {
	LoadRuntimePlan(context.Context, install.OperationID, install.PlanDigest) (RuntimePlanAuthority, error)
	SaveRuntimePlan(context.Context, RuntimePlanAuthority) error
}

// OperationRepository restores authenticated PF-001 aggregate evidence.
type OperationRepository interface {
	Load(context.Context, install.OperationID) (*install.Operation, error)
}

// ReadinessReceiptRepository resolves an authenticated successful readiness receipt.
type ReadinessReceiptRepository interface {
	LoadReadinessReceipt(context.Context, install.Digest) (readiness.Receipt, error)
}

// ResourceInventoryRepository resolves an authenticated, rollback-checked resource snapshot.
type ResourceInventoryRepository interface {
	Load(context.Context, string) (resourceinventory.Snapshot, error)
}

// Dependencies make every dynamic authority source explicit. Construction
// fails if any capability is absent or typed nil.
type Dependencies struct {
	Plans             Repository
	RuntimePlans      RuntimePlanRepository
	RuntimeEvidence   RuntimeEvidenceResolver
	Operations        OperationRepository
	ReadinessReceipts ReadinessReceiptRepository
	Resources         ResourceInventoryRepository
	OperationID       install.OperationID
}
