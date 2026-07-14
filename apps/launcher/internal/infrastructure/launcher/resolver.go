package launcher

import (
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrapresolver"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpbootstrapapp"
)

// NewProtectedResolver wires the concrete immutable plan and authenticated
// operation repositories behind the purpose-separated rollback-anchored
// bootstrap pointer journal.
func NewProtectedResolver(
	journals bootstrapresolver.JournalProvider,
	plans bootstrapresolver.CanonicalPlanRepository,
	operations bootstrapresolver.InstallOperationRepository,
	clock bootstrapresolver.Clock,
) (mcpbootstrapapp.BootstrapResolver, error) {
	planAuthority, err := bootstrapresolver.NewPlanRepositoryAdapter(plans)
	if err != nil {
		return nil, err
	}
	operationAuthority, err := bootstrapresolver.NewOperationAuthorityAdapter(operations)
	if err != nil {
		return nil, err
	}
	return bootstrapresolver.New(journals, planAuthority, operationAuthority, clock)
}
