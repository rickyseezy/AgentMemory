package installphase

import (
	"context"
	"errors"
	"strconv"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/resourceapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
)

// NetworkVolumePhase is the concrete EnsureNetworkAndVolumes phase adapter.
type NetworkVolumePhase struct {
	plans     NetworkVolumePlanQuery
	resources ManagedResourceEnsurer
	capacity  ArtifactCapacityApplication
}

// NewNetworkVolumePhase requires authenticated plan resolution and the exact
// Docker ownership use case.
func NewNetworkVolumePhase(
	plans NetworkVolumePlanQuery,
	resources ManagedResourceEnsurer,
	capacity ArtifactCapacityApplication,
) (*NetworkVolumePhase, error) {
	if nilPort(plans) || nilPort(resources) || nilPort(capacity) {
		return nil, errors.New("network and volume phase capabilities are required")
	}
	return &NetworkVolumePhase{plans: plans, resources: resources, capacity: capacity}, nil
}

// EnsureNetworkAndVolumes returns only the complete authenticated inventory
// digest as success evidence; Docker names or running state are insufficient.
func (p *NetworkVolumePhase) EnsureNetworkAndVolumes(
	ctx context.Context,
	request installapp.PhaseRequest,
) (installapp.PhaseOutput, error) {
	if !validRequest(request) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	plan, err := p.plans.ResolveNetworkVolumePlan(ctx, request.PlanDigest())
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodePlanUnavailable)
	}
	if !plan.PlanDigest.Equal(request.PlanDigest()) || !plan.RuntimeOwnership.Resolved() ||
		plan.Endpoint.String() == "" || !plan.CapacityCommand.ParentPlanDigest.Equal(request.PlanDigest()) ||
		plan.CapacityCommand.OperationID != request.OperationID().String() ||
		plan.CapacityCommand.InstallationID != plan.InstallationID || plan.CapacityCommand.ReleaseID != plan.Release ||
		plan.CapacityCommand.GenerationID != plan.GenerationID {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	result, err := p.resources.EnsureNetworkAndVolumes(ctx, resourceapp.Command{
		InstallationID: plan.InstallationID, GenerationID: plan.GenerationID,
		Release: plan.Release, CreationOperation: plan.CreationOperation, Endpoint: plan.Endpoint,
	})
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeResourceUnavailable)
	}
	if result.InventoryVersion == 0 || result.InventoryDigest.IsZero() {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	prepared, err := p.capacity.PrepareSecretProjectionCapacity(ctx, plan.CapacityCommand, plan.GenerationID)
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeReservationUnavailable)
	}
	if !validPreparedProjectionCapacity(prepared, plan.CapacityCommand) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	return completedOutput(
		request.PlanDigest(),
		result.InventoryDigest,
		plan.RuntimeOwnership,
		"retain.managed_resources",
		"installation.continue",
		"inventory_version",
		strconv.FormatUint(result.InventoryVersion, 10),
	)
}

func validPreparedProjectionCapacity(result artifactapp.CapacityResult, command artifactapp.CapacityCommand) bool {
	if result.Version == 0 || len(command.SecretProjections) != 6 {
		return false
	}
	expected := make(map[string]artifactapp.SecretProjectionCapacity, len(command.SecretProjections))
	for _, projection := range command.SecretProjections {
		if projection.Name == "" || projection.Purpose == "" || projection.ReservedBytes == 0 {
			return false
		}
		if _, duplicate := expected[projection.Name]; duplicate {
			return false
		}
		expected[projection.Name] = projection
	}
	seen := make(map[string]struct{}, len(expected))
	for _, lease := range result.Leases {
		if artifactacquisition.LeasePurpose(lease.Purpose) != artifactacquisition.LeaseSecretProjection {
			if lease.State == string(artifactacquisition.LeaseTransferred) {
				return false
			}
			continue
		}
		projection, exists := expected[lease.ArtifactID]
		if !exists || lease.ResourcePurpose != projection.Purpose || lease.Bytes != projection.ReservedBytes ||
			lease.Owner != command.OperationID || lease.NewOwner != command.GenerationID ||
			lease.PlanDigest != command.ParentPlanDigest.String() ||
			lease.ProjectionInstallationID != command.InstallationID || lease.ProjectionReleaseID != command.ReleaseID ||
			lease.ProjectionGenerationID != command.GenerationID ||
			lease.State != string(artifactacquisition.LeaseTransferred) || lease.ReceiptToken == "" ||
			lease.TargetDigest != "" || lease.UsageBytes != 0 || lease.ReleaseFrom != "" || lease.ReleaseKind != "" {
			return false
		}
		if _, duplicate := seen[lease.ArtifactID]; duplicate {
			return false
		}
		seen[lease.ArtifactID] = struct{}{}
	}
	return len(seen) == len(expected)
}

var _ installapp.NetworkVolumePort = (*NetworkVolumePhase)(nil)
