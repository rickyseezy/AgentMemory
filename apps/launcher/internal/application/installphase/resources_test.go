package installphase

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/resourceapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001NetworkVolumePhaseBindsAuthenticatedInventoryDigest(t *testing.T) {
	t.Parallel()

	request, plan, query, resources, capacity := resourcePhaseFixture(t)
	phase, err := NewNetworkVolumePhase(query, resources, capacity)
	if err != nil {
		t.Fatal(err)
	}
	output, err := phase.EnsureNetworkAndVolumes(context.Background(), request)
	if err != nil || output.Outcome() != installapp.PhaseOutcomeCompleted ||
		!output.OutputDigest().Equal(resources.result.InventoryDigest) || resources.last.InstallationID != plan.InstallationID ||
		resources.last.GenerationID != plan.GenerationID || resources.last.Release != plan.Release ||
		resources.last.CreationOperation != plan.CreationOperation || resources.last.Endpoint.String() != plan.Endpoint.String() {
		t.Fatalf("EnsureNetworkAndVolumes() = %+v, %v, command=%+v", output, err, resources.last)
	}
	if capacity.prepareGeneration != plan.GenerationID || capacity.prepareCommand.OperationID != request.OperationID().String() {
		t.Fatalf("projection capacity command=%+v generation=%q", capacity.prepareCommand, capacity.prepareGeneration)
	}
}

func TestPF001NetworkVolumePhaseRejectsMissingCrossPlanOrIncompleteInventory(t *testing.T) {
	t.Parallel()

	request, _, query, resources, capacity := resourcePhaseFixture(t)
	tests := []struct {
		name      string
		configure func()
	}{
		{name: "plan error", configure: func() { query.err = errors.New("raw path") }},
		{name: "plan mismatch", configure: func() { query.plan.PlanDigest, _ = install.BindPlan([]byte("other")) }},
		{name: "ownership", configure: func() { query.plan.RuntimeOwnership = install.RuntimeOwnershipUndetermined }},
		{name: "resource error", configure: func() { resources.err = errors.New("raw Docker") }},
		{name: "capacity error", configure: func() { capacity.err = errors.New("raw capacity") }},
		{name: "zero digest", configure: func() { resources.result.InventoryDigest = install.Digest{} }},
		{name: "zero version", configure: func() { resources.result.InventoryVersion = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, localQuery, localResources, localCapacity := resourcePhaseFixture(t)
			query = localQuery
			resources = localResources
			capacity = localCapacity
			test.configure()
			phase, _ := NewNetworkVolumePhase(query, resources, capacity)
			_, err := phase.EnsureNetworkAndVolumes(context.Background(), request)
			var typed *Error
			if !errors.As(err, &typed) || typed.Error() != string(typed.Code()) {
				t.Fatalf("error = %#v", err)
			}
		})
	}

	if _, err := NewNetworkVolumePhase(nil, resources, capacity); err == nil {
		t.Fatal("NewNetworkVolumePhase() accepted nil query")
	}
	if _, err := NewNetworkVolumePhase(query, nil, capacity); err == nil {
		t.Fatal("NewNetworkVolumePhase() accepted nil resources")
	}
	if _, err := NewNetworkVolumePhase(query, resources, nil); err == nil {
		t.Fatal("NewNetworkVolumePhase() accepted nil capacity")
	}
	phase, _ := NewNetworkVolumePhase(query, resources, capacity)
	if _, err := phase.EnsureNetworkAndVolumes(context.Background(), installapp.PhaseRequest{}); err == nil {
		t.Fatal("network volume phase accepted an invalid request")
	}
}

func resourcePhaseFixture(t *testing.T) (installapp.PhaseRequest, NetworkVolumePlan, *networkVolumePlanQuery, *managedResourceEnsurer, *artifactCapacityApplication) {
	t.Helper()
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	planDigest, _ := install.BindPlan([]byte("canonical plan"))
	request, err := installapp.NewPhaseRequestForIntegration(operationID, planDigest, 1, []byte("canonical plan"))
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := containerengine.NewEndpoint("unix:///var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	plan := NetworkVolumePlan{
		PlanDigest: planDigest, InstallationID: "019f5f20-1234-7abc-8123-0123456789ab",
		GenerationID: "019f5f21-5678-7def-9123-abcdef012345", Release: "release-v1",
		CreationOperation: operationID.String(), Endpoint: endpoint,
		RuntimeOwnership: install.RuntimeOwnershipReusedExternal,
	}
	identity, _ := composeplan.NewIdentity(plan.InstallationID, plan.GenerationID)
	projectionAuthority, _ := identity.SecretProjectionCapacities()
	projections := make([]artifactapp.SecretProjectionCapacity, 0, len(projectionAuthority))
	for _, authority := range projectionAuthority {
		projections = append(projections, artifactapp.SecretProjectionCapacity{
			Name: authority.Name(), Purpose: authority.Purpose(), ReservedBytes: authority.ReservedBytes(),
		})
	}
	plan.CapacityCommand = artifactapp.CapacityCommand{
		OperationID: operationID.String(), ParentPlanDigest: planDigest,
		InstallationID: plan.InstallationID, ReleaseID: plan.Release, GenerationID: plan.GenerationID,
		Plan: artifactPhasePlan(t), SecretProjections: projections,
		HostCAS:          artifactapp.CapacityTarget{Kind: artifactapp.CapacityHostCAS, Locator: "/cas"},
		HostRelease:      artifactapp.CapacityTarget{Kind: artifactapp.CapacityHostRelease, Locator: "/releases/release-1"},
		DockerEngine:     artifactapp.CapacityTarget{Kind: artifactapp.CapacityDockerEngine, Locator: "engine"},
		DockerDataVolume: artifactapp.CapacityTarget{Kind: artifactapp.CapacityDockerDataVolume, Locator: "volume"},
	}
	query := &networkVolumePlanQuery{plan: plan}
	resources := &managedResourceEnsurer{result: resourceapp.Result{
		InventoryVersion: 14, InventoryDigest: install.DigestBytes([]byte("inventory")), Created: 7,
	}}
	return request, plan, query, resources, &artifactCapacityApplication{}
}

type networkVolumePlanQuery struct {
	plan NetworkVolumePlan
	err  error
}

func (q *networkVolumePlanQuery) ResolveNetworkVolumePlan(context.Context, install.PlanDigest) (NetworkVolumePlan, error) {
	return q.plan, q.err
}

type managedResourceEnsurer struct {
	result resourceapp.Result
	last   resourceapp.Command
	err    error
}

func (e *managedResourceEnsurer) EnsureNetworkAndVolumes(
	_ context.Context,
	command resourceapp.Command,
) (resourceapp.Result, error) {
	e.last = command
	return e.result, e.err
}
