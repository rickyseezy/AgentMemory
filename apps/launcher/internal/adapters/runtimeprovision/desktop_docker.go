package runtimeprovision

import (
	"context"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/dockercli"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

// DesktopDockerInspector discovers Docker Desktop only through two exact
// signed executables, the authority's local endpoint, and native installed-
// application identity evidence. It never reads or changes Docker contexts.
type DesktopDockerInspector struct {
	docker      argvprocess.Runner
	compose     argvprocess.Runner
	probe       *dockercli.Probe
	application runtimeport.DesktopInstalledApplicationProbe
}

// NewDesktopDockerInspector constructs a complete fail-closed Desktop inspector.
func NewDesktopDockerInspector(
	docker argvprocess.Runner,
	compose argvprocess.Runner,
	application runtimeport.DesktopInstalledApplicationProbe,
) (*DesktopDockerInspector, error) {
	if desktopNilDependency(docker) || desktopNilDependency(compose) || desktopNilDependency(application) {
		return nil, ErrProvisionIntegrity
	}
	dockerAuthority := docker.ExecutableAuthority()
	composeAuthority := compose.ExecutableAuthority()
	if !desktopExecutablePair(dockerAuthority, composeAuthority) {
		return nil, ErrProvisionIntegrity
	}
	executors, err := dockercli.NewExecutors(docker, compose)
	if err != nil {
		return nil, ErrProvisionIntegrity
	}
	probe, err := dockercli.NewProbe(executors)
	if err != nil {
		return nil, ErrProvisionIntegrity
	}
	return &DesktopDockerInspector{docker: docker, compose: compose, probe: probe, application: application}, nil
}

// InspectDesktopRuntime re-proves installed application identity, signed
// product version, Engine/Compose versions, Linux-container mode, the exact
// endpoint, cloud-offload absence, and the complete unrelated workload count.
func (i *DesktopDockerInspector) InspectDesktopRuntime(
	ctx context.Context,
	plan runtimeinstall.Plan,
	authority runtimeport.DesktopAuthority,
) (runtimeport.DesktopRuntimeEvidence, error) {
	if ctx == nil {
		return runtimeport.DesktopRuntimeEvidence{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return runtimeport.DesktopRuntimeEvidence{}, err
	}
	if i == nil || i.probe == nil || desktopNilDependency(i.application) || !authority.ValidFor(plan) ||
		!desktopRunnersMatchAuthority(i.docker, i.compose, authority) {
		return runtimeport.DesktopRuntimeEvidence{}, ErrProvisionIntegrity
	}
	application, err := i.application.ProbeDesktopInstalledApplication(ctx, authority)
	if err != nil || !application.VerifiedFor(authority) {
		return runtimeport.DesktopRuntimeEvidence{}, sanitizeDesktopBoundary(ctx, err, ErrProvisionIntegrity)
	}
	if !application.Present() {
		if plan.Action() != runtimeinstall.PlanActionInstallCertified {
			return runtimeport.DesktopRuntimeEvidence{}, ErrRuntimeConflict
		}
		return runtimeport.NewDesktopRuntimeEvidence(runtimeport.DesktopRuntimeEvidenceInput{
			Condition: runtimeinstall.RuntimeConditionAbsent,
		})
	}
	endpoint, err := containerengine.NewEndpoint(authority.Endpoint())
	if err != nil {
		return runtimeport.DesktopRuntimeEvidence{}, ErrProvisionIntegrity
	}
	observed, probeError := i.probe.Probe(ctx, endpoint)
	if probeError != nil {
		if ctx.Err() != nil {
			return runtimeport.DesktopRuntimeEvidence{}, ctx.Err()
		}
		condition := runtimeinstall.RuntimeConditionStopped
		if plan.Action() == runtimeinstall.PlanActionRepairManaged {
			condition = runtimeinstall.RuntimeConditionDamaged
		}
		if plan.Action() == runtimeinstall.PlanActionAdoptCompatible || plan.Action() == runtimeinstall.PlanActionBlock {
			return runtimeport.DesktopRuntimeEvidence{}, ErrRuntimeConflict
		}
		return runtimeport.NewDesktopRuntimeEvidence(runtimeport.DesktopRuntimeEvidenceInput{
			Condition: condition, Ownership: desktopOwnership(plan.Action()), Product: "docker_desktop",
			RuntimeVersion: application.RuntimeVersion(), Endpoint: authority.Endpoint(), ApplicationPresent: true,
			PublisherVerified: true, LocalEndpoint: true, UnrelatedWorkloads: authority.UnrelatedWorkloads(),
		})
	}
	if observed.Architecture != authority.Architecture().String() || observed.OSType != "linux" {
		return runtimeport.DesktopRuntimeEvidence{}, ErrRuntimeConflict
	}
	workloads, err := i.desktopContainerWorkloads(ctx, authority)
	if err != nil {
		return runtimeport.DesktopRuntimeEvidence{}, sanitizeDesktopBoundary(ctx, err, ErrProbeFailed)
	}
	operatingSystem := strings.ToLower(strings.TrimSpace(observed.OperatingSystem))
	evidence, err := runtimeport.NewDesktopRuntimeEvidence(runtimeport.DesktopRuntimeEvidenceInput{
		Condition: runtimeinstall.RuntimeConditionRunning, Ownership: desktopOwnership(plan.Action()),
		Product: "docker_desktop", RuntimeVersion: application.RuntimeVersion(), EngineVersion: observed.ServerVersion,
		ComposeVersion: observed.ComposeVersion, Endpoint: authority.Endpoint(), ApplicationPresent: true,
		ApplicationRunning: true, PublisherVerified: true, LocalEndpoint: true, LinuxContainers: true,
		CloudOffload: strings.Contains(operatingSystem, "cloud") || strings.Contains(operatingSystem, "offload"),
		TCPListener:  false, UnrelatedWorkloads: workloads,
	})
	if err != nil {
		return runtimeport.DesktopRuntimeEvidence{}, ErrProbeFailed
	}
	if !evidence.Compatible(authority) {
		return runtimeport.DesktopRuntimeEvidence{}, ErrRuntimeConflict
	}
	return evidence, nil
}

func desktopExecutablePair(docker, compose argvprocess.ExecutableAuthority) bool {
	if !docker.Valid() || !compose.Valid() || docker.Role() != argvprocess.ExecutableRoleDockerCLI ||
		compose.Role() != argvprocess.ExecutableRoleComposePlugin || !docker.SameSignedPlan(compose) ||
		docker.CanonicalPath() == compose.CanonicalPath() || docker.CanonicalID() == compose.CanonicalID() {
		return false
	}
	return docker.Platform() == "darwin" || docker.Platform() == "windows"
}

func desktopRunnersMatchAuthority(
	docker argvprocess.Runner,
	compose argvprocess.Runner,
	authority runtimeport.DesktopAuthority,
) bool {
	if desktopNilDependency(docker) || desktopNilDependency(compose) || !authority.Valid() {
		return false
	}
	dockerAuthority := docker.ExecutableAuthority()
	composeAuthority := compose.ExecutableAuthority()
	return desktopExecutablePair(dockerAuthority, composeAuthority) &&
		dockerAuthority.Platform() == authority.Platform().String() &&
		dockerAuthority.Architecture() == authority.Architecture().String() &&
		runtimeinstall.Hash(dockerAuthority.RuntimePlanDigest()) == authority.PlanDigest() &&
		runtimeinstall.Hash(composeAuthority.RuntimePlanDigest()) == authority.PlanDigest() &&
		dockerAuthority.CanonicalPath() == authority.DockerCLIPath() &&
		composeAuthority.CanonicalPath() == authority.ComposePluginPath() &&
		dockerAuthority.SHA256() == authority.DockerCLISHA256() &&
		composeAuthority.SHA256() == authority.ComposePluginSHA256() &&
		dockerAuthority.OwnerIdentity() == authority.ExecutableOwnerIdentity() &&
		composeAuthority.OwnerIdentity() == authority.ExecutableOwnerIdentity() &&
		dockerAuthority.PublisherIdentity() == authority.ExecutablePublisherIdentity() &&
		composeAuthority.PublisherIdentity() == authority.ExecutablePublisherIdentity() &&
		dockerAuthority.PublisherPolicyID() == authority.ExecutablePublisherPolicyID() &&
		composeAuthority.PublisherPolicyID() == authority.ExecutablePublisherPolicyID()
}

func (i *DesktopDockerInspector) desktopContainerWorkloads(
	ctx context.Context,
	authority runtimeport.DesktopAuthority,
) (uint32, error) {
	if i == nil || !desktopRunnersMatchAuthority(i.docker, i.compose, authority) {
		return 0, ErrProvisionIntegrity
	}
	executable := i.docker.ExecutableAuthority().CanonicalPath()
	invocation, err := argvprocess.NewInvocation(executable, []string{
		"--host", authority.Endpoint(), "container", "ls", "--all", "--quiet", "--no-trunc",
	})
	if err != nil {
		return 0, ErrProvisionIntegrity
	}
	result, err := i.docker.Run(ctx, invocation)
	if err != nil {
		return 0, err
	}
	if result.ExitCode != 0 || result.OutputTruncated || len(result.StandardOutput) > maximumDockerInventoryBytes ||
		len(result.StandardError) > maximumDockerInventoryBytes {
		return 0, ErrProbeFailed
	}
	return parseContainerIDs(result.StandardOutput)
}

func desktopOwnership(action runtimeinstall.PlanAction) runtimeinstall.OwnershipDisposition {
	if action == runtimeinstall.PlanActionInstallCertified || action == runtimeinstall.PlanActionRepairManaged {
		return runtimeinstall.OwnershipProvisionedByAgentMemory
	}
	return runtimeinstall.OwnershipReusedExternal
}

var _ runtimeport.DesktopRuntimeInspector = (*DesktopDockerInspector)(nil)
