package runtimeprovision

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/dockercli"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const maximumDockerInventoryBytes = 1024 * 1024

// EndpointEvidence proves the exact owner/type/locality of the rootless socket.
type EndpointEvidence struct {
	exists bool
	inode  uint64
	mode   uint32
	noTCP  bool
	digest runtimeinstall.Hash
}

// NewEndpointEvidence validates native endpoint facts.
func NewEndpointEvidence(exists bool, inode uint64, mode uint32, noTCP bool) (EndpointEvidence, error) {
	if exists && (inode == 0 || mode&0o600 != 0o600 || mode&0o007 != 0) || !exists && (inode != 0 || mode != 0 || noTCP) {
		return EndpointEvidence{}, ErrProbeFailed
	}
	encoded, _ := json.Marshal(struct {
		Exists bool   `json:"exists"`
		Inode  uint64 `json:"inode"`
		Mode   uint32 `json:"mode"`
		NoTCP  bool   `json:"no_tcp"`
	}{Exists: exists, Inode: inode, Mode: mode, NoTCP: noTCP})
	return EndpointEvidence{
		exists: exists, inode: inode, mode: mode, noTCP: noTCP, digest: runtimeinstall.Sum(encoded),
	}, nil
}

// Exists reports whether the exact authorized socket exists.
func (e EndpointEvidence) Exists() bool { return e.exists }

// NoTCPListener reports whether the endpoint process tree owns no listening TCP socket.
func (e EndpointEvidence) NoTCPListener() bool { return e.noTCP }

// Digest returns the socket identity/locality proof.
func (e EndpointEvidence) Digest() runtimeinstall.Hash { return e.digest }

// EndpointProbe proves a local rootless socket through native APIs.
type EndpointProbe interface {
	ProbeLinuxEndpoint(context.Context, runtimeport.LinuxAuthority) (EndpointEvidence, error)
}

// RuntimeEvidence is a complete read-only Docker discovery result.
type RuntimeEvidence struct {
	condition       runtimeinstall.RuntimeCondition
	endpoint        EndpointEvidence
	runtimeVersion  string
	composeVersion  string
	architecture    runtimeinstall.Architecture
	rootless        bool
	linuxContainers bool
	cloudOffload    bool
	workloads       uint32
	digest          runtimeinstall.Hash
}

// RuntimeEvidenceInput is used by the exact Docker inspector and tests.
type RuntimeEvidenceInput struct {
	Condition       runtimeinstall.RuntimeCondition
	Endpoint        EndpointEvidence
	RuntimeVersion  string
	ComposeVersion  string
	Architecture    runtimeinstall.Architecture
	Rootless        bool
	LinuxContainers bool
	CloudOffload    bool
	Workloads       uint32
}

// NewRuntimeEvidence validates a discovery observation.
func NewRuntimeEvidence(input RuntimeEvidenceInput) (RuntimeEvidence, error) {
	if input.Condition == runtimeinstall.RuntimeConditionUnknown || input.Endpoint.Digest().IsZero() ||
		input.Condition == runtimeinstall.RuntimeConditionRunning && (!input.Endpoint.Exists() ||
			input.RuntimeVersion == "" || input.ComposeVersion == "" ||
			input.Architecture != runtimeinstall.ArchitectureAMD64 && input.Architecture != runtimeinstall.ArchitectureARM64) ||
		input.Condition != runtimeinstall.RuntimeConditionRunning &&
			(input.RuntimeVersion != "" || input.ComposeVersion != "" || input.Architecture != runtimeinstall.ArchitectureUnknown ||
				input.Rootless || input.LinuxContainers || input.CloudOffload) {
		return RuntimeEvidence{}, ErrProbeFailed
	}
	evidence := RuntimeEvidence{
		condition: input.Condition, endpoint: input.Endpoint, runtimeVersion: input.RuntimeVersion,
		composeVersion: input.ComposeVersion, architecture: input.Architecture, rootless: input.Rootless,
		linuxContainers: input.LinuxContainers, cloudOffload: input.CloudOffload, workloads: input.Workloads,
	}
	encoded, _ := json.Marshal(struct {
		Architecture string `json:"architecture"`
		Cloud        bool   `json:"cloud_offload"`
		Compose      string `json:"compose_version"`
		Condition    uint8  `json:"condition"`
		Endpoint     string `json:"endpoint_digest"`
		Linux        bool   `json:"linux_containers"`
		Rootless     bool   `json:"rootless"`
		Runtime      string `json:"runtime_version"`
		Workloads    uint32 `json:"workloads"`
	}{
		Architecture: input.Architecture.String(), Cloud: input.CloudOffload,
		Compose: input.ComposeVersion, Condition: uint8(input.Condition), Endpoint: input.Endpoint.Digest().String(),
		Linux: input.LinuxContainers, Rootless: input.Rootless, Runtime: input.RuntimeVersion,
		Workloads: input.Workloads,
	})
	evidence.digest = runtimeinstall.Sum(encoded)
	return evidence, nil
}

// Digest returns every bounded runtime discovery fact.
func (e RuntimeEvidence) Digest() runtimeinstall.Hash { return e.digest }

// Condition returns the observed local runtime state.
func (e RuntimeEvidence) Condition() runtimeinstall.RuntimeCondition { return e.condition }

// Workloads returns the exact unrelated container inventory count.
func (e RuntimeEvidence) Workloads() uint32 { return e.workloads }

// Compatible proves exact Engine/Compose/architecture/Linux/rootless/no-TCP/no-cloud policy.
func (e RuntimeEvidence) Compatible(authority runtimeport.LinuxAuthority) bool {
	return authority.Valid() && e.condition == runtimeinstall.RuntimeConditionRunning &&
		e.runtimeVersion == authority.RuntimeVersion() && e.composeVersion == authority.ComposeVersion() &&
		e.architecture == authority.Architecture() && e.rootless && e.linuxContainers && !e.cloudOffload &&
		e.endpoint.Exists() && e.endpoint.NoTCPListener() && e.workloads == authority.UnrelatedWorkloads()
}

// DockerInspector performs only explicitly addressed, retained-executable argv calls.
type DockerInspector struct {
	docker   argvprocess.Runner
	compose  argvprocess.Runner
	probe    *dockercli.Probe
	endpoint EndpointProbe
}

// NewDockerInspector binds direct Docker and Compose executables from one signed plan.
func NewDockerInspector(
	docker argvprocess.Runner,
	compose argvprocess.Runner,
	endpoint EndpointProbe,
) (*DockerInspector, error) {
	if docker == nil || compose == nil || endpoint == nil {
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
	return &DockerInspector{docker: docker, compose: compose, probe: probe, endpoint: endpoint}, nil
}

// Inspect re-probes current external state and refuses plan drift.
func (i *DockerInspector) Inspect(
	ctx context.Context,
	plan runtimeinstall.Plan,
	authority runtimeport.LinuxAuthority,
) (RuntimeEvidence, error) {
	if ctx == nil {
		return RuntimeEvidence{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return RuntimeEvidence{}, err
	}
	if i == nil || i.probe == nil || !authority.ValidFor(plan) || !runnersMatchAuthority(i.docker, i.compose, authority) {
		return RuntimeEvidence{}, ErrProvisionIntegrity
	}
	endpoint, err := i.endpoint.ProbeLinuxEndpoint(ctx, authority)
	if err != nil {
		return RuntimeEvidence{}, sanitizedContextError(ctx, ErrProbeFailed)
	}
	if !endpoint.Exists() {
		switch plan.Action() {
		case runtimeinstall.PlanActionInstallCertified:
			return NewRuntimeEvidence(RuntimeEvidenceInput{
				Condition: runtimeinstall.RuntimeConditionAbsent, Endpoint: endpoint,
				Workloads: authority.UnrelatedWorkloads(),
			})
		case runtimeinstall.PlanActionStartCompatible:
			return NewRuntimeEvidence(RuntimeEvidenceInput{
				Condition: runtimeinstall.RuntimeConditionStopped, Endpoint: endpoint,
				Workloads: authority.UnrelatedWorkloads(),
			})
		case runtimeinstall.PlanActionRepairManaged:
			return NewRuntimeEvidence(RuntimeEvidenceInput{
				Condition: runtimeinstall.RuntimeConditionDamaged, Endpoint: endpoint,
				Workloads: authority.UnrelatedWorkloads(),
			})
		case runtimeinstall.PlanActionAdoptCompatible, runtimeinstall.PlanActionBlock,
			runtimeinstall.PlanActionUnknown:
			return RuntimeEvidence{}, ErrRuntimeConflict
		default:
			return RuntimeEvidence{}, ErrRuntimeConflict
		}
	}
	engineEndpoint, err := containerengine.NewEndpoint(authority.Endpoint())
	if err != nil {
		return RuntimeEvidence{}, ErrProvisionIntegrity
	}
	probe, err := i.probe.Probe(ctx, engineEndpoint)
	if err != nil {
		return RuntimeEvidence{}, sanitizedContextError(ctx, ErrRuntimeConflict)
	}
	workloads, err := i.containerWorkloads(ctx, authority.Endpoint())
	if err != nil {
		return RuntimeEvidence{}, sanitizedContextError(ctx, ErrProbeFailed)
	}
	var architecture runtimeinstall.Architecture
	switch probe.Architecture {
	case "amd64":
		architecture = runtimeinstall.ArchitectureAMD64
	case "arm64":
		architecture = runtimeinstall.ArchitectureARM64
	default:
		return RuntimeEvidence{}, ErrRuntimeConflict
	}
	rootless := false
	for _, option := range probe.SecurityOptions {
		option = strings.ToLower(strings.TrimSpace(option))
		if option == "rootless" || option == "name=rootless" {
			rootless = true
		}
	}
	operatingSystem := strings.ToLower(probe.OperatingSystem)
	evidence, err := NewRuntimeEvidence(RuntimeEvidenceInput{
		Condition: runtimeinstall.RuntimeConditionRunning, Endpoint: endpoint,
		RuntimeVersion: probe.ServerVersion, ComposeVersion: probe.ComposeVersion,
		Architecture: architecture, Rootless: rootless, LinuxContainers: probe.OSType == "linux",
		CloudOffload: strings.Contains(operatingSystem, "offload") || strings.Contains(operatingSystem, "cloud"),
		Workloads:    workloads,
	})
	if err != nil {
		return RuntimeEvidence{}, ErrProbeFailed
	}
	if !evidence.Compatible(authority) {
		return RuntimeEvidence{}, ErrRuntimeConflict
	}
	return evidence, nil
}

func runnersMatchAuthority(
	docker argvprocess.Runner,
	compose argvprocess.Runner,
	authority runtimeport.LinuxAuthority,
) bool {
	if docker == nil || compose == nil || !authority.Valid() {
		return false
	}
	dockerAuthority := docker.ExecutableAuthority()
	composeAuthority := compose.ExecutableAuthority()
	return dockerAuthority.Valid() && composeAuthority.Valid() &&
		dockerAuthority.Role() == argvprocess.ExecutableRoleDockerCLI &&
		composeAuthority.Role() == argvprocess.ExecutableRoleComposePlugin &&
		dockerAuthority.Platform() == "linux" && composeAuthority.Platform() == "linux" &&
		dockerAuthority.Architecture() == authority.Architecture().String() &&
		composeAuthority.Architecture() == authority.Architecture().String() &&
		runtimeinstall.Hash(dockerAuthority.RuntimePlanDigest()) == authority.PlanDigest() &&
		runtimeinstall.Hash(composeAuthority.RuntimePlanDigest()) == authority.PlanDigest() &&
		dockerAuthority.SameSignedPlan(composeAuthority)
}

func (i *DockerInspector) containerWorkloads(ctx context.Context, endpoint string) (uint32, error) {
	authority := i.docker.ExecutableAuthority()
	invocation, err := argvprocess.NewInvocation(authority.CanonicalPath(), []string{
		"--host", endpoint, "container", "ls", "--all", "--quiet", "--no-trunc",
	})
	if err != nil {
		return 0, ErrProbeFailed
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

func parseContainerIDs(raw []byte) (uint32, error) {
	text := strings.TrimSuffix(string(raw), "\n")
	if text == "" {
		return 0, nil
	}
	lines := strings.Split(text, "\n")
	seen := make(map[string]struct{}, len(lines))
	for _, line := range lines {
		if len(line) != 64 {
			return 0, ErrProbeFailed
		}
		for _, character := range line {
			if character < '0' || character > '9' {
				if character < 'a' || character > 'f' {
					return 0, ErrProbeFailed
				}
			}
		}
		if _, duplicate := seen[line]; duplicate {
			return 0, ErrProbeFailed
		}
		seen[line] = struct{}{}
	}
	if uint64(len(seen)) > uint64(^uint32(0)) {
		return 0, ErrProbeFailed
	}
	return uint32(len(seen)), nil // #nosec G115 -- explicit MaxUint32 check above proves the conversion safe.
}
