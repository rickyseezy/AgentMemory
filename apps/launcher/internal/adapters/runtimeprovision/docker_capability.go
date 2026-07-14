package runtimeprovision

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const (
	capabilityProbeHTTPDeadline = 10 * time.Second
	capabilityProbeHTTPPoll     = 100 * time.Millisecond
	capabilityCleanupDeadline   = 20 * time.Second
)

type probeWorkspace struct {
	directory string
	inputPath string
	digest    runtimeinstall.Hash
	cleanup   func() error
}

type dockerCapabilityProjection struct {
	platform, architecture    string
	endpoint                  string
	probeImage                string
	probeContract             string
	dockerPath, composePath   string
	workspacePrefix           string
	plan, policy, imageDigest runtimeinstall.Hash
	unrelatedWorkloads        uint32
}

type composeCapabilityService struct {
	Command     []string          `json:"command"`
	Image       string            `json:"image"`
	Labels      map[string]string `json:"labels"`
	NetworkMode string            `json:"network_mode"`
	PullPolicy  string            `json:"pull_policy"`
	ReadOnly    bool              `json:"read_only"`
}

func (w probeWorkspace) valid(prefix string) bool {
	return prefix != "" && strings.HasPrefix(w.directory, prefix) &&
		w.inputPath == filepath.Join(w.directory, "input.bin") && !w.digest.IsZero() && w.cleanup != nil
}

func (p dockerCapabilityProjection) valid() bool {
	return (p.platform == "linux" || p.platform == "darwin" || p.platform == "windows") &&
		(p.architecture == "amd64" || p.architecture == "arm64") && p.endpoint != "" &&
		!p.plan.IsZero() && !p.policy.IsZero() && !p.imageDigest.IsZero() && p.probeContract == "1" &&
		p.probeImage == "docker.io/rickyseezy/agentmemory-runtime-probe@sha256:"+p.imageDigest.String() &&
		p.workspacePrefix != ""
}

// DockerCapabilityProbe runs the signed v1 probe-image contract through only
// the explicit local endpoint, then proves all pre-existing workloads remain.
type DockerCapabilityProbe struct {
	docker           argvprocess.Runner
	compose          argvprocess.Runner
	workspace        func(context.Context, runtimeport.LinuxAuthority) (probeWorkspace, error)
	desktopWorkspace func(context.Context, runtimeport.DesktopAuthority) (probeWorkspace, error)
}

// NewDockerCapabilityProbe constructs the production active probe adapter.
func NewDockerCapabilityProbe(docker, compose argvprocess.Runner) (*DockerCapabilityProbe, error) {
	if nilDependency(docker) || nilDependency(compose) {
		return nil, ErrProvisionIntegrity
	}
	dockerAuthority := docker.ExecutableAuthority()
	composeAuthority := compose.ExecutableAuthority()
	if !dockerAuthority.Valid() || !composeAuthority.Valid() ||
		dockerAuthority.Role() != argvprocess.ExecutableRoleDockerCLI ||
		composeAuthority.Role() != argvprocess.ExecutableRoleComposePlugin ||
		(dockerAuthority.Platform() != "linux" && dockerAuthority.Platform() != "darwin" && dockerAuthority.Platform() != "windows") ||
		composeAuthority.Platform() != dockerAuthority.Platform() ||
		!dockerAuthority.SameSignedPlan(composeAuthority) ||
		dockerAuthority.CanonicalPath() == composeAuthority.CanonicalPath() {
		return nil, ErrProvisionIntegrity
	}
	return &DockerCapabilityProbe{
		docker: docker, compose: compose, workspace: prepareNativeProbeWorkspace,
		desktopWorkspace: prepareNativeDesktopProbeWorkspace,
	}, nil
}

// VerifyLinuxCapabilities executes the complete compensated probe sequence.
func (p *DockerCapabilityProbe) VerifyLinuxCapabilities(
	ctx context.Context,
	authority runtimeport.LinuxAuthority,
	runtimeEvidence RuntimeEvidence,
	managedStateDigest runtimeinstall.Hash,
) (CapabilityEvidence, error) {
	if ctx == nil {
		return CapabilityEvidence{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return CapabilityEvidence{}, err
	}
	projection := linuxDockerCapabilityProjection(authority)
	if p == nil || nilDependency(p.docker) || nilDependency(p.compose) || p.workspace == nil || !authority.Valid() ||
		!runtimeEvidence.Compatible(authority) || !dockerToolchainMatches(p.docker, p.compose, projection) ||
		authority.ProbeContractVersion() != "1" || managedStateDigest.IsZero() {
		return CapabilityEvidence{}, ErrProvisionIntegrity
	}
	workspace, err := p.workspace(ctx, authority)
	if err != nil || !workspace.valid(projection.workspacePrefix) {
		return CapabilityEvidence{}, sanitizedContextError(ctx, ErrProbeFailed)
	}
	if _, err := p.executeProjectedProbe(ctx, projection, workspace); err != nil {
		return CapabilityEvidence{}, err
	}
	return NewCapabilityEvidence(CapabilityEvidenceInput{
		EngineAPI: true, Compose: true, Architecture: true, LinuxContainers: true,
		Rootless: true, NoTCPListener: true, BindReadOnly: true, NetworkIsolation: true,
		VolumePersistence: true, LoopbackPublish: true, WorkloadsPreserved: true,
		LocalExecution: true, ManagedStateDigest: managedStateDigest,
		PolicyDigest: authority.CapabilityPolicyDigest(),
	})
}

// VerifyDesktopCapabilities executes the same complete compensated active
// Engine, Compose, bind, network, volume, loopback, local-execution, image,
// and workload-preservation contract through the exact Desktop endpoint.
func (p *DockerCapabilityProbe) VerifyDesktopCapabilities(
	ctx context.Context,
	authority runtimeport.DesktopAuthority,
) (runtimeinstall.Hash, error) {
	if ctx == nil {
		return runtimeinstall.Hash{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return runtimeinstall.Hash{}, err
	}
	projection := desktopDockerCapabilityProjection(authority)
	if p == nil || nilDependency(p.docker) || nilDependency(p.compose) || p.desktopWorkspace == nil ||
		!authority.Valid() || !dockerToolchainMatches(p.docker, p.compose, projection) {
		return runtimeinstall.Hash{}, ErrProvisionIntegrity
	}
	workspace, err := p.desktopWorkspace(ctx, authority)
	if err != nil || !workspace.valid(projection.workspacePrefix) {
		return runtimeinstall.Hash{}, sanitizedContextError(ctx, ErrProbeFailed)
	}
	return p.executeProjectedProbe(ctx, projection, workspace)
}

func (p *DockerCapabilityProbe) executeProjectedProbe(
	ctx context.Context,
	authority dockerCapabilityProjection,
	workspace probeWorkspace,
) (runtimeinstall.Hash, error) {
	initial, err := p.workloadSnapshot(ctx, authority)
	if err != nil || uint64(len(initial)) != uint64(authority.unrelatedWorkloads) {
		_ = workspace.cleanup()
		return runtimeinstall.Hash{}, sanitizedContextError(ctx, ErrRuntimeConflict)
	}
	if err := p.verifyProbeImage(ctx, authority); err != nil {
		_ = workspace.cleanup()
		return runtimeinstall.Hash{}, sanitizedContextError(ctx, ErrProbeFailed)
	}
	prefix := "agentmemory-probe-" + authority.plan.String()[:20]
	labels := []string{
		"com.agentmemory.runtime-probe=1",
		"com.agentmemory.plan=" + authority.plan.String(),
		"com.agentmemory.policy=" + authority.policy.String(),
	}
	if err := p.cleanupOwned(ctx, authority, prefix, labels); err != nil {
		_ = workspace.cleanup()
		return runtimeinstall.Hash{}, sanitizedContextError(ctx, ErrProbeFailed)
	}
	cleanupWorkspace := true
	defer func() {
		if cleanupWorkspace {
			_ = workspace.cleanup()
		}
	}()
	probeError := p.runProbeSequence(ctx, authority, workspace, prefix, labels)
	cleanupContext, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), capabilityCleanupDeadline)
	cleanupError := p.cleanupOwned(cleanupContext, authority, prefix, labels)
	cancelCleanup()
	workspaceError := workspace.cleanup()
	cleanupWorkspace = false
	if probeError != nil || cleanupError != nil || workspaceError != nil {
		return runtimeinstall.Hash{}, sanitizedContextError(ctx, ErrProbeFailed)
	}
	final, err := p.workloadSnapshot(ctx, authority)
	if err != nil || !slices.Equal(initial, final) {
		return runtimeinstall.Hash{}, sanitizedContextError(ctx, ErrRuntimeConflict)
	}
	encoded, _ := json.Marshal(struct {
		Plan, Policy, Image, Workspace string
		Initial, Final                 []string
	}{
		Plan: authority.plan.String(), Policy: authority.policy.String(), Image: authority.imageDigest.String(),
		Workspace: workspace.digest.String(), Initial: slices.Clone(initial), Final: slices.Clone(final),
	})
	return runtimeinstall.Sum(encoded), nil
}

func linuxDockerCapabilityProjection(authority runtimeport.LinuxAuthority) dockerCapabilityProjection {
	return dockerCapabilityProjection{
		platform: "linux", architecture: authority.Architecture().String(), endpoint: authority.Endpoint(),
		probeImage: authority.ProbeImage(), probeContract: authority.ProbeContractVersion(),
		workspacePrefix: authority.RuntimeDirectory() + "/agentmemory-runtime-probe-",
		plan:            authority.PlanDigest(), policy: authority.CapabilityPolicyDigest(), imageDigest: authority.ProbeImageDigest(),
		unrelatedWorkloads: authority.UnrelatedWorkloads(),
	}
}

func desktopDockerCapabilityProjection(authority runtimeport.DesktopAuthority) dockerCapabilityProjection {
	workspacePrefix := authority.HomeDirectory() + "/Library/Caches/AgentMemory/runtime-probe-"
	if authority.Platform() == runtimeinstall.PlatformWindows {
		workspacePrefix = authority.HomeDirectory() + `\AppData\Local\AgentMemory\runtime-probe-`
	}
	return dockerCapabilityProjection{
		platform: authority.Platform().String(), architecture: authority.Architecture().String(), endpoint: authority.Endpoint(),
		probeImage: authority.ProbeImage(), probeContract: authority.ProbeContractVersion(),
		dockerPath: authority.DockerCLIPath(), composePath: authority.ComposePluginPath(), workspacePrefix: workspacePrefix,
		plan: authority.PlanDigest(), policy: authority.CapabilityPolicyDigest(), imageDigest: authority.ProbeImageDigest(),
		unrelatedWorkloads: authority.UnrelatedWorkloads(),
	}
}

func dockerRunnerMatches(runner argvprocess.Runner, authority dockerCapabilityProjection) bool {
	if nilDependency(runner) || !authority.valid() {
		return false
	}
	executable := runner.ExecutableAuthority()
	return executable.Valid() && executable.Role() == argvprocess.ExecutableRoleDockerCLI &&
		executable.Platform() == authority.platform && executable.Architecture() == authority.architecture &&
		runtimeinstall.Hash(executable.RuntimePlanDigest()) == authority.plan &&
		(authority.dockerPath == "" || executable.CanonicalPath() == authority.dockerPath)
}

func dockerToolchainMatches(
	docker argvprocess.Runner,
	compose argvprocess.Runner,
	authority dockerCapabilityProjection,
) bool {
	if !dockerRunnerMatches(docker, authority) || nilDependency(compose) {
		return false
	}
	dockerAuthority := docker.ExecutableAuthority()
	composeAuthority := compose.ExecutableAuthority()
	return composeAuthority.Valid() && composeAuthority.Role() == argvprocess.ExecutableRoleComposePlugin &&
		composeAuthority.Platform() == authority.platform &&
		composeAuthority.Architecture() == authority.architecture &&
		runtimeinstall.Hash(composeAuthority.RuntimePlanDigest()) == authority.plan &&
		(authority.composePath == "" || composeAuthority.CanonicalPath() == authority.composePath) &&
		dockerAuthority.SameSignedPlan(composeAuthority)
}

func (p *DockerCapabilityProbe) verifyProbeImage(
	ctx context.Context,
	authority dockerCapabilityProjection,
) error {
	template := `{"Id":{{json .Id}},"RepoDigests":{{json .RepoDigests}}}`
	output, err := p.run(ctx, authority, []string{
		"image", "inspect", "--format", template, "--", authority.probeImage,
	})
	if err != nil {
		return err
	}
	var document struct {
		ID          string   `json:"Id"`
		RepoDigests []string `json:"RepoDigests"`
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil || !validSHA256Identifier(document.ID) ||
		!slices.Contains(document.RepoDigests, authority.probeImage) {
		return ErrProbeFailed
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrProbeFailed
	}
	return nil
}

func validSHA256Identifier(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range strings.TrimPrefix(value, "sha256:") {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}

func (p *DockerCapabilityProbe) runProbeSequence(
	ctx context.Context,
	authority dockerCapabilityProjection,
	workspace probeWorkspace,
	prefix string,
	labels []string,
) error {
	networkName, volumeName, containerName := prefix+"-network", prefix+"-volume", prefix+"-http"
	if err := p.requireComposeOK(ctx, authority, prefix, labels); err != nil {
		return err
	}
	labelArguments := make([]string, 0, len(labels)*2)
	for _, label := range labels {
		labelArguments = append(labelArguments, "--label", label)
	}
	bindArguments := make([]string, 0, 12+len(labelArguments))
	bindArguments = append(bindArguments, "run", "--rm", "--pull", "never", "--network", "none")
	bindArguments = append(bindArguments, labelArguments...)
	bindArguments = append(bindArguments,
		"--mount", "type=bind,source="+workspace.inputPath+",target=/probe/input,readonly",
		authority.probeImage, "bind-read-only", "/probe/input", workspace.digest.String(),
	)
	if err := p.requireOK(ctx, authority, bindArguments); err != nil {
		return err
	}

	networkArguments := make([]string, 0, 7+len(labelArguments))
	networkArguments = append(networkArguments, "network", "create", "--driver", "bridge", "--internal")
	networkArguments = append(networkArguments, labelArguments...)
	networkArguments = append(networkArguments, "--", networkName)
	networkID, err := p.run(ctx, authority, networkArguments)
	if err != nil {
		return err
	}
	if count, parseError := parseContainerIDs(networkID); parseError != nil || count != 1 {
		return ErrProbeFailed
	}
	networkProbe := make([]string, 0, 8+len(labelArguments))
	networkProbe = append(networkProbe, "run", "--rm", "--pull", "never", "--network", networkName)
	networkProbe = append(networkProbe, labelArguments...)
	networkProbe = append(networkProbe, authority.probeImage, "network-isolation")
	if err := p.requireOK(ctx, authority, networkProbe); err != nil {
		return err
	}

	volumeArguments := make([]string, 0, 6+len(labelArguments))
	volumeArguments = append(volumeArguments, "volume", "create", "--driver", "local")
	volumeArguments = append(volumeArguments, labelArguments...)
	volumeArguments = append(volumeArguments, "--name", volumeName)
	createdVolume, err := p.run(ctx, authority, volumeArguments)
	if err != nil || strings.TrimSuffix(string(createdVolume), "\n") != volumeName {
		return ErrProbeFailed
	}
	volumeToken := authority.policy.String()
	for _, operation := range []string{"volume-write", "volume-read"} {
		arguments := make([]string, 0, 12+len(labelArguments))
		arguments = append(arguments, "run", "--rm", "--pull", "never", "--network", "none")
		arguments = append(arguments, labelArguments...)
		arguments = append(arguments,
			"--mount", "type=volume,source="+volumeName+",target=/probe/state",
			authority.probeImage, operation, "/probe/state", volumeToken,
		)
		if err := p.requireOK(ctx, authority, arguments); err != nil {
			return err
		}
	}

	publishArguments := make([]string, 0, 13+len(labelArguments))
	publishArguments = append(publishArguments,
		"run", "--detach", "--pull", "never", "--name", containerName,
		"--network", "none", "--publish", "127.0.0.1::8080",
	)
	publishArguments = append(publishArguments, labelArguments...)
	publishArguments = append(publishArguments, authority.probeImage, "loopback-http", "8080")
	containerID, err := p.run(ctx, authority, publishArguments)
	if err != nil {
		return err
	}
	if count, parseError := parseContainerIDs(containerID); parseError != nil || count != 1 {
		return ErrProbeFailed
	}
	portOutput, err := p.run(ctx, authority, []string{"container", "port", "--", containerName, "8080/tcp"})
	if err != nil {
		return err
	}
	port, err := parseLoopbackPort(portOutput)
	if err != nil || p.awaitLoopbackHTTP(ctx, port) != nil {
		return ErrProbeFailed
	}
	return nil
}

func (p *DockerCapabilityProbe) requireComposeOK(
	ctx context.Context,
	authority dockerCapabilityProjection,
	prefix string,
	labels []string,
) error {
	if ctx == nil || !dockerToolchainMatches(p.docker, p.compose, authority) {
		return ErrProvisionIntegrity
	}
	labelMap := make(map[string]string, len(labels))
	for _, label := range labels {
		key, value, present := strings.Cut(label, "=")
		if !present || key == "" || value == "" {
			return ErrProvisionIntegrity
		}
		labelMap[key] = value
	}
	document := struct {
		Services map[string]composeCapabilityService `json:"services"`
	}{
		Services: map[string]composeCapabilityService{
			"capability": {
				Command: []string{"network-isolation"}, Image: authority.probeImage, Labels: labelMap,
				NetworkMode: "none", PullPolicy: "never", ReadOnly: true,
			},
		},
	}
	configuration, err := json.Marshal(document)
	if err != nil {
		return ErrProvisionIntegrity
	}
	arguments := []string{
		"--host", authority.endpoint, "--ansi", "never", "--project-name", prefix + "-compose",
		"--file", "-", "run", "--rm", "--no-deps", "--pull", "never",
		"--name", prefix + "-compose", "capability", "network-isolation",
	}
	invocation, err := argvprocess.NewInvocationWithStandardInput(
		p.compose.ExecutableAuthority().CanonicalPath(), arguments, configuration,
	)
	if err != nil {
		return ErrProvisionIntegrity
	}
	result, err := p.compose.Run(ctx, invocation)
	if err != nil || result.ExitCode != 0 || result.OutputTruncated ||
		len(result.StandardError) > maximumDockerInventoryBytes || string(result.StandardOutput) != "ok\n" {
		return ErrProbeFailed
	}
	return nil
}

func (p *DockerCapabilityProbe) requireOK(
	ctx context.Context,
	authority dockerCapabilityProjection,
	arguments []string,
) error {
	output, err := p.run(ctx, authority, arguments)
	if err != nil || string(output) != "ok\n" {
		return ErrProbeFailed
	}
	return nil
}

func (p *DockerCapabilityProbe) workloadSnapshot(
	ctx context.Context,
	authority dockerCapabilityProjection,
) ([]string, error) {
	output, err := p.run(ctx, authority, []string{"container", "ls", "--all", "--quiet", "--no-trunc"})
	if err != nil {
		return nil, err
	}
	text := strings.TrimSuffix(string(output), "\n")
	if text == "" {
		return []string{}, nil
	}
	identifiers := strings.Split(text, "\n")
	if count, err := parseContainerIDs(output); err != nil || int(count) != len(identifiers) {
		return nil, ErrProbeFailed
	}
	slices.Sort(identifiers)
	return identifiers, nil
}

func (p *DockerCapabilityProbe) cleanupOwned(
	ctx context.Context,
	authority dockerCapabilityProjection,
	prefix string,
	labels []string,
) error {
	filterArguments := make([]string, 0, len(labels)*2)
	for _, label := range labels {
		filterArguments = append(filterArguments, "--filter", "label="+label)
	}
	resources := []struct {
		kind   string
		format string
	}{
		{kind: "container", format: "{{.Names}}"},
		{kind: "network", format: "{{.Name}}"},
		{kind: "volume", format: "{{.Name}}"},
	}
	for _, resource := range resources {
		arguments := []string{resource.kind, "ls"}
		if resource.kind == "container" {
			arguments = append(arguments, "--all")
		}
		arguments = append(arguments, filterArguments...)
		arguments = append(arguments, "--format", resource.format)
		output, err := p.run(ctx, authority, arguments)
		if err != nil {
			return err
		}
		names, err := parseOwnedNames(output, prefix)
		if err != nil {
			return err
		}
		for _, name := range names {
			if resource.kind == "container" {
				_, _ = p.run(ctx, authority, []string{"container", "stop", "--time", "5", "--", name})
				if _, err := p.run(ctx, authority, []string{"container", "rm", "--", name}); err != nil {
					return err
				}
				continue
			}
			if _, err := p.run(ctx, authority, []string{resource.kind, "rm", "--", name}); err != nil {
				return err
			}
		}
	}
	return nil
}

func parseOwnedNames(raw []byte, prefix string) ([]string, error) {
	text := strings.TrimSuffix(string(raw), "\n")
	if text == "" {
		return nil, nil
	}
	names := strings.Split(text, "\n")
	if len(names) > 64 {
		return nil, ErrProbeFailed
	}
	for _, name := range names {
		if !strings.HasPrefix(name, prefix) || len(name) > 128 || strings.ContainsAny(name, " \t\r/\\") {
			return nil, ErrRuntimeConflict
		}
	}
	slices.Sort(names)
	for index := 1; index < len(names); index++ {
		if names[index] == names[index-1] {
			return nil, ErrProbeFailed
		}
	}
	return names, nil
}

func parseLoopbackPort(raw []byte) (uint16, error) {
	value := strings.TrimSuffix(string(raw), "\n")
	if !strings.HasPrefix(value, "127.0.0.1:") || strings.Contains(value, "\n") {
		return 0, ErrProbeFailed
	}
	parsed, err := strconv.ParseUint(strings.TrimPrefix(value, "127.0.0.1:"), 10, 16)
	if err != nil || parsed == 0 {
		return 0, ErrProbeFailed
	}
	return uint16(parsed), nil
}

func (p *DockerCapabilityProbe) awaitLoopbackHTTP(ctx context.Context, port uint16) error {
	probeContext := ctx
	cancel := func() {}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		probeContext, cancel = context.WithTimeout(ctx, capabilityProbeHTTPDeadline)
	}
	defer cancel()
	address := net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(port), 10))
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(dialContext context.Context, network, candidate string) (net.Conn, error) {
			if network != "tcp" || candidate != address {
				return nil, ErrProbeFailed
			}
			return (&net.Dialer{}).DialContext(dialContext, network, candidate)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	url := "http://" + address + "/ready"
	ticker := time.NewTicker(capabilityProbeHTTPPoll)
	defer ticker.Stop()
	for {
		request, err := http.NewRequestWithContext(probeContext, http.MethodGet, url, nil)
		if err != nil {
			return ErrProbeFailed
		}
		response, err := client.Do(request) // #nosec G704 -- exact loopback address and fixed path are adapter-generated.
		if err == nil {
			body, readError := io.ReadAll(io.LimitReader(response.Body, 2))
			closeError := response.Body.Close()
			if readError == nil && closeError == nil && response.StatusCode == http.StatusNoContent && len(body) == 0 {
				return nil
			}
		} else if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		select {
		case <-probeContext.Done():
			return probeContext.Err()
		case <-ticker.C:
		}
	}
}

func (p *DockerCapabilityProbe) run(
	ctx context.Context,
	authority dockerCapabilityProjection,
	operation []string,
) ([]byte, error) {
	if ctx == nil || !dockerRunnerMatches(p.docker, authority) || len(operation) == 0 {
		return nil, ErrProvisionIntegrity
	}
	arguments := make([]string, 0, len(operation)+2)
	arguments = append(arguments, "--host", authority.endpoint)
	arguments = append(arguments, operation...)
	invocation, err := argvprocess.NewInvocation(p.docker.ExecutableAuthority().CanonicalPath(), arguments)
	if err != nil {
		return nil, ErrProvisionIntegrity
	}
	result, err := p.docker.Run(ctx, invocation)
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 || result.OutputTruncated || len(result.StandardOutput) > maximumDockerInventoryBytes ||
		len(result.StandardError) > maximumDockerInventoryBytes {
		return nil, ErrProbeFailed
	}
	return append([]byte(nil), result.StandardOutput...), nil
}

var _ CapabilityProbe = (*DockerCapabilityProbe)(nil)
