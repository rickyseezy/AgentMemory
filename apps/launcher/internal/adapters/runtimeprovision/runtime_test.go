package runtimeprovision

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestDockerInspectorUsesExactEndpointSignedVersionsRootlessAndWorkloadInventory(t *testing.T) {
	t.Parallel()
	host, catalog := adapterBaseHostCatalog(t)
	discovery, err := runtimeinstall.NewRuntimeDiscovery(
		runtimeinstall.RuntimeConditionRunning, "docker_engine", "29.6.1",
		"unix:///run/user/1000/docker.sock", true, true, true,
		runtimeinstall.OwnershipReusedExternal, 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := runtimeinstall.NewPlanV1(host, discovery, catalog)
	if err != nil {
		t.Fatal(err)
	}
	authority := adapterLinuxAuthority(t, plan, 1)
	docker := newDockerScriptRunner(t, authority, argvprocess.ExecutableRoleDockerCLI)
	compose := newDockerScriptRunner(t, authority, argvprocess.ExecutableRoleComposePlugin)
	endpoint, _ := NewEndpointEvidence(true, 99, 0o660, true)
	inspector, err := NewDockerInspector(docker, compose, staticEndpointProbe{evidence: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := inspector.Inspect(context.Background(), plan, authority)
	if err != nil || !evidence.Compatible(authority) || evidence.Workloads() != 1 {
		t.Fatalf("Inspect() = compatible:%v workloads:%d error:%v", evidence.Compatible(authority), evidence.Workloads(), err)
	}
	if !allInvocationsUseEndpoint(docker.invocations, authority.Endpoint()) ||
		!allInvocationsUseEndpoint(compose.invocations, authority.Endpoint()) {
		t.Fatal("Docker inspection used ambient context instead of the exact endpoint")
	}
}

func TestDockerInspectorRejectsMaliciousOutputPlanDriftAndUnsafeRuntimeModes(t *testing.T) {
	t.Parallel()
	host, catalog := adapterBaseHostCatalog(t)
	discovery, _ := runtimeinstall.NewRuntimeDiscovery(
		runtimeinstall.RuntimeConditionRunning, "docker_engine", "29.6.1",
		"unix:///run/user/1000/docker.sock", true, true, true,
		runtimeinstall.OwnershipReusedExternal, 1,
	)
	plan, _ := runtimeinstall.NewPlanV1(host, discovery, catalog)
	authority := adapterLinuxAuthority(t, plan, 1)
	endpoint, _ := NewEndpointEvidence(true, 99, 0o660, true)

	tests := []struct {
		name   string
		mutate func(*dockerScriptRunner, *dockerScriptRunner)
	}{
		{name: "duplicate workloads", mutate: func(docker, _ *dockerScriptRunner) {
			docker.workloads = strings.Repeat("a", 64) + "\n" + strings.Repeat("a", 64) + "\n"
		}},
		{name: "wrong engine version", mutate: func(docker, _ *dockerScriptRunner) { docker.runtimeVersion = "29.6.0" }},
		{name: "cloud offload", mutate: func(docker, _ *dockerScriptRunner) { docker.operatingSystem = "Docker Cloud Offload" }},
		{name: "not rootless", mutate: func(docker, _ *dockerScriptRunner) { docker.rootless = false }},
		{name: "windows containers", mutate: func(docker, _ *dockerScriptRunner) { docker.osType = "windows" }},
		{name: "wrong compose", mutate: func(_, compose *dockerScriptRunner) { compose.composeVersion = "5.1.3" }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			docker := newDockerScriptRunner(t, authority, argvprocess.ExecutableRoleDockerCLI)
			compose := newDockerScriptRunner(t, authority, argvprocess.ExecutableRoleComposePlugin)
			test.mutate(docker, compose)
			inspector, inspectError := NewDockerInspector(docker, compose, staticEndpointProbe{evidence: endpoint})
			if inspectError != nil {
				t.Fatal(inspectError)
			}
			if _, inspectError = inspector.Inspect(context.Background(), plan, authority); inspectError == nil {
				t.Fatalf("Inspect(%s) succeeded", test.name)
			}
		})
	}

	otherPlan, _ := runtimeinstall.NewPlanV1(host, runtimeinstall.NewAbsentRuntimeDiscovery(), catalog)
	if _, err := (&DockerInspector{
		docker:  newDockerScriptRunner(t, authority, argvprocess.ExecutableRoleDockerCLI),
		compose: newDockerScriptRunner(t, authority, argvprocess.ExecutableRoleComposePlugin),
		probe:   nil, endpoint: staticEndpointProbe{evidence: endpoint},
	}).Inspect(context.Background(), otherPlan, authority); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("cross-plan Inspect() error = %v", err)
	}
}

func TestDockerInspectorClassifiesOnlyPlanAuthorizedMissingSocketStates(t *testing.T) {
	t.Parallel()
	installPlan, installAuthority := adapterAuthority(t)
	docker := newDockerScriptRunner(t, installAuthority, argvprocess.ExecutableRoleDockerCLI)
	compose := newDockerScriptRunner(t, installAuthority, argvprocess.ExecutableRoleComposePlugin)
	absentEndpoint, _ := NewEndpointEvidence(false, 0, 0, false)
	inspector, _ := NewDockerInspector(docker, compose, staticEndpointProbe{evidence: absentEndpoint})
	evidence, err := inspector.Inspect(context.Background(), installPlan, installAuthority)
	if err != nil || evidence.Condition() != runtimeinstall.RuntimeConditionAbsent {
		t.Fatalf("Install missing socket = %v %v", evidence.Condition(), err)
	}

	host, catalog := adapterBaseHostCatalog(t)
	stopped, _ := runtimeinstall.NewRuntimeDiscovery(
		runtimeinstall.RuntimeConditionStopped, "docker_engine", "29.6.1", installAuthority.Endpoint(),
		true, true, true, runtimeinstall.OwnershipReusedExternal, 0,
	)
	startPlan, _ := runtimeinstall.NewPlanV1(host, stopped, catalog)
	startAuthority := adapterLinuxAuthority(t, startPlan, 0)
	inspector, _ = NewDockerInspector(
		newDockerScriptRunner(t, startAuthority, argvprocess.ExecutableRoleDockerCLI),
		newDockerScriptRunner(t, startAuthority, argvprocess.ExecutableRoleComposePlugin),
		staticEndpointProbe{evidence: absentEndpoint},
	)
	evidence, err = inspector.Inspect(context.Background(), startPlan, startAuthority)
	if err != nil || evidence.Condition() != runtimeinstall.RuntimeConditionStopped {
		t.Fatalf("Start missing socket = %v %v", evidence.Condition(), err)
	}
	damaged, _ := runtimeinstall.NewRuntimeDiscovery(
		runtimeinstall.RuntimeConditionDamaged, "docker_engine", "29.6.1", installAuthority.Endpoint(),
		true, true, false, runtimeinstall.OwnershipProvisionedByAgentMemory, 0,
	)
	repairPlan, _ := runtimeinstall.NewPlanV1(host, damaged, catalog)
	repairAuthority := adapterLinuxAuthority(t, repairPlan, 0)
	inspector, _ = NewDockerInspector(
		newDockerScriptRunner(t, repairAuthority, argvprocess.ExecutableRoleDockerCLI),
		newDockerScriptRunner(t, repairAuthority, argvprocess.ExecutableRoleComposePlugin),
		staticEndpointProbe{evidence: absentEndpoint},
	)
	evidence, err = inspector.Inspect(context.Background(), repairPlan, repairAuthority)
	if err != nil || evidence.Condition() != runtimeinstall.RuntimeConditionDamaged {
		t.Fatalf("Repair missing socket = %v %v", evidence.Condition(), err)
	}
	running, _ := runtimeinstall.NewRuntimeDiscovery(
		runtimeinstall.RuntimeConditionRunning, "docker_engine", "29.6.1", installAuthority.Endpoint(),
		true, true, true, runtimeinstall.OwnershipReusedExternal, 0,
	)
	adoptPlan, _ := runtimeinstall.NewPlanV1(host, running, catalog)
	adoptAuthority := adapterLinuxAuthority(t, adoptPlan, 0)
	inspector, _ = NewDockerInspector(
		newDockerScriptRunner(t, adoptAuthority, argvprocess.ExecutableRoleDockerCLI),
		newDockerScriptRunner(t, adoptAuthority, argvprocess.ExecutableRoleComposePlugin),
		staticEndpointProbe{evidence: absentEndpoint},
	)
	if _, err := inspector.Inspect(context.Background(), adoptPlan, adoptAuthority); !errors.Is(err, ErrRuntimeConflict) {
		t.Fatalf("Adopt missing socket error = %v", err)
	}
}

func TestDockerInspectorSanitizesEndpointAndInventoryFailures(t *testing.T) {
	t.Parallel()
	host, catalog := adapterBaseHostCatalog(t)
	discovery, _ := runtimeinstall.NewRuntimeDiscovery(
		runtimeinstall.RuntimeConditionRunning, "docker_engine", "29.6.1",
		"unix:///run/user/1000/docker.sock", true, true, true,
		runtimeinstall.OwnershipReusedExternal, 1,
	)
	plan, _ := runtimeinstall.NewPlanV1(host, discovery, catalog)
	authority := adapterLinuxAuthority(t, plan, 1)
	endpoint, _ := NewEndpointEvidence(true, 99, 0o660, true)
	for _, test := range []struct {
		name   string
		mutate func(*dockerScriptRunner)
		probe  staticEndpointProbe
	}{
		{name: "endpoint", probe: staticEndpointProbe{err: errors.New("native detail")}},
		{name: "architecture", probe: staticEndpointProbe{evidence: endpoint}, mutate: func(runner *dockerScriptRunner) { runner.architecture = "ppc64le" }},
		{name: "inventory error", probe: staticEndpointProbe{evidence: endpoint}, mutate: func(runner *dockerScriptRunner) { runner.containerErr = errors.New("inventory detail") }},
		{name: "inventory exit", probe: staticEndpointProbe{evidence: endpoint}, mutate: func(runner *dockerScriptRunner) { runner.containerExit = 2 }},
		{name: "inventory truncation", probe: staticEndpointProbe{evidence: endpoint}, mutate: func(runner *dockerScriptRunner) { runner.containerTruncated = true }},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			docker := newDockerScriptRunner(t, authority, argvprocess.ExecutableRoleDockerCLI)
			if test.mutate != nil {
				test.mutate(docker)
			}
			inspector, constructError := NewDockerInspector(
				docker,
				newDockerScriptRunner(t, authority, argvprocess.ExecutableRoleComposePlugin),
				test.probe,
			)
			if constructError != nil {
				t.Fatal(constructError)
			}
			if _, inspectError := inspector.Inspect(context.Background(), plan, authority); inspectError == nil {
				t.Fatal("unsafe inspection unexpectedly succeeded")
			}
		})
	}
	inspector, _ := NewDockerInspector(
		newDockerScriptRunner(t, authority, argvprocess.ExecutableRoleDockerCLI),
		newDockerScriptRunner(t, authority, argvprocess.ExecutableRoleComposePlugin),
		staticEndpointProbe{evidence: endpoint},
	)
	var nilContext context.Context
	if _, err := inspector.Inspect(nilContext, plan, authority); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil inspection context error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := inspector.Inspect(cancelled, plan, authority); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled inspection error = %v", err)
	}
}

type staticEndpointProbe struct {
	evidence EndpointEvidence
	err      error
}

func (p staticEndpointProbe) ProbeLinuxEndpoint(context.Context, runtimeport.LinuxAuthority) (EndpointEvidence, error) {
	return p.evidence, p.err
}

type dockerScriptRunner struct {
	authority          argvprocess.ExecutableAuthority
	runtimeVersion     string
	composeVersion     string
	operatingSystem    string
	osType             string
	architecture       string
	rootless           bool
	workloads          string
	containerErr       error
	containerExit      int
	containerTruncated bool
	invocations        [][]string
}

func newDockerScriptRunner(
	t *testing.T,
	authority runtimeport.LinuxAuthority,
	role argvprocess.ExecutableRole,
) *dockerScriptRunner {
	t.Helper()
	path, id := "/usr/bin/docker", "docker-cli"
	if role == argvprocess.ExecutableRoleComposePlugin {
		path, id = "/usr/libexec/docker/cli-plugins/docker-compose", "compose-plugin"
	}
	executable, err := argvprocess.NewExecutableAuthority(argvprocess.ExecutableAuthorityInput{
		CanonicalID: id, CanonicalPath: path, SHA256: [32]byte(runtimeinstall.Sum([]byte(id))),
		OwnerIdentity: "uid:0", PublisherIdentity: "docker-linux-packages",
		PublisherPolicyID:     "linux-package-signature-v1",
		ReleaseManifestDigest: [32]byte(runtimeinstall.Sum([]byte("release"))),
		RuntimePlanDigest:     [32]byte(authority.PlanDigest()), Role: role,
		Platform: "linux", Architecture: authority.Architecture().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &dockerScriptRunner{
		authority: executable, runtimeVersion: authority.RuntimeVersion(), composeVersion: authority.ComposeVersion(),
		operatingSystem: "Ubuntu 24.04", osType: "linux", architecture: "x86_64", rootless: true,
		workloads: strings.Repeat("a", 64) + "\n",
	}
}

func (r *dockerScriptRunner) ExecutableAuthority() argvprocess.ExecutableAuthority {
	return r.authority
}

func (r *dockerScriptRunner) Run(_ context.Context, invocation argvprocess.Invocation) (argvprocess.Result, error) {
	arguments := invocation.Arguments()
	r.invocations = append(r.invocations, slices.Clone(arguments))
	output := ""
	switch {
	case slices.Contains(arguments, "version") && slices.Contains(arguments, "--short"):
		output = r.composeVersion + "\n"
	case slices.Contains(arguments, "version"):
		output = `{"ClientVersion":"` + r.runtimeVersion + `","ServerVersion":"` + r.runtimeVersion + `","APIVersion":"1.53"}`
	case slices.Contains(arguments, "info"):
		security := `[]`
		if r.rootless {
			security = `["name=rootless","name=seccomp"]`
		}
		output = `{"OperatingSystem":"` + r.operatingSystem + `","Architecture":"` + r.architecture + `","OSType":"` +
			r.osType + `","SecurityOptions":` + security + `,"NCPU":8,"MemTotal":34359738368}`
	case slices.Contains(arguments, "container"):
		if r.containerErr != nil {
			return argvprocess.Result{}, r.containerErr
		}
		return argvprocess.Result{
			ExitCode: r.containerExit, StandardOutput: []byte(r.workloads), OutputTruncated: r.containerTruncated,
		}, nil
	default:
		return argvprocess.Result{}, ErrProbeFailed
	}
	return argvprocess.Result{ExitCode: 0, StandardOutput: []byte(output)}, nil
}

func allInvocationsUseEndpoint(invocations [][]string, endpoint string) bool {
	if len(invocations) == 0 {
		return false
	}
	for _, arguments := range invocations {
		if len(arguments) < 2 || arguments[0] != "--host" || arguments[1] != endpoint {
			return false
		}
	}
	return true
}
