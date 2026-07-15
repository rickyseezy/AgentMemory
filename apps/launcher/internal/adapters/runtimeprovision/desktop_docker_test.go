package runtimeprovision

import (
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestDesktopDockerInspectorDiscoversExactSignedLocalLinuxContainerRuntime(t *testing.T) {
	t.Parallel()
	plan, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformDarwin)
	docker, compose := desktopDockerRunners(t, authority)
	application := desktopInstalledApplicationFake{evidence: desktopInstalledApplicationEvidence(t, authority, true)}
	inspector, err := NewDesktopDockerInspector(docker, compose, application)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := inspector.InspectDesktopRuntime(context.Background(), plan, authority)
	if err != nil || !evidence.Compatible(authority) || evidence.Condition() != runtimeinstall.RuntimeConditionRunning ||
		evidence.Ownership() != runtimeinstall.OwnershipProvisionedByAgentMemory || evidence.Workloads() != authority.UnrelatedWorkloads() {
		t.Fatalf("InspectDesktopRuntime() = %#v, %v", evidence, err)
	}
	wantDocker := [][]string{
		{"--host", authority.Endpoint(), "version", "--format", `{"ClientVersion":{{json .Client.Version}},"ServerVersion":{{json .Server.Version}},"APIVersion":{{json .Server.APIVersion}}}`},
		{"--host", authority.Endpoint(), "info", "--format", `{"OperatingSystem":{{json .OperatingSystem}},"Architecture":{{json .Architecture}},"OSType":{{json .OSType}},"SecurityOptions":{{json .SecurityOptions}},"NCPU":{{json .NCPU}},"MemTotal":{{json .MemTotal}}}`},
		{"--host", authority.Endpoint(), "container", "ls", "--all", "--quiet", "--no-trunc"},
	}
	if !reflect.DeepEqual(docker.arguments, wantDocker) || !reflect.DeepEqual(compose.arguments, [][]string{
		{"--host", authority.Endpoint(), "version", "--short"},
	}) {
		t.Fatalf("docker argv=%#v compose argv=%#v", docker.arguments, compose.arguments)
	}
	for _, invocation := range append(slicesCloneArguments(docker.arguments), compose.arguments...) {
		if len(invocation) < 2 || invocation[0] != "--host" || invocation[1] != authority.Endpoint() {
			t.Fatalf("ambient Docker endpoint invocation: %v", invocation)
		}
	}
}

func TestDesktopDockerInspectorReportsExactAbsenceWithoutExecutingDocker(t *testing.T) {
	t.Parallel()
	plan, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformWindows)
	docker, compose := desktopDockerRunners(t, authority)
	inspector, err := NewDesktopDockerInspector(
		docker, compose,
		desktopInstalledApplicationFake{evidence: desktopInstalledApplicationEvidence(t, authority, false)},
	)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := inspector.InspectDesktopRuntime(context.Background(), plan, authority)
	if err != nil || evidence.Condition() != runtimeinstall.RuntimeConditionAbsent || evidence.Compatible(authority) {
		t.Fatalf("absent evidence = %#v, %v", evidence, err)
	}
	if len(docker.arguments) != 0 || len(compose.arguments) != 0 {
		t.Fatal("Docker executables ran for an absent application")
	}
}

func TestDesktopDockerInspectorReturnsStoppedWhileInstalledEngineStarts(t *testing.T) {
	t.Parallel()
	plan, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformWindows)
	docker, compose := desktopDockerRunners(t, authority)
	docker.runError = errors.New("named pipe is not ready")
	inspector, err := NewDesktopDockerInspector(
		docker, compose,
		desktopInstalledApplicationFake{evidence: desktopInstalledApplicationEvidence(t, authority, true)},
	)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := inspector.InspectDesktopRuntime(context.Background(), plan, authority)
	if err != nil || evidence.Condition() != runtimeinstall.RuntimeConditionStopped || evidence.Compatible(authority) ||
		evidence.Ownership() != runtimeinstall.OwnershipProvisionedByAgentMemory {
		t.Fatalf("starting evidence = %#v, %v", evidence, err)
	}
}

func TestDesktopDockerInspectorRejectsCloudOffloadVersionArchitectureWorkloadAndRunnerDrift(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*desktopBoundRunner, *desktopBoundRunner, *desktopInstalledApplicationFake)
	}{
		{name: "cloud offload", mutate: func(docker, _ *desktopBoundRunner, _ *desktopInstalledApplicationFake) {
			docker.results[1].StandardOutput = []byte(desktopDockerInfo("Docker Desktop cloud offload", "arm64", "linux"))
		}},
		{name: "Windows containers", mutate: func(docker, _ *desktopBoundRunner, _ *desktopInstalledApplicationFake) {
			docker.results[1].StandardOutput = []byte(desktopDockerInfo("Docker Desktop", "arm64", "windows"))
		}},
		{name: "architecture", mutate: func(docker, _ *desktopBoundRunner, _ *desktopInstalledApplicationFake) {
			docker.results[1].StandardOutput = []byte(desktopDockerInfo("Docker Desktop", "amd64", "linux"))
		}},
		{name: "engine version", mutate: func(docker, _ *desktopBoundRunner, _ *desktopInstalledApplicationFake) {
			docker.results[0].StandardOutput = []byte(`{"ClientVersion":"29.6.1","ServerVersion":"29.5.0","APIVersion":"1.52"}`)
		}},
		{name: "compose version", mutate: func(_ *desktopBoundRunner, compose *desktopBoundRunner, _ *desktopInstalledApplicationFake) {
			compose.results[0].StandardOutput = []byte("5.0.0\n")
		}},
		{name: "workload drift", mutate: func(docker, _ *desktopBoundRunner, _ *desktopInstalledApplicationFake) {
			docker.results[2].StandardOutput = []byte(strings.Repeat("a", 64) + "\n")
		}},
		{name: "workload command failure", mutate: func(docker, _ *desktopBoundRunner, _ *desktopInstalledApplicationFake) {
			docker.results[2].ExitCode = 2
		}},
		{name: "application binding", mutate: func(_ *desktopBoundRunner, _ *desktopBoundRunner, application *desktopInstalledApplicationFake) {
			application.evidence = runtimeport.DesktopInstalledApplicationEvidence{}
		}},
		{name: "runner drift", mutate: func(docker, _ *desktopBoundRunner, _ *desktopInstalledApplicationFake) {
			docker.authority = argvprocess.ExecutableAuthority{}
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			plan, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformDarwin)
			docker, compose := desktopDockerRunners(t, authority)
			application := &desktopInstalledApplicationFake{evidence: desktopInstalledApplicationEvidence(t, authority, true)}
			inspector, err := NewDesktopDockerInspector(docker, compose, application)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(docker, compose, application)
			evidence, err := inspector.InspectDesktopRuntime(context.Background(), plan, authority)
			if err == nil && (evidence.Compatible(authority) || evidence.Condition() == runtimeinstall.RuntimeConditionRunning) {
				t.Fatal("unsafe desktop runtime observation was accepted as running and compatible")
			}
		})
	}
}

func TestDesktopDockerInspectorConstructorAndContextFailClosed(t *testing.T) {
	t.Parallel()
	_, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformDarwin)
	docker, compose := desktopDockerRunners(t, authority)
	application := desktopInstalledApplicationFake{evidence: desktopInstalledApplicationEvidence(t, authority, true)}
	for _, candidate := range []struct {
		docker      argvprocess.Runner
		compose     argvprocess.Runner
		application runtimeport.DesktopInstalledApplicationProbe
	}{
		{compose: compose, application: application},
		{docker: docker, application: application},
		{docker: docker, compose: compose},
	} {
		if inspector, err := NewDesktopDockerInspector(candidate.docker, candidate.compose, candidate.application); err == nil || inspector != nil {
			t.Fatal("incomplete desktop inspector was constructed")
		}
	}
	if _, err := NewDesktopDockerInspector(docker, docker, application); err == nil {
		t.Fatal("duplicate Docker executable role was accepted")
	}
	inspector, err := NewDesktopDockerInspector(docker, compose, application)
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := desktopAdapterAuthority(t, runtimeinstall.PlatformDarwin)
	var nilContext context.Context
	if _, err := inspector.InspectDesktopRuntime(nilContext, plan, authority); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil context error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := inspector.InspectDesktopRuntime(cancelled, plan, authority); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context error = %v", err)
	}
	if _, err := (*DesktopDockerInspector)(nil).InspectDesktopRuntime(context.Background(), plan, authority); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("nil inspector error = %v", err)
	}
	if desktopOwnership(runtimeinstall.PlanActionInstallCertified) != runtimeinstall.OwnershipProvisionedByAgentMemory ||
		desktopOwnership(runtimeinstall.PlanActionRepairManaged) != runtimeinstall.OwnershipProvisionedByAgentMemory ||
		desktopOwnership(runtimeinstall.PlanActionAdoptCompatible) != runtimeinstall.OwnershipReusedExternal {
		t.Fatal("desktop ownership mapping drifted")
	}
}

type desktopBoundRunner struct {
	mu        sync.Mutex
	authority argvprocess.ExecutableAuthority
	results   []argvprocess.Result
	arguments [][]string
	runError  error
}

func (r *desktopBoundRunner) ExecutableAuthority() argvprocess.ExecutableAuthority {
	if r == nil {
		return argvprocess.ExecutableAuthority{}
	}
	return r.authority
}

func (r *desktopBoundRunner) Run(_ context.Context, invocation argvprocess.Invocation) (argvprocess.Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.arguments = append(r.arguments, invocation.Arguments())
	if r.runError != nil {
		return argvprocess.Result{}, r.runError
	}
	if len(r.results) == 0 {
		return argvprocess.Result{}, errors.New("unexpected desktop Docker invocation")
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result, nil
}

type desktopInstalledApplicationFake struct {
	evidence runtimeport.DesktopInstalledApplicationEvidence
	err      error
}

func (f desktopInstalledApplicationFake) ProbeDesktopInstalledApplication(
	context.Context,
	runtimeport.DesktopAuthority,
) (runtimeport.DesktopInstalledApplicationEvidence, error) {
	return f.evidence, f.err
}

func desktopDockerRunners(
	t testing.TB,
	authority runtimeport.DesktopAuthority,
) (*desktopBoundRunner, *desktopBoundRunner) {
	t.Helper()
	release := runtimeinstall.Sum([]byte("signed-desktop-executables"))
	dockerAuthority := desktopExecutableAuthority(t, authority, authority.DockerCLIPath(), "desktop-docker-cli", argvprocess.ExecutableRoleDockerCLI, release)
	composeAuthority := desktopExecutableAuthority(t, authority, authority.ComposePluginPath(), "desktop-compose-plugin", argvprocess.ExecutableRoleComposePlugin, release)
	docker := &desktopBoundRunner{
		authority: dockerAuthority,
		results: []argvprocess.Result{
			{StandardOutput: []byte(`{"ClientVersion":"29.6.1","ServerVersion":"29.6.1","APIVersion":"1.52"}`)},
			{StandardOutput: []byte(desktopDockerInfo("Docker Desktop", authority.Architecture().String(), "linux"))},
			{StandardOutput: nil},
		},
	}
	compose := &desktopBoundRunner{
		authority: composeAuthority,
		results:   []argvprocess.Result{{StandardOutput: []byte(authority.ComposeVersion() + "\n")}},
	}
	return docker, compose
}

func desktopExecutableAuthority(
	t testing.TB,
	authority runtimeport.DesktopAuthority,
	path string,
	id string,
	role argvprocess.ExecutableRole,
	release runtimeinstall.Hash,
) argvprocess.ExecutableAuthority {
	t.Helper()
	digest := authority.DockerCLISHA256()
	if role == argvprocess.ExecutableRoleComposePlugin {
		digest = authority.ComposePluginSHA256()
	}
	executable, err := argvprocess.NewExecutableAuthority(argvprocess.ExecutableAuthorityInput{
		CanonicalID: id, CanonicalPath: path, SHA256: [sha256.Size]byte(digest), OwnerIdentity: authority.ExecutableOwnerIdentity(),
		PublisherIdentity: authority.ExecutablePublisherIdentity(), PublisherPolicyID: authority.ExecutablePublisherPolicyID(),
		ReleaseManifestDigest: [32]byte(release), RuntimePlanDigest: [32]byte(authority.PlanDigest()),
		Role: role, Platform: authority.Platform().String(), Architecture: authority.Architecture().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return executable
}

func desktopInstalledApplicationEvidence(
	t testing.TB,
	authority runtimeport.DesktopAuthority,
	present bool,
) runtimeport.DesktopInstalledApplicationEvidence {
	t.Helper()
	input := runtimeport.DesktopInstalledApplicationEvidenceInput{AuthorityDigest: authority.Digest(), Present: present}
	if present {
		publisher := authority.Publisher()
		input.RuntimeVersion = authority.RuntimeVersion()
		input.PublisherKind = publisher.Kind()
		input.PublisherIdentity = publisher.Identity()
		input.CertificateSHA256 = publisher.CertificateSHA256()
		input.NativeVerified = true
	}
	evidence, err := runtimeport.NewDesktopInstalledApplicationEvidence(input)
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func desktopDockerInfo(operatingSystem, architecture, osType string) string {
	return `{"OperatingSystem":"` + operatingSystem + `","Architecture":"` + architecture +
		`","OSType":"` + osType + `","SecurityOptions":["name=seccomp"],"NCPU":8,"MemTotal":25769803776}`
}

func slicesCloneArguments(input [][]string) [][]string {
	clone := make([][]string, len(input))
	for index := range input {
		clone[index] = append([]string(nil), input[index]...)
	}
	return clone
}
