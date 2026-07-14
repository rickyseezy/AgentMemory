package runtimeprovision

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestDockerCapabilityProbeExecutesAndCompensatesCompleteSignedProbeContract(t *testing.T) {
	t.Parallel()
	plan, authority := adapterAuthority(t)
	server := newLoopbackProbeServer(t)
	defer server.Close()
	port := uint16(server.Listener.Addr().(*net.TCPAddr).Port) // #nosec G115 -- test listener ports are uint16.
	runner := newCapabilityRunner(t, authority, port)
	compose := newCapabilityComposeRunner(t, authority)
	probe, err := NewDockerCapabilityProbe(runner, compose)
	if err != nil {
		t.Fatal(err)
	}
	cleanupCalls := 0
	probe.workspace = func(context.Context, runtimeport.LinuxAuthority) (probeWorkspace, error) {
		directory := authority.RuntimeDirectory() + "/agentmemory-runtime-probe-" + plan.Digest().String()[:20]
		return probeWorkspace{
			directory: directory, inputPath: directory + "/input.bin",
			digest: authority.CapabilityPolicyDigest(), cleanup: func() error { cleanupCalls++; return nil },
		}, nil
	}
	endpoint, _ := NewEndpointEvidence(true, 88, 0o660, true)
	runtimeEvidence, _ := NewRuntimeEvidence(RuntimeEvidenceInput{
		Condition: runtimeinstall.RuntimeConditionRunning, Endpoint: endpoint,
		RuntimeVersion: authority.RuntimeVersion(), ComposeVersion: authority.ComposeVersion(),
		Architecture: authority.Architecture(), Rootless: true, LinuxContainers: true,
		Workloads: authority.UnrelatedWorkloads(),
	})
	evidence, err := probe.VerifyLinuxCapabilities(
		context.Background(), authority, runtimeEvidence, runtimeinstall.Sum([]byte("managed-state")),
	)
	if err != nil || evidence.Digest().IsZero() {
		t.Fatalf("VerifyLinuxCapabilities() error = %v", err)
	}
	if cleanupCalls != 1 || runner.container != "" || runner.network != "" || runner.volume != "" {
		t.Fatalf("compensation incomplete: cleanup=%d container=%q network=%q volume=%q", cleanupCalls, runner.container, runner.network, runner.volume)
	}
	for _, invocation := range runner.invocations {
		if len(invocation) < 2 || invocation[0] != "--host" || invocation[1] != authority.Endpoint() {
			t.Fatalf("ambient endpoint invocation: %v", invocation)
		}
	}
	if !runner.sawBind || !runner.sawNetwork || runner.volumeRuns != 2 || !runner.sawPublish {
		t.Fatalf("probe coverage bind=%v network=%v volume=%d publish=%v", runner.sawBind, runner.sawNetwork, runner.volumeRuns, runner.sawPublish)
	}
	if !compose.sawRun {
		t.Fatal("direct signed Compose executable did not run the active probe workload")
	}
}

func TestDockerCapabilityProbeRejectsPolicyImageWorkspaceAndWorkloadDrift(t *testing.T) {
	t.Parallel()
	_, authority := adapterAuthority(t)
	endpoint, _ := NewEndpointEvidence(true, 88, 0o660, true)
	runtimeEvidence, _ := NewRuntimeEvidence(RuntimeEvidenceInput{
		Condition: runtimeinstall.RuntimeConditionRunning, Endpoint: endpoint,
		RuntimeVersion: authority.RuntimeVersion(), ComposeVersion: authority.ComposeVersion(),
		Architecture: authority.Architecture(), Rootless: true, LinuxContainers: true,
	})
	runner := newCapabilityRunner(t, authority, 1)
	probe, _ := NewDockerCapabilityProbe(runner, newCapabilityComposeRunner(t, authority))
	probe.workspace = func(context.Context, runtimeport.LinuxAuthority) (probeWorkspace, error) {
		return probeWorkspace{directory: "/tmp/unsafe", inputPath: "/tmp/unsafe/input.bin", cleanup: func() error { return nil }}, nil
	}
	managedState := runtimeinstall.Sum([]byte("managed-state"))
	if _, err := probe.VerifyLinuxCapabilities(context.Background(), authority, runtimeEvidence, managedState); err == nil {
		t.Fatal("unsafe workspace retained capability authority")
	}
	runner.imageAuthentic = false
	probe.workspace = func(context.Context, runtimeport.LinuxAuthority) (probeWorkspace, error) {
		directory := authority.RuntimeDirectory() + "/agentmemory-runtime-probe-test"
		return probeWorkspace{directory: directory, inputPath: directory + "/input.bin", digest: authority.CapabilityPolicyDigest(), cleanup: func() error { return nil }}, nil
	}
	if _, err := probe.VerifyLinuxCapabilities(context.Background(), authority, runtimeEvidence, managedState); err == nil {
		t.Fatal("untrusted probe image retained capability authority")
	}
	runner.imageAuthentic = true
	runner.workloads = []string{strings.Repeat("a", 64)}
	if _, err := probe.VerifyLinuxCapabilities(context.Background(), authority, runtimeEvidence, managedState); err == nil {
		t.Fatal("workload drift retained capability authority")
	}
}

func TestDockerCapabilityProbeCompensatesEveryFailedProbeStage(t *testing.T) {
	t.Parallel()
	plan, authority := adapterAuthority(t)
	server := newLoopbackProbeServer(t)
	defer server.Close()
	port := uint16(server.Listener.Addr().(*net.TCPAddr).Port) // #nosec G115 -- test listener ports are uint16.
	endpoint, _ := NewEndpointEvidence(true, 88, 0o660, true)
	runtimeEvidence, _ := NewRuntimeEvidence(RuntimeEvidenceInput{
		Condition: runtimeinstall.RuntimeConditionRunning, Endpoint: endpoint,
		RuntimeVersion: authority.RuntimeVersion(), ComposeVersion: authority.ComposeVersion(),
		Architecture: authority.Architecture(), Rootless: true, LinuxContainers: true,
	})
	for _, failure := range []struct {
		token string
		mode  string
	}{
		{token: "inspect", mode: "error"},
		{token: "compose", mode: "error"},
		{token: "network-isolation", mode: "exit"},
		{token: "volume-write", mode: "truncated"},
		{token: "--detach", mode: "error"},
		{token: "port", mode: "error"},
		{token: "rm", mode: "error"},
	} {
		failure := failure
		t.Run(failure.token+"-"+failure.mode, func(t *testing.T) {
			runner := newCapabilityRunner(t, authority, port)
			compose := newCapabilityComposeRunner(t, authority)
			if failure.token == "compose" {
				compose.fail = true
			} else {
				runner.failToken, runner.failMode = failure.token, failure.mode
			}
			probe, err := NewDockerCapabilityProbe(runner, compose)
			if err != nil {
				t.Fatal(err)
			}
			directory := authority.RuntimeDirectory() + "/agentmemory-runtime-probe-" + plan.Digest().String()[:20]
			probe.workspace = func(context.Context, runtimeport.LinuxAuthority) (probeWorkspace, error) {
				return probeWorkspace{
					directory: directory, inputPath: directory + "/input.bin",
					digest: authority.CapabilityPolicyDigest(), cleanup: func() error { return nil },
				}, nil
			}
			if _, err := probe.VerifyLinuxCapabilities(
				context.Background(), authority, runtimeEvidence, runtimeinstall.Sum([]byte("managed")),
			); err == nil {
				t.Fatal("failed probe stage unexpectedly produced capability evidence")
			}
		})
	}
}

func TestDockerCapabilityProbeConstructorContextAndImageParserFailClosed(t *testing.T) {
	t.Parallel()
	plan, authority := adapterAuthority(t)
	if _, err := NewDockerCapabilityProbe(nil, nil); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("nil runner constructor error = %v", err)
	}
	if _, err := NewDockerCapabilityProbe(
		newDockerScriptRunner(t, authority, argvprocess.ExecutableRoleComposePlugin),
		newDockerScriptRunner(t, authority, argvprocess.ExecutableRoleComposePlugin),
	); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("wrong-role constructor error = %v", err)
	}
	runner := newCapabilityRunner(t, authority, 1)
	probe, _ := NewDockerCapabilityProbe(runner, newCapabilityComposeRunner(t, authority))
	directory := authority.RuntimeDirectory() + "/agentmemory-runtime-probe-" + plan.Digest().String()[:20]
	probe.workspace = func(context.Context, runtimeport.LinuxAuthority) (probeWorkspace, error) {
		return probeWorkspace{
			directory: directory, inputPath: directory + "/input.bin",
			digest: authority.CapabilityPolicyDigest(), cleanup: func() error { return nil },
		}, nil
	}
	endpoint, _ := NewEndpointEvidence(true, 88, 0o660, true)
	runtimeEvidence, _ := NewRuntimeEvidence(RuntimeEvidenceInput{
		Condition: runtimeinstall.RuntimeConditionRunning, Endpoint: endpoint,
		RuntimeVersion: authority.RuntimeVersion(), ComposeVersion: authority.ComposeVersion(),
		Architecture: authority.Architecture(), Rootless: true, LinuxContainers: true,
	})
	var nilContext context.Context
	if _, err := probe.VerifyLinuxCapabilities(nilContext, authority, runtimeEvidence, runtimeinstall.Sum([]byte("managed"))); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil context error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := probe.VerifyLinuxCapabilities(cancelled, authority, runtimeEvidence, runtimeinstall.Sum([]byte("managed"))); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context error = %v", err)
	}
	if _, err := probe.VerifyLinuxCapabilities(context.Background(), authority, runtimeEvidence, runtimeinstall.Hash{}); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("zero managed-state error = %v", err)
	}
	for _, imageOutput := range []string{
		`{"Id":"sha256:` + strings.Repeat("1", 64) + `","RepoDigests":["` + authority.ProbeImage() + `"],"extra":true}`,
		`{"Id":"sha256:` + strings.Repeat("1", 64) + `","RepoDigests":["` + authority.ProbeImage() + `"]} trailing`,
		`{"Id":"","RepoDigests":["` + authority.ProbeImage() + `"]}`,
		`{"Id":"sha256:short","RepoDigests":["` + authority.ProbeImage() + `"]}`,
	} {
		runner.imageOutput = imageOutput
		if _, err := probe.VerifyLinuxCapabilities(
			context.Background(), authority, runtimeEvidence, runtimeinstall.Sum([]byte("managed")),
		); err == nil {
			t.Fatal("malformed image receipt unexpectedly succeeded")
		}
	}
}

func TestCapabilityOutputParsersAreStrict(t *testing.T) {
	t.Parallel()
	if !validSHA256Identifier("sha256:"+strings.Repeat("a", 64)) ||
		validSHA256Identifier("sha256:"+strings.Repeat("g", 64)) || validSHA256Identifier("sha512:"+strings.Repeat("a", 64)) {
		t.Fatal("SHA-256 image identifier validation drifted")
	}
	if port, err := parseLoopbackPort([]byte("127.0.0.1:32768\n")); err != nil || port != 32768 {
		t.Fatalf("parseLoopbackPort() = %d %v", port, err)
	}
	for _, raw := range []string{"0.0.0.0:80\n", "127.0.0.1:0\n", "127.0.0.1:65536\n", "127.0.0.1:80\nextra"} {
		if _, err := parseLoopbackPort([]byte(raw)); err == nil {
			t.Fatalf("parseLoopbackPort(%q) succeeded", raw)
		}
	}
	if names, err := parseOwnedNames([]byte("agentmemory-probe-a\nagentmemory-probe-b\n"), "agentmemory-probe-"); err != nil || len(names) != 2 {
		t.Fatalf("parseOwnedNames() = %v %v", names, err)
	}
	for _, raw := range []string{"foreign\n", "agentmemory-probe-a\nagentmemory-probe-a\n", "agentmemory-probe-a/child\n"} {
		if _, err := parseOwnedNames([]byte(raw), "agentmemory-probe-"); err == nil {
			t.Fatalf("parseOwnedNames(%q) succeeded", raw)
		}
	}
}

func TestLoopbackCapabilityProbeHonorsCallerDeadline(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if err := (&DockerCapabilityProbe{}).awaitLoopbackHTTP(ctx, 1); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("loopback deadline error = %v", err)
	}
}

func TestDesktopDockerCapabilityProbeExecutesCompleteCompensatedSignedContract(t *testing.T) {
	t.Parallel()
	_, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformDarwin)
	server := newLoopbackProbeServer(t)
	defer server.Close()
	port := uint16(server.Listener.Addr().(*net.TCPAddr).Port) // #nosec G115 -- test listener ports are uint16.
	release := runtimeinstall.Sum([]byte("desktop-capability-release"))
	runner := &capabilityRunner{
		authority: desktopExecutableAuthority(
			t, authority, authority.DockerCLIPath(), "desktop-capability-docker", argvprocess.ExecutableRoleDockerCLI, release,
		),
		probeImage: authority.ProbeImage(), port: port, imageAuthentic: true,
	}
	compose := &capabilityComposeRunner{
		authority: desktopExecutableAuthority(
			t, authority, authority.ComposePluginPath(), "desktop-capability-compose", argvprocess.ExecutableRoleComposePlugin, release,
		),
		probeImage: authority.ProbeImage(), endpoint: authority.Endpoint(),
	}
	probe, err := NewDockerCapabilityProbe(runner, compose)
	if err != nil {
		t.Fatal(err)
	}
	cleanupCalls := 0
	projection := desktopDockerCapabilityProjection(authority)
	probe.desktopWorkspace = func(context.Context, runtimeport.DesktopAuthority) (probeWorkspace, error) {
		directory := projection.workspacePrefix + authority.PlanDigest().String()[:20]
		return probeWorkspace{
			directory: directory, inputPath: directory + "/input.bin", digest: authority.CapabilityPolicyDigest(),
			cleanup: func() error { cleanupCalls++; return nil },
		}, nil
	}
	receipt, err := probe.VerifyDesktopCapabilities(context.Background(), authority)
	if err != nil || receipt.IsZero() {
		t.Fatalf("VerifyDesktopCapabilities() = %s, %v", receipt, err)
	}
	if cleanupCalls != 1 || !runner.sawBind || !runner.sawNetwork || runner.volumeRuns != 2 || !runner.sawPublish ||
		!compose.sawRun || runner.container != "" || runner.network != "" || runner.volume != "" {
		t.Fatalf("desktop probe cleanup=%d bind=%t network=%t volume=%d publish=%t compose=%t resources=%q/%q/%q",
			cleanupCalls, runner.sawBind, runner.sawNetwork, runner.volumeRuns, runner.sawPublish, compose.sawRun,
			runner.container, runner.network, runner.volume)
	}
	for _, invocation := range runner.invocations {
		if len(invocation) < 2 || invocation[0] != "--host" || invocation[1] != authority.Endpoint() {
			t.Fatalf("ambient Desktop endpoint invocation: %v", invocation)
		}
	}
}

func TestDesktopDockerCapabilityProbeRejectsRunnerWorkspaceImageAndWorkloadDrift(t *testing.T) {
	t.Parallel()
	_, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformDarwin)
	release := runtimeinstall.Sum([]byte("desktop-capability-release"))
	newProbe := func(t *testing.T) (*DockerCapabilityProbe, *capabilityRunner) {
		runner := &capabilityRunner{
			authority: desktopExecutableAuthority(
				t, authority, authority.DockerCLIPath(), "desktop-capability-docker", argvprocess.ExecutableRoleDockerCLI, release,
			),
			probeImage: authority.ProbeImage(), port: 1, imageAuthentic: true,
		}
		compose := &capabilityComposeRunner{
			authority: desktopExecutableAuthority(
				t, authority, authority.ComposePluginPath(), "desktop-capability-compose", argvprocess.ExecutableRoleComposePlugin, release,
			),
			probeImage: authority.ProbeImage(), endpoint: authority.Endpoint(),
		}
		probe, err := NewDockerCapabilityProbe(runner, compose)
		if err != nil {
			t.Fatal(err)
		}
		projection := desktopDockerCapabilityProjection(authority)
		probe.desktopWorkspace = func(context.Context, runtimeport.DesktopAuthority) (probeWorkspace, error) {
			directory := projection.workspacePrefix + "test"
			return probeWorkspace{
				directory: directory, inputPath: directory + "/input.bin", digest: authority.CapabilityPolicyDigest(),
				cleanup: func() error { return nil },
			}, nil
		}
		return probe, runner
	}

	probe, runner := newProbe(t)
	runner.imageAuthentic = false
	if _, err := probe.VerifyDesktopCapabilities(context.Background(), authority); err == nil {
		t.Fatal("untrusted Desktop probe image was accepted")
	}
	probe, runner = newProbe(t)
	runner.workloads = []string{strings.Repeat("a", 64)}
	if _, err := probe.VerifyDesktopCapabilities(context.Background(), authority); err == nil {
		t.Fatal("unexpected Desktop workload inventory was accepted")
	}
	probe, _ = newProbe(t)
	probe.desktopWorkspace = func(context.Context, runtimeport.DesktopAuthority) (probeWorkspace, error) {
		return probeWorkspace{directory: "/tmp/ambient", inputPath: "/tmp/ambient/input.bin", digest: authority.CapabilityPolicyDigest(), cleanup: func() error { return nil }}, nil
	}
	if _, err := probe.VerifyDesktopCapabilities(context.Background(), authority); err == nil {
		t.Fatal("ambient Desktop workspace was accepted")
	}
	probe, _ = newProbe(t)
	probe.docker = nil
	if _, err := probe.VerifyDesktopCapabilities(context.Background(), authority); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("missing Desktop runner error = %v", err)
	}
	if _, err := (*DockerCapabilityProbe)(nil).VerifyDesktopCapabilities(context.Background(), authority); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("nil Desktop probe error = %v", err)
	}
	var nilContext context.Context
	if _, err := probe.VerifyDesktopCapabilities(nilContext, authority); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil Desktop context error = %v", err)
	}
}

func newLoopbackProbeServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/ready" {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server.Listener = listener
	server.Start()
	return server
}

type capabilityRunner struct {
	mu             sync.Mutex
	authority      argvprocess.ExecutableAuthority
	probeImage     string
	port           uint16
	imageAuthentic bool
	imageOutput    string
	failToken      string
	failMode       string
	failed         bool
	workloads      []string
	container      string
	network        string
	volume         string
	invocations    [][]string
	sawBind        bool
	sawNetwork     bool
	volumeRuns     int
	sawPublish     bool
}

type capabilityComposeRunner struct {
	authority  argvprocess.ExecutableAuthority
	probeImage string
	endpoint   string
	fail       bool
	sawRun     bool
}

func newCapabilityComposeRunner(
	t *testing.T,
	authority runtimeport.LinuxAuthority,
) *capabilityComposeRunner {
	t.Helper()
	base := newDockerScriptRunner(t, authority, argvprocess.ExecutableRoleComposePlugin)
	return &capabilityComposeRunner{
		authority: base.authority, probeImage: authority.ProbeImage(), endpoint: authority.Endpoint(),
	}
}

func (r *capabilityComposeRunner) ExecutableAuthority() argvprocess.ExecutableAuthority {
	return r.authority
}

func (r *capabilityComposeRunner) Run(
	_ context.Context,
	invocation argvprocess.Invocation,
) (argvprocess.Result, error) {
	if r.fail {
		return argvprocess.Result{}, errors.New("injected Compose runner failure")
	}
	arguments := invocation.Arguments()
	configuration := string(invocation.StandardInput())
	if invocation.Executable() != r.authority.CanonicalPath() || len(arguments) < 17 ||
		arguments[0] != "--host" || arguments[1] != r.endpoint ||
		!slices.Contains(arguments, "run") || !slices.Contains(arguments, "--rm") ||
		!slices.Contains(arguments, "--no-deps") || !slices.Contains(arguments, "network-isolation") ||
		!strings.Contains(configuration, r.probeImage) ||
		!strings.Contains(configuration, `"network_mode":"none"`) ||
		!strings.Contains(configuration, `"pull_policy":"never"`) ||
		!strings.Contains(configuration, `"read_only":true`) ||
		!strings.Contains(configuration, "com.agentmemory.runtime-probe") {
		return argvprocess.Result{}, ErrProbeFailed
	}
	r.sawRun = true
	return argvprocess.Result{ExitCode: 0, StandardOutput: []byte("ok\n")}, nil
}

func newCapabilityRunner(
	t *testing.T,
	authority runtimeport.LinuxAuthority,
	port uint16,
) *capabilityRunner {
	t.Helper()
	base := newDockerScriptRunner(t, authority, argvprocess.ExecutableRoleDockerCLI)
	return &capabilityRunner{
		authority: base.authority, probeImage: authority.ProbeImage(), port: port, imageAuthentic: true,
	}
}

func (r *capabilityRunner) ExecutableAuthority() argvprocess.ExecutableAuthority { return r.authority }

func (r *capabilityRunner) Run(_ context.Context, invocation argvprocess.Invocation) (argvprocess.Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	arguments := invocation.Arguments()
	r.invocations = append(r.invocations, slices.Clone(arguments))
	operation := arguments[2:]
	if !r.failed && r.failToken != "" && slices.Contains(operation, r.failToken) {
		r.failed = true
		switch r.failMode {
		case "error":
			return argvprocess.Result{}, errors.New("injected runner failure")
		case "exit":
			return argvprocess.Result{ExitCode: 2}, nil
		case "truncated":
			return argvprocess.Result{OutputTruncated: true}, nil
		}
	}
	output := ""
	switch {
	case len(operation) >= 2 && operation[0] == "image" && operation[1] == "inspect":
		if r.imageOutput != "" {
			output = r.imageOutput
			break
		}
		reference := r.probeImage
		if !r.imageAuthentic {
			reference = "docker.io/attacker/probe@sha256:" + strings.Repeat("0", 64)
		}
		output = `{"Id":"sha256:` + strings.Repeat("1", 64) + `","RepoDigests":["` + reference + `"]}`
	case len(operation) >= 2 && operation[0] == "container" && operation[1] == "ls":
		if slices.Contains(operation, "--filter") {
			output = line(r.container)
		} else {
			output = lines(r.workloads)
		}
	case len(operation) >= 2 && operation[0] == "network" && operation[1] == "ls":
		output = line(r.network)
	case len(operation) >= 2 && operation[0] == "volume" && operation[1] == "ls":
		output = line(r.volume)
	case len(operation) >= 2 && operation[0] == "network" && operation[1] == "create":
		r.network = operation[len(operation)-1]
		output = strings.Repeat("b", 64) + "\n"
	case len(operation) >= 2 && operation[0] == "volume" && operation[1] == "create":
		r.volume = valueAfter(operation, "--name")
		output = r.volume + "\n"
	case len(operation) > 0 && operation[0] == "run" && slices.Contains(operation, "--detach"):
		r.container = valueAfter(operation, "--name")
		r.sawPublish = true
		output = strings.Repeat("c", 64) + "\n"
	case len(operation) > 0 && operation[0] == "run":
		if slices.ContainsFunc(operation, func(value string) bool { return strings.HasPrefix(value, "type=bind,") }) {
			r.sawBind = true
		}
		if slices.Contains(operation, "network-isolation") {
			r.sawNetwork = true
		}
		if slices.Contains(operation, "volume-write") || slices.Contains(operation, "volume-read") {
			r.volumeRuns++
		}
		output = "ok\n"
	case slices.Equal(operation[:min(2, len(operation))], []string{"container", "port"}):
		output = "127.0.0.1:" + strconv.FormatUint(uint64(r.port), 10) + "\n"
	case slices.Equal(operation[:min(2, len(operation))], []string{"container", "stop"}):
		output = r.container + "\n"
	case slices.Equal(operation[:min(2, len(operation))], []string{"container", "rm"}):
		output, r.container = r.container+"\n", ""
	case slices.Equal(operation[:min(2, len(operation))], []string{"network", "rm"}):
		output, r.network = r.network+"\n", ""
	case slices.Equal(operation[:min(2, len(operation))], []string{"volume", "rm"}):
		output, r.volume = r.volume+"\n", ""
	default:
		return argvprocess.Result{}, ErrProbeFailed
	}
	return argvprocess.Result{ExitCode: 0, StandardOutput: []byte(output)}, nil
}

func valueAfter(values []string, wanted string) string {
	for index := 0; index+1 < len(values); index++ {
		if values[index] == wanted {
			return values[index+1]
		}
	}
	return ""
}

func line(value string) string {
	if value == "" {
		return ""
	}
	return value + "\n"
}

func lines(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return strings.Join(values, "\n") + "\n"
}
