package dockercli

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
)

func TestPF001DockerProbeUsesExactEndpointAndClosedArgv(t *testing.T) {
	t.Parallel()

	runner := &recordingRunner{results: []argvprocess.Result{
		{StandardOutput: []byte(`{"ClientVersion":"27.5.1","ServerVersion":"27.5.1","APIVersion":"1.47"}`)},
		{StandardOutput: []byte(`{"OperatingSystem":"Docker Desktop","Architecture":"aarch64","OSType":"linux","SecurityOptions":["name=seccomp"],"NCPU":8,"MemTotal":25769803776}`)},
		{StandardOutput: []byte("v2.32.4\n")},
	}}
	probe, err := NewProbe(testExecutors(t, runner, runner))
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := containerengine.NewEndpoint("unix:///Users/local/.docker/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	result, err := probe.Probe(context.Background(), endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if result.ServerVersion != "27.5.1" || result.ComposeVersion != "v2.32.4" || result.OSType != "linux" ||
		result.Architecture != "arm64" {
		t.Fatalf("probe result = %+v", result)
	}
	want := [][]string{
		{"--host", endpoint.String(), "version", "--format", `{"ClientVersion":{{json .Client.Version}},"ServerVersion":{{json .Server.Version}},"APIVersion":{{json .Server.APIVersion}}}`},
		{"--host", endpoint.String(), "info", "--format", `{"OperatingSystem":{{json .OperatingSystem}},"Architecture":{{json .Architecture}},"OSType":{{json .OSType}},"SecurityOptions":{{json .SecurityOptions}},"NCPU":{{json .NCPU}},"MemTotal":{{json .MemTotal}}}`},
		{"--host", endpoint.String(), "version", "--short"},
	}
	if !reflect.DeepEqual(runner.arguments, want) {
		t.Fatalf("argv = %#v, want %#v", runner.arguments, want)
	}
}

func TestPF001DockerProbeFailsClosedOnMalformedIncompleteOrExtraJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		version string
		info    string
		compose string
	}{
		{name: "unknown version field", version: `{"ClientVersion":"27","ServerVersion":"27","APIVersion":"1","secret":"x"}`, info: validInfo(), compose: validCompose()},
		{name: "Windows containers", version: validVersion(), info: `{"OperatingSystem":"Windows","Architecture":"amd64","OSType":"windows","SecurityOptions":[],"NCPU":8,"MemTotal":25769803776}`, compose: validCompose()},
		{name: "unsupported architecture", version: validVersion(), info: `{"OperatingSystem":"Docker","Architecture":"riscv64","OSType":"linux","SecurityOptions":[],"NCPU":8,"MemTotal":25769803776}`, compose: validCompose()},
		{name: "missing compose", version: validVersion(), info: validInfo(), compose: `{}`},
		{name: "trailing value", version: validVersion() + `{}`, info: validInfo(), compose: validCompose()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			runner := &recordingRunner{results: []argvprocess.Result{
				{StandardOutput: []byte(test.version)},
				{StandardOutput: []byte(test.info)},
				{StandardOutput: []byte(test.compose)},
			}}
			probe, err := NewProbe(testExecutors(t, runner, runner))
			if err != nil {
				t.Fatal(err)
			}
			endpoint, err := containerengine.NewEndpoint("unix:///run/user/1000/docker.sock")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := probe.Probe(context.Background(), endpoint); err == nil {
				t.Fatal("invalid Docker response was accepted")
			}
		})
	}
}

func TestPF001DockerProbePropagatesCancellationWithoutContinuing(t *testing.T) {
	t.Parallel()

	runner := &recordingRunner{runError: context.Canceled}
	probe, err := NewProbe(testExecutors(t, runner, runner))
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := containerengine.NewEndpoint("unix:///var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probe.Probe(context.Background(), endpoint); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	if len(runner.arguments) != 1 {
		t.Fatalf("calls after cancellation = %d", len(runner.arguments))
	}
}

func TestPF001DockerProbeRequiresDependencies(t *testing.T) {
	t.Parallel()

	if _, err := NewProbe(Executors{}); err == nil {
		t.Fatal("missing signed executors accepted")
	}
}

func TestPF001DockerProbeRejectsEveryBoundedProcessFailure(t *testing.T) {
	t.Parallel()

	endpoint, err := containerengine.NewEndpoint("unix:///var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		endpoint containerengine.Endpoint
		result   argvprocess.Result
	}{
		{name: "empty endpoint"},
		{name: "nonzero exit", endpoint: endpoint, result: argvprocess.Result{ExitCode: 1, StandardOutput: []byte("x")}},
		{name: "truncated", endpoint: endpoint, result: argvprocess.Result{OutputTruncated: true, StandardOutput: []byte("x")}},
		{name: "empty output", endpoint: endpoint},
		{name: "oversized output", endpoint: endpoint, result: argvprocess.Result{StandardOutput: []byte(strings.Repeat("x", maximumDockerJSON+1))}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runner := &recordingRunner{results: []argvprocess.Result{test.result}}
			probe, err := NewProbe(testExecutors(t, runner, runner))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := probe.Probe(context.Background(), test.endpoint); err == nil {
				t.Fatal("invalid bounded process result was accepted")
			}
		})
	}

	for _, value := range []string{"", strings.Repeat("1", 129), "v2.3/unsafe"} {
		if validVersionString(value) {
			t.Fatalf("invalid version %q was accepted", value)
		}
	}
}

func TestPF001DockerProbeStopsAtInfoAndComposeFailures(t *testing.T) {
	t.Parallel()

	endpoint, _ := containerengine.NewEndpoint("unix:///var/run/docker.sock")
	tests := []struct {
		name    string
		results []argvprocess.Result
		calls   int
	}{
		{name: "info command", results: []argvprocess.Result{{StandardOutput: []byte(validVersion())}, {ExitCode: 1, StandardOutput: []byte("x")}}, calls: 2},
		{name: "compose command", results: []argvprocess.Result{{StandardOutput: []byte(validVersion())}, {StandardOutput: []byte(validInfo())}, {ExitCode: 1, StandardOutput: []byte("x")}}, calls: 3},
		{name: "malformed info", results: []argvprocess.Result{{StandardOutput: []byte(validVersion())}, {StandardOutput: []byte(`{"OperatingSystem":`)}, {StandardOutput: []byte(validCompose())}}, calls: 3},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runner := &recordingRunner{results: append([]argvprocess.Result(nil), test.results...)}
			probe, _ := NewProbe(testExecutors(t, runner, runner))
			if _, err := probe.Probe(context.Background(), endpoint); err == nil || len(runner.arguments) != test.calls {
				t.Fatalf("Probe() error=%v calls=%d", err, len(runner.arguments))
			}
		})
	}
}

type recordingRunner struct {
	arguments [][]string
	results   []argvprocess.Result
	runError  error
}

func (r *recordingRunner) Run(_ context.Context, invocation argvprocess.Invocation) (argvprocess.Result, error) {
	r.arguments = append(r.arguments, invocation.Arguments())
	if r.runError != nil {
		return argvprocess.Result{}, r.runError
	}
	if len(r.results) == 0 {
		return argvprocess.Result{}, errors.New("unexpected invocation")
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result, nil
}

func validVersion() string {
	return `{"ClientVersion":"27","ServerVersion":"27","APIVersion":"1"}`
}

func validInfo() string {
	return `{"OperatingSystem":"Docker","Architecture":"amd64","OSType":"linux","SecurityOptions":[],"NCPU":8,"MemTotal":25769803776}`
}

func validCompose() string { return "v2.32.4\n" }
