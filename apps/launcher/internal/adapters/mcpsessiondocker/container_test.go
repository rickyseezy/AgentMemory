package mcpsessiondocker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpsessionapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/mcpsession"
)

const testContainerID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

func TestPF005ContainerCreatesInspectsThenStartsWithExactHardenedArgv(t *testing.T) {
	t.Parallel()
	plan := dockerPlan(t, "/Users/ricky/Project [α];$(false)")
	process := &processPort{}
	process.captureResults = [][]byte{[]byte(testContainerID + "\n"), inspectDocument(t, plan)}
	container, err := NewContainer(process)
	if err != nil {
		t.Fatalf("NewContainer() error = %v", err)
	}
	var output, diagnostics bytes.Buffer

	err = container.Run(context.Background(), plan, mcpsessionapp.Streams{
		Input: strings.NewReader("request\n"), Output: &output, Diagnostics: &diagnostics,
	})

	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(process.captureArguments) != 2 || len(process.streamArguments) != 1 {
		t.Fatalf("process calls capture=%d stream=%d", len(process.captureArguments), len(process.streamArguments))
	}
	create := process.captureArguments[0]
	wantPrefix := []string{
		"--host", plan.RuntimeEndpoint(), "container", "create", "--name", containerName(plan),
		"--rm", "--pull", "never", "--interactive", "--attach", "stdin", "--attach", "stdout",
		"--attach", "stderr", "--init", "--read-only", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges:true", "--pids-limit", "128", "--memory", "536870912",
		"--memory-swap", "536870912", "--cpus", "1.000", "--network", plan.Network(),
	}
	if !slices.Equal(create[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("create prefix = %#v", create)
	}
	workspaceMount := "type=bind,source=" + plan.WorkspaceMount().Source() +
		",target=/workspace,readonly,bind-propagation=rprivate,bind-recursive=readonly"
	credentialMount := "type=bind,source=" + plan.CredentialMount().Source() +
		",target=/run/secrets/agentmemory-session,readonly,bind-propagation=rprivate"
	for _, required := range []string{
		"--log-driver", "none", "--user", "10001:10001", "--workdir", "/workspace",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=67108864,mode=0700,uid=10001,gid=10001",
		workspaceMount, credentialMount, plan.Image(),
		"--session-id", plan.SessionID(),
	} {
		if !slices.Contains(create, required) {
			t.Fatalf("create argv missing %q: %#v", required, create)
		}
	}
	for _, forbidden := range []string{"--privileged", "--tty", "-t", "--publish", "-p", "/var/run/docker.sock"} {
		if slices.Contains(create, forbidden) {
			t.Fatalf("create argv contains forbidden %q: %#v", forbidden, create)
		}
	}
	wantInspect := []string{
		"--host", plan.RuntimeEndpoint(), "container", "inspect", "--type", "container", containerName(plan),
	}
	if !reflect.DeepEqual(process.captureArguments[1], wantInspect) {
		t.Fatalf("inspect argv = %#v", process.captureArguments[1])
	}
	wantStart := []string{
		"--host", plan.RuntimeEndpoint(), "container", "start", "--attach", "--interactive", containerName(plan),
	}
	if !reflect.DeepEqual(process.streamArguments[0], wantStart) {
		t.Fatalf("start argv = %#v", process.streamArguments[0])
	}
	if process.streams.Output != &output || process.streams.Diagnostics != &diagnostics {
		t.Fatal("MCP and diagnostic streams were substituted")
	}
}

func TestPF005ContainerRejectsInspectSubstitutionBeforeStarting(t *testing.T) {
	t.Parallel()
	plan := dockerPlan(t, "/workspace")
	document := inspectDocument(t, plan)
	var decoded []map[string]any
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	decoded[0]["HostConfig"].(map[string]any)["Privileged"] = true
	tampered, _ := json.Marshal(decoded)
	process := &processPort{captureResults: [][]byte{[]byte(testContainerID + "\n"), tampered}}
	container, _ := NewContainer(process)

	if err := container.Run(context.Background(), plan, validStreams()); err == nil {
		t.Fatal("Run(tampered inspect) error = nil")
	}
	if len(process.streamArguments) != 0 {
		t.Fatal("tampered container was started")
	}
}

func TestPF005ContainerRemovalIsExactAndIdempotent(t *testing.T) {
	t.Parallel()
	plan := dockerPlan(t, "/workspace")
	process := &processPort{}
	container, _ := NewContainer(process)
	if err := container.Remove(context.Background(), plan); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	want := []string{
		"--host", plan.RuntimeEndpoint(), "container", "rm", "--force", "--volumes", containerName(plan),
	}
	if !reflect.DeepEqual(process.captureArguments[0], want) {
		t.Fatalf("remove argv = %#v", process.captureArguments[0])
	}
	process.captureError = ErrContainerNotFound
	if err := container.Remove(context.Background(), plan); err != nil {
		t.Fatalf("Remove(not found) error = %v", err)
	}
}

func TestPF005ContainerEncodesCommaAndQuotePathsWithoutShellInterpretation(t *testing.T) {
	t.Parallel()
	plan := dockerPlan(t, `/workspace,team/quote"folder`)
	process := &processPort{captureResults: [][]byte{[]byte(testContainerID + "\n"), inspectDocument(t, plan)}}
	container, _ := NewContainer(process)
	if err := container.Run(context.Background(), plan, validStreams()); err != nil {
		t.Fatalf("Run(comma path) error = %v", err)
	}
	want := `type=bind,"source=/workspace,team/quote""folder",target=/workspace,readonly,` +
		`bind-propagation=rprivate,bind-recursive=readonly`
	if !slices.Contains(process.captureArguments[0], want) {
		t.Fatalf("encoded mount missing %q from %#v", want, process.captureArguments[0])
	}
}

func TestPF005ContainerRejectsPartialComposition(t *testing.T) {
	t.Parallel()
	if _, err := NewContainer(nil); err == nil {
		t.Fatal("NewContainer(nil) error = nil")
	}
}

func TestPF005ContainerRefusesSharingAndRecursiveReadonlyFailuresWithoutFallback(t *testing.T) {
	t.Parallel()
	for _, failure := range []string{
		"docker desktop file sharing denied",
		"recursive read-only bind unsupported",
	} {
		failure := failure
		t.Run(failure, func(t *testing.T) {
			t.Parallel()
			plan := dockerPlan(t, "/Users/ricky/Project α")
			process := &processPort{captureError: errors.New(failure)}
			container, err := NewContainer(process)
			if err != nil {
				t.Fatal(err)
			}
			if err := container.Run(t.Context(), plan, validStreams()); err == nil {
				t.Fatal("Docker create failure was hidden")
			}
			if len(process.captureArguments) != 1 || len(process.streamArguments) != 0 {
				t.Fatalf("calls=%+v/%+v", process.captureArguments, process.streamArguments)
			}
			arguments := process.captureArguments[0]
			if !slices.Contains(arguments, mountArgument(plan.WorkspaceMount())) ||
				!strings.Contains(mountArgument(plan.WorkspaceMount()), "bind-recursive=readonly") {
				t.Fatal("secure recursive-readonly request was weakened")
			}
		})
	}
}

type processPort struct {
	captureArguments [][]string
	streamArguments  [][]string
	captureResults   [][]byte
	captureError     error
	streams          mcpsessionapp.Streams
}

func (p *processPort) Capture(_ context.Context, arguments []string) ([]byte, error) {
	p.captureArguments = append(p.captureArguments, append([]string(nil), arguments...))
	if p.captureError != nil {
		return nil, p.captureError
	}
	index := len(p.captureArguments) - 1
	if index >= len(p.captureResults) {
		return nil, nil
	}
	return append([]byte(nil), p.captureResults[index]...), nil
}

func (p *processPort) Stream(
	_ context.Context,
	arguments []string,
	streams mcpsessionapp.Streams,
) error {
	p.streamArguments = append(p.streamArguments, append([]string(nil), arguments...))
	p.streams = streams
	return nil
}

func dockerPlan(t testing.TB, workspacePath string) mcpsession.ExecutionPlan {
	t.Helper()
	workspace, err := mcpsession.NewWorkspaceIdentity(mcpsession.WorkspaceIdentityInput{
		LogicalPath: workspacePath, RealPath: workspacePath, DeviceIdentity: "dev:1",
		PathFingerprint: strings.Repeat("a", 64), GitCoverage: mcpsession.GitCoverageNone,
	})
	if err != nil {
		t.Fatalf("NewWorkspaceIdentity() error = %v", err)
	}
	issued := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	credential, err := mcpsession.NewCredentialLease(
		strings.Repeat("c", 64), "/owner/session.key", issued, issued.Add(12*time.Hour),
	)
	if err != nil {
		t.Fatalf("NewCredentialLease() error = %v", err)
	}
	plan, err := mcpsession.NewExecutionPlan(mcpsession.ExecutionPlanInput{
		SessionID: "019d2b4e-7a10-7def-8abc-0123456789ab", InstallationID: "019d2b4e-7a11-7def-8abc-0123456789ab",
		AgentID: "codex", ReleaseID: "v1.0.0", ManifestDigest: strings.Repeat("d", 64),
		SecurityEpoch: 7, RuntimeEndpoint: "unix:///var/run/docker.sock",
		Workspace: workspace,
		Image:     "registry.local/agentmemory/mcp-session@sha256:" + strings.Repeat("b", 64),
		Network:   "agentmemory_019d2b4e7a117def8abc0123456789ab_internal", Credential: credential,
	})
	if err != nil {
		t.Fatalf("NewExecutionPlan() error = %v", err)
	}
	return plan
}

func validStreams() mcpsessionapp.Streams {
	return mcpsessionapp.Streams{
		Input: strings.NewReader(""), Output: &bytes.Buffer{}, Diagnostics: &bytes.Buffer{},
	}
}

func inspectDocument(t testing.TB, plan mcpsession.ExecutionPlan) []byte {
	t.Helper()
	document := []map[string]any{{
		"Id": testContainerID, "Name": "/" + containerName(plan),
		"Config": map[string]any{
			"Image": plan.Image(), "User": "10001:10001", "WorkingDir": "/workspace",
			"Tty": false, "OpenStdin": true, "AttachStdin": true, "AttachStdout": true,
			"AttachStderr": true,
			"Labels":       expectedLabels(plan),
			"Cmd":          []string{"--session-id", plan.SessionID()},
		},
		"HostConfig": map[string]any{
			"AutoRemove": true, "ReadonlyRootfs": true, "Privileged": false,
			"CapAdd": []string{}, "CapDrop": []string{"ALL"},
			"SecurityOpt": []string{"no-new-privileges:true"}, "NetworkMode": plan.Network(),
			"PidsLimit": 128, "Memory": 536870912, "MemorySwap": 536870912,
			"NanoCpus": 1000000000, "PortBindings": map[string]any{}, "Binds": []string{},
			"Devices": []any{},
			"Tmpfs":   map[string]string{"/tmp": "rw,noexec,nosuid,nodev,size=67108864,mode=0700,uid=10001,gid=10001"},
		},
		"Mounts": []map[string]any{
			{"Type": "bind", "Source": plan.WorkspaceMount().Source(), "Destination": "/workspace", "RW": false, "Propagation": "rprivate"},
			{"Type": "bind", "Source": plan.CredentialMount().Source(), "Destination": "/run/secrets/agentmemory-session", "RW": false, "Propagation": "rprivate"},
		},
	}}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	return encoded
}
