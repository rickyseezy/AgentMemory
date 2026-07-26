package dockercli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/provideradapterapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/provideradapter"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/providerprotocol"
)

func TestPRO002ProviderRuntimeUsesOnlyClosedComposeTemplateAndExactCommands(t *testing.T) {
	t.Parallel()
	plan := providerAdapterPlan(t)
	runner := &providerComposeRunner{}
	endpoint, _ := containerengine.NewEndpoint("unix:///run/user/1000/docker.sock")
	runtimeAdapter, err := NewProviderAdapterRuntime(testExecutorsForCompose(t, runner), endpoint)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := runtimeAdapter.Start(context.Background(), plan)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if handle.InstanceID() != plan.ServiceName() || len(runner.invocations) != 2 {
		t.Fatalf("handle/invocations = %#v/%d", handle, len(runner.invocations))
	}
	for _, invocation := range runner.invocations {
		arguments := invocation.Arguments()
		if invocation.Executable() != testPlatformToolPath("/verified/docker-compose") || !slices.Contains(arguments, "--file") ||
			!slices.Contains(arguments, "-") || slices.Contains(arguments, "--privileged") || slices.Contains(arguments, "--build") {
			t.Fatalf("unsafe invocation: %v", arguments)
		}
		assertClosedProviderCompose(t, invocation.StandardInput(), plan)
	}
	if err := runtimeAdapter.Stop(context.Background(), handle); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if len(runner.invocations) != 3 || !slices.Contains(runner.invocations[2].Arguments(), "rm") ||
		!slices.Contains(runner.invocations[2].Arguments(), "--force") {
		t.Fatalf("unsafe cleanup: %v", runner.invocations[2].Arguments())
	}
	if err := runtimeAdapter.Stop(context.Background(), handle); !errors.Is(err, provideradapterapp.ErrRuntime) {
		t.Fatalf("replayed stop = %v", err)
	}
}

func TestPRO002ProviderRuntimeReturnsCleanupAuthorityAfterPartialComposeFailure(t *testing.T) {
	t.Parallel()
	plan := providerAdapterPlan(t)
	runner := &providerComposeRunner{failAt: 2}
	endpoint, _ := containerengine.NewEndpoint("unix:///run/user/1000/docker.sock")
	runtimeAdapter, _ := NewProviderAdapterRuntime(testExecutorsForCompose(t, runner), endpoint)
	handle, err := runtimeAdapter.Start(context.Background(), plan)
	if err == nil || !handle.Valid() {
		t.Fatalf("partial failure lost cleanup handle: %#v %v", handle, err)
	}
	runner.failAt = 0
	if err := runtimeAdapter.Stop(context.Background(), handle); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}

func TestPRO002ClosedComposeRendererRejectsZeroPlan(t *testing.T) {
	t.Parallel()
	if _, err := renderProviderAdapterCompose(provideradapter.DeploymentPlan{}); !errors.Is(err, provideradapter.ErrInvalidDeployment) {
		t.Fatalf("zero plan = %v", err)
	}
}

func TestPRO009GatewayCapabilityExistsOnlyInsideAnOperationScopedContainer(t *testing.T) {
	t.Parallel()
	plan := providerAdapterPlanFor(t, true)
	raw, err := renderProviderAdapterCompose(plan)
	if err != nil {
		t.Fatal(err)
	}
	var document providerComposeDocument
	if json.Unmarshal(raw, &document) != nil {
		t.Fatal("invalid rendered JSON")
	}
	service := document.Services[plan.ServiceName()]
	if len(document.Volumes) != 0 || len(service.Volumes) != 0 {
		t.Fatalf("persistent runtime received operation authority: %#v", document)
	}
	operationRaw, err := renderProviderAdapterComposeFor(
		plan,
		"amop_123456789012_1234567890123456789",
		"adapter_12345678901234567890",
		strings.Repeat("a", 64),
	)
	if err != nil || json.Unmarshal(operationRaw, &document) != nil {
		t.Fatal("invalid operation-scoped Compose JSON")
	}
	service = document.Services["adapter_12345678901234567890"]
	if len(document.Volumes) != 1 || len(service.Volumes) != 1 ||
		document.Volumes["provider_gateway_capability"].Name != plan.CapabilitySecret() ||
		!document.Volumes["provider_gateway_capability"].External ||
		service.Volumes[0] != (providerServiceVolume{
			Type: "volume", Source: "provider_gateway_capability",
			Target: "/run/provider-gateway", ReadOnly: true,
		}) {
		t.Fatalf("operation gateway capability escaped closed mount: %#v", document)
	}
}

func TestPRO002RuntimeContainsCrashHangOOMAndPIDExhaustion(t *testing.T) {
	t.Parallel()
	plan := providerAdapterPlan(t)
	endpoint, _ := containerengine.NewEndpoint("unix:///run/user/1000/docker.sock")
	for _, mode := range []string{"crash", "hang", "oom", "pid"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			runner := &providerChaosRunner{mode: mode}
			runtimeAdapter, _ := NewProviderAdapterRuntime(testExecutorsForCompose(t, runner), endpoint)
			started := time.Now()
			handle, err := runtimeAdapter.Start(context.Background(), plan)
			if err == nil || !handle.Valid() {
				t.Fatalf("%s escaped containment: %#v %v", mode, handle, err)
			}
			if time.Since(started) > time.Second {
				t.Fatalf("%s exceeded bounded failure time", mode)
			}
			runner.mode = ""
			if err := runtimeAdapter.Stop(context.Background(), handle); err != nil {
				t.Fatalf("%s cleanup: %v", mode, err)
			}
		})
	}
}

func TestPRO009OperationSupervisorRunsOneClosedContainerAndAlwaysCleansIt(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil { //nolint:gosec // Private directories require execute permission.
		t.Fatal(err)
	}
	request, response := providerOperationFrames(t, "operation-pro009")
	runner := &providerOperationRunner{response: response}
	endpoint, _ := containerengine.NewEndpoint("unix:///run/user/1000/docker.sock")
	supervisor, err := NewProviderAdapterOperationSupervisor(
		testExecutorsForCompose(t, runner), endpoint, directory,
	)
	if err != nil {
		t.Fatal(err)
	}
	actualResponse, err := supervisor.Execute(
		context.Background(), providerAdapterPlanFor(t, true), "operation-pro009", request,
	)
	if err != nil || !bytes.Equal(actualResponse, runner.response) {
		t.Fatalf("Execute()=%x/%v", actualResponse, err)
	}
	if len(runner.invocations) != 3 ||
		!slices.Contains(runner.invocations[0].Arguments(), "config") ||
		!slices.Contains(runner.invocations[1].Arguments(), "run") ||
		!slices.Contains(runner.invocations[1].Arguments(), "--rm") ||
		!slices.Contains(runner.invocations[1].Arguments(), "--no-deps") ||
		!slices.Contains(runner.invocations[2].Arguments(), "down") ||
		!slices.Contains(runner.invocations[2].Arguments(), "--remove-orphans") {
		t.Fatalf("operation lifecycle = %#v", runner.invocations)
	}
	if !bytes.Equal(runner.request, request) {
		t.Fatalf("operation input changed: %x", runner.request)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("operation configuration leaked: %#v/%v", entries, err)
	}
	assertOperationCompose(t, runner.configuration)
}

func TestPRO009OperationSupervisorRejectsUnsafeRuntimeAndBoundsOutput(t *testing.T) {
	t.Parallel()
	endpoint, _ := containerengine.NewEndpoint("unix:///run/user/1000/docker.sock")
	directory := t.TempDir()
	if runtime.GOOS != "windows" {
		if err := os.Chmod(directory, 0o755); err != nil { //nolint:gosec // Adversarial test deliberately creates an unsafe directory.
			t.Fatal(err)
		}
		if supervisor, err := NewProviderAdapterOperationSupervisor(
			testExecutorsForCompose(t, &providerOperationRunner{}), endpoint, directory,
		); err == nil || supervisor != nil {
			t.Fatalf("unsafe directory accepted: %#v/%v", supervisor, err)
		}
	}
	if err := os.Chmod(directory, 0o700); err != nil { //nolint:gosec // Private directories require execute permission.
		t.Fatal(err)
	}
	request, _ := providerOperationFrames(t, "operation-pro009")
	runner := &providerOperationRunner{
		response: bytes.Repeat([]byte("x"), maximumProviderOperationFrameBytes+1),
	}
	supervisor, err := NewProviderAdapterOperationSupervisor(
		testExecutorsForCompose(t, runner), endpoint, directory,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := supervisor.Execute(
		context.Background(), providerAdapterPlan(t), "operation-pro009",
		request,
	); err == nil || result != nil {
		t.Fatalf("oversized output accepted: %d/%v", len(result), err)
	}
}

func TestPRO009OperationSupervisorRejectsUnboundOrMalformedFramesBeforeEscape(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil { //nolint:gosec // Private directories require execute permission.
		t.Fatal(err)
	}
	endpoint, _ := containerengine.NewEndpoint("unix:///run/user/1000/docker.sock")
	request, response := providerOperationFrames(t, "operation-pro009")
	cases := []struct {
		name      string
		operation string
		request   []byte
		response  []byte
		runs      int
	}{
		{name: "malformed request", operation: "operation-pro009", request: []byte{0, 0, 0, 2, '{', '}'}, response: response},
		{name: "unbound request", operation: "different-operation", request: request, response: response},
		{name: "malformed response", operation: "operation-pro009", request: request, response: []byte{0, 0, 0, 2, '{', '}'}, runs: 3},
		{name: "unbound response", operation: "operation-pro009", request: request, response: providerOperationResponse(t, "different-operation"), runs: 3},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			runner := &providerOperationRunner{response: testCase.response}
			supervisor, err := NewProviderAdapterOperationSupervisor(
				testExecutorsForCompose(t, runner), endpoint, directory,
			)
			if err != nil {
				t.Fatal(err)
			}
			actual, executeErr := supervisor.Execute(
				context.Background(), providerAdapterPlanFor(t, true),
				testCase.operation, testCase.request,
			)
			if executeErr == nil || actual != nil {
				t.Fatalf("unsafe frame accepted: %x/%v", actual, executeErr)
			}
			if len(runner.invocations) != testCase.runs {
				t.Fatalf("container escape count=%d, want %d", len(runner.invocations), testCase.runs)
			}
		})
	}
}

func TestPRO009OperationSupervisorReconcilesOnlyExactAuthorizedPlanOrphans(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil { //nolint:gosec // Private directories require execute permission.
		t.Fatal(err)
	}
	plan := providerAdapterPlanFor(t, true)
	containerID := bytes.Repeat([]byte("a"), 64)
	docker := &providerOrphanRunner{
		containerID: string(containerID),
		labels: map[string]string{
			providerManagedLabel:         "true",
			providerKindLabel:            providerAdapterKind,
			providerPlanDigestLabel:      plan.Digest().Hex(),
			providerOperationDigestLabel: string(bytes.Repeat([]byte("b"), 64)),
			"com.docker.compose.project": "ambient-compose-metadata",
		},
	}
	endpoint, _ := containerengine.NewEndpoint("unix:///run/user/1000/docker.sock")
	supervisor, err := NewProviderAdapterOperationSupervisor(
		testExecutors(t, docker, &providerOperationRunner{}), endpoint, directory,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Reconcile(context.Background(), []provideradapter.DeploymentPlan{plan}); err != nil {
		t.Fatalf("Reconcile()=%v", err)
	}
	if !docker.removed || len(docker.invocations) != 4 {
		t.Fatalf("orphan lifecycle=%#v removed=%t", docker.invocations, docker.removed)
	}
	for _, invocation := range docker.invocations {
		if invocation.Executable() != testPlatformToolPath("/verified/docker") ||
			slices.Contains(invocation.Arguments(), plan.Image()) {
			t.Fatalf("unsafe orphan command: %#v", invocation.Arguments())
		}
	}
	if arguments := docker.invocations[2].Arguments(); !slices.Equal(
		arguments[len(arguments)-4:],
		[]string{"rm", "--force", "--", docker.containerID},
	) {
		t.Fatalf("remove did not bind exact ID: %v", arguments)
	}
}

func TestPRO009OperationSupervisorRejectsOrphanOwnershipDriftBeforeRemoval(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil { //nolint:gosec // Private directories require execute permission.
		t.Fatal(err)
	}
	plan := providerAdapterPlanFor(t, true)
	docker := &providerOrphanRunner{
		containerID: string(bytes.Repeat([]byte("a"), 64)),
		labels: map[string]string{
			providerManagedLabel:         "true",
			providerKindLabel:            providerAdapterKind,
			providerPlanDigestLabel:      string(bytes.Repeat([]byte("c"), 64)),
			providerOperationDigestLabel: string(bytes.Repeat([]byte("b"), 64)),
		},
	}
	endpoint, _ := containerengine.NewEndpoint("unix:///run/user/1000/docker.sock")
	supervisor, err := NewProviderAdapterOperationSupervisor(
		testExecutors(t, docker, &providerOperationRunner{}), endpoint, directory,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Reconcile(
		context.Background(), []provideradapter.DeploymentPlan{plan},
	); !errors.Is(err, provideradapterapp.ErrRuntime) || docker.removed {
		t.Fatalf("ownership drift=%v removed=%t", err, docker.removed)
	}
	if len(docker.invocations) != 2 {
		t.Fatalf("unsafe removal attempted: %#v", docker.invocations)
	}
}

type providerComposeRunner struct {
	invocations []argvprocess.Invocation
	failAt      int
}

func (r *providerComposeRunner) Run(_ context.Context, invocation argvprocess.Invocation) (argvprocess.Result, error) {
	r.invocations = append(r.invocations, invocation)
	if r.failAt == len(r.invocations) {
		return argvprocess.Result{ExitCode: 1}, nil
	}
	return argvprocess.Result{StandardOutput: []byte("{}")}, nil
}

type providerChaosRunner struct {
	calls int
	mode  string
}

type providerOperationRunner struct {
	invocations   []argvprocess.Invocation
	configuration []byte
	request       []byte
	response      []byte
}

type providerOrphanRunner struct {
	invocations []argvprocess.Invocation
	containerID string
	labels      map[string]string
	removed     bool
}

func (r *providerOrphanRunner) Run(
	_ context.Context,
	invocation argvprocess.Invocation,
) (argvprocess.Result, error) {
	r.invocations = append(r.invocations, invocation)
	arguments := invocation.Arguments()
	switch {
	case slices.Contains(arguments, "ls"):
		if r.removed {
			return argvprocess.Result{}, nil
		}
		return argvprocess.Result{StandardOutput: []byte(r.containerID + "\n")}, nil
	case slices.Contains(arguments, "inspect"):
		document, err := json.Marshal(providerOrphanDocument{
			ID: r.containerID, Labels: r.labels,
		})
		if err != nil {
			return argvprocess.Result{}, err
		}
		return argvprocess.Result{StandardOutput: document}, nil
	case slices.Contains(arguments, "rm"):
		r.removed = true
		return argvprocess.Result{StandardOutput: []byte(r.containerID + "\n")}, nil
	default:
		return argvprocess.Result{ExitCode: 1}, nil
	}
}

func (r *providerOperationRunner) Run(
	_ context.Context,
	invocation argvprocess.Invocation,
) (argvprocess.Result, error) {
	r.invocations = append(r.invocations, invocation)
	arguments := invocation.Arguments()
	if slices.Contains(arguments, "config") {
		index := slices.Index(arguments, "--file")
		if index < 0 || index+1 >= len(arguments) {
			return argvprocess.Result{ExitCode: 1}, nil
		}
		value, err := os.ReadFile(filepath.Clean(arguments[index+1]))
		if err != nil {
			return argvprocess.Result{}, err
		}
		r.configuration = value
		return argvprocess.Result{StandardOutput: []byte("{}")}, nil
	}
	return argvprocess.Result{}, nil
}

func (r *providerOperationRunner) RunStreaming(
	ctx context.Context,
	invocation argvprocess.Invocation,
	streams argvprocess.Streams,
) error {
	delayed := ctx.Err()
	if delayed != nil {
		return delayed
	}
	r.invocations = append(r.invocations, invocation)
	request, err := io.ReadAll(streams.Input())
	if err != nil {
		return err
	}
	r.request = request
	_, err = streams.Output().Write(r.response)
	return err
}

func (r *providerChaosRunner) Run(ctx context.Context, _ argvprocess.Invocation) (argvprocess.Result, error) {
	r.calls++
	if r.calls != 2 || r.mode == "" {
		return argvprocess.Result{StandardOutput: []byte("{}")}, nil
	}
	switch r.mode {
	case "crash":
		return argvprocess.Result{}, errors.New("container process crashed")
	case "hang":
		<-ctx.Done()
		return argvprocess.Result{}, ctx.Err()
	case "oom":
		return argvprocess.Result{ExitCode: 137}, nil
	case "pid":
		return argvprocess.Result{ExitCode: 1, StandardError: []byte("pids limit")}, nil
	default:
		return argvprocess.Result{}, errors.New("unknown chaos mode")
	}
}

func providerAdapterPlan(t testing.TB) provideradapter.DeploymentPlan {
	return providerAdapterPlanFor(t, false)
}

func providerAdapterPlanFor(t testing.TB, gateway bool) provideradapter.DeploymentPlan {
	t.Helper()
	digest := func(value string) provideradapter.Digest { return provideradapter.DigestBytes([]byte(value)) }
	image := digest("go-reference-image")
	manifest, err := provideradapter.NewManifest(provideradapter.ManifestInput{
		AdapterID: "go-reference", Image: "registry.example/custom/go@sha256:" + image.Hex(), ImageDigest: image,
		Protocol: provideradapter.ProtocolRangeInput{Minimum: 1, Maximum: 1}, Transport: provideradapter.TransportFramedStdio,
		Operations: []provideradapter.Operation{provideradapter.OperationGetManifest, provideradapter.OperationValidateConfiguration,
			provideradapter.OperationProbe, provideradapter.OperationHealth, provideradapter.OperationEmbedDocuments,
			provideradapter.OperationCancel, provideradapter.OperationShutdown},
		Permissions: provideradapter.PermissionInput{GatewayAccess: gateway},
		Limits:      provideradapter.LimitInput{CPUsMilli: 250, MemoryBytes: 134217728, PIDs: 32, TimeoutMilliseconds: 100, ScratchBytes: 16777216},
		Evidence:    provideradapter.EvidenceInput{SignatureBundle: digest("signature"), CycloneDXSBOM: digest("cdx"), SPDXSBOM: digest("spdx"), Provenance: digest("provenance"), License: digest("license"), Vulnerability: digest("vulnerability")},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := manifest.DeploymentPlan("018f0000-0000-7000-8000-000000000711")
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func providerOperationFrames(t testing.TB, operationID string) ([]byte, []byte) {
	t.Helper()
	request := providerprotocol.Request{
		JSONRPC: "2.0", ID: operationID, Method: providerprotocol.MethodEmbedDocuments,
		Params: providerprotocol.RequestParameters{
			ProtocolVersion: 1, OperationID: operationID,
			ProfileID:  "018f0000-0000-7000-8000-000000000711",
			Purpose:    providerprotocol.PurposeRetrievalDocument,
			ContentIDs: []string{"content-1"}, Classification: providerprotocol.ClassificationInternal,
			DeadlineUnixMicros: 1784707230000000, IdempotencyKey: operationID,
			TraceParent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
			Payload:     []byte(`{"texts":["alpha"]}`),
		},
	}
	framedRequest, err := providerprotocol.EncodeRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	return framedRequest, providerOperationResponse(t, operationID)
}

func providerOperationResponse(t testing.TB, operationID string) []byte {
	t.Helper()
	response := providerprotocol.Response{
		JSONRPC: "2.0", ID: operationID,
		Result: &providerprotocol.ResponseResult{
			OperationID: operationID, ContentIDs: []string{"content-1"},
			Items:      []providerprotocol.ItemResult{{ContentID: "content-1", Vector: []float32{1, 2}}},
			Dimensions: 2, ModelRevision: "model-revision-1",
		},
	}
	framed, err := providerprotocol.EncodeResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	return framed
}

func assertClosedProviderCompose(t testing.TB, raw []byte, plan provideradapter.DeploymentPlan) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document providerComposeDocument
	if err := decoder.Decode(&document); err != nil {
		t.Fatalf("compose: %v", err)
	}
	service := document.Services[plan.ServiceName()]
	if document.Name != plan.ProjectName() || len(document.Services) != 1 || len(document.Networks) != 1 ||
		service.Image != plan.Image() || !service.ReadOnly || service.User != "65532:65532" ||
		!slices.Equal(service.CapDrop, []string{"ALL"}) || !slices.Equal(service.SecurityOpt, []string{"no-new-privileges:true"}) ||
		len(service.Networks) != 1 || service.Networks[0] != "am_internal" || len(service.Tmpfs) != 1 ||
		document.Networks["am_internal"].Name != plan.ExternalNetwork() || !document.Networks["am_internal"].External {
		t.Fatalf("compose escaped policy: %#v", document)
	}
	for _, forbidden := range []string{"volumes", "ports", "privileged", "network_mode", "docker.sock", "environment", "build"} {
		if bytes.Contains(raw, []byte(`"`+forbidden+`"`)) {
			t.Fatalf("forbidden Compose key %q: %s", forbidden, raw)
		}
	}
}

func assertOperationCompose(t testing.TB, raw []byte) {
	t.Helper()
	var document providerComposeDocument
	if json.Unmarshal(raw, &document) != nil || len(document.Services) != 1 ||
		len(document.Networks) != 1 || len(document.Volumes) != 1 {
		t.Fatalf("operation Compose invalid: %s", raw)
	}
	for _, service := range document.Services {
		if !service.ReadOnly || service.User != "65532:65532" ||
			!slices.Equal(service.CapDrop, []string{"ALL"}) ||
			len(service.Networks) != 1 || len(service.Tmpfs) != 1 ||
			len(service.Volumes) != 1 ||
			service.Volumes[0].Type != "volume" ||
			service.Volumes[0].Target != "/run/provider-gateway" ||
			!service.Volumes[0].ReadOnly {
			t.Fatalf("operation escaped sandbox: %#v", service)
		}
	}
	for _, forbidden := range []string{
		"ports", "privileged", "docker.sock", "environment", "build", "bind",
	} {
		if bytes.Contains(raw, []byte(`"`+forbidden+`"`)) {
			t.Fatalf("forbidden operation key %q: %s", forbidden, raw)
		}
	}
}
