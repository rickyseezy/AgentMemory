package dockercli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/provideradapterapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/provideradapter"
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

func TestPRO002GatewayAccessMountsOnlyInstallationScopedCapability(t *testing.T) {
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
	if len(document.Secrets) != 1 || len(service.Secrets) != 1 || service.Secrets[0].Mode != 0o400 ||
		document.Secrets["provider_gateway_capability"].Name != plan.CapabilitySecret() {
		t.Fatalf("gateway capability escaped closed mount: %#v", document)
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
