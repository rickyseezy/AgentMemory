package dockercli

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/resourceinventory"
)

const (
	resourceInstallation = "019f5f20-1234-4abc-8123-0123456789ab"
	resourceGeneration   = "019f5f20-1234-7abc-8123-0123456789ab"
)

func TestPF001ManagedResourceInspectUsesExactAddressedArgv(t *testing.T) {
	t.Parallel()
	endpoint := resourceEndpoint(t)
	plan := resourcePlan(t)
	for _, spec := range []resourceinventory.Spec{plan[0], plan[1]} {
		spec := spec
		t.Run(spec.Kind().String(), func(t *testing.T) {
			t.Parallel()
			runner := &resourceRunner{outputs: []argvprocess.Result{
				{StandardOutput: []byte(spec.Name() + "\n")},
				{StandardOutput: inspectDocument(spec)},
			}}
			adapter, err := NewManagedResources(testExecutorsForDocker(t, runner))
			if err != nil {
				t.Fatal(err)
			}
			observed, err := adapter.Inspect(context.Background(), endpoint, spec)
			if err != nil || observed.Name() != spec.Name() {
				t.Fatalf("Inspect()=(%+v,%v)", observed, err)
			}
			resource := spec.Kind().String()
			wantList := []string{"--host", endpoint.String(), resource, "ls", "--format", "{{.Name}}", "--filter", "name=^" + spec.Name() + "$"}
			if !reflect.DeepEqual(runner.invocations[0].Arguments(), wantList) {
				t.Fatalf("list argv=%q want=%q", runner.invocations[0].Arguments(), wantList)
			}
			format := volumeInspectTemplate
			if spec.Kind() == resourceinventory.KindNetwork {
				format = networkInspectTemplate
			}
			wantInspect := []string{"--host", endpoint.String(), resource, "inspect", "--format", format, "--", spec.Name()}
			if !reflect.DeepEqual(runner.invocations[1].Arguments(), wantInspect) || runner.invocations[1].Executable() != testPlatformToolPath("/verified/docker") {
				t.Fatalf("inspect=%q %q", runner.invocations[1].Executable(), runner.invocations[1].Arguments())
			}
		})
	}
}

func TestPF001ManagedResourceCreateUsesClosedPolicyAndInspectsImmediately(t *testing.T) {
	t.Parallel()
	endpoint := resourceEndpoint(t)
	for _, spec := range []resourceinventory.Spec{resourcePlan(t)[0], resourcePlan(t)[1]} {
		spec := spec
		t.Run(spec.Kind().String(), func(t *testing.T) {
			t.Parallel()
			identity := spec.Name()
			if spec.Kind() == resourceinventory.KindNetwork {
				identity = strings.Repeat("a", 64)
			}
			runner := &resourceRunner{outputs: []argvprocess.Result{
				{}, // exact preflight absence
				{StandardOutput: []byte(identity + "\n")},
				{StandardOutput: []byte(spec.Name() + "\n")},
				{StandardOutput: inspectDocument(spec)},
			}}
			adapter, _ := NewManagedResources(testExecutorsForDocker(t, runner))
			observed, err := adapter.Create(context.Background(), endpoint, spec)
			if err != nil || observed.ObjectID() != identity {
				t.Fatalf("Create()=(%+v,%v)", observed, err)
			}
			if len(runner.invocations) != 4 {
				t.Fatalf("invocations=%d", len(runner.invocations))
			}
			arguments := runner.invocations[1].Arguments()
			if arguments[0] != "--host" || arguments[1] != endpoint.String() || arguments[len(arguments)-1] != spec.Name() {
				t.Fatalf("create argv=%q", arguments)
			}
			joined := strings.Join(arguments, " ")
			for key, value := range spec.Labels() {
				if !strings.Contains(joined, "--label "+key+"="+value) {
					t.Fatalf("missing label %s in %q", key, arguments)
				}
			}
			if strings.Contains(joined, " -f ") || strings.Contains(joined, "--force") || strings.Contains(joined, "type=bind") {
				t.Fatalf("unsafe create argv=%q", arguments)
			}
		})
	}
}

func TestPF001ManagedResourceRemoveRechecksInventoryAuthorization(t *testing.T) {
	t.Parallel()
	endpoint := resourceEndpoint(t)
	spec := resourcePlan(t)[0]
	authorization := removalAuthorization(t, spec)
	runner := &resourceRunner{outputs: []argvprocess.Result{
		{StandardOutput: []byte(spec.Name() + "\n")},
		{StandardOutput: inspectDocument(spec)},
		{},
		{},
	}}
	adapter, _ := NewManagedResources(testExecutorsForDocker(t, runner))
	if err := adapter.Remove(context.Background(), endpoint, authorization); err != nil {
		t.Fatal(err)
	}
	wantRemove := []string{"--host", endpoint.String(), "network", "rm", "--", spec.Name()}
	if !reflect.DeepEqual(runner.invocations[2].Arguments(), wantRemove) {
		t.Fatalf("remove=%q want=%q", runner.invocations[2].Arguments(), wantRemove)
	}
	if len(runner.invocations) != 4 {
		t.Fatalf("remove did not verify before and after: %d", len(runner.invocations))
	}
}

func TestPF001ManagedResourceRefusesMalformedForeignAndAmbiguousState(t *testing.T) {
	t.Parallel()
	endpoint := resourceEndpoint(t)
	spec := resourcePlan(t)[0]
	tests := []struct {
		name    string
		outputs []argvprocess.Result
		want    error
	}{
		{name: "absent", outputs: []argvprocess.Result{{}}, want: containerengine.ErrManagedResourceNotFound},
		{name: "ambiguous list", outputs: []argvprocess.Result{{StandardOutput: []byte(spec.Name() + "\nother\n")}}, want: containerengine.ErrManagedResourceResponse},
		{name: "duplicate JSON", outputs: []argvprocess.Result{{StandardOutput: []byte(spec.Name())}, {StandardOutput: duplicateInspectDocument(spec)}}, want: containerengine.ErrManagedResourceResponse},
		{name: "unknown JSON", outputs: []argvprocess.Result{{StandardOutput: []byte(spec.Name())}, {StandardOutput: []byte(`{"Name":"x","Future":true}`)}}, want: containerengine.ErrManagedResourceResponse},
		{name: "missing JSON field", outputs: []argvprocess.Result{{StandardOutput: []byte(spec.Name())}, {StandardOutput: []byte(strings.Replace(string(inspectDocument(spec)), `,"Options":{}`, "", 1))}}, want: containerengine.ErrManagedResourceResponse},
		{name: "truncated", outputs: []argvprocess.Result{{StandardOutput: []byte(spec.Name()), OutputTruncated: true}}, want: containerengine.ErrManagedResourceOperation},
		{name: "nonzero", outputs: []argvprocess.Result{{ExitCode: 1, StandardError: []byte("sensitive")}}, want: containerengine.ErrManagedResourceOperation},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runner := &resourceRunner{outputs: test.outputs}
			adapter, _ := NewManagedResources(testExecutorsForDocker(t, runner))
			_, err := adapter.Inspect(context.Background(), endpoint, spec)
			if !errors.Is(err, test.want) || strings.Contains(err.Error(), "sensitive") {
				t.Fatalf("Inspect() error=%v want=%v", err, test.want)
			}
		})
	}
}

func TestPF001ManagedResourceRefusesCollisionBeforeCreateAndRemove(t *testing.T) {
	t.Parallel()
	endpoint := resourceEndpoint(t)
	spec := resourcePlan(t)[1]
	runner := &resourceRunner{outputs: []argvprocess.Result{{StandardOutput: []byte(spec.Name())}, {StandardOutput: inspectDocument(spec)}}}
	adapter, _ := NewManagedResources(testExecutorsForDocker(t, runner))
	if _, err := adapter.Create(context.Background(), endpoint, spec); !errors.Is(err, containerengine.ErrManagedResourceCollision) || len(runner.invocations) != 2 {
		t.Fatalf("Create existing error=%v calls=%d", err, len(runner.invocations))
	}

	network := resourcePlan(t)[0]
	authorization := removalAuthorization(t, network)
	document := strings.Replace(string(inspectDocument(network)), `"io.agentmemory.managed":"true"`, `"io.agentmemory.managed":"false"`, 1)
	runner = &resourceRunner{outputs: []argvprocess.Result{{StandardOutput: []byte(network.Name())}, {StandardOutput: []byte(document)}}}
	adapter, _ = NewManagedResources(testExecutorsForDocker(t, runner))
	if err := adapter.Remove(context.Background(), endpoint, authorization); !errors.Is(err, containerengine.ErrManagedResourceCollision) || len(runner.invocations) != 2 {
		t.Fatalf("Remove foreign error=%v calls=%d", err, len(runner.invocations))
	}
}

func TestPF001ManagedResourceConstructorAndCancellation(t *testing.T) {
	t.Parallel()
	if _, err := NewManagedResources(Executors{}); err == nil {
		t.Fatal("accepted missing signed executors")
	}
	runner := &resourceRunner{err: context.Canceled}
	adapter, _ := NewManagedResources(testExecutorsForDocker(t, runner))
	_, err := adapter.Inspect(context.Background(), resourceEndpoint(t), resourcePlan(t)[0])
	if !errors.Is(err, context.Canceled) || !errors.Is(err, containerengine.ErrManagedResourceOperation) {
		t.Fatalf("cancellation error=%v", err)
	}
}

func TestPF001ManagedResourceVolumeRemovalAndCreateResponseMismatch(t *testing.T) {
	t.Parallel()
	endpoint := resourceEndpoint(t)
	volume := resourcePlan(t)[1]
	authorization := removalAuthorization(t, volume)
	runner := &resourceRunner{outputs: []argvprocess.Result{
		{StandardOutput: []byte(volume.Name())},
		{StandardOutput: inspectDocument(volume)},
		{},
		{},
	}}
	adapter, _ := NewManagedResources(testExecutorsForDocker(t, runner))
	if err := adapter.Remove(context.Background(), endpoint, authorization); err != nil {
		t.Fatal(err)
	}
	want := []string{"--host", endpoint.String(), "volume", "rm", "--", volume.Name()}
	if !reflect.DeepEqual(runner.invocations[2].Arguments(), want) {
		t.Fatalf("volume remove=%q", runner.invocations[2].Arguments())
	}

	network := resourcePlan(t)[0]
	runner = &resourceRunner{outputs: []argvprocess.Result{{}, {StandardOutput: []byte("not-an-id")}}}
	adapter, _ = NewManagedResources(testExecutorsForDocker(t, runner))
	if _, err := adapter.Create(context.Background(), endpoint, network); !errors.Is(err, containerengine.ErrManagedResourceResponse) {
		t.Fatalf("network create response error=%v", err)
	}
}

func TestPF001ManagedResourceJSONAndValueGuards(t *testing.T) {
	t.Parallel()
	for _, document := range []string{
		`{"array":[{"a":1},2],"scalar":true}`,
		`null`,
		`[1,2,3]`,
	} {
		if err := rejectDuplicateJSONKeys([]byte(document)); err != nil {
			t.Fatalf("valid JSON %s error=%v", document, err)
		}
	}
	for _, document := range []string{
		`{"outer":{"a":1,"a":2}}`,
		`{"a":1} {"b":2}`,
		`{"a":[1,2}`,
	} {
		if err := rejectDuplicateJSONKeys([]byte(document)); err == nil {
			t.Fatalf("invalid JSON %s succeeded", document)
		}
	}
	if safeManagedName("foreign") || safeManagedName("agentmemory_BAD") || safeManagedName("") ||
		!safeManagedName(resourcePlan(t)[0].Name()) {
		t.Fatal("managed name guard changed")
	}
	if lowerHexResourceID(strings.Repeat("A", 64)) || lowerHexResourceID("short") ||
		!lowerHexResourceID(strings.Repeat("a", 64)) {
		t.Fatal("object ID guard changed")
	}
	labels := resourcePlan(t)[0].Labels()
	if !sameLabels(labels, labels) || sameLabels(labels, map[string]string{"different": "labels"}) {
		t.Fatal("exact label comparison changed")
	}
	changed := make(map[string]string, len(labels))
	for key, value := range labels {
		changed[key] = value
	}
	changed["io.agentmemory.managed"] = "false"
	if sameLabels(labels, changed) {
		t.Fatal("label value substitution was accepted")
	}
	if !hasExactJSONFields([]byte(`{"a":1,"b":2}`), "a", "b") ||
		hasExactJSONFields([]byte(`{"a":1,"b":2}`), "a") ||
		hasExactJSONFields([]byte(`not-json`), "a") {
		t.Fatal("exact JSON field guard changed")
	}
	adapter, _ := NewManagedResources(testExecutorsForDocker(t, &resourceRunner{}))
	if _, err := adapter.inspectNamed(
		context.Background(), resourceEndpoint(t), resourceinventory.Kind(255), resourcePlan(t)[0].Name(),
	); !errors.Is(err, containerengine.ErrManagedResourceResponse) {
		t.Fatalf("unknown resource kind error = %v", err)
	}
}

func TestPF001ManagedResourceRemovalFailsClosedAtEveryBoundary(t *testing.T) {
	t.Parallel()

	endpoint := resourceEndpoint(t)
	spec := resourcePlan(t)[0]
	authorization := removalAuthorization(t, spec)
	validList := argvprocess.Result{StandardOutput: []byte(spec.Name())}
	validInspect := argvprocess.Result{StandardOutput: inspectDocument(spec)}
	tests := []struct {
		name    string
		auth    resourceinventory.RemovalAuthorization
		outputs []argvprocess.Result
		want    error
	}{
		{name: "invalid authorization", want: containerengine.ErrManagedResourceCollision},
		{name: "resource vanished before authorization", auth: authorization, outputs: []argvprocess.Result{{}}, want: containerengine.ErrManagedResourceNotFound},
		{name: "remove command failed", auth: authorization, outputs: []argvprocess.Result{validList, validInspect, {ExitCode: 1}}, want: containerengine.ErrManagedResourceOperation},
		{name: "resource still exists", auth: authorization, outputs: []argvprocess.Result{validList, validInspect, {}, validList, validInspect}, want: containerengine.ErrManagedResourceCollision},
		{name: "absence probe failed", auth: authorization, outputs: []argvprocess.Result{validList, validInspect, {}, {ExitCode: 1}}, want: containerengine.ErrManagedResourceOperation},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runner := &resourceRunner{outputs: append([]argvprocess.Result(nil), test.outputs...)}
			adapter, err := NewManagedResources(testExecutorsForDocker(t, runner))
			if err != nil {
				t.Fatal(err)
			}
			if err := adapter.Remove(context.Background(), endpoint, test.auth); !errors.Is(err, test.want) {
				t.Fatalf("Remove() error = %v, want %v", err, test.want)
			}
		})
	}

	foreignDocument := strings.Replace(
		string(validInspect.StandardOutput),
		strings.Repeat("a", 64),
		strings.Repeat("b", 64),
		1,
	)
	runner := &resourceRunner{outputs: []argvprocess.Result{validList, {StandardOutput: []byte(foreignDocument)}}}
	adapter, _ := NewManagedResources(testExecutorsForDocker(t, runner))
	if err := adapter.Remove(context.Background(), endpoint, authorization); !errors.Is(err, containerengine.ErrManagedResourceCollision) {
		t.Fatalf("Remove(foreign object) error = %v", err)
	}
}

func TestPF001ManagedResourceCreationRejectsEveryUnverifiedBoundary(t *testing.T) {
	t.Parallel()

	endpoint := resourceEndpoint(t)
	if adapter, err := NewManagedResources(testExecutorsForDocker(t, &resourceRunner{})); err != nil {
		t.Fatal(err)
	} else if _, err := adapter.Create(context.Background(), containerengine.Endpoint{}, resourceinventory.Spec{}); !errors.Is(err, containerengine.ErrManagedResourceResponse) {
		t.Fatalf("Create(invalid) error = %v", err)
	}

	volume := resourcePlan(t)[1]
	runner := &resourceRunner{outputs: []argvprocess.Result{{}, {StandardOutput: []byte("substituted-volume")}}}
	adapter, _ := NewManagedResources(testExecutorsForDocker(t, runner))
	if _, err := adapter.Create(context.Background(), endpoint, volume); !errors.Is(err, containerengine.ErrManagedResourceResponse) {
		t.Fatalf("Create(volume response mismatch) error = %v", err)
	}

	network := resourcePlan(t)[0]
	createdID := strings.Repeat("b", 64)
	runner = &resourceRunner{outputs: []argvprocess.Result{
		{}, {StandardOutput: []byte(createdID)}, {StandardOutput: []byte(network.Name())},
		{StandardOutput: inspectDocument(network)},
	}}
	adapter, _ = NewManagedResources(testExecutorsForDocker(t, runner))
	if _, err := adapter.Create(context.Background(), endpoint, network); !errors.Is(err, containerengine.ErrManagedResourceCollision) {
		t.Fatalf("Create(post-inspect substitution) error = %v", err)
	}
}

func TestPF001ManagedResourceRunnerBoundsAllDiagnostics(t *testing.T) {
	t.Parallel()

	endpoint := resourceEndpoint(t)
	spec := resourcePlan(t)[0]
	tests := []struct {
		name   string
		ctx    context.Context
		result argvprocess.Result
		err    error
	}{
		{name: "nil context"},
		{name: "runner failure", ctx: context.Background(), err: errors.New("raw runtime detail")},
		{name: "deadline", ctx: context.Background(), err: context.DeadlineExceeded},
		{name: "oversized stdout", ctx: context.Background(), result: argvprocess.Result{StandardOutput: []byte(strings.Repeat("x", maximumDockerJSON+1))}},
		{name: "oversized stderr", ctx: context.Background(), result: argvprocess.Result{StandardError: []byte(strings.Repeat("x", maximumDockerJSON+1))}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runner := &resourceRunner{outputs: []argvprocess.Result{test.result}, err: test.err}
			adapter, _ := NewManagedResources(testExecutorsForDocker(t, runner))
			_, err := adapter.Inspect(test.ctx, endpoint, spec)
			if !errors.Is(err, containerengine.ErrManagedResourceOperation) ||
				strings.Contains(err.Error(), "raw runtime detail") {
				t.Fatalf("Inspect() error = %v", err)
			}
		})
	}
}

func resourceEndpoint(t *testing.T) containerengine.Endpoint {
	t.Helper()
	endpoint, err := containerengine.NewEndpoint("unix:///var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	return endpoint
}

func resourcePlan(t *testing.T) []resourceinventory.Spec {
	t.Helper()
	plan, err := resourceinventory.BuildPlan(resourceInstallation, resourceGeneration, "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func inspectDocument(spec resourceinventory.Spec) []byte {
	labels := `{"io.agentmemory.generation":"` + spec.Labels()["io.agentmemory.generation"] + `","io.agentmemory.installation":"` + resourceInstallation + `","io.agentmemory.managed":"true","io.agentmemory.purpose":"` + string(spec.Purpose()) + `","io.agentmemory.release":"0.1.0"}`
	if spec.Kind() == resourceinventory.KindNetwork {
		return []byte(`{"Name":"` + spec.Name() + `","ID":"` + strings.Repeat("a", 64) + `","Driver":"bridge","Scope":"local","Internal":true,"Attachable":false,"Ingress":false,"ConfigOnly":false,"Labels":` + labels + `,"Options":{}}`)
	}
	return []byte(`{"Name":"` + spec.Name() + `","Driver":"local","Scope":"local","Labels":` + labels + `,"Options":{}}`)
}

func duplicateInspectDocument(spec resourceinventory.Spec) []byte {
	document := string(inspectDocument(spec))
	return []byte(strings.Replace(document, `{"Name":`, `{"Name":"duplicate","Name":`, 1))
}

func removalAuthorization(t *testing.T, spec resourceinventory.Spec) resourceinventory.RemovalAuthorization {
	t.Helper()
	inventory, _ := resourceinventory.New(resourceInstallation)
	_, _ = inventory.Begin(spec, "install-1")
	objectID := spec.Name()
	if spec.Kind() == resourceinventory.KindNetwork {
		objectID = strings.Repeat("a", 64)
	}
	observed, _ := resourceinventory.NewObserved(spec.Kind(), spec.Name(), objectID, spec.Labels())
	_, _ = inventory.Record(spec, "install-1", observed)
	authorization, err := inventory.AuthorizeRemoval(observed)
	if err != nil {
		t.Fatal(err)
	}
	return authorization
}

type resourceRunner struct {
	invocations []argvprocess.Invocation
	outputs     []argvprocess.Result
	err         error
}

func (r *resourceRunner) Run(_ context.Context, invocation argvprocess.Invocation) (argvprocess.Result, error) {
	r.invocations = append(r.invocations, invocation)
	if r.err != nil {
		return argvprocess.Result{}, r.err
	}
	if len(r.outputs) == 0 {
		return argvprocess.Result{}, errors.New("unexpected invocation")
	}
	result := r.outputs[0]
	r.outputs = r.outputs[1:]
	return result, nil
}
