package dockercli

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeremovalapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeremoval"
)

func TestPF001DockerRuntimeDependencyScannerUsesSevenFixedBoundedObservations(t *testing.T) {
	t.Parallel()
	ownership := dockerScannerOwnershipFixture(t)
	docker := &inventoryRunner{outputs: [][]byte{
		{},
		{},
		{},
		[]byte("{\"Name\":\"bridge\"}\n{\"Name\":\"host\"}\n{\"Name\":\"none\"}\n"),
		[]byte("{\"Name\":\"default\",\"DockerEndpoint\":\"unix:///run/user/1000/docker.sock\"}\n"),
	}}
	compose := &inventoryRunner{outputs: [][]byte{[]byte("[]")}}
	active := &activeClientScannerStub{observation: ActiveClientObservation{
		EvidenceDigest: runtimeinstall.Sum([]byte("no-active-clients")),
	}}
	scanner, err := NewRuntimeDependencyScanner(testExecutors(t, docker, compose), active)
	if err != nil {
		t.Fatal(err)
	}
	scan, err := scanner.ScanRuntimeDependencies(context.Background(), runtimeremovalapp.ScanRequest{
		Endpoint: ownership.Endpoint(), Ownership: ownership,
	})
	if err != nil || !scan.SafeToRemove() || len(scan.Proofs()) != 7 || active.calls != 1 {
		t.Fatalf("scan = %+v/%v active=%d", scan, err, active.calls)
	}
	wantDocker := [][]string{
		{"--host", ownership.Endpoint(), "container", "ls", "--all", "--no-trunc", "--format", "json"},
		{"--host", ownership.Endpoint(), "image", "ls", "--all", "--no-trunc", "--digests", "--format", "json"},
		{"--host", ownership.Endpoint(), "volume", "ls", "--format", "json"},
		{"--host", ownership.Endpoint(), "network", "ls", "--no-trunc", "--format", "json"},
		{"--host", ownership.Endpoint(), "context", "ls", "--format", "json"},
	}
	if !reflect.DeepEqual(docker.arguments, wantDocker) {
		t.Fatalf("Docker argv = %#v", docker.arguments)
	}
	wantCompose := [][]string{{"--host", ownership.Endpoint(), "ls", "--all", "--format", "json"}}
	if !reflect.DeepEqual(compose.arguments, wantCompose) {
		t.Fatalf("Compose argv = %#v", compose.arguments)
	}
}

func TestPF001DockerRuntimeDependencyScannerCountsOnlyActualRemovalDependencies(t *testing.T) {
	t.Parallel()
	ownership := dockerScannerOwnershipFixture(t)
	docker := &inventoryRunner{outputs: [][]byte{
		[]byte("{\"ID\":\"container-a\"}\n"),
		[]byte("{\"ID\":\"image-a\"}\n"),
		[]byte("{\"Name\":\"volume-a\"}\n"),
		[]byte("{\"Name\":\"bridge\"}\n{\"Name\":\"project-network\"}\n"),
		[]byte("{\"Name\":\"default\",\"DockerEndpoint\":\"unix:///run/user/1000/docker.sock\"}\n" +
			"{\"Name\":\"project\",\"DockerEndpoint\":\"unix:///run/user/1000/docker.sock\"}\n" +
			"{\"Name\":\"remote\",\"DockerEndpoint\":\"unix:///other.sock\"}\n"),
	}}
	compose := &inventoryRunner{outputs: [][]byte{[]byte("[{\"Name\":\"project-a\"}]")}}
	active := &activeClientScannerStub{observation: ActiveClientObservation{
		Count: 2, EvidenceDigest: runtimeinstall.Sum([]byte("two-active-clients")),
	}}
	scanner, _ := NewRuntimeDependencyScanner(testExecutors(t, docker, compose), active)
	scan, err := scanner.ScanRuntimeDependencies(context.Background(), runtimeremovalapp.ScanRequest{
		Endpoint: ownership.Endpoint(), Ownership: ownership,
	})
	if err != nil || scan.SafeToRemove() {
		t.Fatalf("dependent scan = %+v/%v", scan, err)
	}
	wantCounts := []uint64{1, 1, 1, 1, 1, 1, 2}
	for index, proof := range scan.Proofs() {
		if proof.Count() != wantCounts[index] {
			t.Fatalf("proof %s count = %d", proof.Kind(), proof.Count())
		}
	}
}

func TestPF001DockerRuntimeDependencyScannerFailsClosedOnAmbiguousEvidence(t *testing.T) {
	t.Parallel()
	ownership := dockerScannerOwnershipFixture(t)
	for name, output := range map[string][]byte{
		"duplicate":  []byte("{\"ID\":\"a\",\"ID\":\"b\"}\n"),
		"not object": []byte("\"container\"\n"),
		"trailing":   []byte("{\"ID\":\"a\"} garbage\n"),
	} {
		t.Run(name, func(t *testing.T) {
			docker := &inventoryRunner{outputs: [][]byte{output}}
			scanner, _ := NewRuntimeDependencyScanner(
				testExecutors(t, docker, &inventoryRunner{}),
				&activeClientScannerStub{observation: ActiveClientObservation{
					EvidenceDigest: runtimeinstall.Sum([]byte("active")),
				}},
			)
			_, err := scanner.ScanRuntimeDependencies(context.Background(), runtimeremovalapp.ScanRequest{
				Endpoint: ownership.Endpoint(), Ownership: ownership,
			})
			if !errors.Is(err, runtimeremovalapp.ErrScanUncertain) {
				t.Fatalf("scan error = %v", err)
			}
		})
	}
	var typedNil *activeClientScannerStub
	if scanner, err := NewRuntimeDependencyScanner(
		testExecutors(t, &inventoryRunner{}, &inventoryRunner{}), typedNil,
	); err == nil || scanner != nil {
		t.Fatal("typed-nil active client scanner was accepted")
	}
}

func TestPF001DockerRuntimeDependencyEvidenceIsStableAcrossCLIOrdering(t *testing.T) {
	t.Parallel()
	firstCount, first, err := inventoryEvidence(
		runtimeremoval.DependencyContainers,
		[]byte("{\"ID\":\"b\",\"Name\":\"two\"}\n{\"ID\":\"a\",\"Name\":\"one\"}\n"), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	secondCount, second, err := inventoryEvidence(
		runtimeremoval.DependencyContainers,
		[]byte("{\"Name\":\"one\",\"ID\":\"a\"}\n{\"Name\":\"two\",\"ID\":\"b\"}\n"), nil,
	)
	if err != nil || firstCount != 2 || secondCount != 2 || first != second {
		t.Fatalf("stable evidence = %d/%s %d/%s err=%v", firstCount, first, secondCount, second, err)
	}
}

type inventoryRunner struct {
	outputs   [][]byte
	arguments [][]string
}

func (r *inventoryRunner) Run(_ context.Context, invocation argvprocess.Invocation) (argvprocess.Result, error) {
	r.arguments = append(r.arguments, invocation.Arguments())
	if len(r.outputs) == 0 {
		return argvprocess.Result{}, errors.New("unexpected inventory invocation")
	}
	output := r.outputs[0]
	r.outputs = r.outputs[1:]
	return argvprocess.Result{StandardOutput: output}, nil
}

type activeClientScannerStub struct {
	observation ActiveClientObservation
	calls       int
}

func (s *activeClientScannerStub) ScanActiveRuntimeClients(
	_ context.Context,
	_ containerengine.Endpoint,
) (ActiveClientObservation, error) {
	s.calls++
	return s.observation, nil
}

func dockerScannerOwnershipFixture(t *testing.T) runtimeinstall.RuntimeOwnershipRecord {
	t.Helper()
	host, err := runtimeinstall.NewHostCapabilities(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "24.04", true, true, true, true,
		8, 32<<30, 24<<30, 100<<30,
	)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := runtimeinstall.NewCertifiedRuntime(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "docker_engine", "29.6.1", "stable", 7,
		runtimeinstall.Sum([]byte("catalog")), runtimeinstall.RuntimeTermsInput{
			ID: runtimeinstall.DockerEngineTermsID, Version: "apache-2.0", URL: "https://docs.docker.com/engine/",
			Digest: runtimeinstall.Sum([]byte("terms")), Presentation: runtimeinstall.TermsPresentationAgentMemory,
		}, 1, 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := runtimeinstall.NewPlanV1(host, runtimeinstall.NewAbsentRuntimeDiscovery(), catalog)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := runtimeinstall.NewOperation("019f60a0-1111-7abc-8123-0123456789ab", plan.Digest())
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range runtimeinstall.OrderedPhases() {
		artifact := runtimeinstall.Hash{}
		if phase >= runtimeinstall.PhaseVerifyRuntimeArtifact {
			artifact = runtimeinstall.Sum([]byte("runtime-artifact"))
		}
		ownership := runtimeinstall.OwnershipUnknown
		if phase == runtimeinstall.PhaseVerifyRuntimeCapabilities {
			ownership = runtimeinstall.OwnershipProvisionedByAgentMemory
		}
		evidence, evidenceError := runtimeinstall.NewTransitionEvidence(
			phase, operation.Attempt(), plan.Digest(), runtimeinstall.Sum([]byte("before-"+phase.String())),
			runtimeinstall.Sum([]byte("after-"+phase.String())), artifact, ownership,
		)
		if evidenceError != nil || operation.Complete(phase, evidence) != nil {
			t.Fatalf("complete %s: %v", phase, evidenceError)
		}
	}
	authority, err := runtimeinstall.NewRuntimeOwnershipAuthority(runtimeinstall.RuntimeOwnershipAuthoritySnapshot{
		Vendor: plan.Product(), Version: plan.Version(), Channel: plan.Channel(),
		Endpoint: "unix:///run/user/1000/docker.sock", Context: "explicit-local-endpoint",
		Publisher: "docker-stable:key", PublisherDigest: runtimeinstall.Sum([]byte("publisher")),
		ArtifactDigest: runtimeinstall.Sum([]byte("runtime-artifact")),
		Components:     []string{"engine@29.6.1"}, Settings: []string{"service:docker.service"},
	})
	if err != nil {
		t.Fatal(err)
	}
	record, err := runtimeinstall.NewRuntimeOwnershipRecord(plan, operation.Snapshot(), authority, nil)
	if err != nil {
		t.Fatal(err)
	}
	return record
}
