package launcher

import (
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/artifactfs"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/dockercli"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installphase"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productstack"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/resourceapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/resourceinventory"
)

func TestPF001NativeProductApplicationsDelegateOnlyExactRuntimeBindings(t *testing.T) {
	t.Parallel()
	_, authority, _ := nativeRuntimeExecutionFixture(t)
	endpoint, err := containerengine.NewEndpoint("unix:///var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	runtimeAuthority := nativeProductRuntime{
		verified: nativeVerifiedRuntimeExecution{authority: authority},
		endpoint: endpoint,
	}
	capacity := &nativeProductCapacityStub{}
	resources := &nativeProductResourceStub{}
	stack := &nativeProductStackStub{}
	applications := &nativeProductApplications{
		capacityApplication: func(context.Context) (installphase.ArtifactCapacityApplication, nativeProductRuntime, error) {
			return capacity, runtimeAuthority, nil
		},
		resourceApplication: func(context.Context) (installphase.ManagedResourceEnsurer, nativeProductRuntime, error) {
			return resources, runtimeAuthority, nil
		},
		stackApplication: func(context.Context) (productstack.Ensurer, nativeProductRuntime, error) {
			return stack, runtimeAuthority, nil
		},
	}
	command := artifactapp.CapacityCommand{
		OperationID: authority.OperationID().String(), ParentPlanDigest: authority.ParentPlanDigest(),
		DockerEngine:     artifactapp.CapacityTarget{Kind: artifactapp.CapacityDockerEngine, Locator: endpoint.String()},
		DockerDataVolume: artifactapp.CapacityTarget{Kind: artifactapp.CapacityDockerDataVolume, Locator: endpoint.String()},
	}
	if _, err := applications.ReserveCapacity(t.Context(), command); err != nil {
		t.Fatal(err)
	}
	if _, err := applications.ConsumeArtifactExpansion(t.Context(), command, "compose"); err != nil {
		t.Fatal(err)
	}
	if _, err := applications.PrepareSecretProjectionCapacity(t.Context(), command, "generation"); err != nil {
		t.Fatal(err)
	}
	if _, err := applications.TransferActivationCapacity(t.Context(), command, "generation", "installation"); err != nil {
		t.Fatal(err)
	}
	if _, err := applications.ReleaseOperationCapacity(t.Context(), command); err != nil {
		t.Fatal(err)
	}
	if _, err := applications.CompensateOperationCapacity(t.Context(), command); err != nil {
		t.Fatal(err)
	}
	if _, err := applications.ReleaseActivatedCapacity(t.Context(), command, "generation", "installation"); err != nil {
		t.Fatal(err)
	}
	resourceCommand := resourceapp.Command{
		CreationOperation: authority.OperationID().String(), Endpoint: endpoint,
	}
	if _, err := applications.EnsureNetworkAndVolumes(t.Context(), resourceCommand); err != nil {
		t.Fatal(err)
	}
	authorization := nativeProductStackAuthorization(t, authority.OperationID(), authority.ParentPlanDigest(), endpoint)
	if _, err := applications.RunMigrations(t.Context(), authorization); err != nil {
		t.Fatal(err)
	}
	startAuthorization := nativeProductStackAuthorizationFor(
		t,
		productstack.OperationStartCoreAndGraph,
		authority.OperationID(),
		authority.ParentPlanDigest(),
		endpoint,
	)
	if _, err := applications.StartCoreAndGraph(t.Context(), startAuthorization); err != nil {
		t.Fatal(err)
	}
	if capacity.calls != 7 || resources.calls != 1 || stack.migrations != 1 || stack.starts != 1 {
		t.Fatalf("delegations=%d/%d/%d/%d", capacity.calls, resources.calls, stack.migrations, stack.starts)
	}

	foreign := command
	foreign.OperationID = "foreign"
	if _, err := applications.ReserveCapacity(t.Context(), foreign); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("foreign capacity error=%v", err)
	}
	resourceCommand.CreationOperation = "foreign"
	if _, err := applications.EnsureNetworkAndVolumes(t.Context(), resourceCommand); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("foreign resource error=%v", err)
	}
}

func TestPF001NativeProductApplicationsFailClosedBeforeDelegation(t *testing.T) {
	t.Parallel()
	var absent *nativeProductApplications
	if _, err := absent.ReserveCapacity(t.Context(), artifactapp.CapacityCommand{}); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("absent capacity error=%v", err)
	}
	if _, err := absent.ConsumeArtifactExpansion(t.Context(), artifactapp.CapacityCommand{}, "artifact"); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("absent expansion error=%v", err)
	}
	if _, err := absent.PrepareSecretProjectionCapacity(t.Context(), artifactapp.CapacityCommand{}, "generation"); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("absent secret capacity error=%v", err)
	}
	if _, err := absent.TransferActivationCapacity(t.Context(), artifactapp.CapacityCommand{}, "generation", "installation"); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("absent activation transfer error=%v", err)
	}
	if _, err := absent.ReleaseOperationCapacity(t.Context(), artifactapp.CapacityCommand{}); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("absent release error=%v", err)
	}
	if _, err := absent.CompensateOperationCapacity(t.Context(), artifactapp.CapacityCommand{}); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("absent compensation error=%v", err)
	}
	if _, err := absent.ReleaseActivatedCapacity(t.Context(), artifactapp.CapacityCommand{}, "generation", "installation"); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("absent activated release error=%v", err)
	}
	if _, err := absent.EnsureNetworkAndVolumes(t.Context(), resourceapp.Command{}); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("absent resources error=%v", err)
	}
	if _, err := absent.RunMigrations(t.Context(), productstack.Authorization{}); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("absent stack error=%v", err)
	}
	if _, err := absent.StartCoreAndGraph(t.Context(), productstack.Authorization{}); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("absent stack start error=%v", err)
	}
	resolver := &nativeProductRuntimeResolverStub{err: errors.New("private runtime error")}
	applications := &nativeProductApplications{runtime: resolver}
	if _, _, err := applications.buildCapacityApplication(t.Context()); err == nil || resolver.calls != 1 {
		t.Fatalf("capacity build error=%v calls=%d", err, resolver.calls)
	}
	if _, _, err := applications.buildResourceApplication(t.Context()); err == nil || resolver.calls != 2 {
		t.Fatalf("resource build error=%v calls=%d", err, resolver.calls)
	}
	if _, _, err := applications.buildStackApplication(t.Context()); err == nil || resolver.calls != 3 {
		t.Fatalf("stack build error=%v calls=%d", err, resolver.calls)
	}
	private := errors.New("private operation-scoped application failure")
	failing := &nativeProductApplications{
		capacityApplication: func(context.Context) (installphase.ArtifactCapacityApplication, nativeProductRuntime, error) {
			return nil, nativeProductRuntime{}, private
		},
		resourceApplication: func(context.Context) (installphase.ManagedResourceEnsurer, nativeProductRuntime, error) {
			return nil, nativeProductRuntime{}, private
		},
		stackApplication: func(context.Context) (productstack.Ensurer, nativeProductRuntime, error) {
			return nil, nativeProductRuntime{}, private
		},
	}
	for name, invoke := range map[string]func() error{
		"expansion": func() error {
			_, err := failing.ConsumeArtifactExpansion(t.Context(), artifactapp.CapacityCommand{}, "artifact")
			return err
		},
		"secret projection": func() error {
			_, err := failing.PrepareSecretProjectionCapacity(t.Context(), artifactapp.CapacityCommand{}, "generation")
			return err
		},
		"activation transfer": func() error {
			_, err := failing.TransferActivationCapacity(t.Context(), artifactapp.CapacityCommand{}, "generation", "installation")
			return err
		},
		"operation release": func() error {
			_, err := failing.ReleaseOperationCapacity(t.Context(), artifactapp.CapacityCommand{})
			return err
		},
		"operation compensation": func() error {
			_, err := failing.CompensateOperationCapacity(t.Context(), artifactapp.CapacityCommand{})
			return err
		},
		"activated release": func() error {
			_, err := failing.ReleaseActivatedCapacity(t.Context(), artifactapp.CapacityCommand{}, "generation", "installation")
			return err
		},
	} {
		if err := invoke(); !errors.Is(err, errNativeInstallerIntegrity) || !errors.Is(err, private) {
			t.Fatalf("%s error=%v", name, err)
		}
	}
	//lint:ignore SA1012 Deliberate nil-context product application boundary attack.
	if _, err := applications.resolve(nil); !errors.Is(err, errNativeInstallerIntegrity) { //nolint:staticcheck // Security regression fixture; owner=security expiry=2027-07-14.
		t.Fatalf("nil context error=%v", err)
	}

	executors := nativeProductExecutors(t)
	storeRoot := filepath.Join(nativeReleaseAuthorityBundleRoot(t), "product-cas")
	if err := ensureNativePrivateDirectory(t.Context(), storeRoot); err != nil {
		t.Fatal(err)
	}
	store, err := artifactfs.NewStore(storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	boundRuntime := nativeProductRuntime{
		executors: executors,
		verified: nativeVerifiedRuntimeExecution{
			authority: nativeRuntimeExecutionAuthority(t),
		},
		endpoint: nativeProductEndpoint(t),
	}
	bound := &nativeProductApplications{
		runtime:       &nativeProductRuntimeResolverStub{runtime: boundRuntime},
		artifactStore: store,
		resourceState: &nativeProductResourceRepository{},
	}
	if _, _, err := bound.buildCapacityApplication(t.Context()); err == nil {
		t.Fatal("capacity accepted missing verified helper inventory")
	}
	if resourceApplication, resolved, err := bound.buildResourceApplication(t.Context()); err != nil ||
		resourceApplication == nil || resolved.endpoint.String() != boundRuntime.endpoint.String() {
		t.Fatalf("resource application=%T runtime=%+v error=%v", resourceApplication, resolved, err)
	}
	if stackApplication, resolved, err := bound.buildStackApplication(t.Context()); err != nil ||
		stackApplication == nil || resolved.endpoint.String() != boundRuntime.endpoint.String() {
		t.Fatalf("stack application=%T runtime=%+v error=%v", stackApplication, resolved, err)
	}
	invalidRuntime := boundRuntime
	invalidRuntime.executors = dockercli.Executors{}
	bound.runtime = &nativeProductRuntimeResolverStub{runtime: invalidRuntime}
	if _, _, err := bound.buildCapacityApplication(t.Context()); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("invalid capacity executors error=%v", err)
	}
	if _, _, err := bound.buildResourceApplication(t.Context()); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("invalid resource executors error=%v", err)
	}
	if _, _, err := bound.buildStackApplication(t.Context()); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("invalid stack executors error=%v", err)
	}
}

func nativeRuntimeExecutionAuthority(t testing.TB) installplanapp.RuntimePlanAuthority {
	t.Helper()
	_, authority, _ := nativeRuntimeExecutionFixture(t)
	return authority
}

func nativeProductEndpoint(t testing.TB) containerengine.Endpoint {
	t.Helper()
	endpoint, err := containerengine.NewEndpoint("unix:///var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	return endpoint
}

func nativeProductExecutors(t testing.TB) dockercli.Executors {
	t.Helper()
	release := sha256.Sum256([]byte("release"))
	plan := sha256.Sum256([]byte("plan"))
	trust := sha256.Sum256([]byte("publisher trust"))
	newAuthority := func(id, path string, role argvprocess.ExecutableRole) argvprocess.ExecutableAuthority {
		owner := "uid:0"
		if runtime.GOOS == "windows" {
			owner = "sid:S-1-5-32-544"
		}
		authority, err := argvprocess.NewExecutableAuthority(argvprocess.ExecutableAuthorityInput{
			CanonicalID: id, CanonicalPath: path, SHA256: sha256.Sum256([]byte(id)),
			OwnerIdentity: owner, PublisherIdentity: "publisher", PublisherPolicyID: "policy",
			PublisherTrustDigest: trust, ReleaseManifestDigest: release, RuntimePlanDigest: plan,
			Role: role, Platform: runtime.GOOS, Architecture: runtime.GOARCH,
		})
		if err != nil {
			t.Fatal(err)
		}
		return authority
	}
	dockerPath := "/opt/agentmemory/docker"
	composePath := "/opt/agentmemory/docker-compose"
	if runtime.GOOS == "windows" {
		dockerPath = `C:\Program Files\AgentMemory\docker.exe`
		composePath = `C:\Program Files\AgentMemory\docker-compose.exe`
	}
	dockerRunner := &nativeProductRunner{
		authority: newAuthority("docker", dockerPath, argvprocess.ExecutableRoleDockerCLI),
		output:    []byte(`{"ID":"local-daemon","DockerRootDir":"/var/lib/docker","Driver":"overlay2","DriverStatus":[["Backing Filesystem","extfs"],["Supports d_type","true"]],"OperatingSystem":"Docker Desktop","OSType":"linux","Architecture":"` + runtime.GOARCH + `","Name":"local","ServerVersion":"28.0.0"}`),
	}
	composeRunner := &nativeProductRunner{
		authority: newAuthority("compose", composePath, argvprocess.ExecutableRoleComposePlugin),
	}
	executors, err := dockercli.NewExecutors(dockerRunner, composeRunner)
	if err != nil {
		t.Fatal(err)
	}
	return executors
}

type nativeProductRunner struct {
	authority argvprocess.ExecutableAuthority
	output    []byte
	calls     int
}

func (r *nativeProductRunner) ExecutableAuthority() argvprocess.ExecutableAuthority {
	return r.authority
}

func (r *nativeProductRunner) Run(context.Context, argvprocess.Invocation) (argvprocess.Result, error) {
	r.calls++
	return argvprocess.Result{StandardOutput: append([]byte(nil), r.output...)}, nil
}

func (r *nativeProductRunner) RunStreaming(
	context.Context,
	argvprocess.Invocation,
	argvprocess.Streams,
) error {
	r.calls++
	return nil
}

type nativeProductResourceRepository struct{}

func (*nativeProductResourceRepository) Load(context.Context, string) (resourceinventory.Snapshot, error) {
	return resourceinventory.Snapshot{}, resourceapp.ErrInventoryNotFound
}

func (*nativeProductResourceRepository) Save(context.Context, uint64, resourceinventory.Snapshot) error {
	return nil
}

func TestPF001RuntimePhaseCompletionRequiresExactContiguousEvidence(t *testing.T) {
	t.Parallel()
	operationID := nativeGraphOperationID(t)
	planDigest := nativeGraphPlanDigest(t)
	operation, err := install.NewOperation(operationID, planDigest)
	if err != nil {
		t.Fatal(err)
	}
	if runtimePhaseCompleted(operation, planDigest, operationID) {
		t.Fatal("pristine runtime reported complete")
	}
	if err := operation.CompleteStep(nativeProductEvidence(
		t,
		install.PhaseVerifyHost,
		planDigest,
		install.RuntimeOwnershipUndetermined,
	)); err != nil {
		t.Fatal(err)
	}
	if err := operation.CompleteStep(nativeProductEvidence(
		t,
		install.PhaseEnsureContainerRuntime,
		planDigest,
		install.RuntimeOwnershipProvisionedByAgentMemory,
	)); err != nil {
		t.Fatal(err)
	}
	if !runtimePhaseCompleted(operation, planDigest, operationID) ||
		runtimePhaseCompleted(operation, install.PlanDigest{}, operationID) {
		t.Fatal("runtime completion binding mismatch")
	}
}

func TestPF001NativeProductAuthorityRequiresCompletedOperationBeforePlanResolution(t *testing.T) {
	t.Parallel()
	_, authority, _ := nativeRuntimeExecutionFixture(t)
	plans := &installplanapp.Application{}
	verifier := &nativeRuntimeExecutionVerifier{}
	platform := &nativePlatformRuntimeFactory{}
	loadingFailure := &nativeCancellationRepository{loadErr: errors.New("private operation failure")}
	resolver, err := newNativeProductAuthorityResolver(
		authority.ParentPlanDigest(), authority.OperationID(), plans, loadingFailure, verifier, platform,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveProductRuntime(t.Context()); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("operation loading error=%v", err)
	}
	var absent *nativeProductAuthorityResolver
	if _, err := absent.ResolveProductRuntime(t.Context()); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("absent resolver error=%v", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := resolver.ResolveProductRuntime(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled resolver error=%v", err)
	}

	operation, err := install.NewOperation(authority.OperationID(), authority.ParentPlanDigest())
	if err != nil {
		t.Fatal(err)
	}
	resolver.operations = &nativeCancellationRepository{operation: operation}
	if _, err := resolver.ResolveProductRuntime(t.Context()); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("incomplete runtime phase error=%v", err)
	}
	if candidate, err := newNativeProductAuthorityResolver(
		install.PlanDigest{}, install.OperationID{}, nil, nil, nil, nil,
	); candidate != nil || !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("incomplete resolver=%+v error=%v", candidate, err)
	}
}

func TestPF001NativeProductExecutorsRejectIncompleteSignedRuntimeAuthority(t *testing.T) {
	t.Parallel()
	var absent *nativePlatformRuntimeFactory
	if _, err := absent.buildProductExecutors(t.Context(), nativeVerifiedRuntimeExecution{}); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("absent factory error=%v", err)
	}
	factory := &nativePlatformRuntimeFactory{release: &nativeReleaseAuthority{}}
	if _, err := factory.buildProductExecutors(t.Context(), nativeVerifiedRuntimeExecution{}); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("incomplete authority error=%v", err)
	}
	request, authority, certified := nativeRuntimeExecutionFixture(t)
	if _, err := factory.buildPlatformProductExecutors(t.Context(), nativeVerifiedRuntimeExecution{
		request: request, authority: authority, runtime: certified,
	}); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("unverified desktop authority error=%v", err)
	}
	if _, err := factory.buildPlatformProductExecutors(t.Context(), nativeVerifiedRuntimeExecution{}); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("foreign platform authority error=%v", err)
	}
	wantLinuxError := errNativeInstallerUnavailable
	if runtime.GOOS == "linux" {
		wantLinuxError = errNativeInstallerIntegrity
	}
	if _, err := factory.buildLinuxProductExecutors(t.Context(), nativeVerifiedRuntimeExecution{}); !errors.Is(err, wantLinuxError) {
		t.Fatalf("Linux executor error=%v want=%v", err, wantLinuxError)
	}
}

func nativeProductEvidence(
	t testing.TB,
	phase install.Phase,
	plan install.PlanDigest,
	ownership install.RuntimeOwnership,
) install.StepEvidence {
	t.Helper()
	compensation, err := install.NewCompensationBoundary("retain.runtime")
	if err != nil {
		t.Fatal(err)
	}
	action, err := install.NewSafeAction("installation.continue")
	if err != nil {
		t.Fatal(err)
	}
	input := install.StepEvidenceInput{
		Phase: phase, Attempt: 1, PlanDigest: plan,
		InputDigest: install.DigestBytes([]byte("input")), OutputDigest: install.DigestBytes([]byte("output")),
		RuntimeOwnership: ownership, CompensationBoundary: compensation, NextSafeAction: action,
	}
	if phase == install.PhaseEnsureContainerRuntime {
		input.VerifiedArtifactDigest = install.DigestBytes([]byte("runtime receipt"))
	}
	evidence, err := install.NewStepEvidence(input)
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func nativeProductStackAuthorization(
	t testing.TB,
	operationID install.OperationID,
	plan install.PlanDigest,
	endpoint containerengine.Endpoint,
) productstack.Authorization {
	return nativeProductStackAuthorizationFor(t, productstack.OperationMigrate, operationID, plan, endpoint)
}

func nativeProductStackAuthorizationFor(
	t testing.TB,
	operation productstack.Operation,
	operationID install.OperationID,
	plan install.PlanDigest,
	endpoint containerengine.Endpoint,
) productstack.Authorization {
	t.Helper()
	identity, err := composeplan.NewIdentity(
		"019f5f23-5678-7def-9123-abcdef012347",
		"019f5f23-5678-7def-8123-abcdef012348",
	)
	if err != nil {
		t.Fatal(err)
	}
	source, err := containerengine.NewComposeReleaseSource(
		endpoint,
		identity,
		"v1.0.0",
		"/tmp/agentmemory/release",
		"/tmp/agentmemory/release/compose.yaml",
		"/tmp/agentmemory/release/empty.env",
		artifactDigest("compose"),
		120,
	)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := productstack.NewAuthorization(
		operation,
		operationID,
		plan,
		1,
		install.RuntimeOwnershipProvisionedByAgentMemory,
		source,
	)
	if err != nil {
		t.Fatal(err)
	}
	return authorization
}

func artifactDigest(value string) releaseinventory.Digest {
	return releaseinventory.DigestBytes([]byte(value))
}

type nativeProductRuntimeResolverStub struct {
	runtime nativeProductRuntime
	err     error
	calls   int
}

func (s *nativeProductRuntimeResolverStub) ResolveProductRuntime(context.Context) (nativeProductRuntime, error) {
	s.calls++
	return s.runtime, s.err
}

type nativeProductCapacityStub struct{ calls int }

func (s *nativeProductCapacityStub) result() (artifactapp.CapacityResult, error) {
	s.calls++
	return artifactapp.CapacityResult{}, nil
}

func (s *nativeProductCapacityStub) ReserveCapacity(context.Context, artifactapp.CapacityCommand) (artifactapp.CapacityResult, error) {
	return s.result()
}
func (s *nativeProductCapacityStub) ConsumeArtifactExpansion(context.Context, artifactapp.CapacityCommand, string) (artifactapp.CapacityResult, error) {
	return s.result()
}
func (s *nativeProductCapacityStub) PrepareSecretProjectionCapacity(context.Context, artifactapp.CapacityCommand, string) (artifactapp.CapacityResult, error) {
	return s.result()
}
func (s *nativeProductCapacityStub) TransferActivationCapacity(context.Context, artifactapp.CapacityCommand, string, string) (artifactapp.CapacityResult, error) {
	return s.result()
}
func (s *nativeProductCapacityStub) ReleaseOperationCapacity(context.Context, artifactapp.CapacityCommand) (artifactapp.CapacityResult, error) {
	return s.result()
}
func (s *nativeProductCapacityStub) CompensateOperationCapacity(context.Context, artifactapp.CapacityCommand) (artifactapp.CapacityResult, error) {
	return s.result()
}
func (s *nativeProductCapacityStub) ReleaseActivatedCapacity(context.Context, artifactapp.CapacityCommand, string, string) (artifactapp.CapacityResult, error) {
	return s.result()
}

type nativeProductResourceStub struct{ calls int }

func (s *nativeProductResourceStub) EnsureNetworkAndVolumes(context.Context, resourceapp.Command) (resourceapp.Result, error) {
	s.calls++
	return resourceapp.Result{}, nil
}

type nativeProductStackStub struct {
	migrations int
	starts     int
}

func (s *nativeProductStackStub) RunMigrations(context.Context, productstack.Authorization) (productstack.Receipt, error) {
	s.migrations++
	return productstack.Receipt{}, nil
}

func (s *nativeProductStackStub) StartCoreAndGraph(context.Context, productstack.Authorization) (productstack.Receipt, error) {
	s.starts++
	return productstack.Receipt{}, nil
}
