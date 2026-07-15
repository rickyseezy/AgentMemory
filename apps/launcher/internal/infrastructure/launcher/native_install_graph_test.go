package launcher

import (
	"context"
	"reflect"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/activereleaseapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/agentconfigapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/hostverifyapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installphase"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/brainbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productinstall"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productstack"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/readinessapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/rebootapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/resourceapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeinstallapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/installplan"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/readiness"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/resourceinventory"
)

func TestPF001NativeInstallGraphComposesAllFourteenProductionPhases(t *testing.T) {
	t.Parallel()
	dependencies := nativeInstallGraphFixture()
	factory, err := newNativeInstallApplicationFactory(dependencies)
	if err != nil || factory == nil {
		t.Fatalf("factory=(%v,%v)", factory, err)
	}
	authority := nativeInstallAuthority{
		OperationID: nativeGraphOperationID(t),
		PlanDigest:  nativeGraphPlanDigest(t), CanonicalPlan: []byte("canonical"),
	}
	application, err := factory(t.Context(), authority)
	if err != nil || application == nil {
		t.Fatalf("application=(%v,%v)", application, err)
	}
	if _, ok := application.(*installapp.InstallApplication); !ok {
		t.Fatalf("application type=%T", application)
	}
}

func TestPF001NativeInstallGraphRejectsEveryMissingProductionCapability(t *testing.T) {
	t.Parallel()
	base := nativeInstallGraphFixture()
	value := reflect.ValueOf(&base).Elem()
	typeOfDependencies := value.Type()
	for index := 0; index < value.NumField(); index++ {
		candidate := base
		field := reflect.ValueOf(&candidate).Elem().Field(index)
		field.Set(reflect.Zero(field.Type()))
		if factory, err := newNativeInstallApplicationFactory(candidate); factory != nil || err == nil {
			t.Fatalf("missing %s accepted: factory=%v error=%v", typeOfDependencies.Field(index).Name, factory, err)
		}
	}
	foreignAuthority := &nativeGraphOperations{}
	candidate := base
	candidate.Cancellation = foreignAuthority
	if factory, err := newNativeInstallApplicationFactory(candidate); factory != nil || err == nil {
		t.Fatalf("split operation/cancellation authority accepted: factory=%v error=%v", factory, err)
	}
}

func TestPF001NativeInstallGraphRejectsInvalidOperationAuthority(t *testing.T) {
	t.Parallel()
	factory, err := newNativeInstallApplicationFactory(nativeInstallGraphFixture())
	if err != nil {
		t.Fatal(err)
	}
	for name, authority := range map[string]nativeInstallAuthority{
		"empty":          {},
		"operation":      {PlanDigest: nativeGraphPlanDigest(t), CanonicalPlan: []byte("canonical")},
		"plan digest":    {OperationID: nativeGraphOperationID(t), CanonicalPlan: []byte("canonical")},
		"canonical plan": {OperationID: nativeGraphOperationID(t), PlanDigest: nativeGraphPlanDigest(t)},
	} {
		if application, buildError := factory(t.Context(), authority); application != nil || buildError == nil {
			t.Fatalf("%s authority accepted: application=%v error=%v", name, application, buildError)
		}
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if application, buildError := factory(cancelled, nativeInstallAuthority{
		OperationID: nativeGraphOperationID(t), PlanDigest: nativeGraphPlanDigest(t), CanonicalPlan: []byte("canonical"),
	}); application != nil || buildError == nil {
		t.Fatalf("cancelled authority accepted: application=%v error=%v", application, buildError)
	}
}

func nativeInstallGraphFixture() nativeInstallGraphDependencies {
	operations := &nativeGraphOperations{}
	return nativeInstallGraphDependencies{
		Plans: &nativeGraphPlans{}, RuntimePlans: &nativeGraphRuntimePlans{},
		RuntimeEvidence: &nativeGraphRuntimeEvidence{}, Operations: operations,
		Cancellation: operations, ReadinessReceipts: &nativeGraphReadinessReceipts{},
		ResourceInventory: &nativeGraphResourceInventory{}, InstallationLock: &nativeGraphLockPort{},
		RebootCoordinator: &nativeGraphReboot{},
		HostVerifier:      &nativeGraphHost{}, RuntimeEnsurer: func(
			context.Context, *installplanapp.Application, nativeInstallAuthority,
		) (installphase.RuntimeEnsurer, error) {
			return &nativeGraphRuntime{}, nil
		},
		ProductApplications: func(
			context.Context, *installplanapp.Application, nativeInstallAuthority,
		) (nativeProductCapabilities, error) {
			return nativeProductCapabilities{
				Capacity:         &nativeGraphCapacity{},
				ManagedResources: &nativeGraphResources{},
				ProductStack:     &nativeGraphStack{},
			}, nil
		},
		ReleaseVerifier: &nativeGraphRelease{}, Artifacts: &nativeGraphArtifacts{},
		Directories: &nativeGraphDirectories{}, Secrets: &nativeGraphSecrets{},
		BrainBootstrap:     &nativeGraphBrain{},
		AgentConfiguration: &nativeGraphAgent{}, Readiness: &nativeGraphReadiness{},
		ActiveRelease: &nativeGraphActiveRelease{},
	}
}

func nativeGraphOperationID(t testing.TB) install.OperationID {
	t.Helper()
	value, err := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func nativeGraphPlanDigest(t testing.TB) install.PlanDigest {
	t.Helper()
	value, err := install.BindPlan([]byte("canonical"))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

type nativeGraphPlans struct{}

func (*nativeGraphPlans) Save(context.Context, installplan.Plan) error { return nil }
func (*nativeGraphPlans) Load(context.Context, install.PlanDigest) (installplan.Plan, error) {
	return installplan.Plan{}, nil
}

type nativeGraphRuntimePlans struct{}

func (*nativeGraphRuntimePlans) LoadRuntimePlan(context.Context, install.OperationID, install.PlanDigest) (installplanapp.RuntimePlanAuthority, error) {
	return installplanapp.RuntimePlanAuthority{}, nil
}
func (*nativeGraphRuntimePlans) SaveRuntimePlan(context.Context, installplanapp.RuntimePlanAuthority) error {
	return nil
}

type nativeGraphRuntimeEvidence struct{}

func (*nativeGraphRuntimeEvidence) ResolveRuntimeEvidence(context.Context, installplanapp.RuntimeEvidenceRequest) (installplanapp.RuntimeEvidence, error) {
	return installplanapp.RuntimeEvidence{}, nil
}

// A blank byte gives each pointer distinct identity. Go may coalesce pointers
// to separate zero-sized values, which would invalidate this authority-split
// security test on some architectures.
type nativeGraphOperations struct{ _ byte }

func (*nativeGraphOperations) Load(context.Context, install.OperationID) (*install.Operation, error) {
	return nil, nil
}
func (*nativeGraphOperations) Save(context.Context, install.OperationSnapshot) error { return nil }
func (*nativeGraphOperations) Request(context.Context, installapp.CancellationRequest) (installapp.CancellationIntent, error) {
	return installapp.CancellationIntent{}, nil
}
func (*nativeGraphOperations) Observe(context.Context, install.OperationID, install.PlanDigest) (installapp.CancellationIntent, error) {
	return installapp.CancellationIntent{}, nil
}
func (*nativeGraphOperations) Wait(context.Context, install.OperationID, install.PlanDigest) (installapp.CancellationIntent, error) {
	return installapp.CancellationIntent{}, nil
}
func (*nativeGraphOperations) Acknowledge(context.Context, installapp.CancellationIntent, install.State) (installapp.CancellationIntent, error) {
	return installapp.CancellationIntent{}, nil
}

type nativeGraphReadinessReceipts struct{}

func (*nativeGraphReadinessReceipts) LoadReadinessReceipt(context.Context, install.Digest) (readiness.Receipt, error) {
	return readiness.Receipt{}, nil
}

type nativeGraphResourceInventory struct{}

func (*nativeGraphResourceInventory) Load(context.Context, string) (resourceinventory.Snapshot, error) {
	return resourceinventory.Snapshot{}, nil
}

type nativeGraphLockPort struct{}

type nativeGraphReboot struct{}

func (*nativeGraphReboot) Register(context.Context, rebootapp.Binding) error { return nil }
func (*nativeGraphReboot) Consume(context.Context, rebootapp.Binding) error  { return nil }
func (*nativeGraphReboot) Remove(context.Context, install.OperationID) error { return nil }

func (*nativeGraphLockPort) Acquire(context.Context) (installapp.InstallationLock, error) {
	return nativeGraphLock{}, nil
}

type nativeGraphHost struct{}

func (*nativeGraphHost) Verify(context.Context, hostverifyapp.Command) (hostverifyapp.Verification, error) {
	return hostverifyapp.Verification{}, nil
}

type nativeGraphRuntime struct{}

func (*nativeGraphRuntime) Ensure(context.Context, runtimeinstallapp.Command) (runtimeinstallapp.Result, error) {
	return runtimeinstallapp.Result{}, nil
}

type nativeGraphRelease struct{}

func (*nativeGraphRelease) VerifyRelease(context.Context, releaseinventory.SignedManifest) (installphase.VerifiedRelease, error) {
	return installphase.VerifiedRelease{}, nil
}

type nativeGraphArtifacts struct{}

func (*nativeGraphArtifacts) ReserveSpace(context.Context, artifactapp.Command) (artifactapp.ReserveResult, error) {
	return artifactapp.ReserveResult{}, nil
}
func (*nativeGraphArtifacts) Acquire(context.Context, artifactapp.Command) (artifactapp.AcquireResult, error) {
	return artifactapp.AcquireResult{}, nil
}
func (*nativeGraphArtifacts) ReleaseReservation(context.Context, artifactapp.Command, artifactacquisition.ReleaseReason) (artifactapp.ReleaseResult, error) {
	return artifactapp.ReleaseResult{}, nil
}
func (*nativeGraphArtifacts) ReleaseReservationIfPresent(context.Context, artifactapp.Command, artifactacquisition.ReleaseReason) (artifactapp.ReleaseResult, error) {
	return artifactapp.ReleaseResult{}, nil
}

type nativeGraphCapacity struct{}

func (*nativeGraphCapacity) ReserveCapacity(context.Context, artifactapp.CapacityCommand) (artifactapp.CapacityResult, error) {
	return artifactapp.CapacityResult{}, nil
}
func (*nativeGraphCapacity) ConsumeArtifactExpansion(context.Context, artifactapp.CapacityCommand, string) (artifactapp.CapacityResult, error) {
	return artifactapp.CapacityResult{}, nil
}
func (*nativeGraphCapacity) PrepareSecretProjectionCapacity(context.Context, artifactapp.CapacityCommand, string) (artifactapp.CapacityResult, error) {
	return artifactapp.CapacityResult{}, nil
}
func (*nativeGraphCapacity) TransferActivationCapacity(context.Context, artifactapp.CapacityCommand, string, string) (artifactapp.CapacityResult, error) {
	return artifactapp.CapacityResult{}, nil
}
func (*nativeGraphCapacity) ReleaseOperationCapacity(context.Context, artifactapp.CapacityCommand) (artifactapp.CapacityResult, error) {
	return artifactapp.CapacityResult{}, nil
}
func (*nativeGraphCapacity) CompensateOperationCapacity(context.Context, artifactapp.CapacityCommand) (artifactapp.CapacityResult, error) {
	return artifactapp.CapacityResult{}, nil
}
func (*nativeGraphCapacity) ReleaseActivatedCapacity(context.Context, artifactapp.CapacityCommand, string, string) (artifactapp.CapacityResult, error) {
	return artifactapp.CapacityResult{}, nil
}

type nativeGraphDirectories struct{}

func (*nativeGraphDirectories) EnsureDirectories(context.Context, productinstall.DirectoryCommand) (productinstall.DirectoryReceipt, error) {
	return productinstall.DirectoryReceipt{}, nil
}

type nativeGraphSecrets struct{}

func (*nativeGraphSecrets) EnsureSecrets(context.Context, productinstall.SecretCommand) (productinstall.SecretReceipt, error) {
	return productinstall.SecretReceipt{}, nil
}

type nativeGraphResources struct{}

func (*nativeGraphResources) EnsureNetworkAndVolumes(context.Context, resourceapp.Command) (resourceapp.Result, error) {
	return resourceapp.Result{}, nil
}

type nativeGraphStack struct{}

func (*nativeGraphStack) RunMigrations(context.Context, productstack.Authorization) (productstack.Receipt, error) {
	return productstack.Receipt{}, nil
}
func (*nativeGraphStack) StartCoreAndGraph(context.Context, productstack.Authorization) (productstack.Receipt, error) {
	return productstack.Receipt{}, nil
}

type nativeGraphBrain struct{}

func (*nativeGraphBrain) BootstrapLocalBrain(context.Context, brainbootstrap.Authorization) (brainbootstrap.Receipt, error) {
	return brainbootstrap.Receipt{}, nil
}

type nativeGraphAgent struct{}

func (*nativeGraphAgent) Merge(context.Context, agentconfigapp.MergeRequest) (agentconfigapp.MergeResult, error) {
	return agentconfigapp.MergeResult{}, nil
}

type nativeGraphReadiness struct{}

func (*nativeGraphReadiness) Verify(context.Context, readinessapp.Command) (readinessapp.Verification, error) {
	return readinessapp.Verification{}, nil
}

type nativeGraphActiveRelease struct{}

func (*nativeGraphActiveRelease) Commit(context.Context, activereleaseapp.Command) (activereleaseapp.Result, error) {
	return activereleaseapp.Result{}, nil
}

type nativeGraphLock struct{}

func (nativeGraphLock) Release(context.Context) error { return nil }
