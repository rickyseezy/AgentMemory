package installplanapp

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productinstall"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productstack"
	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/installplan"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/readiness"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/resourceinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestApplicationProjectsEveryStaticPlanBinding(t *testing.T) {
	t.Parallel()
	plan := applicationPlan(t)
	fixture := newApplicationFixture(t, plan)
	application, err := New(fixture.dependencies())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	host, err := application.ResolveHostVerificationPlan(ctx, plan.Digest())
	if err != nil || !host.ParentPlanDigest.Equal(plan.Digest()) || !host.SignedHostPlan.Valid() ||
		!host.SignedHostPlan.Plan().Digest().Equal(plan.SignedHostPlan().Plan().Digest()) ||
		host.StorageTarget != plan.HostStorageTarget() ||
		host.RuntimeOwnership != install.RuntimeOwnershipUndetermined {
		t.Fatalf("host projection = %+v/%v", host, err)
	}
	release, err := application.ResolveReleasePlan(ctx, plan.Digest())
	if err != nil || !release.PlanDigest.Equal(plan.Digest()) || release.ReleaseID != "agentmemory-1.0.0" ||
		release.ReleaseSequence != 42 || release.ManifestDigest.IsZero() ||
		release.RuntimeOwnership != install.RuntimeOwnershipProvisionedByAgentMemory {
		t.Fatalf("release projection = %+v/%v", release, err)
	}
	artifacts, err := application.ResolveArtifactAcquisitionPlan(ctx, plan.Digest())
	if err != nil || !artifacts.ParentPlanDigest.Equal(plan.Digest()) || artifacts.AcquisitionPlanDigest.IsZero() ||
		artifacts.ComposeArtifactID != "compose" || artifacts.HostCASCapacity.Kind != artifactapp.CapacityHostCAS ||
		artifacts.DockerEngineCapacity.Kind != artifactapp.CapacityDockerEngine ||
		artifacts.DockerVolumeCapacity.Kind != artifactapp.CapacityDockerDataVolume {
		t.Fatalf("artifact projection = %+v/%v", artifacts, err)
	}
	network, err := application.ResolveNetworkVolumePlan(ctx, plan.Digest())
	if err != nil || !network.PlanDigest.Equal(plan.Digest()) || network.InstallationID != plan.InstallationID() ||
		network.GenerationID != plan.GenerationID() || network.Release != "agentmemory-1.0.0" ||
		network.CreationOperation != plan.OperationID().String() || network.Endpoint.String() != plan.RuntimeEndpoint() {
		t.Fatalf("network projection = %+v/%v", network, err)
	}
	readiness, err := application.ResolveReadinessPlan(ctx, plan.Digest())
	if err != nil || !readiness.PlanDigest.Equal(plan.Digest()) || readiness.ReleaseID != "agentmemory-1.0.0" ||
		readiness.GenerationID != plan.GenerationID() || readiness.ManifestDigest.IsZero() ||
		!readiness.ComposeDigest.Equal(applicationNormalizedComposeDigest()) ||
		readiness.CoreEndpoint != plan.Product().CoreEndpoint() || readiness.APICredentialPath == "" {
		t.Fatalf("readiness projection = %+v/%v", readiness, err)
	}
	agent, err := application.ResolveAgentConfigurationPlan(ctx, plan.Digest(), plan.OperationID(), 12)
	if err != nil || !agent.ParentPlanDigest().Equal(plan.Digest()) || agent.OperationID() != plan.OperationID() ||
		agent.Attempt() != 12 || agent.Location().String() != "/home/user/.agent/config.json" ||
		agent.Target().Command() != "/opt/agentmemory/bin/agentmemory" || agent.ParentBindingDigest().IsZero() {
		t.Fatalf("agent projection = %+v/%v", agent, err)
	}
	directories, err := application.ResolveDirectoryCommand(ctx, plan.Digest(), plan.OperationID(), 12)
	if err != nil || !directories.Valid() || directories.OperationID() != plan.OperationID() ||
		!directories.ParentPlanDigest().Equal(plan.Digest()) || directories.Attempt() != 12 ||
		len(directories.Directories()) != 6 ||
		directories.Directories()[0].Purpose() != productinstall.DirectoryBackups {
		t.Fatalf("directory command = %+v/%v", directories, err)
	}
	secrets, err := application.ResolveSecretCommand(ctx, plan.Digest(), plan.OperationID(), 12)
	if err != nil || !secrets.Valid() || secrets.OperationID() != plan.OperationID() ||
		!secrets.ParentPlanDigest().Equal(plan.Digest()) || secrets.Attempt() != 12 ||
		secrets.SecretDirectory() != plan.Product().SecretDirectory() || len(secrets.Secrets()) != 7 ||
		secrets.Secrets()[0].Purpose() != installplan.SecretAPICredential {
		t.Fatalf("secret command = %+v/%v", secrets, err)
	}
	for _, operation := range []productstack.Operation{
		productstack.OperationMigrate,
		productstack.OperationStartCoreAndGraph,
	} {
		authorization, stackError := application.ResolveStackAuthorization(
			ctx, plan.Digest(), plan.OperationID(), 12, operation,
		)
		if stackError != nil || !authorization.Valid() || authorization.Operation() != operation ||
			authorization.OperationID() != plan.OperationID() ||
			!authorization.ParentPlanDigest().Equal(plan.Digest()) || authorization.Attempt() != 12 ||
			authorization.Source().Endpoint().String() != plan.RuntimeEndpoint() ||
			authorization.Source().ConfigurationPath() != plan.Product().ComposeConfigurationPath() ||
			authorization.Source().EmptyEnvironmentPath() != plan.Product().EmptyEnvironmentPath() {
			t.Fatalf("stack authorization %q = %+v/%v", operation, authorization, stackError)
		}
		composeArtifact, _ := plan.AcquisitionPlan().Artifact(plan.ComposeArtifactID())
		if !authorization.Source().SourceDigest().Equal(composeArtifact.Digest()) {
			t.Fatal("stack authorization lost signed Compose source digest")
		}
	}
	brain, err := application.ResolveBrainBootstrapAuthorization(ctx, plan.Digest(), plan.OperationID(), 13)
	if err != nil || !brain.Valid() || brain.OperationID() != plan.OperationID() ||
		!brain.ParentPlanDigest().Equal(plan.Digest()) || brain.Attempt() != 13 ||
		brain.CoreEndpoint() != plan.Product().CoreEndpoint() ||
		brain.BrainID() != plan.Product().InitialBrainID() ||
		brain.BrainName() != plan.Product().InitialBrainName() ||
		brain.OwnerPrincipalID() != plan.Product().OwnerPrincipalID() ||
		brain.APICredentialPath() != plan.Product().SecretFiles()[0].Path() {
		t.Fatalf("Brain bootstrap authorization = %+v/%v", brain, err)
	}
}

func TestApplicationDerivesRuntimeAndActivationFromAuthenticatedEvidence(t *testing.T) {
	t.Parallel()
	plan := applicationPlan(t)
	fixture := newApplicationFixture(t, plan)
	application, err := New(fixture.dependencies())
	if err != nil {
		t.Fatal(err)
	}
	runtimePlan, err := application.ResolveRuntimePlan(context.Background(), plan.Digest(), plan.OperationID())
	if err != nil || !runtimePlan.ParentPlanDigest().Equal(plan.Digest()) ||
		runtimePlan.PlanDigest() != runtimeinstall.Sum(runtimePlan.CanonicalPlan()) ||
		!runtimePlan.SignedCatalogEvidenceDigest().Equal(fixture.runtimeEvidence.evidence.SignedCatalogEvidenceDigest()) ||
		runtimePlan.SignedCatalogEvidenceDigest().Equal(plan.RuntimeCatalogDigest()) || fixture.runtimeEvidence.calls != 1 ||
		!fixture.runtimeEvidence.request.SignedHostPlan.Valid() ||
		!fixture.runtimeEvidence.request.SignedHostPlan.Plan().Digest().Equal(plan.SignedHostPlan().Plan().Digest()) ||
		!fixture.runtimeEvidence.request.HostEvidenceDigest.Equal(fixture.runtimeEvidence.evidence.HostEvidenceDigest()) ||
		fixture.runtimeEvidence.request.HostStorageTarget != plan.HostStorageTarget() ||
		fixture.runtimeEvidence.request.RuntimeEndpoint != plan.RuntimeEndpoint() {
		t.Fatalf("runtime projection = %+v/%v", runtimePlan, err)
	}
	if _, err := runtimeinstall.DecodePlanV1(runtimePlan.CanonicalPlan()); err != nil {
		t.Fatalf("runtime canonical plan = %v", err)
	}
	if _, err := application.ResolveRuntimePlan(context.Background(), plan.Digest(), plan.OperationID()); err != nil || fixture.runtimeEvidence.calls != 1 {
		t.Fatalf("runtime replay = %v/calls=%d", err, fixture.runtimeEvidence.calls)
	}
	activation, err := application.ResolveActivationPlan(context.Background(), plan.Digest(), plan.OperationID())
	if err != nil || !activation.PlanDigest.Equal(plan.Digest()) || activation.InstallationID != plan.InstallationID() ||
		!activation.ReadinessReceiptDigest.Equal(fixture.receipt.Digest()) ||
		activation.ResourceInventoryVersion != fixture.inventory.Version || activation.ResourceInventoryDigest.IsZero() ||
		activation.CapacityCommand.OperationID != plan.OperationID().String() ||
		activation.CapacityCommand.Plan.Digest().IsZero() {
		t.Fatalf("activation projection = %+v/%v", activation, err)
	}
	foreignOperation, _ := install.NewOperationID("019f5f9f-0000-7abc-8123-0123456789ab")
	if _, err := application.ResolveRuntimePlan(context.Background(), plan.Digest(), foreignOperation); !errors.Is(err, ErrRuntimeEvidenceUnavailable) {
		t.Fatalf("foreign runtime operation error = %v", err)
	}
	if _, err := application.ResolveActivationPlan(context.Background(), plan.Digest(), foreignOperation); !errors.Is(err, ErrActivationEvidenceUnavailable) {
		t.Fatalf("foreign activation operation error = %v", err)
	}
}

func TestPF001PristineTemplateDerivesRuntimeOwnershipOnlyFromAuthenticatedRuntimeEvidence(t *testing.T) {
	t.Parallel()
	template := applicationPlan(t)
	product := applicationProductInput()
	agent := template.AgentConfiguration()
	plan, err := installplan.RebindV1(template, installplan.RebindInput{
		OperationID: template.OperationID(), InstallationID: template.InstallationID(),
		GenerationID: template.GenerationID(), RuntimeEndpoint: template.RuntimeEndpoint(),
		SecurityEpoch: template.SecurityEpoch(), HostStorageTarget: "/home/user/.agentmemory",
		Product: product,
		Capacity: installplan.CapacityInput{
			HostCAS: "/var/lib/agentmemory/cas", HostRelease: product.ReleaseDirectory,
			DockerEngine: template.RuntimeEndpoint(), DockerDataVolume: "agentmemory-core-data",
		},
		AgentConfiguration: installplan.AgentConfigurationInput{
			AgentHost: agent.AgentHost(), ConfigLocation: agent.ConfigLocation(), EntryID: agent.EntryID(),
			ExpectedManagedEntryDigest: agent.ExpectedManagedEntryDigest(), LauncherDigest: agent.LauncherDigest(),
			LauncherPath: agent.LauncherPath(),
		},
	})
	if err != nil || plan.RuntimeOwnership() != install.RuntimeOwnershipUndetermined {
		t.Fatalf("RebindV1() ownership=%s error=%v", plan.RuntimeOwnership(), err)
	}
	fixture := newApplicationFixture(t, plan)
	application, err := New(fixture.dependencies())
	if err != nil {
		t.Fatal(err)
	}
	release, err := application.ResolveReleasePlan(context.Background(), plan.Digest())
	if err != nil || release.RuntimeOwnership != install.RuntimeOwnershipProvisionedByAgentMemory {
		t.Fatalf("runtime ownership=%s error=%v", release.RuntimeOwnership, err)
	}

	fixture.operations.operation = nil
	if _, err := application.ResolveReleasePlan(context.Background(), plan.Digest()); !errors.Is(err, ErrPlanIntegrity) {
		t.Fatalf("missing runtime evidence error=%v", err)
	}
}

func TestApplicationRuntimeAuthorityFailsClosedAndReconcilesOnePublisherRace(t *testing.T) {
	t.Parallel()
	privateFailure := errors.New("private runtime authority failure")
	tests := []struct {
		name      string
		configure func(testing.TB, *applicationFixture)
		want      error
	}{
		{name: "repository failure", configure: func(_ testing.TB, fixture *applicationFixture) {
			fixture.runtimePlans.loadErr = privateFailure
		}, want: privateFailure},
		{name: "resolver failure", configure: func(_ testing.TB, fixture *applicationFixture) {
			fixture.runtimeEvidence.err = privateFailure
		}, want: ErrRuntimeEvidenceUnavailable},
		{name: "foreign host evidence", configure: func(t testing.TB, fixture *applicationFixture) {
			base := fixture.runtimeEvidence.evidence
			foreign, err := NewRuntimeEvidence(
				base.Host(), base.Discovery(), base.Catalog(), install.DigestBytes([]byte("foreign host")),
				base.DiscoveryEvidenceDigest(), base.CatalogResourceEvidenceDigest(),
				base.SignedCatalogEvidenceDigest(),
			)
			if err != nil {
				t.Fatal(err)
			}
			fixture.runtimeEvidence.evidence = foreign
		}, want: ErrRuntimeEvidenceUnavailable},
		{name: "terminal parent operation", configure: func(t testing.TB, fixture *applicationFixture) {
			if err := fixture.operations.operation.Cancel(fixture.plan.Digest()); err != nil {
				t.Fatal(err)
			}
		}, want: ErrRuntimeEvidenceUnavailable},
		{name: "immutable publication race", configure: func(_ testing.TB, fixture *applicationFixture) {
			fixture.runtimePlans.conflictReplay = true
		}},
		{name: "foreign immutable conflict", configure: func(_ testing.TB, fixture *applicationFixture) {
			fixture.runtimePlans.saveErr = ErrRuntimePlanConflict
		}, want: ErrRuntimePlanConflict},
		{name: "persisted host contradiction", configure: func(t testing.TB, fixture *applicationFixture) {
			application, err := New(fixture.dependencies())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := application.ResolveRuntimePlan(t.Context(), fixture.plan.Digest(), fixture.plan.OperationID()); err != nil {
				t.Fatal(err)
			}
			persisted := fixture.runtimePlans.authority
			contradictory, err := NewRuntimePlanAuthority(
				persisted.OperationID(), persisted.ParentPlanDigest(), persisted.Plan(),
				install.DigestBytes([]byte("foreign host")), persisted.DiscoveryEvidenceDigest(),
				persisted.CatalogResourceEvidenceDigest(), persisted.SignedCatalogEvidenceDigest(),
			)
			if err != nil {
				t.Fatal(err)
			}
			fixture.runtimePlans.authority = contradictory
		}, want: ErrRuntimePlanIntegrity},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			plan := applicationPlan(t)
			fixture := newApplicationFixture(t, plan)
			test.configure(t, fixture)
			application, err := New(fixture.dependencies())
			if err != nil {
				t.Fatal(err)
			}
			_, actual := application.ResolveRuntimePlan(t.Context(), plan.Digest(), plan.OperationID())
			if test.want == nil && actual != nil {
				t.Fatalf("ResolveRuntimePlan() error = %v", actual)
			}
			if test.want != nil && !errors.Is(actual, test.want) {
				t.Fatalf("ResolveRuntimePlan() error = %v, want %v", actual, test.want)
			}
		})
	}
}

func TestApplicationActivationRejectsMissingOrContradictoryDurableEvidence(t *testing.T) {
	t.Parallel()
	privateFailure := errors.New("private activation repository failure")
	tests := []struct {
		name      string
		configure func(testing.TB, *applicationFixture)
		want      error
	}{
		{name: "operation failure", configure: func(_ testing.TB, fixture *applicationFixture) {
			fixture.operations.err = privateFailure
		}, want: ErrActivationEvidenceUnavailable},
		{name: "missing readiness phase", configure: func(t testing.TB, fixture *applicationFixture) {
			operation, err := install.NewOperation(fixture.plan.OperationID(), fixture.plan.Digest())
			if err != nil {
				t.Fatal(err)
			}
			fixture.operations.operation = operation
		}, want: ErrActivationEvidenceUnavailable},
		{name: "cancelled after readiness", configure: func(t testing.TB, fixture *applicationFixture) {
			if err := fixture.operations.operation.Cancel(fixture.plan.Digest()); err != nil {
				t.Fatal(err)
			}
		}, want: ErrActivationEvidenceUnavailable},
		{name: "receipt repository failure", configure: func(_ testing.TB, fixture *applicationFixture) {
			fixture.receipts.err = privateFailure
		}, want: privateFailure},
		{name: "missing receipt", configure: func(_ testing.TB, fixture *applicationFixture) {
			fixture.receipts.receipt = readiness.Receipt{}
		}, want: ErrActivationEvidenceUnavailable},
		{name: "inventory repository failure", configure: func(_ testing.TB, fixture *applicationFixture) {
			fixture.resources.err = privateFailure
		}, want: privateFailure},
		{name: "pending inventory member", configure: func(_ testing.TB, fixture *applicationFixture) {
			fixture.resources.snapshot.Entries[0].State = string(resourceinventory.EntryPending)
			fixture.resources.snapshot.Entries[0].ObjectID = ""
		}, want: ErrActivationEvidenceUnavailable},
		{name: "foreign creation operation", configure: func(_ testing.TB, fixture *applicationFixture) {
			fixture.resources.snapshot.Entries[0].CreationOperation = "019f5f9f-0000-7abc-8123-0123456789ab"
		}, want: ErrActivationEvidenceUnavailable},
		{name: "missing inventory member", configure: func(_ testing.TB, fixture *applicationFixture) {
			fixture.resources.snapshot.Entries = fixture.resources.snapshot.Entries[1:]
		}, want: ErrActivationEvidenceUnavailable},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			plan := applicationPlan(t)
			fixture := newApplicationFixture(t, plan)
			test.configure(t, fixture)
			application, err := New(fixture.dependencies())
			if err != nil {
				t.Fatal(err)
			}
			_, actual := application.ResolveActivationPlan(t.Context(), plan.Digest(), plan.OperationID())
			if !errors.Is(actual, test.want) {
				t.Fatalf("ResolveActivationPlan() error = %v, want %v", actual, test.want)
			}
		})
	}
}

func TestApplicationFailsClosedForForeignStaticEvidence(t *testing.T) {
	t.Parallel()
	plan := applicationPlan(t)
	fixture := newApplicationFixture(t, plan)
	application, err := New(fixture.dependencies())
	if err != nil {
		t.Fatal(err)
	}
	foreignOperation, _ := install.NewOperationID("019f5f9f-0000-7abc-8123-0123456789ab")
	if _, err := application.ResolveAgentConfigurationPlan(context.Background(), plan.Digest(), foreignOperation, 1); !errors.Is(err, ErrPlanIntegrity) {
		t.Fatalf("foreign operation error = %v", err)
	}
	foreign, _ := install.BindPlan([]byte("foreign plan"))
	if _, err := application.ResolveReleasePlan(context.Background(), foreign); !errors.Is(err, ErrPlanIntegrity) {
		t.Fatalf("foreign digest error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := application.ResolveReleasePlan(cancelled, plan.Digest()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
	if _, err := application.ResolveAgentConfigurationPlan(context.Background(), plan.Digest(), plan.OperationID(), 0); !errors.Is(err, ErrPlanIntegrity) {
		t.Fatalf("zero attempt error = %v", err)
	}
	if _, err := application.ResolveStackAuthorization(
		context.Background(), plan.Digest(), foreignOperation, 1, productstack.OperationMigrate,
	); !errors.Is(err, ErrPlanIntegrity) {
		t.Fatalf("foreign stack operation error = %v", err)
	}
	if _, err := application.ResolveBrainBootstrapAuthorization(
		context.Background(), plan.Digest(), foreignOperation, 1,
	); !errors.Is(err, ErrPlanIntegrity) {
		t.Fatalf("foreign Brain bootstrap operation error = %v", err)
	}
	if _, err := application.ResolveStackAuthorization(
		context.Background(), plan.Digest(), plan.OperationID(), 1, productstack.Operation("shell"),
	); !errors.Is(err, ErrPlanIntegrity) {
		t.Fatalf("unknown stack operation error = %v", err)
	}
	//lint:ignore SA1012 Intentionally verifies fail-closed handling of an absent context.
	if _, err := application.ResolveReleasePlan(nil, plan.Digest()); !errors.Is(err, ErrPlanIntegrity) { //nolint:staticcheck // Intentional absent-context boundary test.
		t.Fatalf("nil context error = %v", err)
	}
	if _, err := application.ResolveReleasePlan(context.Background(), install.PlanDigest{}); !errors.Is(err, ErrPlanIntegrity) {
		t.Fatalf("zero digest error = %v", err)
	}
}

func TestApplicationRejectsNilAndRepositoryFailures(t *testing.T) {
	t.Parallel()
	plan := applicationPlan(t)
	fixture := newApplicationFixture(t, plan)
	if _, err := New(Dependencies{}); !errors.Is(err, ErrPlanIntegrity) {
		t.Fatalf("New(empty) error = %v", err)
	}
	var typedNil *exactPlanRepository
	typedNilDependencies := fixture.dependencies()
	typedNilDependencies.Plans = typedNil
	if _, err := New(typedNilDependencies); !errors.Is(err, ErrPlanIntegrity) {
		t.Fatalf("New(typed nil) error = %v", err)
	}
	zeroOperationDependencies := fixture.dependencies()
	zeroOperationDependencies.OperationID = install.OperationID{}
	if _, err := New(zeroOperationDependencies); !errors.Is(err, ErrPlanIntegrity) {
		t.Fatalf("New(zero operation) error = %v", err)
	}
	missing := []func(*Dependencies){
		func(value *Dependencies) { value.RuntimePlans = nil },
		func(value *Dependencies) { value.RuntimeEvidence = nil },
		func(value *Dependencies) { value.Operations = nil },
		func(value *Dependencies) { value.ReadinessReceipts = nil },
		func(value *Dependencies) { value.Resources = nil },
	}
	for _, remove := range missing {
		dependencies := fixture.dependencies()
		remove(&dependencies)
		if _, err := New(dependencies); !errors.Is(err, ErrPlanIntegrity) {
			t.Fatalf("New(missing dependency) error = %v", err)
		}
	}
	repositoryFailure := fixture.dependencies()
	repositoryFailure.Plans = &exactPlanRepository{err: ErrPlanNotFound}
	application, err := New(repositoryFailure)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := application.ResolveReadinessPlan(context.Background(), plan.Digest()); !errors.Is(err, ErrPlanNotFound) {
		t.Fatalf("repository error = %v", err)
	}
	empty := fixture.dependencies()
	empty.Plans = &exactPlanRepository{}
	emptyApplication, err := New(empty)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := emptyApplication.ResolveReleasePlan(context.Background(), plan.Digest()); !errors.Is(err, ErrPlanIntegrity) {
		t.Fatalf("empty repository plan error = %v", err)
	}
}

type exactPlanRepository struct {
	plan installplan.Plan
	err  error
}

func (r *exactPlanRepository) Save(context.Context, installplan.Plan) error { return r.err }

func (r *exactPlanRepository) Load(context.Context, install.PlanDigest) (installplan.Plan, error) {
	return r.plan, r.err
}

type applicationFixture struct {
	plan            installplan.Plan
	runtimePlans    *memoryRuntimePlanRepository
	runtimeEvidence *runtimeEvidenceResolverStub
	operations      *operationRepositoryStub
	receipts        *readinessRepositoryStub
	resources       *resourceRepositoryStub
	receipt         readiness.Receipt
	inventory       resourceinventory.Snapshot
}

func newApplicationFixture(t testing.TB, plan installplan.Plan) *applicationFixture {
	t.Helper()
	receipt := applicationReadinessReceipt(t, plan)
	operation := applicationOperation(t, plan, receipt.Digest())
	var hostEvidence install.Digest
	for _, evidence := range operation.CompletedEvidence() {
		if evidence.Phase() == install.PhaseVerifyHost {
			hostEvidence = evidence.OutputDigest()
		}
	}
	innerCatalogDigest := install.DigestBytes([]byte("inner signed runtime catalog manifest"))
	catalogHash, err := runtimeinstall.ParseHash(innerCatalogDigest.String())
	if err != nil {
		t.Fatal(err)
	}
	host, err := runtimeinstall.NewHostCapabilities(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "6.8.0", true, true, true, true,
		8, 32*1024*1024*1024, 24*1024*1024*1024, 100*1024*1024*1024,
	)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := runtimeinstall.NewCertifiedRuntime(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "docker-engine", "28.0.0", "stable", 42,
		catalogHash, runtimeinstall.RuntimeTermsInput{
			ID: runtimeinstall.DockerEngineTermsID, Version: "apache-2.0", URL: "https://docs.docker.com/engine/",
			Digest: runtimeinstall.Sum([]byte("accepted terms")), Presentation: runtimeinstall.TermsPresentationAgentMemory,
		}, 1024, 4096,
	)
	if err != nil {
		t.Fatal(err)
	}
	runtimeEvidence, err := NewRuntimeEvidence(
		host, runtimeinstall.NewAbsentRuntimeDiscovery(), catalog, hostEvidence,
		install.DigestBytes([]byte("runtime discovery evidence")), plan.RuntimeCatalogDigest(),
		innerCatalogDigest,
	)
	if err != nil {
		t.Fatal(err)
	}
	inventory := applicationInventory(t, plan)
	return &applicationFixture{
		plan: plan, runtimePlans: &memoryRuntimePlanRepository{},
		runtimeEvidence: &runtimeEvidenceResolverStub{evidence: runtimeEvidence},
		operations:      &operationRepositoryStub{operation: operation},
		receipts:        &readinessRepositoryStub{receipt: receipt},
		resources:       &resourceRepositoryStub{snapshot: inventory}, receipt: receipt, inventory: inventory,
	}
}

func (f *applicationFixture) dependencies() Dependencies {
	return Dependencies{
		Plans: &exactPlanRepository{plan: f.plan}, RuntimePlans: f.runtimePlans,
		RuntimeEvidence: f.runtimeEvidence, Operations: f.operations,
		ReadinessReceipts: f.receipts, Resources: f.resources, OperationID: f.plan.OperationID(),
	}
}

type memoryRuntimePlanRepository struct {
	authority      RuntimePlanAuthority
	found          bool
	loadErr        error
	saveErr        error
	conflictReplay bool
}

func (r *memoryRuntimePlanRepository) LoadRuntimePlan(
	context.Context,
	install.OperationID,
	install.PlanDigest,
) (RuntimePlanAuthority, error) {
	if r.loadErr != nil {
		return RuntimePlanAuthority{}, r.loadErr
	}
	if !r.found {
		return RuntimePlanAuthority{}, ErrRuntimePlanNotFound
	}
	return r.authority, nil
}

func (r *memoryRuntimePlanRepository) SaveRuntimePlan(_ context.Context, authority RuntimePlanAuthority) error {
	if r.conflictReplay {
		r.authority, r.found = authority, true
		return ErrRuntimePlanConflict
	}
	if r.saveErr != nil {
		return r.saveErr
	}
	if r.found && !r.authority.Equal(authority) {
		return ErrRuntimePlanConflict
	}
	r.authority, r.found = authority, true
	return nil
}

type runtimeEvidenceResolverStub struct {
	evidence RuntimeEvidence
	err      error
	calls    int
	request  RuntimeEvidenceRequest
}

func (r *runtimeEvidenceResolverStub) ResolveRuntimeEvidence(
	_ context.Context,
	request RuntimeEvidenceRequest,
) (RuntimeEvidence, error) {
	r.calls++
	r.request = request
	return r.evidence, r.err
}

type operationRepositoryStub struct {
	operation *install.Operation
	err       error
}

func (r *operationRepositoryStub) Load(context.Context, install.OperationID) (*install.Operation, error) {
	return r.operation, r.err
}

type readinessRepositoryStub struct {
	receipt readiness.Receipt
	err     error
}

func (r *readinessRepositoryStub) LoadReadinessReceipt(context.Context, install.Digest) (readiness.Receipt, error) {
	return r.receipt, r.err
}

type resourceRepositoryStub struct {
	snapshot resourceinventory.Snapshot
	err      error
}

func (r *resourceRepositoryStub) Load(context.Context, string) (resourceinventory.Snapshot, error) {
	return r.snapshot, r.err
}

func applicationOperation(t testing.TB, plan installplan.Plan, readinessDigest install.Digest) *install.Operation {
	t.Helper()
	operation, err := install.NewOperation(plan.OperationID(), plan.Digest())
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range install.OrderedPhases() {
		if phase == install.PhaseCommitActiveRelease {
			break
		}
		ownership := plan.RuntimeOwnership()
		if phase == install.PhaseVerifyHost {
			ownership = install.RuntimeOwnershipUndetermined
		} else if ownership == install.RuntimeOwnershipUndetermined {
			ownership = install.RuntimeOwnershipProvisionedByAgentMemory
		}
		output := install.DigestBytes([]byte("output:" + phase.String()))
		if phase == install.PhaseVerifyReadiness {
			output = readinessDigest
		}
		artifact := install.Digest{}
		if install.PhaseRequiresVerifiedArtifact(phase) {
			artifact = install.DigestBytes([]byte("artifact:" + phase.String()))
		}
		if phase == install.PhaseEnsureCoreAndGraph {
			artifact = applicationNormalizedComposeDigest()
		}
		boundary, _ := install.NewCompensationBoundary("preserve.test_state")
		action, _ := install.NewSafeAction("installation.continue")
		evidence, evidenceError := install.NewStepEvidence(install.StepEvidenceInput{
			Phase: phase, Attempt: operation.Attempt(), PlanDigest: plan.Digest(),
			InputDigest: install.DigestBytes([]byte("input:" + phase.String())), OutputDigest: output,
			VerifiedArtifactDigest: artifact, RuntimeOwnership: ownership,
			CompensationBoundary: boundary, NextSafeAction: action,
		})
		if evidenceError != nil {
			t.Fatalf("construct %s evidence: %v", phase, evidenceError)
		}
		if completeError := operation.CompleteStep(evidence); completeError != nil {
			t.Fatalf("complete %s: %v", phase, completeError)
		}
	}
	return operation
}

func applicationReadinessReceipt(t testing.TB, plan installplan.Plan) readiness.Receipt {
	t.Helper()
	manifest := plan.SignedRelease().Manifest()
	manifestDigest, _ := install.ParseDigest(manifest.Digest().Hex())
	composeDigest := applicationNormalizedComposeDigest()
	evaluatedAt := time.Date(2026, time.July, 14, 8, 0, 0, 0, time.UTC)
	results := make([]readiness.Result, 0, len(readiness.RequiredProbes()))
	for _, probe := range readiness.RequiredProbes() {
		result, err := readiness.NewResult(readiness.ResultInput{
			Probe: probe, Status: readiness.StatusPassed, OperationID: plan.OperationID(), PlanDigest: plan.Digest(),
			ReleaseID: manifest.ReleaseID(), GenerationID: plan.GenerationID(),
			ManifestDigest: manifestDigest, ComposeDigest: composeDigest,
			EvidenceDigest: install.DigestBytes([]byte("probe:" + probe.String())), ObservedAt: evaluatedAt,
		})
		if err != nil {
			t.Fatal(err)
		}
		results = append(results, result)
	}
	receipt, failures := readiness.NewGate().Evaluate(readiness.GateInput{
		OperationID: plan.OperationID(), PlanDigest: plan.Digest(), ReleaseID: manifest.ReleaseID(),
		GenerationID: plan.GenerationID(), ManifestDigest: manifestDigest, ComposeDigest: composeDigest,
		EvaluatedAt: evaluatedAt, Results: results,
	})
	if len(failures) != 0 {
		t.Fatalf("readiness failures: %+v", failures)
	}
	return receipt
}

func applicationNormalizedComposeDigest() install.Digest {
	return install.DigestBytes([]byte("normalized compose configuration"))
}

func applicationInventory(t testing.TB, plan installplan.Plan) resourceinventory.Snapshot {
	t.Helper()
	inventory, err := resourceinventory.New(plan.InstallationID())
	if err != nil {
		t.Fatal(err)
	}
	specs, err := resourceinventory.BuildPlan(
		plan.InstallationID(), plan.GenerationID(), plan.SignedRelease().Manifest().ReleaseID(),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range specs {
		if _, err := inventory.Begin(spec, plan.OperationID().String()); err != nil {
			t.Fatal(err)
		}
		objectID := spec.Name()
		if spec.Kind() == resourceinventory.KindNetwork {
			objectID = strings.Repeat("a", 64)
		}
		observed, err := resourceinventory.NewObserved(spec.Kind(), spec.Name(), objectID, spec.Labels())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := inventory.Record(spec, plan.OperationID().String(), observed); err != nil {
			t.Fatal(err)
		}
	}
	return inventory.Snapshot()
}

func applicationPlan(t testing.TB) installplan.Plan {
	t.Helper()
	operation, _ := install.NewOperationID("019f5f1f-0000-7abc-8123-0123456789ab")
	signed := applicationSignedManifest(t)
	product := applicationProductInput()
	plan, err := installplan.NewV1(installplan.Input{
		OperationID:      operation,
		InstallationID:   "019f5f20-1234-7abc-8123-0123456789ab",
		GenerationID:     "019f5f21-5678-7def-9123-abcdef012345",
		RuntimeEndpoint:  "unix:///var/run/docker.sock",
		RuntimeOwnership: install.RuntimeOwnershipProvisionedByAgentMemory,
		SecurityEpoch:    1,
		SignedHostPlan:   applicationSignedHostPlan(t),
		SignedRelease:    signed,
		Product:          product,
		RuntimeCatalog:   installplan.RuntimeCatalogInput{ResourceID: "runtime-catalog"},
		Artifacts: installplan.ArtifactInput{
			ComposeArtifactID:     "compose",
			Artifacts:             applicationArtifactInputs(signed.Manifest()),
			RollbackHeadroomBytes: 1024, SafetyHeadroomBytes: 2048,
			Capacity: installplan.CapacityInput{
				HostCAS: "/var/lib/agentmemory/cas", HostRelease: product.ReleaseDirectory, DockerEngine: "unix:///var/run/docker.sock",
				DockerDataVolume: "agentmemory-core-data",
			},
		},
		AgentConfiguration: installplan.AgentConfigurationInput{
			ConfigLocation: "/home/user/.agent/config.json",
			EntryID:        "019f5f22-5678-7def-9123-abcdef012346",
			LauncherDigest: agentconfigdomain.DigestBytes([]byte("signed launcher")),
			LauncherPath:   "/opt/agentmemory/bin/agentmemory",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func applicationSignedHostPlan(t testing.TB) hostverification.SignedPlan {
	t.Helper()
	plan, err := hostverification.NewPlan(hostverification.Input{
		PolicyID: "host-policy-2026-07", SigningKeyID: "host-root-2026",
		Platform: hostverification.PlatformTuple{
			OperatingSystem: hostverification.OperatingSystemLinux, Product: "ubuntu",
			Architecture: hostverification.ArchitectureAMD64, Version: "24.04", Build: "6.8.0-63-generic",
		},
		MinimumCPUCores: 4, MinimumMemoryBytes: 8 << 30, MinimumFreeDiskBytes: 40 << 30,
		StorageTarget: "/home/user/.agentmemory",
		RequiredPorts: []hostverification.LoopbackEndpoint{{Family: hostverification.LoopbackIPv4, Port: 9411}},
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := hostverification.NewSignedPlan(plan, plan.SigningKeyID(), bytes.Repeat([]byte{0x24}, 64))
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func applicationProductInput() installplan.ProductInput {
	root := "/home/user/.agentmemory"
	secretRoot := root + "/secrets"
	return installplan.ProductInput{
		ReleaseDirectory: root + "/releases/1.0.0", ConfigurationDirectory: root + "/config",
		RuntimeDirectory: root + "/runtime", SecretDirectory: secretRoot, BackupDirectory: root + "/backups",
		ComposeProjectDirectory:  root + "/releases/1.0.0/compose",
		ComposeConfigurationPath: root + "/releases/1.0.0/compose/compose.yaml",
		EmptyEnvironmentPath:     root + "/releases/1.0.0/compose/empty.env",
		EgressAttestationPath:    root + "/runtime/egress-attestation.json",
		CoreEndpoint:             "http://127.0.0.1:9411", InitialBrainID: "019f5f23-5678-7def-9123-abcdef012347",
		InitialBrainName: "local", OwnerPrincipalID: "019f5f24-5678-7def-9123-abcdef012348",
		OwnerGrantID: "019f5f25-5678-7def-9123-abcdef012349", OwnerSubjectDigest: install.DigestBytes([]byte("owner subject")),
		SecretFiles: []installplan.SecretFileInput{
			{Purpose: installplan.SecretInstallationRootKey, Path: secretRoot + "/installation-root-key"},
			{Purpose: installplan.SecretAPICredential, Path: secretRoot + "/api-credential"},
			{Purpose: installplan.SecretAttestationHMACKey, Path: secretRoot + "/attestation-hmac-key"},
			{Purpose: installplan.SecretNeo4jPassword, Path: secretRoot + "/neo4j-password"},
			{Purpose: installplan.SecretEmbeddingCapability, Path: secretRoot + "/embedding-capability"},
			{Purpose: installplan.SecretRerankerCapability, Path: secretRoot + "/reranker-capability"},
			{Purpose: installplan.SecretExtractorCapability, Path: secretRoot + "/extractor-capability"},
		},
	}
}

func applicationArtifactInputs(manifest releaseinventory.Manifest) []artifactacquisition.ArtifactInput {
	result := make([]artifactacquisition.ArtifactInput, 0, len(manifest.Resources()))
	for _, resource := range manifest.Resources() {
		if resource.Kind() == releaseinventory.ResourceKindOCIImage || resource.Kind() == releaseinventory.ResourceKindOCIIndex {
			continue
		}
		input := artifactacquisition.ArtifactInput{
			ID: resource.ID(), Digest: resource.Digest(), Size: resource.Size(), Sources: resource.SourceAllowlist(),
			Chunks: []artifactacquisition.ChunkInput{{Offset: 0, Size: resource.Size(), Digest: resource.Digest()}},
		}
		if target, exists := resource.ExpandedTarget(); exists {
			input.ExpandedBytes, input.ExpandedDigest = target.Bytes(), target.Digest()
			input.TargetKind, input.TargetStorageID, input.TargetAuthorityDigest = target.Kind(), target.StorageID(), target.AuthorityDigest()
		}
		result = append(result, input)
	}
	return result
}

func applicationSignedManifest(t testing.TB) releaseinventory.SignedManifest {
	t.Helper()
	platform, _ := releaseinventory.NewPlatform("linux", "amd64")
	compose := applicationSubject(t, "compose", releaseinventory.ResourceKindComposeBundle,
		releaseinventory.ResourcePurposeComposeLock, releaseinventory.MediaTypeComposeLock, platform, "bundle://compose")
	runtimeCatalog := applicationSubject(t, "runtime-catalog", releaseinventory.ResourceKindRuntimeCatalog,
		releaseinventory.ResourcePurposeRuntimeCatalog, releaseinventory.MediaTypeRuntimeCatalog, platform, "bundle://runtime-catalog")
	indexDigest := releaseinventory.DigestBytes([]byte("image-index"))
	index := applicationSubject(t, "image-index", releaseinventory.ResourceKindOCIIndex,
		releaseinventory.ResourcePurposeOCIIndex, releaseinventory.MediaTypeOCIIndex, releaseinventory.Platform{},
		"registry.example/agentmemory/image-index@sha256:"+indexDigest.Hex())
	imageDigest := releaseinventory.DigestBytes([]byte("image"))
	imageInput := applicationSubjectInput("image", releaseinventory.ResourceKindOCIImage,
		releaseinventory.ResourcePurposeOCIPlatformManifest, releaseinventory.MediaTypeOCIManifest, platform,
		"registry.example/agentmemory/image@sha256:"+imageDigest.Hex(), imageDigest)
	imageInput.OCIIndexDigest = indexDigest
	imageInput.OCIIndexResourceID = "image-index"
	image := applicationMustResource(t, imageInput)
	resources := make([]releaseinventory.Resource, 0, 24)
	for _, subject := range []releaseinventory.Resource{compose, runtimeCatalog, index, image} {
		resources = append(resources, subject)
		resources = append(resources, applicationEvidence(t, subject)...)
	}
	protocol, _ := releaseinventory.NewProtocolRange(1, 3)
	versionRange, _ := releaseinventory.NewVersionRange(releaseinventory.VersionRangeInput{Minimum: "1.0.0", Maximum: "1.0.0"})
	compatibility, _ := releaseinventory.NewCompatibility(releaseinventory.CompatibilityInput{
		Launcher: versionRange, CoreAPI: versionRange, MCP: versionRange, Provider: versionRange,
		Schema: versionRange, Compose: versionRange, SQLite: versionRange, Neo4j: versionRange,
		RuntimeCatalog: versionRange,
	})
	revocations := []byte("signed revocation set")
	trust, _ := releaseinventory.NewTrustPolicy(releaseinventory.SignatureTrustModeKeyID,
		"release-root-2026", releaseinventory.DigestBytes(revocations), "")
	history, _ := releaseinventory.NewReleaseHistory(nil, nil)
	topology, _ := releaseinventory.NewDockerTopology(applicationTopology())
	manifest, err := releaseinventory.NewManifest(releaseinventory.ManifestInput{
		SchemaVersion: 1, ReleaseID: "agentmemory-1.0.0", Version: "1.0.0", BuildID: "build-20260701-1",
		SourceCommit:   strings.Repeat("a", 40),
		BuildTimestamp: time.Date(2026, time.June, 30, 23, 0, 0, 0, time.UTC),
		Channel:        releaseinventory.ReleaseChannelStable, Sequence: 42, DataGeneration: 6,
		ValidFrom:  time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC),
		ValidUntil: time.Date(2027, time.July, 1, 0, 0, 0, 0, time.UTC),
		Protocol:   protocol, Compatibility: compatibility, TrustPolicy: trust, ReleaseHistory: history,
		LicensePolicyDigest:       releaseinventory.DigestBytes([]byte("license-policy")),
		VulnerabilityPolicyDigest: releaseinventory.DigestBytes([]byte("vulnerability-policy")),
		DockerTopology:            topology, Resources: resources,
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := releaseinventory.NewSignedManifest(manifest, releaseinventory.SignatureBundleInput{
		SchemaVersion: releaseinventory.SupportedSignatureBundleSchemaMajor,
		TrustMode:     releaseinventory.SignatureTrustModeKeyID, TrustRootID: "release-root-2026",
		Signature: bytes.Repeat([]byte{0x42}, releaseinventory.ManifestSignatureSize), RevocationSet: revocations,
	})
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func applicationSubject(t testing.TB, id string, kind releaseinventory.ResourceKind,
	purpose releaseinventory.ResourcePurpose, media string, platform releaseinventory.Platform,
	source string) releaseinventory.Resource {
	t.Helper()
	return applicationMustResource(t, applicationSubjectInput(id, kind, purpose, media, platform, source,
		releaseinventory.DigestBytes([]byte(id))))
}

func applicationSubjectInput(id string, kind releaseinventory.ResourceKind,
	purpose releaseinventory.ResourcePurpose, media string, platform releaseinventory.Platform,
	source string, digest releaseinventory.Digest) releaseinventory.ResourceInput {
	input := releaseinventory.ResourceInput{
		ID: id, Kind: kind, Purpose: purpose, MediaType: media, Platform: platform,
		Digest: digest, Size: uint64(len(id) + 1), SourceRef: source, SourceAllowlist: []string{source},
		CycloneDXSBOMResourceID: id + "-cyclonedx", SPDXSBOMResourceID: id + "-spdx",
		ProvenanceResourceID: id + "-provenance", LicenseResourceID: id + "-licenses",
		VulnerabilityResourceID: id + "-vulnerabilities",
	}
	if kind == releaseinventory.ResourceKindComposeBundle {
		input.ExpandedTarget = releaseinventory.ReleaseExpandedTargetInput{
			Kind: releaseinventory.ExpandedTargetComposeBundle, StorageID: "compose/compose.yaml",
			Digest: digest, Bytes: input.Size,
		}
	}
	return input
}

func applicationEvidence(t testing.TB, subject releaseinventory.Resource) []releaseinventory.Resource {
	t.Helper()
	types := []struct {
		suffix  string
		kind    releaseinventory.ResourceKind
		purpose releaseinventory.ResourcePurpose
		media   string
	}{
		{"cyclonedx", releaseinventory.ResourceKindCycloneDXSBOM, releaseinventory.ResourcePurposeCycloneDXSBOM, releaseinventory.MediaTypeCycloneDX},
		{"spdx", releaseinventory.ResourceKindSPDXSBOM, releaseinventory.ResourcePurposeSPDXSBOM, releaseinventory.MediaTypeSPDX},
		{"provenance", releaseinventory.ResourceKindProvenance, releaseinventory.ResourcePurposeSLSAProvenance, releaseinventory.MediaTypeSLSAProvenance},
		{"licenses", releaseinventory.ResourceKindLicense, releaseinventory.ResourcePurposeLicenseEvaluation, releaseinventory.MediaTypeLicenseEvaluation},
		{"vulnerabilities", releaseinventory.ResourceKindVulnerabilityReport, releaseinventory.ResourcePurposeVulnerabilityReport, releaseinventory.MediaTypeVulnerabilityEvaluation},
	}
	result := make([]releaseinventory.Resource, 0, len(types))
	for _, evidence := range types {
		id := subject.ID() + "-" + evidence.suffix
		input := releaseinventory.ResourceInput{
			ID: id, Kind: evidence.kind, Purpose: evidence.purpose, MediaType: evidence.media,
			Digest: releaseinventory.DigestBytes([]byte(id)), Size: uint64(len(id)),
			SourceRef: "bundle://" + id, SourceAllowlist: []string{"bundle://" + id},
			SubjectResourceID: subject.ID(), SubjectDigest: subject.Digest(),
		}
		if evidence.kind == releaseinventory.ResourceKindLicense {
			input.PolicySnapshotDigest = releaseinventory.DigestBytes([]byte("license-policy"))
			input.QualificationResult = releaseinventory.QualificationResultPassed
		}
		if evidence.kind == releaseinventory.ResourceKindVulnerabilityReport {
			input.PolicySnapshotDigest = releaseinventory.DigestBytes([]byte("vulnerability-policy"))
			input.QualificationResult = releaseinventory.QualificationResultPassed
			input.QualificationExpiresAt = time.Date(2027, time.August, 1, 0, 0, 0, 0, time.UTC)
		}
		result = append(result, applicationMustResource(t, input))
	}
	return result
}

func applicationMustResource(t testing.TB, input releaseinventory.ResourceInput) releaseinventory.Resource {
	t.Helper()
	resource, err := releaseinventory.NewResource(input)
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func applicationTopology() releaseinventory.DockerTopologyInput {
	labels := []releaseinventory.TopologyLabelInput{{Key: "com.agentmemory.managed", Value: "true"}}
	return releaseinventory.DockerTopologyInput{
		Profiles: []string{"default"},
		Networks: []releaseinventory.DockerNetworkInput{{ID: "internal", Internal: true, Labels: labels}},
		Volumes:  []releaseinventory.DockerVolumeInput{{ID: "core-data", Purpose: "canonical-data", Labels: labels}},
		HealthProbes: []releaseinventory.HealthProbeInput{{
			ID: "core-ready", Kind: releaseinventory.HealthProbeKindHTTP, HTTPPath: "/ready", Port: 8080,
			IntervalSeconds: 10, TimeoutSeconds: 3, Retries: 5,
		}},
		Services: []releaseinventory.DockerServiceInput{{
			ID: "core", ImageResourceIDs: []string{"image"}, Profiles: []string{"default"}, NetworkIDs: []string{"internal"},
			VolumeMounts:  []releaseinventory.VolumeMountInput{{VolumeID: "core-data", Target: "/var/lib/agentmemory"}},
			HealthProbeID: "core-ready", UserID: 1000, GroupID: 1000,
			ReadOnlyRootFilesystem: true, NoNewPrivileges: true,
			PublishedPorts: []releaseinventory.PortBindingInput{{Host: "127.0.0.1", HostPort: 38765, ContainerPort: 8080}},
			Labels:         labels,
		}},
	}
}
