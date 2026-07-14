package installplanfs

import (
	"bytes"
	"context"
	"errors"
	"testing"

	firststartadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/firststart"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/firststartapp"
	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/installplan"
)

func TestPF001FirstStartBinderDerivesOnlyPerHostAuthorityFromVerifiedTemplate(t *testing.T) {
	t.Parallel()
	templatePlan := ownerSelectedTemplatePlan(t)
	template, err := firststartapp.NewTemplate(templatePlan.CanonicalBytes())
	if err != nil {
		t.Fatal(err)
	}
	operation, _ := install.NewOperationID("019f6f1f-0000-7abc-8123-0123456789ab")
	preparation, err := firststartapp.NewPreparation(
		agentconfigdomain.AgentHostCodex, template.Digest(), operation,
		[]string{
			"019f6f20-1234-7abc-8123-0123456789ab", "019f6f21-5678-7def-9123-abcdef012345",
			"019f6f22-5678-7def-9123-abcdef012346", "019f6f23-5678-7def-9123-abcdef012347",
			"019f6f24-5678-7def-9123-abcdef012348", "019f6f25-5678-7def-9123-abcdef012349",
		}, 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	launcher := agentconfigdomain.DigestBytes([]byte("signed launcher"))
	owner := install.DigestBytes([]byte("native owner"))
	projection := firststartadapter.HostProjection{
		StorageRoot: "/home/owner/.agentmemory", RuntimeEndpoint: "unix:///var/run/docker.sock",
		ConfigurationPath: "/home/owner/.codex/config.toml",
		LauncherPath:      "/opt/agentmemory/bin/agentmemory", LauncherDigest: launcher,
		OwnerSubjectDigest: owner,
	}
	source := &binderProjectionStub{projection: projection}
	binder, err := firststartadapter.NewPlanBinder(source)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := binder.Bind(t.Context(), template, preparation)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := installplan.DecodeV1(prepared.CanonicalPlan())
	if err != nil {
		t.Fatal(err)
	}
	if plan.OperationID() != preparation.OperationID() ||
		plan.InstallationID() != preparation.InstallationID() ||
		plan.GenerationID() != preparation.GenerationID() ||
		plan.HostStorageTarget() != projection.StorageRoot ||
		plan.AgentConfiguration().AgentHost() != preparation.Host() ||
		plan.AgentConfiguration().ConfigLocation() != projection.ConfigurationPath ||
		!plan.Product().OwnerSubjectDigest().Equal(owner) ||
		plan.Product().InitialBrainID() != preparation.BrainID() ||
		plan.Product().OwnerPrincipalID() != preparation.OwnerPrincipalID() ||
		plan.Product().OwnerGrantID() != preparation.OwnerGrantID() ||
		!bytes.Equal(plan.SignedRelease().SignaturePayload(), templatePlan.SignedRelease().SignaturePayload()) ||
		!bytes.Equal(plan.SignedHostPlan().Signature(), templatePlan.SignedHostPlan().Signature()) {
		t.Fatal("bound plan lost a host identity or signed template authority")
	}
	if source.host != preparation.Host() || bytes.Equal(plan.CanonicalBytes(), templatePlan.CanonicalBytes()) {
		t.Fatal("binder did not consume the selected host or derive unique canonical bytes")
	}
}

func TestPF001FirstStartBinderFailsClosedOnSubstitutionAndBoundaryFailure(t *testing.T) {
	t.Parallel()
	var typedNil *binderProjectionStub
	if binder, err := firststartadapter.NewPlanBinder(typedNil); binder != nil || !errors.Is(err, firststartapp.ErrIntegrity) {
		t.Fatalf("typed nil binder=%v error=%v", binder, err)
	}
	binder, _ := firststartadapter.NewPlanBinder(&binderProjectionStub{err: errors.New("private")})
	//lint:ignore SA1012 Deliberate absent-context boundary test.
	if _, err := binder.Bind(nil, firststartapp.Template{}, firststartapp.Preparation{}); !errors.Is(err, firststartapp.ErrIntegrity) { //nolint:staticcheck
		t.Fatalf("nil context error=%v", err)
	}
	if _, err := binder.Bind(t.Context(), firststartapp.Template{}, firststartapp.Preparation{}); !errors.Is(err, firststartapp.ErrIntegrity) {
		t.Fatalf("zero authority error=%v", err)
	}
	if !errors.Is(firststartFailureFromBinder(t, errors.New("private")), firststartapp.ErrUnavailable) ||
		!errors.Is(firststartFailureFromBinder(t, firststartapp.ErrIntegrity), firststartapp.ErrIntegrity) ||
		!errors.Is(firststartFailureFromBinder(t, context.Canceled), context.Canceled) {
		t.Fatal("binder boundary errors were not safely mapped")
	}
}

func firststartFailureFromBinder(t *testing.T, failure error) error {
	t.Helper()
	templatePlan := ownerSelectedTemplatePlan(t)
	template, _ := firststartapp.NewTemplate(templatePlan.CanonicalBytes())
	operation, _ := install.NewOperationID("019f6f1f-0000-7abc-8123-0123456789ab")
	preparation, _ := firststartapp.NewPreparation(
		agentconfigdomain.AgentHostCodex, template.Digest(), operation,
		[]string{
			"019f6f20-1234-7abc-8123-0123456789ab", "019f6f21-5678-7def-9123-abcdef012345",
			"019f6f22-5678-7def-9123-abcdef012346", "019f6f23-5678-7def-9123-abcdef012347",
			"019f6f24-5678-7def-9123-abcdef012348", "019f6f25-5678-7def-9123-abcdef012349",
		}, 1,
	)
	binder, _ := firststartadapter.NewPlanBinder(&binderProjectionStub{err: failure})
	_, err := binder.Bind(t.Context(), template, preparation)
	return err
}

func ownerSelectedTemplatePlan(t testing.TB) installplan.Plan {
	t.Helper()
	operation, _ := install.NewOperationID("019f5f1f-0000-7abc-8123-0123456789ab")
	signed := filesystemSignedManifest(t)
	policy := filesystemSignedHostPlan(t).Plan()
	ownerPolicy, err := hostverification.NewPlan(hostverification.Input{
		PolicyID: policy.PolicyID(), SigningKeyID: policy.SigningKeyID(), Platform: policy.Platform(),
		MinimumCPUCores: policy.MinimumCPUCores(), MinimumMemoryBytes: policy.MinimumMemoryBytes(),
		MinimumFreeDiskBytes: policy.MinimumFreeDiskBytes(),
		StorageTargetMode:    hostverification.StorageTargetOwnerSelected,
		RequiredPorts:        policy.RequiredPorts(),
	})
	if err != nil {
		t.Fatal(err)
	}
	signedHost, err := hostverification.NewSignedPlan(
		ownerPolicy, ownerPolicy.SigningKeyID(), bytes.Repeat([]byte{0x24}, 64),
	)
	if err != nil {
		t.Fatal(err)
	}
	product := filesystemProductInput()
	plan, err := installplan.NewV1(installplan.Input{
		OperationID: operation, InstallationID: "019f5f20-1234-7abc-8123-0123456789ab",
		GenerationID:    "019f5f21-5678-7def-9123-abcdef012345",
		RuntimeEndpoint: "unix:///var/run/docker.sock", RuntimeOwnership: install.RuntimeOwnershipUndetermined,
		SecurityEpoch: 1, SignedHostPlan: signedHost, HostStorageTarget: "/home/user/.agentmemory",
		SignedRelease: signed, Product: product,
		RuntimeCatalog: installplan.RuntimeCatalogInput{ResourceID: "runtime-catalog"},
		Artifacts: installplan.ArtifactInput{
			ComposeArtifactID: "compose", Artifacts: filesystemArtifactInputs(signed.Manifest()),
			RollbackHeadroomBytes: 1024, SafetyHeadroomBytes: 2048,
			Capacity: installplan.CapacityInput{
				HostCAS: "/home/user/.agentmemory/cas", HostRelease: product.ReleaseDirectory,
				DockerEngine: "unix:///var/run/docker.sock", DockerDataVolume: "agentmemory-core-data",
			},
		},
		AgentConfiguration: installplan.AgentConfigurationInput{
			AgentHost:      agentconfigdomain.AgentHostCodex,
			ConfigLocation: "/home/user/.codex/config.toml",
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

type binderProjectionStub struct {
	projection firststartadapter.HostProjection
	err        error
	host       agentconfigdomain.AgentHost
}

func (s *binderProjectionStub) Project(
	_ context.Context,
	host agentconfigdomain.AgentHost,
) (firststartadapter.HostProjection, error) {
	s.host = host
	return s.projection, s.err
}
