package runtimeprovision

import (
	"testing"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF006VerifiedDesktopCatalogProductionProjectorsPreserveExactAuthority(t *testing.T) {
	t.Parallel()
	catalog, plan, binding, trust, authority := verifiedDesktopCatalogProjectionFixture(t)

	projectedAuthority, err := (verifiedCatalogDesktopProjector{catalog: catalog}).ProjectDesktopAuthority(
		plan.CanonicalBytes(), binding, trust,
	)
	if err != nil || projectedAuthority.Digest() != authority.Digest() {
		t.Fatalf("ProjectDesktopAuthority() digest=%s error=%v", projectedAuthority.Digest(), err)
	}

	projectedArtifacts, err := (verifiedCatalogDesktopArtifactProjector{catalog: catalog}).ProjectDesktopArtifactPlan(authority)
	if err != nil || len(projectedArtifacts.Artifacts()) != 1 ||
		projectedArtifacts.Digest() != releaseinventory.Digest(catalog.Manifest().Digest()) {
		t.Fatalf("ProjectDesktopArtifactPlan() artifacts=%d digest=%s error=%v",
			len(projectedArtifacts.Artifacts()), projectedArtifacts.Digest(), err)
	}
}

func TestPF006VerifiedDesktopCatalogProductionConstructorsUseOnlyVerifiedProjection(t *testing.T) {
	t.Parallel()
	catalog, plan, binding, trust, authority := verifiedDesktopCatalogProjectionFixture(t)
	host := &desktopHostBindingProviderFake{binding: binding}
	resolver, err := NewCatalogDesktopAuthorityResolver(
		catalog, host, &desktopTrustResolverFake{digest: trust},
	)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver.ResolveDesktopAuthority(t.Context(), plan.CanonicalBytes())
	if err != nil || resolved.Digest() != authority.Digest() {
		t.Fatalf("ResolveDesktopAuthority() digest=%s error=%v", resolved.Digest(), err)
	}

	artifactPlan, err := catalog.DesktopArtifactPlan(authority)
	if err != nil {
		t.Fatal(err)
	}
	cas := successfulLinuxArtifactCAS(artifactPlan)
	materializer := &desktopArtifactMaterializerFake{}
	acquirer, err := NewCatalogDesktopArtifactAcquirer(catalog, cas, materializer)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := acquirer.AcquireDesktopArtifact(t.Context(), authority)
	if err != nil || !evidence.AcquiredFor(authority) || materializer.calls != 1 {
		t.Fatalf("AcquireDesktopArtifact() acquired=%t calls=%d error=%v",
			evidence.AcquiredFor(authority), materializer.calls, err)
	}
}

func verifiedDesktopCatalogProjectionFixture(
	t testing.TB,
) (runtimecatalogapp.VerifiedCatalog, runtimeinstall.Plan, runtimecatalogapp.DesktopHostBinding, runtimecatalog.Digest, runtimeport.DesktopAuthority) {
	t.Helper()
	catalog := verifiedObservationCatalog(t)
	certified, err := catalog.CertifiedRuntime()
	if err != nil {
		t.Fatal(err)
	}
	host, err := runtimeinstall.NewHostCapabilities(
		runtimeinstall.PlatformDarwin, runtimeinstall.ArchitectureARM64, "15.5.0",
		true, true, true, true, 8, 32<<30, 24<<30, 100<<30,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := runtimeinstall.NewPlanV1(host, runtimeinstall.NewAbsentRuntimeDiscovery(), certified)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := runtimecatalogapp.NewDesktopHostBinding(runtimecatalogapp.DesktopHostBindingInput{
		Platform: runtimeinstall.PlatformDarwin, Architecture: runtimeinstall.ArchitectureARM64,
		PrincipalID: "uid:501", UserName: "agentmemory", MachineDigest: runtimeinstall.Sum([]byte("machine")),
		HomeDirectory: "/Users/agentmemory",
		ArtifactPath:  "/Users/agentmemory/Library/Caches/AgentMemory/runtime/Docker.dmg",
		Endpoint:      "unix:///Users/agentmemory/.docker/run/docker.sock",
	})
	if err != nil {
		t.Fatal(err)
	}
	trust := runtimecatalog.DigestBytes([]byte("native certificate"))
	authority, err := catalog.DesktopAuthority(plan.CanonicalBytes(), binding, trust)
	if err != nil {
		t.Fatal(err)
	}
	return catalog, plan, binding, trust, authority
}
