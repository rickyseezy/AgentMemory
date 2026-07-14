package runtimecatalogapp

import (
	"errors"
	"testing"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestVerifiedCatalogProjectsCompleteDesktopAuthority(t *testing.T) {
	t.Parallel()
	signed, source := signedCatalog(t)
	verified, err := mustApplication(t, validDependencies(t, &anchorRepository{loadErr: ErrCatalogAnchorNotFound})).Verify(
		t.Context(), validRequest(signed, source),
	)
	if err != nil {
		t.Fatal(err)
	}
	certified, err := verified.CertifiedRuntime()
	if err != nil {
		t.Fatal(err)
	}
	host, err := runtimeinstall.NewHostCapabilities(
		runtimeinstall.PlatformDarwin, runtimeinstall.ArchitectureARM64, "15.5.0",
		true, true, true, true, 8, 16_000_000_000, 8_589_934_592, 100_000_000_000,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := runtimeinstall.NewPlanV1(host, runtimeinstall.NewAbsentRuntimeDiscovery(), certified)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := NewDesktopHostBinding(DesktopHostBindingInput{
		Platform: runtimeinstall.PlatformDarwin, Architecture: runtimeinstall.ArchitectureARM64,
		PrincipalID: "uid:501", UserName: "agentmemory", MachineDigest: runtimeinstall.Sum([]byte("machine")),
		HomeDirectory: "/Users/agentmemory", ArtifactPath: "/Users/agentmemory/.agentmemory/artifacts/Docker.dmg",
		Endpoint: "unix:///Users/agentmemory/.docker/run/docker.sock",
	})
	if err != nil {
		t.Fatal(err)
	}
	certificate := runtimecatalog.DigestBytes([]byte("native certificate"))
	authority, err := verified.DesktopAuthority(plan.CanonicalBytes(), binding, certificate)
	if err != nil || !authority.ValidFor(plan) || authority.Platform() != runtimeinstall.PlatformDarwin ||
		authority.Publisher().CertificateSHA256() != runtimeinstall.Hash(certificate) ||
		authority.ArtifactSourceURL() != "https://desktop.docker.com/mac/main/arm64/Docker.dmg" ||
		authority.ProbeContractVersion() != "1" {
		t.Fatalf("authority=%+v error=%v", authority, err)
	}
	acquisition, err := verified.DesktopArtifactPlan(authority)
	artifacts := acquisition.Artifacts()
	if err != nil || len(artifacts) != 1 || artifacts[0].ID() != desktopInstallerArtifactID ||
		!artifacts[0].Digest().Equal(releaseinventory.Digest(authority.ArtifactSHA256())) ||
		artifacts[0].Sources()[0] != authority.ArtifactSourceURL() ||
		acquisition.Totals().DownloadBytes() != authority.ArtifactBytes() ||
		acquisition.Totals().ExpandedBytes() != 0 ||
		acquisition.Totals().RollbackHeadroomBytes() != 200_000_000 ||
		acquisition.Totals().SafetyHeadroomBytes() != 100_000_000 ||
		acquisition.Totals().RequiredBytes() != 1_000_000_000 {
		t.Fatalf("desktop acquisition=%+v artifacts=%+v error=%v", acquisition, artifacts, err)
	}
}

func TestDesktopAuthorityProjectionRejectsUnverifiedOrForeignInputs(t *testing.T) {
	t.Parallel()
	if binding, err := NewDesktopHostBinding(DesktopHostBindingInput{}); err == nil || binding != (DesktopHostBinding{}) {
		t.Fatalf("zero binding=%+v error=%v", binding, err)
	}
	windows, err := NewDesktopHostBinding(DesktopHostBindingInput{
		Platform: runtimeinstall.PlatformWindows, Architecture: runtimeinstall.ArchitectureAMD64,
		PrincipalID: "sid:S-1-5-21-1", UserName: "Agent", MachineDigest: runtimeinstall.Sum([]byte("machine")),
		HomeDirectory: `C:\Users\Agent`, ArtifactPath: `C:\Users\Agent\.agentmemory\Docker.exe`,
		Endpoint: "npipe:////./pipe/docker_engine",
	})
	if err != nil || windows.input.Platform != runtimeinstall.PlatformWindows {
		t.Fatalf("windows binding=%+v error=%v", windows, err)
	}
	if _, err := (VerifiedCatalog{}).DesktopAuthority(nil, windows, runtimecatalog.Digest{}); !errors.Is(err, runtimeport.ErrDesktopAuthorityUnavailable) {
		t.Fatalf("zero verified catalog error=%v", err)
	}
}
