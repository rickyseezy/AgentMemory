package runtimeprovision

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
)

func TestCertifiedCatalogHostProviderProjectsOnlyCertifiedParentFloors(t *testing.T) {
	t.Parallel()
	manifest := catalogSignatureManifest(t)
	signed := signedCatalogHostPlan(t, hostverification.PlatformTuple{
		OperatingSystem: hostverification.OperatingSystemMacOS, Product: "macos",
		Architecture: hostverification.ArchitectureARM64, Version: "15.5", Build: "24F74",
	}, manifest.Platform().MinimumCPUCores(), manifest.Platform().MinimumMemoryBytes(), manifest.Platform().MinimumFreeDiskBytes())
	provider, err := NewCertifiedCatalogHostProvider(signed, install.DigestBytes([]byte("certified native host receipt")))
	if err != nil {
		t.Fatal(err)
	}
	host, err := provider.CurrentHost(t.Context())
	if err != nil || host.OperatingSystem() != runtimecatalog.OSKindMacOS ||
		host.Architecture() != runtimecatalog.ArchitectureARM64 || host.OSVersion() != "15.5.0" || host.Build() != 24000 {
		t.Fatalf("host=%+v error=%v", host, err)
	}
	if err := manifest.Platform().Supports(host); err != nil {
		t.Fatalf("signed parent floors do not satisfy matching catalog: %v", err)
	}
}

func TestCertifiedCatalogHostProviderNormalizesClosedPlatformConventions(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		platform hostverification.PlatformTuple
		wantOS   runtimecatalog.OSKind
		wantArch runtimecatalog.Architecture
		version  string
		build    uint64
	}{
		{name: "Windows", platform: hostverification.PlatformTuple{
			OperatingSystem: hostverification.OperatingSystemWindows, Product: "product_48",
			Architecture: hostverification.ArchitectureAMD64, Version: "10.0.0", Build: "26100",
		}, wantOS: runtimecatalog.OSKindWindows, wantArch: runtimecatalog.ArchitectureX8664, version: "10.0.0", build: 26100},
		{name: "Linux", platform: hostverification.PlatformTuple{
			OperatingSystem: hostverification.OperatingSystemLinux, Product: "ubuntu",
			Architecture: hostverification.ArchitectureAMD64, Version: "24.04", Build: "6.8.0-63-generic",
		}, wantOS: runtimecatalog.OSKindLinux, wantArch: runtimecatalog.ArchitectureX8664, version: "24.4.0", build: 60800},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider, err := NewCertifiedCatalogHostProvider(
				signedCatalogHostPlan(t, test.platform, 4, 8<<30, 30<<30),
				install.DigestBytes([]byte("certified")),
			)
			if err != nil {
				t.Fatal(err)
			}
			host, err := provider.CurrentHost(t.Context())
			if err != nil || host.OperatingSystem() != test.wantOS || host.Architecture() != test.wantArch ||
				host.OSVersion() != test.version || host.Build() != test.build {
				t.Fatalf("host=%+v error=%v", host, err)
			}
		})
	}
}

func TestCertifiedCatalogHostProviderFailsClosedOnUncertifiedOrAmbiguousProjection(t *testing.T) {
	t.Parallel()
	valid := hostverification.PlatformTuple{
		OperatingSystem: hostverification.OperatingSystemMacOS, Product: "macos",
		Architecture: hostverification.ArchitectureARM64, Version: "15.5", Build: "24F74",
	}
	for name, platform := range map[string]hostverification.PlatformTuple{
		"product": {OperatingSystem: hostverification.OperatingSystemMacOS, Product: "foreign", Architecture: hostverification.ArchitectureARM64, Version: "15.5", Build: "24F74"},
		"version": {OperatingSystem: hostverification.OperatingSystemMacOS, Product: "macos", Architecture: hostverification.ArchitectureARM64, Version: "15.x", Build: "24F74"},
		"build":   {OperatingSystem: hostverification.OperatingSystemMacOS, Product: "macos", Architecture: hostverification.ArchitectureARM64, Version: "15.5", Build: "opaque"},
	} {
		provider, err := NewCertifiedCatalogHostProvider(
			signedCatalogHostPlan(t, platform, 4, 8<<30, 30<<30), install.DigestBytes([]byte("certified")),
		)
		if provider != nil || !errors.Is(err, runtimecatalogapp.ErrDependencyUnavailable) {
			t.Fatalf("%s accepted: provider=%+v error=%v", name, provider, err)
		}
	}
	if provider, err := NewCertifiedCatalogHostProvider(hostverification.SignedPlan{}, install.DigestBytes([]byte("certified"))); provider != nil || err == nil {
		t.Fatalf("zero plan accepted: provider=%+v error=%v", provider, err)
	}
	if provider, err := NewCertifiedCatalogHostProvider(signedCatalogHostPlan(t, valid, 4, 8<<30, 30<<30), install.Digest{}); provider != nil || err == nil {
		t.Fatalf("zero evidence accepted: provider=%+v error=%v", provider, err)
	}
	var absent *CertifiedCatalogHostProvider
	if _, err := absent.CurrentHost(t.Context()); !errors.Is(err, runtimecatalogapp.ErrDependencyUnavailable) {
		t.Fatalf("nil provider error=%v", err)
	}
	provider, err := NewCertifiedCatalogHostProvider(
		signedCatalogHostPlan(t, valid, 4, 8<<30, 30<<30), install.DigestBytes([]byte("certified")),
	)
	if err != nil {
		t.Fatal(err)
	}
	//lint:ignore SA1012 Deliberate nil-context trust-boundary regression fixture.
	if _, err := provider.CurrentHost(nil); !errors.Is(err, runtimecatalogapp.ErrDependencyUnavailable) { //nolint:staticcheck
		t.Fatalf("nil context error=%v", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := provider.CurrentHost(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
}

func signedCatalogHostPlan(
	t testing.TB,
	platform hostverification.PlatformTuple,
	cpus uint32,
	memory uint64,
	disk uint64,
) hostverification.SignedPlan {
	t.Helper()
	plan, err := hostverification.NewPlan(hostverification.Input{
		PolicyID: "agentmemory-host-policy", SigningKeyID: "host-policy-root", Platform: platform,
		MinimumCPUCores: cpus, MinimumMemoryBytes: memory, MinimumFreeDiskBytes: disk,
		StorageTargetMode: hostverification.StorageTargetOwnerSelected,
		RequiredPorts:     []hostverification.LoopbackEndpoint{{Family: hostverification.LoopbackIPv4, Port: 7474}},
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := hostverification.NewSignedPlan(plan, "host-policy-root", []byte("detached-signature"))
	if err != nil {
		t.Fatal(err)
	}
	return signed
}
