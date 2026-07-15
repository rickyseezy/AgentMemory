package runtimeprovision

import (
	"context"
	"errors"
	"testing"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF006LinuxOwnershipAuthorityProjectsExactSignedInventory(t *testing.T) {
	t.Parallel()
	plan, authority := adapterAuthority(t)
	resolver, err := NewLinuxOwnershipAuthorityResolver(staticAuthorityResolver{authority: authority})
	if err != nil {
		t.Fatal(err)
	}
	projected, err := resolver.ResolveRuntimeOwnershipAuthority(context.Background(), plan.CanonicalBytes())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := projected.Snapshot()
	if snapshot.Vendor != plan.Product() || snapshot.Version != plan.Version() ||
		snapshot.Endpoint != authority.Endpoint() || snapshot.Context != explicitLocalEndpointContext ||
		snapshot.ArtifactDigest != authority.ArtifactDigest() || len(snapshot.Components) != 9 ||
		len(snapshot.Settings) != 4 || snapshot.PublisherDigest.IsZero() {
		t.Fatal("Linux ownership projection omitted signed runtime authority")
	}
}

func TestPF006DesktopOwnershipAuthorityProjectsMacOSAndWindowsSettings(t *testing.T) {
	t.Parallel()
	for _, platform := range []runtimeinstall.Platform{runtimeinstall.PlatformDarwin, runtimeinstall.PlatformWindows} {
		platform := platform
		t.Run(platform.String(), func(t *testing.T) {
			t.Parallel()
			plan, authority := desktopAdapterAuthority(t, platform)
			resolver, err := NewDesktopOwnershipAuthorityResolver(desktopAuthorityResolverFake{authority: authority})
			if err != nil {
				t.Fatal(err)
			}
			projected, err := resolver.ResolveRuntimeOwnershipAuthority(context.Background(), plan.CanonicalBytes())
			if err != nil {
				t.Fatal(err)
			}
			snapshot := projected.Snapshot()
			minimumSettings := 4
			if platform == runtimeinstall.PlatformWindows {
				minimumSettings = 8
			}
			if snapshot.Publisher != authority.Publisher().Identity() ||
				snapshot.PublisherDigest != authority.Publisher().CertificateSHA256() ||
				snapshot.ArtifactDigest != authority.ArtifactSHA256() || len(snapshot.Components) != 3 ||
				len(snapshot.Settings) < minimumSettings {
				t.Fatal("Desktop ownership projection omitted publisher, component, or setting authority")
			}
		})
	}
}

func TestPF006OwnershipAuthorityResolversFailClosed(t *testing.T) {
	t.Parallel()
	if resolver, err := NewLinuxOwnershipAuthorityResolver(nil); resolver != nil || err == nil {
		t.Fatal("nil Linux resolver accepted")
	}
	if resolver, err := NewDesktopOwnershipAuthorityResolver(nil); resolver != nil || err == nil {
		t.Fatal("nil Desktop resolver accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	linux, _ := NewLinuxOwnershipAuthorityResolver(staticAuthorityResolver{err: errors.New("private")})
	if _, err := linux.ResolveRuntimeOwnershipAuthority(cancelled, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Linux projection error = %v", err)
	}
	desktop, _ := NewDesktopOwnershipAuthorityResolver(desktopAuthorityResolverFake{err: runtimeport.ErrDesktopAuthorityUnavailable})
	if _, err := desktop.ResolveRuntimeOwnershipAuthority(context.Background(), []byte("invalid")); err == nil {
		t.Fatal("invalid Desktop plan accepted")
	}
}
