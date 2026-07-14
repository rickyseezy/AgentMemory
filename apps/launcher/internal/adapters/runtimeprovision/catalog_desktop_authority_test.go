package runtimeprovision

import (
	"context"
	"errors"
	"testing"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestCatalogDesktopAuthorityResolverJoinsVerifiedProjectionHostAndNativeTrust(t *testing.T) {
	t.Parallel()
	plan, authority := catalogDesktopAuthorityFixture(t)
	projector := &desktopAuthorityProjectorFake{authority: authority}
	host := &desktopHostBindingProviderFake{}
	trust := &desktopTrustResolverFake{digest: runtimecatalog.DigestBytes([]byte("native trust"))}
	resolver := mustCatalogDesktopResolver(t, projector, host, trust)

	resolved, err := resolver.ResolveDesktopAuthority(context.Background(), plan.CanonicalBytes())
	if err != nil || resolved.Digest() != authority.Digest() || projector.calls != 1 || host.calls != 1 || trust.calls != 1 {
		t.Fatalf("ResolveDesktopAuthority()=valid:%v error:%v calls=%d/%d/%d", resolved.Valid(), err, projector.calls, host.calls, trust.calls)
	}
}

func TestVerifiedCatalogDesktopProjectorFailsClosedWithoutVerifiedCatalog(t *testing.T) {
	t.Parallel()
	projector := verifiedCatalogDesktopProjector{}
	if authority, err := projector.ProjectDesktopAuthority(nil, runtimecatalogapp.DesktopHostBinding{}, runtimecatalog.Digest{}); err == nil || authority.Valid() {
		t.Fatalf("zero catalog projection=valid:%t error:%v", authority.Valid(), err)
	}
}

func TestCatalogDesktopAuthorityResolverFailsClosedAtEveryBoundary(t *testing.T) {
	t.Parallel()
	plan, authority := catalogDesktopAuthorityFixture(t)
	validTrust := runtimecatalog.DigestBytes([]byte("native trust"))
	tests := []struct {
		name     string
		resolver *CatalogDesktopAuthorityResolver
		ctx      context.Context
		want     error
	}{
		{name: "nil resolver", ctx: context.Background(), want: runtimeport.ErrDesktopAuthorityUnavailable},
		{name: "nil context", resolver: mustCatalogDesktopResolver(t, &desktopAuthorityProjectorFake{authority: authority}, &desktopHostBindingProviderFake{}, &desktopTrustResolverFake{digest: validTrust}), want: runtimeport.ErrDesktopAuthorityUnavailable},
		{name: "cancelled", resolver: mustCatalogDesktopResolver(t, &desktopAuthorityProjectorFake{authority: authority}, &desktopHostBindingProviderFake{}, &desktopTrustResolverFake{digest: validTrust}), ctx: cancelledAuthorityContext(), want: context.Canceled},
		{name: "host unavailable", resolver: mustCatalogDesktopResolver(t, &desktopAuthorityProjectorFake{authority: authority}, &desktopHostBindingProviderFake{err: errors.New("private host failure")}, &desktopTrustResolverFake{digest: validTrust}), ctx: context.Background(), want: runtimeport.ErrDesktopAuthorityUnavailable},
		{name: "trust unavailable", resolver: mustCatalogDesktopResolver(t, &desktopAuthorityProjectorFake{authority: authority}, &desktopHostBindingProviderFake{}, &desktopTrustResolverFake{err: errors.New("private trust failure")}), ctx: context.Background(), want: runtimeport.ErrDesktopAuthorityUnavailable},
		{name: "projection unavailable", resolver: mustCatalogDesktopResolver(t, &desktopAuthorityProjectorFake{err: runtimeport.ErrDesktopAuthorityUnavailable}, &desktopHostBindingProviderFake{}, &desktopTrustResolverFake{digest: validTrust}), ctx: context.Background(), want: runtimeport.ErrDesktopAuthorityUnavailable},
		{name: "projection invalid", resolver: mustCatalogDesktopResolver(t, &desktopAuthorityProjectorFake{err: errors.New("private projection failure")}, &desktopHostBindingProviderFake{}, &desktopTrustResolverFake{digest: validTrust}), ctx: context.Background(), want: runtimeport.ErrDesktopAuthorityIntegrity},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			resolved, err := test.resolver.ResolveDesktopAuthority(test.ctx, plan.CanonicalBytes())
			if !errors.Is(err, test.want) || resolved.Valid() {
				t.Fatalf("ResolveDesktopAuthority()=valid:%v error:%v want=%v", resolved.Valid(), err, test.want)
			}
		})
	}
	publisher := catalogDesktopPublisher(t)
	digest := runtimecatalog.DigestBytes([]byte("catalog"))
	if _, err := newCatalogDesktopAuthorityResolver(nil, &desktopHostBindingProviderFake{}, &desktopTrustResolverFake{}, publisher, digest, "Docker.dmg"); err == nil {
		t.Fatal("nil projector dependency succeeded")
	}
	if _, err := newCatalogDesktopAuthorityResolver(&desktopAuthorityProjectorFake{}, nil, &desktopTrustResolverFake{}, publisher, digest, "Docker.dmg"); err == nil {
		t.Fatal("nil host dependency succeeded")
	}
	if _, err := newCatalogDesktopAuthorityResolver(&desktopAuthorityProjectorFake{}, &desktopHostBindingProviderFake{}, nil, publisher, digest, "Docker.dmg"); err == nil {
		t.Fatal("nil trust dependency succeeded")
	}
	if _, err := NewCatalogDesktopAuthorityResolver(runtimecatalogapp.VerifiedCatalog{}, &desktopHostBindingProviderFake{}, &desktopTrustResolverFake{}); err == nil {
		t.Fatal("unverified catalog dependency succeeded")
	}
}

func catalogDesktopAuthorityFixture(t testing.TB) (runtimeinstall.Plan, runtimeport.DesktopAuthority) {
	t.Helper()
	return desktopAdapterAuthority(t, runtimeinstall.PlatformDarwin)
}

func catalogDesktopPublisher(t testing.TB) runtimecatalog.PublisherPolicy {
	t.Helper()
	manifest := catalogSignatureManifest(t)
	return manifest.Artifact().Publisher()
}

type desktopAuthorityProjectorFake struct {
	authority runtimeport.DesktopAuthority
	err       error
	calls     int
}

func (f *desktopAuthorityProjectorFake) ProjectDesktopAuthority(
	[]byte,
	runtimecatalogapp.DesktopHostBinding,
	runtimecatalog.Digest,
) (runtimeport.DesktopAuthority, error) {
	f.calls++
	return f.authority, f.err
}

type desktopHostBindingProviderFake struct {
	binding runtimecatalogapp.DesktopHostBinding
	err     error
	calls   int
}

func (f *desktopHostBindingProviderFake) CurrentDesktopHostBinding(
	context.Context,
	runtimecatalog.Digest,
	string,
) (runtimecatalogapp.DesktopHostBinding, error) {
	f.calls++
	return f.binding, f.err
}

type desktopTrustResolverFake struct {
	digest runtimecatalog.Digest
	err    error
	calls  int
}

func (f *desktopTrustResolverFake) NativeTrustDigest(runtimecatalog.PublisherPolicy) (runtimecatalog.Digest, error) {
	f.calls++
	return f.digest, f.err
}

func mustCatalogDesktopResolver(
	t testing.TB,
	projector desktopAuthorityProjector,
	host DesktopHostBindingProvider,
	trust CatalogPublisherTrustResolver,
) *CatalogDesktopAuthorityResolver {
	t.Helper()
	resolver, err := newCatalogDesktopAuthorityResolver(
		projector, host, trust, catalogDesktopPublisher(t), runtimecatalog.DigestBytes([]byte("catalog")), "Docker.dmg",
	)
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}
