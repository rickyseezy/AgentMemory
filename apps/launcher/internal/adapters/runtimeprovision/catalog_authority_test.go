package runtimeprovision

import (
	"context"
	"errors"
	"testing"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
)

func TestCatalogLinuxAuthorityResolverJoinsVerifiedProjectionToNativeHost(t *testing.T) {
	t.Parallel()

	plan, authority := adapterAuthority(t)
	projector := &linuxAuthorityProjectorFake{authority: authority}
	host := &linuxHostBindingProviderFake{}
	resolver, err := newCatalogLinuxAuthorityResolver(projector, host)
	if err != nil {
		t.Fatalf("newCatalogLinuxAuthorityResolver() error = %v", err)
	}
	resolved, err := resolver.ResolveLinuxAuthority(context.Background(), plan.CanonicalBytes())
	if err != nil || resolved.Digest() != authority.Digest() || projector.calls != 1 || host.calls != 1 {
		t.Fatalf("ResolveLinuxAuthority() = %v, %v (project=%d host=%d)", resolved.Valid(), err, projector.calls, host.calls)
	}
}

func TestCatalogLinuxAuthorityResolverFailsClosedAtEveryBoundary(t *testing.T) {
	t.Parallel()

	plan, authority := adapterAuthority(t)
	tests := []struct {
		name     string
		resolver *CatalogLinuxAuthorityResolver
		ctx      context.Context
		want     error
	}{
		{name: "nil resolver", ctx: context.Background(), want: runtimeport.ErrAuthorityUnavailable},
		{name: "nil context", resolver: mustCatalogResolver(t, &linuxAuthorityProjectorFake{authority: authority}, &linuxHostBindingProviderFake{}), want: runtimeport.ErrAuthorityUnavailable},
		{name: "cancelled", resolver: mustCatalogResolver(t, &linuxAuthorityProjectorFake{authority: authority}, &linuxHostBindingProviderFake{}), ctx: cancelledAuthorityContext(), want: context.Canceled},
		{name: "host unavailable", resolver: mustCatalogResolver(t, &linuxAuthorityProjectorFake{authority: authority}, &linuxHostBindingProviderFake{err: errors.New("private host failure")}), ctx: context.Background(), want: runtimeport.ErrAuthorityUnavailable},
		{name: "projection unavailable", resolver: mustCatalogResolver(t, &linuxAuthorityProjectorFake{err: runtimeport.ErrAuthorityUnavailable}, &linuxHostBindingProviderFake{}), ctx: context.Background(), want: runtimeport.ErrAuthorityUnavailable},
		{name: "projection invalid", resolver: mustCatalogResolver(t, &linuxAuthorityProjectorFake{err: errors.New("private projection failure")}, &linuxHostBindingProviderFake{}), ctx: context.Background(), want: runtimeport.ErrAuthorityInvalid},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			resolved, err := test.resolver.ResolveLinuxAuthority(test.ctx, plan.CanonicalBytes())
			if !errors.Is(err, test.want) || resolved.Valid() {
				t.Fatalf("ResolveLinuxAuthority() = valid:%v error:%v, want %v", resolved.Valid(), err, test.want)
			}
		})
	}
	if _, err := newCatalogLinuxAuthorityResolver(nil, &linuxHostBindingProviderFake{}); err == nil {
		t.Fatal("nil projector dependency succeeded")
	}
	if _, err := newCatalogLinuxAuthorityResolver(&linuxAuthorityProjectorFake{}, nil); err == nil {
		t.Fatal("nil host dependency succeeded")
	}
	if _, err := NewCatalogLinuxAuthorityResolver(runtimecatalogapp.VerifiedCatalog{}, &linuxHostBindingProviderFake{}); err == nil {
		t.Fatal("unverified catalog dependency succeeded")
	}
}

type linuxAuthorityProjectorFake struct {
	authority runtimeport.LinuxAuthority
	err       error
	calls     int
}

func (f *linuxAuthorityProjectorFake) ProjectLinuxAuthority(
	[]byte,
	runtimecatalogapp.LinuxHostBinding,
) (runtimeport.LinuxAuthority, error) {
	f.calls++
	return f.authority, f.err
}

type linuxHostBindingProviderFake struct {
	binding runtimecatalogapp.LinuxHostBinding
	err     error
	calls   int
}

func (f *linuxHostBindingProviderFake) CurrentLinuxHostBinding(context.Context) (runtimecatalogapp.LinuxHostBinding, error) {
	f.calls++
	return f.binding, f.err
}

func mustCatalogResolver(
	t testing.TB,
	projector linuxAuthorityProjector,
	host LinuxHostBindingProvider,
) *CatalogLinuxAuthorityResolver {
	t.Helper()
	resolver, err := newCatalogLinuxAuthorityResolver(projector, host)
	if err != nil {
		t.Fatalf("newCatalogLinuxAuthorityResolver() error = %v", err)
	}
	return resolver
}

func cancelledAuthorityContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
