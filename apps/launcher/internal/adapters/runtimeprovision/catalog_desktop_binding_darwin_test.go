//go:build darwin && cgo

package runtimeprovision

import (
	"context"
	"errors"
	"os/user"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestNativeDesktopHostBindingProviderBuildsCatalogAddressedMacBinding(t *testing.T) {
	t.Parallel()
	digest := runtimecatalog.DigestBytes([]byte("catalog"))
	provider := desktopDarwinBindingProviderFixture()
	// The binding has intentionally no exported fields; successful strict
	// construction is the observable adapter contract.
	if _, err := provider.CurrentDesktopHostBinding(context.Background(), digest, "Docker.dmg"); err != nil {
		t.Fatal(err)
	}
}

func TestNativeDesktopHostBindingProviderRejectsUntrustedMacInputs(t *testing.T) {
	t.Parallel()
	digest := runtimecatalog.DigestBytes([]byte("catalog"))
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name     string
		provider *NativeDesktopHostBindingProvider
		ctx      context.Context
		digest   runtimecatalog.Digest
		artifact string
		want     error
	}{
		{name: "nil context", provider: desktopDarwinBindingProviderFixture(), digest: digest, artifact: "Docker.dmg", want: ErrUnsupportedHost},
		{name: "cancelled", provider: desktopDarwinBindingProviderFixture(), ctx: cancelled, digest: digest, artifact: "Docker.dmg", want: context.Canceled},
		{name: "nil provider", ctx: context.Background(), digest: digest, artifact: "Docker.dmg", want: ErrUnsupportedHost},
		{name: "zero digest", provider: desktopDarwinBindingProviderFixture(), ctx: context.Background(), artifact: "Docker.dmg", want: ErrUnsupportedHost},
		{name: "bad artifact", provider: desktopDarwinBindingProviderFixture(), ctx: context.Background(), digest: digest, artifact: "Docker.exe", want: ErrUnsupportedHost},
		{name: "bad architecture", provider: desktopDarwinBindingProviderFixtureWith(func(p *NativeDesktopHostBindingProvider) { p.architecture = "386" }), ctx: context.Background(), digest: digest, artifact: "Docker.dmg", want: ErrUnsupportedHost},
		{name: "root", provider: desktopDarwinBindingProviderFixtureWith(func(p *NativeDesktopHostBindingProvider) { p.uid = func() int { return 0 } }), ctx: context.Background(), digest: digest, artifact: "Docker.dmg", want: ErrUnsupportedHost},
		{name: "foreign user", provider: desktopDarwinBindingProviderFixtureWith(func(p *NativeDesktopHostBindingProvider) {
			p.currentUser = func() (*user.User, error) {
				return &user.User{Uid: "502", Username: "agentmemory", HomeDir: "/Users/agentmemory"}, nil
			}
		}), ctx: context.Background(), digest: digest, artifact: "Docker.dmg", want: ErrUnsupportedHost},
		{name: "user error", provider: desktopDarwinBindingProviderFixtureWith(func(p *NativeDesktopHostBindingProvider) {
			p.currentUser = func() (*user.User, error) { return nil, errors.New("private") }
		}), ctx: context.Background(), digest: digest, artifact: "Docker.dmg", want: ErrUnsupportedHost},
		{name: "home error", provider: desktopDarwinBindingProviderFixtureWith(func(p *NativeDesktopHostBindingProvider) {
			p.home = func() (string, error) { return "", errors.New("private") }
		}), ctx: context.Background(), digest: digest, artifact: "Docker.dmg", want: ErrUnsupportedHost},
		{name: "machine error", provider: desktopDarwinBindingProviderFixtureWith(func(p *NativeDesktopHostBindingProvider) {
			p.machine = func() (runtimeinstall.Hash, error) { return runtimeinstall.Hash{}, errors.New("private") }
		}), ctx: context.Background(), digest: digest, artifact: "Docker.dmg", want: ErrUnsupportedHost},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := test.provider.CurrentDesktopHostBinding(test.ctx, test.digest, test.artifact)
			if !errors.Is(err, test.want) {
				t.Fatalf("CurrentDesktopHostBinding() error=%v want=%v", err, test.want)
			}
		})
	}
}

func desktopDarwinBindingProviderFixture() *NativeDesktopHostBindingProvider {
	return &NativeDesktopHostBindingProvider{
		uid: func() int { return 501 },
		currentUser: func() (*user.User, error) {
			return &user.User{Uid: "501", Username: "agentmemory", HomeDir: "/Users/agentmemory"}, nil
		},
		home: func() (string, error) { return "/Users/agentmemory", nil },
		machine: func() (runtimeinstall.Hash, error) {
			return runtimeinstall.Sum([]byte("machine")), nil
		},
		architecture: "arm64",
	}
}

func desktopDarwinBindingProviderFixtureWith(edit func(*NativeDesktopHostBindingProvider)) *NativeDesktopHostBindingProvider {
	provider := desktopDarwinBindingProviderFixture()
	edit(provider)
	return provider
}
