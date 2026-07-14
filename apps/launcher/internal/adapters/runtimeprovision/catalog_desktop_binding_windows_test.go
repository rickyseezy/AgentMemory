//go:build windows

package runtimeprovision

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
)

func TestNativeDesktopHostBindingProviderBuildsCurrentWindowsBinding(t *testing.T) {
	t.Parallel()
	provider := NewNativeDesktopHostBindingProvider()
	digest := runtimecatalog.DigestBytes([]byte("catalog"))
	if _, err := provider.CurrentDesktopHostBinding(
		context.Background(), digest, "Docker Desktop Installer.exe",
	); err != nil {
		t.Fatal(err)
	}
	if name, err := currentWindowsAccountName(); err != nil || name == "" {
		t.Fatalf("currentWindowsAccountName()=%q,%v", name, err)
	}
}

func TestNativeDesktopHostBindingProviderRejectsInvalidWindowsRequests(t *testing.T) {
	t.Parallel()
	provider := NewNativeDesktopHostBindingProvider()
	digest := runtimecatalog.DigestBytes([]byte("catalog"))
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name     string
		ctx      context.Context
		digest   runtimecatalog.Digest
		artifact string
		want     error
	}{
		{name: "nil context", digest: digest, artifact: "Docker Desktop Installer.exe", want: ErrUnsupportedHost},
		{name: "cancelled", ctx: cancelled, digest: digest, artifact: "Docker Desktop Installer.exe", want: context.Canceled},
		{name: "zero digest", ctx: context.Background(), artifact: "Docker Desktop Installer.exe", want: ErrUnsupportedHost},
		{name: "bad artifact", ctx: context.Background(), digest: digest, artifact: "Docker.dmg", want: ErrUnsupportedHost},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := provider.CurrentDesktopHostBinding(test.ctx, test.digest, test.artifact)
			if !errors.Is(err, test.want) {
				t.Fatalf("CurrentDesktopHostBinding() error=%v want=%v", err, test.want)
			}
		})
	}
}
