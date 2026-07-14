//go:build !darwin && !windows

package runtimeprovision

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
)

// NativeDesktopHostBindingProvider is unavailable on non-desktop hosts.
type NativeDesktopHostBindingProvider struct{}

// NewNativeDesktopHostBindingProvider constructs a fail-closed platform probe.
func NewNativeDesktopHostBindingProvider() *NativeDesktopHostBindingProvider {
	return &NativeDesktopHostBindingProvider{}
}

// CurrentDesktopHostBinding never projects desktop authority off desktop OSes.
func (*NativeDesktopHostBindingProvider) CurrentDesktopHostBinding(
	ctx context.Context,
	_ runtimecatalog.Digest,
	_ string,
) (runtimecatalogapp.DesktopHostBinding, error) {
	if ctx == nil {
		return runtimecatalogapp.DesktopHostBinding{}, ErrUnsupportedHost
	}
	if err := ctx.Err(); err != nil {
		return runtimecatalogapp.DesktopHostBinding{}, err
	}
	return runtimecatalogapp.DesktopHostBinding{}, ErrUnsupportedHost
}

var _ DesktopHostBindingProvider = (*NativeDesktopHostBindingProvider)(nil)
