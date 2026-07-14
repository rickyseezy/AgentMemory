//go:build darwin && !cgo

package runtimeprovision

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
)

// NativeDesktopHostBindingProvider is unavailable without Security.framework.
type NativeDesktopHostBindingProvider struct{}

// NewNativeDesktopHostBindingProvider constructs a fail-closed no-cgo probe.
func NewNativeDesktopHostBindingProvider() *NativeDesktopHostBindingProvider {
	return &NativeDesktopHostBindingProvider{}
}

// CurrentDesktopHostBinding never manufactures macOS machine identity.
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
