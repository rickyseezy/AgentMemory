//go:build !linux

package runtimeprovision

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
)

// NativeLinuxHostBindingProvider is intentionally unavailable off Linux.
type NativeLinuxHostBindingProvider struct{}

// NewNativeLinuxHostBindingProvider constructs the fail-closed off-Linux adapter.
func NewNativeLinuxHostBindingProvider() *NativeLinuxHostBindingProvider {
	return &NativeLinuxHostBindingProvider{}
}

// CurrentLinuxHostBinding rejects use on a non-Linux host.
func (*NativeLinuxHostBindingProvider) CurrentLinuxHostBinding(
	ctx context.Context,
) (runtimecatalogapp.LinuxHostBinding, error) {
	if ctx == nil {
		return runtimecatalogapp.LinuxHostBinding{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return runtimecatalogapp.LinuxHostBinding{}, err
	}
	return runtimecatalogapp.LinuxHostBinding{}, ErrUnsupportedHost
}

var _ LinuxHostBindingProvider = (*NativeLinuxHostBindingProvider)(nil)
