//go:build (!darwin && !windows) || (darwin && !cgo)

package runtimeprovision

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
)

type PrivilegedDesktopCatalogHostProvider struct{}

func NewPrivilegedDesktopHostBindingProvider(string) (DesktopHostBindingProvider, error) {
	return nil, ErrUnsupportedHost
}

func NewPrivilegedDesktopCatalogHostProvider(
	DesktopHostBindingProvider,
) (*PrivilegedDesktopCatalogHostProvider, error) {
	return nil, ErrUnsupportedHost
}

func (*PrivilegedDesktopCatalogHostProvider) CurrentHost(
	context.Context,
) (runtimecatalog.Host, error) {
	return runtimecatalog.Host{}, runtimecatalogapp.ErrDependencyUnavailable
}
