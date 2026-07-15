//go:build (!darwin && !windows) || (darwin && !cgo)

package runtimeprovision

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
)

// PrivilegedDesktopCatalogHostProvider is the unavailable catalog host
// provider used on unsupported desktop targets.
type PrivilegedDesktopCatalogHostProvider struct{}

// NewPrivilegedDesktopHostBindingProvider rejects unsupported desktop hosts.
func NewPrivilegedDesktopHostBindingProvider(string) (DesktopHostBindingProvider, error) {
	return nil, ErrUnsupportedHost
}

// NewPrivilegedDesktopCatalogHostProvider rejects unsupported desktop hosts.
func NewPrivilegedDesktopCatalogHostProvider(
	DesktopHostBindingProvider,
) (*PrivilegedDesktopCatalogHostProvider, error) {
	return nil, ErrUnsupportedHost
}

// CurrentHost reports that privileged desktop host discovery is unavailable.
func (*PrivilegedDesktopCatalogHostProvider) CurrentHost(
	context.Context,
) (runtimecatalog.Host, error) {
	return runtimecatalog.Host{}, runtimecatalogapp.ErrDependencyUnavailable
}
