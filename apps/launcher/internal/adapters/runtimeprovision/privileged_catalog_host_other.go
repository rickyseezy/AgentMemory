//go:build !linux

package runtimeprovision

// PrivilegedLinuxCatalogHostProvider is unavailable away from Linux.
type PrivilegedLinuxCatalogHostProvider struct{}

// NewPrivilegedLinuxCatalogHostProvider fails closed away from Linux.
func NewPrivilegedLinuxCatalogHostProvider(
	LinuxHostBindingProvider,
) (*PrivilegedLinuxCatalogHostProvider, error) {
	return nil, ErrUnsupportedHost
}
