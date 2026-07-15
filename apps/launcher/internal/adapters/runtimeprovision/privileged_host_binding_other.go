//go:build !linux

package runtimeprovision

// NewPrivilegedLinuxHostBindingProvider fails closed away from Linux.
func NewPrivilegedLinuxHostBindingProvider() (*PrivilegedLinuxHostBindingProvider, error) {
	return nil, ErrUnsupportedHost
}
