//go:build darwin && !cgo

package bootstrap

import "errors"

var errDarwinNativeCapabilitiesUnavailable = errors.New("native Darwin security capabilities require cgo")

func newDarwinIdentityCapability() (darwinIdentityCapability, error) {
	return nil, errDarwinNativeCapabilitiesUnavailable
}

func newDarwinKeychainCapability(string) (darwinKeychainCapability, error) {
	return nil, errDarwinNativeCapabilitiesUnavailable
}
