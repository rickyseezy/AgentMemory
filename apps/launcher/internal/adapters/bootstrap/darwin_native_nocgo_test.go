//go:build darwin && !cgo

package bootstrap

import (
	"errors"
	"testing"
)

func TestPF001DarwinNoCGONativeSecurityCapabilitiesFailClosed(t *testing.T) {
	t.Parallel()
	identity, err := newDarwinIdentityCapability()
	if identity != nil || !errors.Is(err, errDarwinNativeCapabilitiesUnavailable) {
		t.Fatalf("no-cgo identity=%+v error=%v", identity, err)
	}
	keychain, err := newDarwinKeychainCapability("io.agentmemory.test")
	if keychain != nil || !errors.Is(err, errDarwinNativeCapabilitiesUnavailable) {
		t.Fatalf("no-cgo keychain=%+v error=%v", keychain, err)
	}
}
