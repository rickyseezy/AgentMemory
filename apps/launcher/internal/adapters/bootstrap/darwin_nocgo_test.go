//go:build darwin && !cgo

package bootstrap

import "testing"

func TestPF001DarwinNativeSecurityCompositionFailsClosedWithoutCGO(t *testing.T) {
	t.Parallel()
	if _, err := NewDarwinOwnerBindingSource(); err == nil {
		t.Fatal("macOS owner source started without native identity capability")
	}
	if _, err := NewDarwinKeychainOperationKeySource(nil); err == nil {
		t.Fatal("macOS key source started without native Keychain capability")
	}
}
