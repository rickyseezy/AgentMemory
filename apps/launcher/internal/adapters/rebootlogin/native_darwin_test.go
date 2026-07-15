//go:build darwin

package rebootlogin

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPF001NativeRegistrarUsesCurrentUserLaunchAgents(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	registrar, err := NewNativeRegistrar()
	if err != nil || registrar == nil {
		t.Fatalf("NewNativeRegistrar() = (%v, %v)", registrar, err)
	}
	info, err := os.Lstat(filepath.Join(home, "Library", "LaunchAgents"))
	if err != nil || !info.IsDir() {
		t.Fatalf("native LaunchAgents root = (%v, %v)", info, err)
	}
}
