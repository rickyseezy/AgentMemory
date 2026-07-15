//go:build linux

package rebootlogin

import (
	"os"
	"path/filepath"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/rebootapp"
)

// NewNativeRegistrar creates the per-user XDG desktop autostart registrar.
func NewNativeRegistrar() (rebootapp.LoginRegistrar, error) {
	configuration, err := os.UserConfigDir()
	if err != nil || configuration == "" || !filepath.IsAbs(configuration) {
		return nil, rebootapp.ErrIntegrity
	}
	return newFileRegistrar(filepath.Join(configuration, "autostart"), ".desktop", renderLinuxEntry)
}
