//go:build darwin

package rebootlogin

import (
	"os"
	"path/filepath"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/rebootapp"
)

// NewNativeRegistrar creates the per-user LaunchAgent registrar documented by
// Apple. Merely publishing the plist avoids launching it in the current session;
// the per-user launchd instance loads it on the next login.
func NewNativeRegistrar() (rebootapp.LoginRegistrar, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" || !filepath.IsAbs(home) {
		return nil, rebootapp.ErrIntegrity
	}
	return newFileRegistrar(filepath.Join(home, "Library", "LaunchAgents"), ".plist", renderDarwinEntry)
}
