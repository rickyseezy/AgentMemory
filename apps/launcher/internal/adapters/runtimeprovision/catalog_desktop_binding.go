package runtimeprovision

import (
	"path/filepath"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func validNativeDesktopArtifactFileName(value string, platform runtimeinstall.Platform) bool {
	if value == "" || len(value) > 255 || value != strings.TrimSpace(value) ||
		filepath.Base(value) != value || strings.ContainsAny(value, "/\\:?#%\x00\r\n") {
		return false
	}
	switch platform {
	case runtimeinstall.PlatformDarwin:
		return strings.HasSuffix(value, ".dmg")
	case runtimeinstall.PlatformWindows:
		return strings.HasSuffix(value, ".exe")
	case runtimeinstall.PlatformUnknown, runtimeinstall.PlatformLinux:
		return false
	}
	return false
}

func validNativeDesktopBindingRequest(
	catalog runtimecatalog.Digest,
	artifact string,
	platform runtimeinstall.Platform,
) bool {
	return !catalog.IsZero() && validNativeDesktopArtifactFileName(artifact, platform)
}
