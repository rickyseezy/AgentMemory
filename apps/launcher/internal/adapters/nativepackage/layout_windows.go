//go:build windows

package nativepackage

import (
	"errors"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func nativeInstalledLayout() (InstalledLayout, error) {
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFilesX64, windows.KF_FLAG_DEFAULT)
	if err != nil || programFiles == "" || !filepath.IsAbs(programFiles) {
		return InstalledLayout{}, errors.New("Windows Program Files authority is unavailable")
	}
	root := filepath.Join(filepath.Clean(programFiles), "AgentMemory")
	return InstalledLayout{
		Launcher:             filepath.Join(root, "agentmemory.exe"),
		RuntimeHelper:        filepath.Join(root, "bin", "agentmemory-runtime-helper.exe"),
		DistributionEnvelope: filepath.Join(root, "resources", "bundle", "bootstrap", "distribution-manifest.json"),
	}, nil
}
