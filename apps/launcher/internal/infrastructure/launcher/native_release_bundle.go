package launcher

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type nativeExecutablePathResolver func() (string, error)

func defaultNativeReleaseBundleRoot() (string, error) {
	return resolveNativeReleaseBundleRoot(os.Executable, runtime.GOOS)
}

// resolveNativeReleaseBundleRoot accepts no environment variable, current
// directory, MCP argument, or mutable configuration. Linux and Windows native
// packaging place the retained bundle at one fixed location relative to the
// launcher. macOS uses the same fixed root-owned Application Support bundle as
// its separately installed privilege helper, avoiding a code-signing cycle.
func resolveNativeReleaseBundleRoot(
	executable nativeExecutablePathResolver,
	operatingSystem string,
) (string, error) {
	if executable == nil {
		return "", errNativeInstallerIntegrity
	}
	path, err := executable()
	if err != nil || path == "" || strings.ContainsRune(path, 0) || !filepath.IsAbs(path) ||
		filepath.Clean(path) != path {
		return "", errNativeInstallerIntegrity
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !filepath.IsAbs(resolved) || filepath.Clean(resolved) != resolved {
		return "", errNativeInstallerIntegrity
	}
	info, err := os.Lstat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errNativeInstallerIntegrity
	}
	directory := filepath.Dir(resolved)
	var root string
	switch operatingSystem {
	case "darwin":
		root = "/Library/Application Support/AgentMemory/resources/bundle"
	case "linux", "windows":
		root = filepath.Join(directory, "resources", "bundle")
	default:
		return "", errNativeInstallerIntegrity
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", errNativeInstallerIntegrity
	}
	return root, nil
}
