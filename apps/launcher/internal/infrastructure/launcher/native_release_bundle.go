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
// directory, MCP argument, or mutable configuration. Native packaging places
// the retained bundle at one fixed location relative to the launched binary.
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
		if filepath.Base(directory) != "MacOS" || filepath.Base(filepath.Dir(directory)) != "Contents" {
			return "", errNativeInstallerIntegrity
		}
		root = filepath.Join(filepath.Dir(directory), "Resources", "bundle")
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
