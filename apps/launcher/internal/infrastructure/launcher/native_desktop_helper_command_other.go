//go:build !darwin && !windows

package launcher

func nativeDesktopHelperElevated() bool { return false }

func nativeDesktopHelperPlatformBoundaries(string) (string, nativeDesktopHelperExchange, error) {
	return "", nil, errNativeInstallerUnavailable
}

func nativeDesktopHelperReleaseBundleRoot() (string, error) {
	return "", errNativeInstallerUnavailable
}
