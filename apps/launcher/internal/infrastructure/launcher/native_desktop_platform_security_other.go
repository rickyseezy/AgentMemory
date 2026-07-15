//go:build !darwin && !windows

package launcher

func newNativeDesktopPlatformSecurity() (nativeDesktopPlatformSecurity, error) {
	return nativeDesktopPlatformSecurity{}, errNativeInstallerUnavailable
}
