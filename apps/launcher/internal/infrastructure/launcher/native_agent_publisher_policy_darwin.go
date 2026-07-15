//go:build darwin

package launcher

func nativeLauncherExecutionPolicy(
	_ *nativeReleaseAuthority,
	_ string,
	manifestDigest [32]byte,
) (string, string, [32]byte, error) {
	return "uid:0", "apple:developer-id-notarized:v1", manifestDigest, nil
}
