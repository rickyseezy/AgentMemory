//go:build windows

package launcher

import "errors"

func nativeLauncherExecutionPolicy(
	release *nativeReleaseAuthority,
	resourceID string,
	_ [32]byte,
) (string, string, [32]byte, error) {
	certificate := release.nativePublisherCertificateDigest(resourceID)
	if certificate.IsZero() {
		return "", "", [32]byte{}, errors.New("launcher signer certificate is unavailable")
	}
	return "sid:S-1-5-32-544", "windows:authenticode:v1", certificate, nil
}
