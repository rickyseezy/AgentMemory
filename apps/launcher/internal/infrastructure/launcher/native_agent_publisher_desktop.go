//go:build darwin || windows

package launcher

import (
	"errors"
	"runtime"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/process"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

func newNativeLauncherPublisherVerifier(
	argvprocess.ExecutableAuthority,
) (process.PublisherVerifier, error) {
	return newNativeDesktopExecutablePublisherVerifier()
}

func nativeLauncherExecutionPolicy(
	release *nativeReleaseAuthority,
	resourceID string,
	manifestDigest [32]byte,
) (string, string, [32]byte, error) {
	switch runtime.GOOS {
	case "darwin":
		return "uid:0", "apple:developer-id-notarized:v1", manifestDigest, nil
	case "windows":
		certificate := release.nativePublisherCertificateDigest(resourceID)
		if certificate.IsZero() {
			return "", "", [32]byte{}, errors.New("launcher signer certificate is unavailable")
		}
		return "sid:S-1-5-32-544", "windows:authenticode:v1", certificate, nil
	default:
		return "", "", [32]byte{}, errors.New("launcher publisher policy is unavailable")
	}
}
