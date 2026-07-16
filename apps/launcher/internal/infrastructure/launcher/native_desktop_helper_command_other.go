//go:build !darwin && !windows

package launcher

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeprovision"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
)

type nativeDesktopHelperExchange interface {
	ReadDesktopMutationRequest(context.Context, string) ([]byte, string, error)
	WriteDesktopMutationReceipt(context.Context, string, []byte) error
	PrincipalID() string
}

// RunNativeDesktopMutationHelper fails closed on platforms that do not install
// the signed macOS/Windows privileged helper.
func RunNativeDesktopMutationHelper(context.Context, []string) error {
	return runtimeport.ErrDesktopMutationIntegrity
}

func newNativeDesktopMutationHelperApplication(
	context.Context,
	string,
	string,
) (*runtimeprovision.DesktopMutationHelperApplication, *nativeReleaseAuthority, []nativeRuntimeResourceCloser, error) {
	return nil, nil, nil, runtimeport.ErrDesktopMutationIntegrity
}

func nativeDesktopHelperElevated() bool { return false }

func nativeDesktopHelperPlatformBoundaries(string) (string, nativeDesktopHelperExchange, error) {
	return "", nil, errNativeInstallerUnavailable
}

func nativeDesktopHelperReleaseBundleRoot() (string, error) {
	return "", errNativeInstallerUnavailable
}
