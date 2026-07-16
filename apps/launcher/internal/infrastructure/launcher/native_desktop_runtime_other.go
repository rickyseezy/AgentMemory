//go:build !darwin && !windows

package launcher

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installphase"
)

func (f *nativePlatformRuntimeFactory) buildDesktopRuntimeApplication(
	ctx context.Context,
	_ nativeVerifiedRuntimeExecution,
) (installphase.RuntimeEnsurer, error) {
	if f == nil || ctx == nil {
		return nil, errNativeInstallerIntegrity
	}
	return nil, errNativeInstallerUnavailable
}

func buildNativeDesktopAuthority(
	context.Context,
	nativeVerifiedRuntimeExecution,
	*nativeReleaseAuthority,
) (nativeDesktopAuthoritySet, error) {
	return nativeDesktopAuthoritySet{}, errNativeInstallerIntegrity
}

func buildNativeDesktopArtifacts(
	nativeVerifiedRuntimeExecution,
	*artifactapp.Application,
	*nativeComposition,
	nativeDesktopPlatformSecurity,
) (nativeDesktopArtifactSet, error) {
	return nativeDesktopArtifactSet{}, errNativeInstallerIntegrity
}

func buildNativeDesktopHelpers(
	*nativeReleaseAuthority,
	nativeVerifiedRuntimeExecution,
) (nativeDesktopHelperSet, error) {
	return nativeDesktopHelperSet{}, errNativeInstallerIntegrity
}
