//go:build !linux

package launcher

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installphase"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
)

func buildNativeLinuxPrivilegeCodec(
	context.Context,
	*nativeReleaseAuthority,
	nativeVerifiedRuntimeExecution,
	runtimeport.LinuxAuthority,
	runtimeprovision.PrivilegeArtifactStager,
) (*runtimeprovision.CanonicalPrivilegeTransportCodec, nativeLinuxHelperAuthority, error) {
	return nil, nativeLinuxHelperAuthority{}, errNativeInstallerUnavailable
}

func (f *nativePlatformRuntimeFactory) buildLinuxRuntimeApplication(
	context.Context,
	nativeVerifiedRuntimeExecution,
) (installphase.RuntimeEnsurer, error) {
	return nil, errNativeInstallerUnavailable
}
