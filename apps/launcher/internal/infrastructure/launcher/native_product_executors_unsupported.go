//go:build !darwin && !linux && !windows

package launcher

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/dockercli"
)

func (*nativePlatformRuntimeFactory) buildPlatformProductExecutors(
	context.Context,
	nativeVerifiedRuntimeExecution,
) (dockercli.Executors, error) {
	return dockercli.Executors{}, errNativeInstallerUnavailable
}
