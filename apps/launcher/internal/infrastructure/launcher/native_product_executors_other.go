//go:build !linux

package launcher

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/dockercli"
)

func (*nativePlatformRuntimeFactory) buildLinuxProductExecutors(
	context.Context,
	nativeVerifiedRuntimeExecution,
) (dockercli.Executors, error) {
	return dockercli.Executors{}, errNativeInstallerUnavailable
}
