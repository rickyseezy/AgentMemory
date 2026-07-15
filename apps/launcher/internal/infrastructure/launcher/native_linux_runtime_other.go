//go:build !linux

package launcher

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installphase"
)

func (f *nativePlatformRuntimeFactory) buildLinuxRuntimeApplication(
	context.Context,
	nativeVerifiedRuntimeExecution,
) (installphase.RuntimeEnsurer, error) {
	return nil, errNativeInstallerUnavailable
}
