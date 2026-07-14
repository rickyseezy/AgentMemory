//go:build !linux

package runtimeprovision

import (
	"context"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
)

func prepareNativeProbeWorkspace(
	ctx context.Context,
	_ runtimeport.LinuxAuthority,
) (probeWorkspace, error) {
	if ctx == nil {
		return probeWorkspace{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return probeWorkspace{}, err
	}
	return probeWorkspace{}, ErrUnsupportedHost
}
