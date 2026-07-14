//go:build !darwin && !windows

package runtimeprovision

import (
	"context"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
)

func prepareNativeDesktopProbeWorkspace(
	ctx context.Context,
	_ runtimeport.DesktopAuthority,
) (probeWorkspace, error) {
	if ctx == nil || ctx.Err() != nil {
		return probeWorkspace{}, context.Canceled
	}
	return probeWorkspace{}, ErrUnsupportedHost
}
