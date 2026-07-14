//go:build (!darwin && !windows) || (darwin && !cgo)

package runtimeprovision

import (
	"context"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
)

func createNativeDesktopMutationExchange(
	ctx context.Context,
	_ runtimeport.DesktopHelperAuthority,
	_ runtimeport.DesktopMutationRequest,
) (nativeDesktopMutationExchange, error) {
	if ctx == nil || ctx.Err() != nil {
		return nativeDesktopMutationExchange{}, context.Canceled
	}
	return nativeDesktopMutationExchange{}, runtimeport.ErrDesktopMutationUnavailable
}

func executeNativeDesktopHelper(
	ctx context.Context,
	_ runtimeport.DesktopHelperAuthority,
	_ string,
) error {
	if ctx == nil || ctx.Err() != nil {
		return context.Canceled
	}
	return runtimeport.ErrDesktopMutationUnavailable
}
