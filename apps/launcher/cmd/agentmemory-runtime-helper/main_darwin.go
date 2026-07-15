//go:build darwin

package main

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/infrastructure/launcher"
)

func runPlatformNativeHelper(ctx context.Context, args []string) error {
	return launcher.RunNativeDesktopMutationHelper(ctx, args)
}
