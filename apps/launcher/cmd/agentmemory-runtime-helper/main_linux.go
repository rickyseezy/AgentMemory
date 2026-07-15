//go:build linux

package main

import (
	"context"
	"os"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/infrastructure/launcher"
)

func runPlatformNativeHelper(ctx context.Context, args []string) error {
	return launcher.RunNativeLinuxPrivilegeHelper(ctx, args, os.Stdin, os.Stdout)
}
