//go:build linux

package main

import (
	"context"
	"os"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/infrastructure/launcher"
)

func main() {
	if launcher.RunNativeLinuxPrivilegeHelper(context.Background(), os.Args[1:], os.Stdin, os.Stdout) != nil {
		os.Exit(1)
	}
}
