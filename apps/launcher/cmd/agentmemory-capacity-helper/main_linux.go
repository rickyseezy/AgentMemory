//go:build linux

// Command agentmemory-capacity-helper is the signed, volume-local PF-001
// physical capacity allocator. It has no generic path or command mode.
package main

import (
	"context"
	"io"
	"os"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/capacityhelper"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, capacityhelper.NewLinuxStore()))
}

func run(arguments []string, stdout io.Writer, stderr io.Writer, store capacityhelper.Store) int {
	service, err := capacityhelper.NewService(store)
	if err == nil {
		var response []byte
		response, err = service.Execute(context.Background(), arguments)
		if err == nil {
			_, err = stdout.Write(response)
		}
	}
	if err != nil {
		_, _ = io.WriteString(stderr, "capacity helper operation failed\n")
		return 1
	}
	return 0
}
