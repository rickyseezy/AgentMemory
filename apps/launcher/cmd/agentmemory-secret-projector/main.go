// Package main exposes the AgentMemory protected-secret projection command.
package main

import (
	"fmt"
	"os"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/secretprojector"
)

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr, secretprojector.RunDefault))
}

func run(args []string, stdout, stderr *os.File, project func() error) int {
	if len(args) != 1 || stdout == nil || stderr == nil || project == nil {
		if stderr != nil {
			_, _ = fmt.Fprintln(stderr, "protected projection failed: argument-contract")
		}
		return 1
	}
	if err := project(); err != nil {
		_, _ = fmt.Fprintln(stderr, err.Error())
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "ok")
	return 0
}
