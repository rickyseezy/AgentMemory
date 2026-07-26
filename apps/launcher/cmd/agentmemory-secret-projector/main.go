// Package main exposes the AgentMemory protected-secret projection command.
package main

import (
	"fmt"
	"os"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/secretprojector"
)

// main is an os.Exit boundary; run is tested directly for every exit contract.
// mutator-disable-func
func main() {
	os.Exit(run(
		os.Args,
		os.Stdout,
		os.Stderr,
		secretprojector.RunDefault,
		secretprojector.RunRemote,
	))
}

func run(
	args []string,
	stdout, stderr *os.File,
	projectDefault, projectRemote func() error,
) int {
	if stdout == nil || stderr == nil || projectDefault == nil || projectRemote == nil {
		if stderr != nil {
			_, _ = fmt.Fprintln(stderr, "protected projection failed: argument-contract")
		}
		return 1
	}
	project := projectDefault
	if len(args) == 2 && args[1] == "remote" {
		project = projectRemote
	} else if len(args) != 1 {
		_, _ = fmt.Fprintln(stderr, "protected projection failed: argument-contract")
		return 1
	}
	if err := project(); err != nil {
		_, _ = fmt.Fprintln(stderr, err.Error())
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "ok")
	return 0
}
