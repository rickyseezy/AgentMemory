package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("check-desktop-packages", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "AgentMemory repository root")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "unexpected positional arguments: %v\n", flags.Args())
		return 2
	}
	if violations := Check(Options{RepositoryRoot: *root}); len(violations) != 0 {
		for _, violation := range violations {
			_, _ = fmt.Fprintf(stderr, "Desktop package check failed: %v\n", violation)
		}
		return 1
	}
	if _, err := fmt.Fprintln(stdout, "Desktop package check passed"); err != nil {
		return 1
	}
	return 0
}
