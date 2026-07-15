package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("check_linux_package", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "repository root containing packaging/linux")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		if _, err := fmt.Fprintf(stderr, "unexpected positional arguments: %v\n", flags.Args()); err != nil {
			return 1
		}
		return 2
	}

	violations := Check(Options{RepositoryRoot: *root})
	for _, violation := range violations {
		if _, err := fmt.Fprintln(stderr, violation); err != nil {
			return 1
		}
	}
	if len(violations) != 0 {
		if _, err := fmt.Fprintf(stderr, "Linux package check failed: %d violation(s)\n", len(violations)); err != nil {
			return 1
		}
		return 1
	}
	if _, err := fmt.Fprintln(stdout, "Linux package check passed"); err != nil {
		return 1
	}
	return 0
}
