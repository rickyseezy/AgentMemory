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
	flags := flag.NewFlagSet("check_launcher_architecture", flag.ContinueOnError)
	flags.SetOutput(stderr)
	repositoryRoot := flags.String("root", ".", "repository root containing apps/launcher")
	launcherPath := flags.String("launcher", defaultLauncherPath, "launcher path relative to the repository root")
	includeTests := flags.Bool("include-tests", false, "apply production import rules to *_test.go files")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		if _, err := fmt.Fprintf(stderr, "unexpected positional arguments: %v\n", flags.Args()); err != nil {
			return 1
		}
		return 2
	}

	violations, err := Check(Options{
		RepositoryRoot: *repositoryRoot,
		LauncherPath:   *launcherPath,
		IncludeTests:   *includeTests,
	})
	if err != nil {
		if _, writeErr := fmt.Fprintf(stderr, "launcher architecture check failed: %v\n", err); writeErr != nil {
			return 1
		}
		return 1
	}
	for _, violation := range violations {
		if _, err := fmt.Fprintln(stderr, violation.String()); err != nil {
			return 1
		}
	}
	if len(violations) != 0 {
		if _, err := fmt.Fprintf(stderr, "launcher architecture check failed: %d violation(s)\n", len(violations)); err != nil {
			return 1
		}
		return 1
	}

	if _, err := fmt.Fprintln(stdout, "launcher architecture check passed"); err != nil {
		return 1
	}
	return 0
}
