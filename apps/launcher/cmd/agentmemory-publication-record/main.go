// Command agentmemory-publication-record hashes the closed qualified candidate
// tree and emits the canonical authority used to promote exact release objects.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
)

func main() { os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr)) }

func run(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("agentmemory-publication-record", flag.ContinueOnError)
	flags.SetOutput(stderr)
	candidateRoot := flags.String("candidate-root", "", "closed qualified candidate tree")
	output := flags.String("output", "", "new canonical publication JSON")
	releaseID := flags.String("release-id", "", "manifest-bound release identifier")
	version := flags.String("version", "", "stable product semantic version")
	buildID := flags.String("build-id", "", "qualified candidate build identifier")
	sourceCommit := flags.String("source-commit", "", "exact clean source revision")
	sourceEpoch := flags.Int64("source-date-epoch", 0, "release commit timestamp as Unix seconds")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "unexpected positional arguments: %v\n", flags.Args())
		return 2
	}
	err := AssemblePublication(ctx, PublicationOptions{
		CandidateRoot: *candidateRoot, Output: *output, ReleaseID: *releaseID, Version: *version,
		BuildID: *buildID, SourceCommit: *sourceCommit, SourceEpoch: *sourceEpoch,
	}, compilePublication)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Publication record creation failed: %v\n", err)
		return 1
	}
	if _, err := fmt.Fprintln(stdout, *output); err != nil {
		return 1
	}
	return 0
}
