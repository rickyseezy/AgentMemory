// Command agentmemory-host-package builds verified deterministic MCP host
// packages without signing or rebuilding any release input.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
)

// main is an os.Exit boundary; run is tested directly across its full contract.
// mutator-disable-func
func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("agentmemory-host-package", flag.ContinueOnError)
	flags.SetOutput(stderr)
	options := PackageOptions{}
	flags.StringVar(&options.CandidateRoot, "candidate-root", "", "qualified candidate root")
	flags.StringVar(&options.Publication, "publication", "", "signed release publication JSON")
	flags.StringVar(&options.PublicationSigstore, "publication-sigstore", "", "publication Sigstore bundle")
	flags.StringVar(&options.Bootstrap, "bootstrap", "", "publisher-verified portable bootstrap binary")
	flags.StringVar(&options.BootstrapSigstore, "bootstrap-sigstore", "", "bootstrap Sigstore bundle")
	flags.StringVar(&options.TrustDocument, "trust", "", "production native release trust JSON")
	flags.StringVar(&options.Output, "output", "", "new .mcpb or .zip output")
	flags.StringVar(&options.RecordOutput, "record-output", "", "new detached package record JSON")
	flags.StringVar(&options.Host, "host", "", "claude, gemini, or generic")
	flags.StringVar(&options.OperatingSystem, "os", "", "darwin, linux, or windows")
	flags.StringVar(&options.Architecture, "arch", "", "amd64 or arm64")
	flags.StringVar(&options.Version, "version", "", "stable semantic version")
	flags.StringVar(&options.SourceCommit, "source-commit", "", "exact lowercase source commit")
	flags.Int64Var(&options.SourceEpoch, "source-date-epoch", 0, "release commit Unix timestamp")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "unexpected positional arguments: %v\n", flags.Args())
		return 2
	}
	if err := AssembleHostPackage(ctx, options, productionVerifierFactory); err != nil {
		_, _ = fmt.Fprintf(stderr, "Host package assembly failed: %v\n", err)
		return 1
	}
	if _, err := fmt.Fprintln(stdout, options.Output); err != nil {
		return 1
	}
	return 0
}
