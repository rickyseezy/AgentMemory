// Command agentmemory-offline-bundle assembles one exact verified retained
// release tree for native packaging and fully offline installation.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/infrastructure/launcher"
)

// main is an os.Exit boundary; run is tested directly across its full contract.
// mutator-disable-func
func main() { os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr)) }

type offlineBundleCommand func(context.Context, AssembleOptions) error

func run(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	return runWithAssembly(ctx, args, stdout, stderr, func(ctx context.Context, options AssembleOptions) error {
		return Assemble(
			ctx, options, processRunner{}, decodeProductionInventory,
			launcher.ValidateNativeReleaseBundle,
		)
	})
}

func runWithAssembly(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	assemble offlineBundleCommand,
) int {
	if assemble == nil {
		_, _ = fmt.Fprintln(stderr, "Offline bundle assembly failed: assembly command is unavailable")
		return 1
	}
	flags := flag.NewFlagSet("agentmemory-offline-bundle", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "clean AgentMemory repository root")
	staging := flags.String("staging", "", "directory containing exactly the signed manifest resources")
	envelope := flags.String("envelope", "", "canonical signed release-manifest envelope")
	trust := flags.String("trust", "", "production native release trust JSON")
	output := flags.String("output", "", "new retained offline-bundle directory")
	sourceEpoch := flags.Int64("source-date-epoch", 0, "release commit timestamp as Unix seconds")
	verificationEpoch := flags.Int64("verification-epoch", 0, "release qualification time as Unix seconds")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "unexpected positional arguments: %v\n", flags.Args())
		return 2
	}
	options := AssembleOptions{
		RepositoryRoot: *root, StagingRoot: *staging, SignedEnvelope: *envelope,
		TrustDocument: *trust, Output: *output, SourceEpoch: *sourceEpoch,
		VerificationEpoch: *verificationEpoch,
	}
	err := assemble(ctx, options)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Offline bundle assembly failed: %v\n", err)
		return 1
	}
	if _, err := fmt.Fprintln(stdout, options.Output); err != nil {
		return 1
	}
	return 0
}
