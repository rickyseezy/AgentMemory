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

func main() { os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr)) }

func run(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
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
	err := Assemble(ctx, AssembleOptions{
		RepositoryRoot: *root, StagingRoot: *staging, SignedEnvelope: *envelope,
		TrustDocument: *trust, Output: *output, SourceEpoch: *sourceEpoch,
		VerificationEpoch: *verificationEpoch,
	}, processRunner{}, decodeProductionInventory, launcher.ValidateNativeReleaseBundle)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Offline bundle assembly failed: %v\n", err)
		return 1
	}
	if _, err := fmt.Fprintln(stdout, *output); err != nil {
		return 1
	}
	return 0
}
