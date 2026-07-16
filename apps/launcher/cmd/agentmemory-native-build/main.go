// Command agentmemory-native-build produces reproducible unsigned native
// artifacts that release signing and manifest assembly consume without rebuild.
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
func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

type nativeBuildCommand func(context.Context, BuildOptions) error

func run(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	return runWithBuild(ctx, args, stdout, stderr, func(ctx context.Context, options BuildOptions) error {
		return Build(ctx, options, processRunner{}, launcher.ValidateNativeReleaseTrustBase64)
	})
}

func runWithBuild(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	build nativeBuildCommand,
) int {
	if build == nil {
		_, _ = fmt.Fprintln(stderr, "Native build failed: build command is unavailable")
		return 1
	}
	flags := flag.NewFlagSet("agentmemory-native-build", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "clean AgentMemory repository root")
	trust := flags.String("trust", "", "production native release trust JSON")
	output := flags.String("output", "", "new native build output directory")
	operatingSystem := flags.String("os", "", "target operating system: linux, windows, or darwin")
	architecture := flags.String("arch", "", "target architecture: amd64 or arm64")
	epoch := flags.Int64("source-date-epoch", 0, "release commit timestamp as Unix seconds")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "unexpected positional arguments: %v\n", flags.Args())
		return 2
	}
	options := BuildOptions{
		RepositoryRoot: *root, TrustDocument: *trust, Output: *output,
		OperatingSystem: *operatingSystem, Architecture: *architecture, SourceEpoch: *epoch,
	}
	if err := build(ctx, options); err != nil {
		_, _ = fmt.Fprintf(stderr, "Native build failed: %v\n", err)
		return 1
	}
	if _, err := fmt.Fprintln(stdout, options.Output); err != nil {
		return 1
	}
	return 0
}
