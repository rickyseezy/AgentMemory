// Command agentmemory-linux-release creates a deterministic nFPM staging tree
// from one clean source revision and one production release authority.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/infrastructure/launcher"
)

// main is an os.Exit boundary; run is tested directly across its full contract.
// mutator-disable-func
func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

type assemblyCommand func(context.Context, AssemblyOptions) error

func run(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	return runWithAssembly(ctx, args, stdout, stderr, func(ctx context.Context, options AssemblyOptions) error {
		return Assemble(
			ctx, options, processRunner{}, launcher.ValidateNativeReleaseTrustBase64,
			resolveProductionNativePackage,
		)
	})
}

func runWithAssembly(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	assemble assemblyCommand,
) int {
	if assemble == nil {
		_, _ = fmt.Fprintln(stderr, "Linux release assembly failed: assembly command is unavailable")
		return 1
	}
	flags := flag.NewFlagSet("agentmemory-linux-release", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "clean AgentMemory repository root")
	bundle := flags.String("bundle", "", "signed retained release bundle root")
	trust := flags.String("trust", "", "production native release trust JSON")
	output := flags.String("output", "", "new nFPM staging directory")
	architecture := flags.String("arch", "", "Linux architecture: amd64 or arm64")
	epoch := flags.Int64("source-date-epoch", 0, "release commit timestamp as Unix seconds")
	verificationEpoch := flags.Int64("verification-epoch", 0, "release qualification time as Unix seconds")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		if _, err := fmt.Fprintf(stderr, "unexpected positional arguments: %v\n", flags.Args()); err != nil {
			return 1
		}
		return 2
	}
	options := AssemblyOptions{
		RepositoryRoot: *root, BundleRoot: *bundle, TrustDocument: *trust,
		Output: *output, Architecture: *architecture, SourceEpoch: *epoch,
		VerificationEpoch: *verificationEpoch,
	}
	if err := assemble(ctx, options); err != nil {
		if _, writeErr := fmt.Fprintf(stderr, "Linux release assembly failed: %v\n", err); writeErr != nil {
			return 1
		}
		return 1
	}
	if _, err := fmt.Fprintln(stdout, options.Output); err != nil {
		return 1
	}
	return 0
}

func resolveProductionNativePackage(
	ctx context.Context,
	root string,
	trust string,
	operatingSystem string,
	architecture string,
	verifiedAt time.Time,
) (verifiedNativePackage, error) {
	selected, err := launcher.ResolveNativeReleasePackage(
		ctx, root, trust, operatingSystem, architecture, verifiedAt,
	)
	if err != nil {
		return verifiedNativePackage{}, err
	}
	launcherResource := selected.Launcher()
	helperResource := selected.Helper()
	return newVerifiedNativePackage(
		selected.OperatingSystem(), selected.Architecture(),
		newVerifiedNativeResource(
			launcherResource.ResourceID(), launcherResource.BundlePath(),
			launcherResource.SHA256(), launcherResource.Size(),
		),
		newVerifiedNativeResource(
			helperResource.ResourceID(), helperResource.BundlePath(),
			helperResource.SHA256(), helperResource.Size(),
		),
	), nil
}

func newVerifiedNativeResource(resourceID string, bundlePath string, digest string, size uint64) verifiedNativeResource {
	return verifiedNativeResource{resourceID: resourceID, bundlePath: bundlePath, sha256: digest, size: size}
}

func newVerifiedNativePackage(
	operatingSystem string,
	architecture string,
	launcherResource verifiedNativeResource,
	helperResource verifiedNativeResource,
) verifiedNativePackage {
	return verifiedNativePackage{
		operatingSystem: operatingSystem,
		architecture:    architecture,
		launcher:        launcherResource,
		helper:          helperResource,
	}
}
