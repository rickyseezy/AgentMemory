// Command agentmemory-native-package-stage creates deterministic macOS and
// Windows package payloads from one fully verified retained release.
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

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("agentmemory-native-package-stage", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "clean AgentMemory repository root")
	bundle := flags.String("bundle", "", "signed retained release bundle root")
	trust := flags.String("trust", "", "production native release trust JSON")
	output := flags.String("output", "", "new package staging directory")
	operatingSystem := flags.String("os", "", "target desktop operating system: darwin or windows")
	architecture := flags.String("arch", "", "target architecture: amd64 or arm64")
	epoch := flags.Int64("source-date-epoch", 0, "release commit timestamp as Unix seconds")
	verificationEpoch := flags.Int64("verification-epoch", 0, "release qualification time as Unix seconds")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "unexpected positional arguments: %v\n", flags.Args())
		return 2
	}
	options := StageOptions{
		RepositoryRoot: *root, BundleRoot: *bundle, TrustDocument: *trust, Output: *output,
		OperatingSystem: *operatingSystem, Architecture: *architecture,
		SourceEpoch: *epoch, VerificationEpoch: *verificationEpoch,
	}
	if err := Stage(
		ctx, options, processRunner{}, launcher.ValidateNativeReleaseTrustBase64,
		resolveProductionNativePackage,
	); err != nil {
		_, _ = fmt.Fprintf(stderr, "Native package staging failed: %v\n", err)
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
	project := func(resource launcher.NativeReleasePackageResource) verifiedNativeResource {
		return verifiedNativeResource{
			resourceID: resource.ResourceID(), bundlePath: resource.BundlePath(),
			sha256: resource.SHA256(), size: resource.Size(),
		}
	}
	return verifiedNativePackage{
		operatingSystem: selected.OperatingSystem(), architecture: selected.Architecture(),
		launcher: project(selected.Launcher()), helper: project(selected.Helper()),
	}, nil
}
