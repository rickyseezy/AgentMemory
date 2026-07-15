// Command agentmemory-release-envelope constructs the canonical signed
// release-manifest envelope from owner-supplied offline signature evidence.
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
	flags := flag.NewFlagSet("agentmemory-release-envelope", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifest := flags.String("manifest", "", "canonical inner release manifest JSON")
	trustMode := flags.String("trust-mode", "", "key_id or certificate_transparency")
	trustRoot := flags.String("trust-root-id", "", "signed manifest trust-root identifier")
	signature := flags.String("signature", "", "raw detached Ed25519 signature for key_id mode")
	sigstore := flags.String("sigstore-bundle", "", "official Sigstore bundle for certificate_transparency mode")
	revocations := flags.String("revocation-set", "", "offline signed revocation evidence")
	trustedTime := flags.String("trusted-time", "", "offline signed trusted-time evidence")
	output := flags.String("output", "", "new canonical distribution envelope")
	epoch := flags.Int64("source-date-epoch", 0, "release commit timestamp as Unix seconds")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "unexpected positional arguments: %v\n", flags.Args())
		return 2
	}
	err := BuildEnvelope(ctx, EnvelopeOptions{
		Manifest: *manifest, TrustMode: *trustMode, TrustRootID: *trustRoot,
		Signature: *signature, SigstoreBundle: *sigstore, RevocationSet: *revocations,
		TrustedTimeEvidence: *trustedTime, Output: *output, SourceEpoch: *epoch,
	}, compileProductionEnvelope)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Release envelope creation failed: %v\n", err)
		return 1
	}
	if _, err := fmt.Fprintln(stdout, *output); err != nil {
		return 1
	}
	return 0
}
