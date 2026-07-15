// Command check_pf001_certification validates the executable PF-001 support
// matrix and independently signed clean-host release evidence.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/rickyseezy/AgentMemory/tools/internal/pf001certification"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("check-pf001-certification", flag.ContinueOnError)
	flags.SetOutput(stderr)
	matrixPath := flags.String("matrix", "contracts/pf001/support-matrix-v1.json", "reviewed PF-001 support matrix")
	emitMatrix := flags.Bool("emit-github-matrix", false, "emit the exact generated GitHub Actions matrix")
	printAuthorityKeyID := flags.Bool("print-authority-key-id", false, "derive the report key ID from the trusted public key")
	canonicalize := flags.String("canonicalize-report", "", "strictly canonicalize an unsigned report to stdout")
	assembleSignature := flags.String("assemble-signature-report", "", "canonical report signed by an external Ed25519 authority")
	rawSignaturePath := flags.String("raw-signature", "", "raw 64-byte Ed25519 signature returned by the external signer")
	campaignRoot := flags.String("campaign-root", "", "raw externally signed campaign directory")
	bundlePath := flags.String("bundle", "", "canonical certification ZIP to reverify")
	publicationPath := flags.String("publication", "", "independently verified release publication record")
	publicKeyBase64 := flags.String("public-key-base64", "", "trusted Ed25519 certification public key")
	expectedVersion := flags.String("expected-version", "", "exact stable release version")
	expectedCommit := flags.String("expected-source-commit", "", "exact lowercase source commit")
	verificationEpoch := flags.Int64("verification-time-unix", 0, "trusted qualification time as Unix seconds")
	requiredCell := flags.String("required-cell", "", "require one generated matrix cell")
	output := flags.String("output", "", "new canonical evidence ZIP output")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "unexpected positional arguments: %v\n", flags.Args())
		return 2
	}
	if (*assembleSignature == "") != (*rawSignaturePath == "") {
		_, _ = fmt.Fprintln(stderr, "signature assembly requires both report and raw signature")
		return 2
	}
	matrix, matrixDigest, err := pf001certification.LoadSupportMatrix(*matrixPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "PF-001 certification check failed: %v\n", err)
		return 1
	}
	modes := 0
	for _, selected := range []bool{
		*emitMatrix, *printAuthorityKeyID, *canonicalize != "", *assembleSignature != "", *campaignRoot != "", *bundlePath != "",
	} {
		if selected {
			modes++
		}
	}
	if modes == 0 {
		if _, err := fmt.Fprintf(stdout, "PF-001 support matrix check passed: %s\n", matrixDigest); err != nil {
			return 1
		}
		return 0
	}
	if modes != 1 {
		_, _ = fmt.Fprintln(stderr, "exactly one certification operation must be selected")
		return 2
	}
	if *emitMatrix {
		if *publicationPath != "" || *publicKeyBase64 != "" || *output != "" || *requiredCell != "" {
			_, _ = fmt.Fprintln(stderr, "matrix generation does not accept campaign inputs")
			return 2
		}
		raw, err := matrix.GitHubMatrix()
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "PF-001 certification check failed: %v\n", err)
			return 1
		}
		if _, err := stdout.Write(append(raw, '\n')); err != nil {
			return 1
		}
		return 0
	}
	if *printAuthorityKeyID {
		if *publicKeyBase64 == "" || *publicationPath != "" || *output != "" || *requiredCell != "" ||
			*expectedVersion != "" || *expectedCommit != "" || *verificationEpoch != 0 {
			_, _ = fmt.Fprintln(stderr, "authority key ID inputs are incomplete or ambiguous")
			return 2
		}
		publicKey, err := pf001certification.DecodePublicKeyBase64(*publicKeyBase64)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "PF-001 certification check failed: %v\n", err)
			return 1
		}
		keyID, err := pf001certification.AuthorityKeyID(publicKey)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "PF-001 certification check failed: %v\n", err)
			return 1
		}
		if _, err := fmt.Fprintln(stdout, keyID); err != nil {
			return 1
		}
		return 0
	}
	if *canonicalize != "" {
		if *publicationPath != "" || *publicKeyBase64 != "" || *output != "" || *requiredCell != "" {
			_, _ = fmt.Fprintln(stderr, "report canonicalization does not accept verification inputs")
			return 2
		}
		raw, err := os.ReadFile(filepath.Clean(*canonicalize)) // #nosec G304 -- explicit operator-selected input.
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "PF-001 certification check failed: %v\n", err)
			return 1
		}
		canonical, err := pf001certification.CanonicalizeReport(raw)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "PF-001 certification check failed: %v\n", err)
			return 1
		}
		if _, err := stdout.Write(canonical); err != nil {
			return 1
		}
		return 0
	}
	if *assembleSignature != "" {
		if *rawSignaturePath == "" || *publicKeyBase64 == "" || *publicationPath != "" || *output != "" ||
			*requiredCell != "" || *expectedVersion != "" || *expectedCommit != "" || *verificationEpoch != 0 {
			_, _ = fmt.Fprintln(stderr, "signature assembly inputs are incomplete or ambiguous")
			return 2
		}
		reportRaw, reportError := os.ReadFile(filepath.Clean(*assembleSignature))      // #nosec G304 -- explicit authority-selected input.
		rawSignature, signatureError := os.ReadFile(filepath.Clean(*rawSignaturePath)) // #nosec G304 -- explicit hardware-signer output.
		publicKey, keyError := pf001certification.DecodePublicKeyBase64(*publicKeyBase64)
		if reportError != nil || signatureError != nil || keyError != nil {
			_, _ = fmt.Fprintln(stderr, "PF-001 certification check failed: signature inputs are unavailable")
			return 1
		}
		envelope, err := pf001certification.AssembleDetachedSignature(reportRaw, publicKey, rawSignature)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "PF-001 certification check failed: %v\n", err)
			return 1
		}
		if _, err := stdout.Write(envelope); err != nil {
			return 1
		}
		return 0
	}
	if *publicationPath == "" || *publicKeyBase64 == "" || *expectedVersion == "" ||
		*expectedCommit == "" || *verificationEpoch <= 0 {
		_, _ = fmt.Fprintln(stderr, "campaign verification inputs are incomplete")
		return 2
	}
	publication, err := pf001certification.LoadPublicationBinding(*publicationPath)
	if err != nil || publication.Version != *expectedVersion || publication.SourceCommit != *expectedCommit {
		_, _ = fmt.Fprintln(stderr, "PF-001 certification check failed: release publication identity mismatch")
		return 1
	}
	publicKey, err := pf001certification.DecodePublicKeyBase64(*publicKeyBase64)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "PF-001 certification check failed: %v\n", err)
		return 1
	}
	options := pf001certification.VerifyOptions{
		Matrix: matrix, MatrixSHA256: matrixDigest, Publication: publication, PublicKey: publicKey,
		VerificationTime: time.Unix(*verificationEpoch, 0).UTC(), RequiredCell: *requiredCell,
	}
	if *campaignRoot != "" {
		root, err := filepath.Abs(*campaignRoot)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "PF-001 certification check failed: campaign root is invalid")
			return 1
		}
		if *output != "" {
			outputPath, err := filepath.Abs(*output)
			if err != nil {
				_, _ = fmt.Fprintln(stderr, "PF-001 certification check failed: output path is invalid")
				return 1
			}
			if err := pf001certification.CreateBundle(filepath.Clean(root), filepath.Clean(outputPath), options); err != nil {
				_, _ = fmt.Fprintf(stderr, "PF-001 certification check failed: %v\n", err)
				return 1
			}
		} else if _, err := pf001certification.VerifyRoot(filepath.Clean(root), options); err != nil {
			_, _ = fmt.Fprintf(stderr, "PF-001 certification check failed: %v\n", err)
			return 1
		}
	} else {
		if *output != "" {
			_, _ = fmt.Fprintln(stderr, "bundle reverification does not accept an output path")
			return 2
		}
		bundle, err := filepath.Abs(*bundlePath)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "PF-001 certification check failed: bundle path is invalid")
			return 1
		}
		if _, err := pf001certification.VerifyBundle(filepath.Clean(bundle), options); err != nil {
			_, _ = fmt.Fprintf(stderr, "PF-001 certification check failed: %v\n", err)
			return 1
		}
	}
	if _, err := fmt.Fprintf(stdout, "PF-001 native certification check passed: %s\n", matrixDigest); err != nil {
		return 1
	}
	return 0
}
