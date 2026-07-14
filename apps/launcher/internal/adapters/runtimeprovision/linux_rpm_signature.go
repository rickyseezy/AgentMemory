package runtimeprovision

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
)

var errRPMSignature = errors.New("rpm package signature validation failed")

type rpmPackageSignatureVerifier interface {
	VerifyRPMPackage(
		context.Context,
		[]byte,
		string,
		artifactacquisition.Artifact,
		io.Reader,
	) error
}

// RPMKeysPackageVerifier authenticates retained packages with the host's
// publisher-verified rpmkeys executable and an operation-owned empty key DB.
type RPMKeysPackageVerifier struct {
	runner argvprocess.Runner
}

// NewRPMKeysPackageVerifier constructs the native verifier from exact signed
// executable authority. The generic process runner prevents PATH substitution.
func NewRPMKeysPackageVerifier(runner argvprocess.Runner) (*RPMKeysPackageVerifier, error) {
	if nilArtifactDependency(runner) || !runner.ExecutableAuthority().Valid() ||
		runner.ExecutableAuthority().Role() != argvprocess.ExecutableRoleRPMKeys ||
		runner.ExecutableAuthority().Platform() != "linux" {
		return nil, errRPMSignature
	}
	return &RPMKeysPackageVerifier{runner: runner}, nil
}

// VerifyRPMPackage imports only the catalog-pinned key, forces RPM's strongest
// signature-and-digest policy, and verifies one exact CAS stream.
func (v *RPMKeysPackageVerifier) VerifyRPMPackage(
	ctx context.Context,
	key []byte,
	fingerprint string,
	artifact artifactacquisition.Artifact,
	packageReader io.Reader,
) error {
	if v == nil || ctx == nil || nilArtifactDependency(v.runner) || len(key) == 0 ||
		fingerprint == "" || artifact.ID() == "" || artifact.Size() == 0 ||
		artifact.Digest().IsZero() || packageReader == nil {
		return errRPMSignature
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	keyring, err := readAPTKeyring(key)
	if err != nil || !keyringContainsExactFingerprint(keyring, fingerprint) {
		return errRPMSignature
	}
	root, err := os.MkdirTemp("", "agentmemory-rpm-verify-")
	if err != nil {
		return errRPMSignature
	}
	defer os.RemoveAll(root) //nolint:errcheck // private best-effort cleanup; verification fails before mutation.
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0o700 {
		return errRPMSignature
	}
	keyPath := filepath.Join(root, "publisher-key.asc")
	packagePath := filepath.Join(root, "package.rpm")
	databasePath := filepath.Join(root, "rpmdb")
	if err = os.Mkdir(databasePath, 0o700); err != nil ||
		writePrivateRPMVerificationFile(keyPath, bytes.NewReader(key), uint64(len(key))) != nil ||
		writePrivateRPMVerificationFile(packagePath, packageReader, artifact.Size()) != nil {
		return errRPMSignature
	}
	if err = v.runRPMKeys(ctx, []string{"--dbpath", databasePath, "--import", keyPath}); err != nil {
		return err
	}
	if err = v.runRPMKeys(ctx, []string{
		"--dbpath", databasePath,
		"--define", "%_pkgverify_level all",
		"--checksig", packagePath,
	}); err != nil {
		return err
	}
	return nil
}

func (v *RPMKeysPackageVerifier) runRPMKeys(ctx context.Context, arguments []string) error {
	authority := v.runner.ExecutableAuthority()
	invocation, err := argvprocess.NewInvocation(authority.CanonicalPath(), arguments)
	if err != nil {
		return errRPMSignature
	}
	result, err := v.runner.Run(ctx, invocation)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errRPMSignature
	}
	if result.ExitCode != 0 || result.OutputTruncated {
		return errRPMSignature
	}
	return nil
}

func writePrivateRPMVerificationFile(path string, reader io.Reader, size uint64) error {
	if size == 0 {
		return errRPMSignature
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- path is a fixed leaf in an operation-owned 0700 directory.
	if err != nil {
		return errRPMSignature
	}
	limit := int64(size) + 1 // #nosec G115 -- artifact validation caps size below MaxInt64.
	written, copyError := io.Copy(file, io.LimitReader(reader, limit))
	syncError := file.Sync()
	closeError := file.Close()
	if copyError != nil || syncError != nil || closeError != nil || written < 0 || uint64(written) != size {
		return errRPMSignature
	}
	return nil
}
