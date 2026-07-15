package nativepackage

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releasepublication"
)

const maximumObjectSignatureBundleBytes = 64 * 1024 * 1024

// ArtifactSignatureVerifier verifies one exact non-zero SHA-256 against an
// offline signature bundle and independently embedded trust.
type ArtifactSignatureVerifier interface {
	VerifyArtifactSignature(context.Context, releaseinventory.Digest, []byte) error
}

// ObjectSignatureVerifier binds the publication-declared signature evidence
// bytes to the exact native object digest before applying cryptographic trust.
type ObjectSignatureVerifier struct {
	evidenceRoot string
	signature    ArtifactSignatureVerifier
}

// NewObjectSignatureVerifier owns one fixed evidence root.
func NewObjectSignatureVerifier(
	evidenceRoot string,
	signature ArtifactSignatureVerifier,
) (*ObjectSignatureVerifier, error) {
	if evidenceRoot == "" || !filepath.IsAbs(evidenceRoot) ||
		filepath.Clean(evidenceRoot) != evidenceRoot || nilCapability(signature) {
		return nil, ErrCandidateIntegrity
	}
	info, err := os.Lstat(evidenceRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrCandidateIntegrity
	}
	canonical, err := filepath.EvalSymlinks(evidenceRoot)
	if err != nil || !filepath.IsAbs(canonical) || filepath.Clean(canonical) != canonical {
		return nil, ErrCandidateIntegrity
	}
	return &ObjectSignatureVerifier{evidenceRoot: canonical, signature: signature}, nil
}

// VerifyPublisher verifies the exact publication-bound object signature. The
// operating system's package transaction independently enforces the declared
// Apple, Microsoft, or Linux native publisher policy during installation.
func (v *ObjectSignatureVerifier) VerifyPublisher(
	ctx context.Context,
	packagePath string,
	artifact releasepublication.Artifact,
) error {
	if v == nil || ctx == nil || v.evidenceRoot == "" || nilCapability(v.signature) ||
		packagePath == "" || !filepath.IsAbs(packagePath) ||
		artifact.Kind() != releasepublication.ArtifactKindNativePackage || artifact.ID() == "" ||
		artifact.Digest().IsZero() || artifact.SignatureBundleDigest().IsZero() ||
		artifact.NativePublisherPolicy() == "" || strings.ContainsAny(artifact.ID(), `/\`) {
		return ErrCandidateIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	bundlePath := filepath.Join(v.evidenceRoot, artifact.ID()+".sigstore.json")
	bundle, err := readBoundedEvidence(bundlePath)
	if err != nil || !releaseinventory.DigestBytes(bundle).Equal(artifact.SignatureBundleDigest()) {
		return ErrCandidateIntegrity
	}
	if err := v.signature.VerifyArtifactSignature(ctx, artifact.Digest(), bundle); err != nil {
		if contextError := ctx.Err(); contextError != nil {
			return contextError
		}
		return ErrCandidateIntegrity
	}
	return ctx.Err()
}

func readBoundedEvidence(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Size() > maximumObjectSignatureBundleBytes {
		return nil, ErrCandidateIntegrity
	}
	// #nosec G304 -- path is one domain-validated evidence leaf beneath a fixed root.
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrCandidateIntegrity
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, ErrCandidateIntegrity
	}
	content, err := io.ReadAll(io.LimitReader(file, maximumObjectSignatureBundleBytes+1))
	if err != nil || int64(len(content)) != info.Size() {
		return nil, ErrCandidateIntegrity
	}
	return content, nil
}

var _ PublisherVerifier = (*ObjectSignatureVerifier)(nil)
