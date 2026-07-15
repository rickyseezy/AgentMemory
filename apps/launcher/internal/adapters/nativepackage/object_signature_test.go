package nativepackage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releasepublication"
)

func TestPF001ObjectSignatureVerifierBindsPublicationEvidenceAndObject(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	bundle := []byte("canonical object signature bundle")
	artifact := artifactWithSignatureDigest(t, releaseinventory.DigestBytes(bundle))
	if err := os.WriteFile(filepath.Join(root, artifact.ID()+".sigstore.json"), bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	signature := &artifactSignatureStub{}
	verifier, err := NewObjectSignatureVerifier(root, signature)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyPublisher(context.Background(), filepath.Join(root, artifact.FileName()), artifact); err != nil {
		t.Fatalf("VerifyPublisher() error = %v", err)
	}
	if !signature.digest.Equal(artifact.Digest()) || string(signature.bundle) != string(bundle) {
		t.Fatalf("signature received %s/%q", signature.digest.Hex(), signature.bundle)
	}
	long := append([]byte(nil), bundle...)
	long[0] ^= 0xff
	if err := os.WriteFile(filepath.Join(root, artifact.ID()+".sigstore.json"), long, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyPublisher(context.Background(), filepath.Join(root, artifact.FileName()), artifact); !errors.Is(err, ErrCandidateIntegrity) {
		t.Fatalf("substituted evidence error = %v", err)
	}
}

func TestPF001ObjectSignatureVerifierRejectsCryptographicFailureAndCancellation(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	bundle := []byte("canonical object signature bundle")
	artifact := artifactWithSignatureDigest(t, releaseinventory.DigestBytes(bundle))
	if err := os.WriteFile(filepath.Join(root, artifact.ID()+".sigstore.json"), bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	signature := &artifactSignatureStub{err: errors.New("private signature diagnostic")}
	verifier, err := NewObjectSignatureVerifier(root, signature)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyPublisher(context.Background(), filepath.Join(root, artifact.FileName()), artifact); !errors.Is(err, ErrCandidateIntegrity) {
		t.Fatalf("signature failure = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifier.VerifyPublisher(cancelled, filepath.Join(root, artifact.FileName()), artifact); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
}

func TestPF001ObjectSignatureVerifierRejectsInvalidComposition(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if verifier, err := NewObjectSignatureVerifier("relative", &artifactSignatureStub{}); verifier != nil ||
		!errors.Is(err, ErrCandidateIntegrity) {
		t.Fatalf("relative root = %T, %v", verifier, err)
	}
	if verifier, err := NewObjectSignatureVerifier(root, (*artifactSignatureStub)(nil)); verifier != nil ||
		!errors.Is(err, ErrCandidateIntegrity) {
		t.Fatalf("nil signature = %T, %v", verifier, err)
	}
	var absent *ObjectSignatureVerifier
	artifact, _ := candidateArtifactFixture(t)
	if err := absent.VerifyPublisher(context.Background(), filepath.Join(root, artifact.FileName()), artifact); !errors.Is(err, ErrCandidateIntegrity) {
		t.Fatalf("nil verifier error = %v", err)
	}
}

type artifactSignatureStub struct {
	digest releaseinventory.Digest
	bundle []byte
	err    error
}

func (s *artifactSignatureStub) VerifyArtifactSignature(
	_ context.Context,
	digest releaseinventory.Digest,
	bundle []byte,
) error {
	s.digest = digest
	s.bundle = append([]byte(nil), bundle...)
	return s.err
}

func artifactWithSignatureDigest(
	t testing.TB,
	signature releaseinventory.Digest,
) releasepublication.Artifact {
	t.Helper()
	artifact, _ := candidateArtifactFixtureWithSignature(t, signature)
	return artifact
}
