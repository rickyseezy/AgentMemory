package provideradaptertrust

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/provideradapterapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/provideradapter"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPRO002SigstorePolicyBindsExactOCIReferenceAndOfflineBundle(t *testing.T) {
	t.Parallel()
	digest := provideradapter.DigestBytes([]byte("image"))
	verifier := &sigstoreStub{}
	policy, err := NewSigstoreImagePolicy(verifier)
	if err != nil {
		t.Fatal(err)
	}
	image := "registry.example/provider/custom@sha256:" + digest.Hex()
	if err := policy.Verify(context.Background(), image, digest, []byte("canonical bundle")); err != nil {
		t.Fatal(err)
	}
	if verifier.calls != 1 || verifier.digest.Hex() != digest.Hex() {
		t.Fatal("signature verifier received substituted subject")
	}
	if err := policy.Verify(context.Background(), "registry.example/provider/custom:latest", digest, []byte("bundle")); !errors.Is(err, provideradapterapp.ErrVerification) {
		t.Fatalf("mutable image=%v", err)
	}
	verifier.err = errors.New("invalid signature")
	if err := policy.Verify(context.Background(), image, digest, []byte("bundle")); !errors.Is(err, provideradapterapp.ErrVerification) {
		t.Fatalf("invalid signature=%v", err)
	}
}

func TestPRO002SigstorePolicyRejectsMissingAuthorityAndInputs(t *testing.T) {
	t.Parallel()
	if _, err := NewSigstoreImagePolicy(nil); !errors.Is(err, provideradapterapp.ErrVerification) {
		t.Fatalf("nil verifier=%v", err)
	}
	digest := provideradapter.DigestBytes([]byte("image"))
	policy, _ := NewSigstoreImagePolicy(&sigstoreStub{})
	image := "registry.example/provider/custom@sha256:" + digest.Hex()
	for _, input := range []struct {
		ctx    context.Context
		image  string
		digest provideradapter.Digest
		bundle []byte
	}{
		{nil, image, digest, []byte("bundle")}, {context.Background(), image, provideradapter.Digest{}, []byte("bundle")},
		{context.Background(), image, digest, nil},
	} {
		if err := policy.Verify(input.ctx, input.image, input.digest, input.bundle); !errors.Is(err, provideradapterapp.ErrVerification) {
			t.Fatalf("invalid input accepted: %#v %v", input, err)
		}
	}
}

type sigstoreStub struct {
	calls  int
	digest releaseinventory.Digest
	err    error
}

func (s *sigstoreStub) VerifyArtifactSignature(_ context.Context, digest releaseinventory.Digest, _ []byte) error {
	s.calls++
	s.digest = digest
	return s.err
}
