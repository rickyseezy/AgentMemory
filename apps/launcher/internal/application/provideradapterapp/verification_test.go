package provideradapterapp

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/provideradapter"
)

func TestPRO002SupplyChainVerifierBindsEveryRequiredDocumentBeforeSignatureAndPolicy(t *testing.T) {
	t.Parallel()
	manifest, source := verificationFixture(t)
	signature := &signaturePolicyStub{}
	policy := &evidencePolicyStub{}
	verifier, _ := NewDigestBoundSupplyChainVerifier(source, signature, policy)
	if err := verifier.Verify(context.Background(), manifest); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if signature.calls != 1 || len(policy.kinds) != 5 {
		t.Fatalf("checks = %d/%v", signature.calls, policy.kinds)
	}

	for _, kind := range []EvidenceKind{EvidenceSignatureBundle, EvidenceCycloneDX, EvidenceSPDX, EvidenceProvenance, EvidenceLicense, EvidenceVulnerability} {
		kind := kind
		t.Run(string(kind)+" tamper", func(t *testing.T) {
			t.Parallel()
			value, localSource := verificationFixture(t)
			localSource.values[kind] = []byte("tampered")
			localVerifier, _ := NewDigestBoundSupplyChainVerifier(localSource, &signaturePolicyStub{}, &evidencePolicyStub{})
			if err := localVerifier.Verify(context.Background(), value); !errors.Is(err, ErrVerification) {
				t.Fatalf("tamper accepted: %v", err)
			}
		})
	}
}

func TestPRO002SupplyChainVerifierFailsClosedOnSignatureAndEvidencePolicy(t *testing.T) {
	t.Parallel()
	manifest, source := verificationFixture(t)
	verifier, _ := NewDigestBoundSupplyChainVerifier(source, &signaturePolicyStub{err: errInjected}, &evidencePolicyStub{})
	if err := verifier.Verify(context.Background(), manifest); !errors.Is(err, ErrVerification) {
		t.Fatalf("signature accepted: %v", err)
	}
	verifier, _ = NewDigestBoundSupplyChainVerifier(source, &signaturePolicyStub{}, &evidencePolicyStub{err: errInjected})
	if err := verifier.Verify(context.Background(), manifest); !errors.Is(err, ErrVerification) {
		t.Fatalf("policy accepted: %v", err)
	}
	if _, err := NewDigestBoundSupplyChainVerifier(nil, &signaturePolicyStub{}, &evidencePolicyStub{}); !errors.Is(err, ErrVerification) {
		t.Fatalf("nil port = %v", err)
	}
}

type evidenceSourceStub struct{ values map[EvidenceKind][]byte }

func (s *evidenceSourceStub) Load(_ context.Context, kind EvidenceKind, _ provideradapter.Digest, _ int64) ([]byte, error) {
	return append([]byte(nil), s.values[kind]...), nil
}

type signaturePolicyStub struct {
	calls int
	err   error
}

func (s *signaturePolicyStub) Verify(context.Context, string, provideradapter.Digest, []byte) error {
	s.calls++
	return s.err
}

type evidencePolicyStub struct {
	kinds []EvidenceKind
	err   error
}

func (s *evidencePolicyStub) Verify(_ context.Context, kind EvidenceKind, _ provideradapter.Digest, _ []byte) error {
	s.kinds = append(s.kinds, kind)
	return s.err
}

func verificationFixture(t testing.TB) (provideradapter.Manifest, *evidenceSourceStub) {
	t.Helper()
	input := manifestInput()
	values := map[EvidenceKind][]byte{
		EvidenceSignatureBundle: []byte("signature"), EvidenceCycloneDX: []byte("cyclonedx"),
		EvidenceSPDX: []byte("spdx"), EvidenceProvenance: []byte("provenance"),
		EvidenceLicense: []byte("license"), EvidenceVulnerability: []byte("vulnerability"),
	}
	input.Evidence = provideradapter.EvidenceInput{
		SignatureBundle: provideradapter.DigestBytes(values[EvidenceSignatureBundle]), CycloneDXSBOM: provideradapter.DigestBytes(values[EvidenceCycloneDX]),
		SPDXSBOM: provideradapter.DigestBytes(values[EvidenceSPDX]), Provenance: provideradapter.DigestBytes(values[EvidenceProvenance]),
		License: provideradapter.DigestBytes(values[EvidenceLicense]), Vulnerability: provideradapter.DigestBytes(values[EvidenceVulnerability]),
	}
	manifest, err := provideradapter.NewManifest(input)
	if err != nil {
		t.Fatal(err)
	}
	return manifest, &evidenceSourceStub{values: values}
}
