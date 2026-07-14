package runtimeprovision

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
)

func TestRuntimePublisherPolicyVerifierAuthorizesOnlyExactIndependentTuple(t *testing.T) {
	t.Parallel()
	policy := catalogSignatureManifest(t).Artifact().Publisher()
	input := publisherInput(policy)
	verifier, err := NewRuntimePublisherPolicyVerifier([]RuntimePublisherPolicyInput{input})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyNativePublisherPolicy(t.Context(), policy); err != nil {
		t.Fatal(err)
	}
	if digest, resolveError := verifier.NativeTrustDigest(policy); resolveError != nil || digest.IsZero() {
		t.Fatalf("native trust digest=%s error=%v", digest.Hex(), resolveError)
	}
	input.Identity = "substituted.publisher"
	if err := verifier.VerifyNativePublisherPolicy(t.Context(), policy); err != nil {
		t.Fatalf("verifier aliases input: %v", err)
	}

	for name, mutation := range map[string]func(*RuntimePublisherPolicyInput){
		"verification": func(value *RuntimePublisherPolicyInput) {
			value.Verification = runtimecatalog.NativeVerificationAuthenticode
		},
		"identity": func(value *RuntimePublisherPolicyInput) { value.Identity = "foreign.publisher" },
		"key":      func(value *RuntimePublisherPolicyInput) { value.SigningKeyIdentity = "foreign.key" },
		"package":  func(value *RuntimePublisherPolicyInput) { value.PackageIdentity = "foreign.package" },
	} {
		candidate := publisherInput(policy)
		mutation(&candidate)
		denying, constructError := NewRuntimePublisherPolicyVerifier([]RuntimePublisherPolicyInput{candidate})
		if constructError != nil {
			t.Fatalf("%s construct: %v", name, constructError)
		}
		if verifyError := denying.VerifyNativePublisherPolicy(t.Context(), policy); !errors.Is(verifyError, runtimecatalogapp.ErrNativePublisherInvalid) {
			t.Fatalf("%s substitution error=%v", name, verifyError)
		}
	}
}

func TestRuntimePublisherPolicyVerifierRejectsMalformedDuplicateAndIncompleteTrust(t *testing.T) {
	t.Parallel()
	valid := publisherInput(catalogSignatureManifest(t).Artifact().Publisher())
	for name, input := range map[string][]RuntimePublisherPolicyInput{
		"nil":                  nil,
		"duplicate":            {valid, valid},
		"unknown verification": {{Verification: "unknown", Identity: valid.Identity, SigningKeyIdentity: valid.SigningKeyIdentity, PackageIdentity: valid.PackageIdentity}},
		"blank identity":       {{Verification: valid.Verification, SigningKeyIdentity: valid.SigningKeyIdentity, PackageIdentity: valid.PackageIdentity}},
		"unsafe key":           {{Verification: valid.Verification, Identity: valid.Identity, SigningKeyIdentity: " key", PackageIdentity: valid.PackageIdentity}},
		"unsafe package":       {{Verification: valid.Verification, Identity: valid.Identity, SigningKeyIdentity: valid.SigningKeyIdentity, PackageIdentity: "package?"}},
		"missing native digest": {{Verification: valid.Verification, Identity: valid.Identity,
			SigningKeyIdentity: valid.SigningKeyIdentity, PackageIdentity: valid.PackageIdentity}},
	} {
		verifier, err := NewRuntimePublisherPolicyVerifier(input)
		if verifier != nil || !errors.Is(err, runtimecatalogapp.ErrNativePublisherInvalid) {
			t.Fatalf("%s accepted: verifier=%+v error=%v", name, verifier, err)
		}
	}
	oversize := make([]RuntimePublisherPolicyInput, maximumRuntimePublisherPolicies+1)
	if verifier, err := NewRuntimePublisherPolicyVerifier(oversize); verifier != nil || err == nil {
		t.Fatalf("oversize accepted: verifier=%+v error=%v", verifier, err)
	}
}

func TestRuntimePublisherPolicyVerifierFailsClosedOnInvalidInvocation(t *testing.T) {
	t.Parallel()
	policy := catalogSignatureManifest(t).Artifact().Publisher()
	verifier, err := NewRuntimePublisherPolicyVerifier([]RuntimePublisherPolicyInput{publisherInput(policy)})
	if err != nil {
		t.Fatal(err)
	}
	var absent *RuntimePublisherPolicyVerifier
	if err := absent.VerifyNativePublisherPolicy(t.Context(), policy); !errors.Is(err, runtimecatalogapp.ErrNativePublisherInvalid) {
		t.Fatalf("nil verifier error=%v", err)
	}
	if digest, resolveError := absent.NativeTrustDigest(policy); !errors.Is(resolveError, runtimecatalogapp.ErrNativePublisherInvalid) || !digest.IsZero() {
		t.Fatalf("nil verifier digest=%s error=%v", digest.Hex(), resolveError)
	}
	if digest, resolveError := verifier.NativeTrustDigest(runtimecatalog.PublisherPolicy{}); !errors.Is(resolveError, runtimecatalogapp.ErrNativePublisherInvalid) || !digest.IsZero() {
		t.Fatalf("zero policy digest=%s error=%v", digest.Hex(), resolveError)
	}
	//lint:ignore SA1012 Deliberate nil-context trust-boundary regression fixture.
	if err := verifier.VerifyNativePublisherPolicy(nil, policy); !errors.Is(err, runtimecatalogapp.ErrNativePublisherInvalid) { //nolint:staticcheck
		t.Fatalf("nil context error=%v", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := verifier.VerifyNativePublisherPolicy(cancelled, policy); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
	if err := verifier.VerifyNativePublisherPolicy(t.Context(), runtimecatalog.PublisherPolicy{}); !errors.Is(err, runtimecatalogapp.ErrNativePublisherInvalid) {
		t.Fatalf("zero policy error=%v", err)
	}
}

func publisherInput(policy runtimecatalog.PublisherPolicy) RuntimePublisherPolicyInput {
	return RuntimePublisherPolicyInput{
		Verification: policy.Verification(), Identity: policy.Identity(),
		SigningKeyIdentity: policy.SigningKeyIdentity(), PackageIdentity: policy.PackageIdentity(),
		NativeTrustSHA256: runtimecatalog.DigestBytes([]byte("native publisher trust anchor")).Hex(),
	}
}
