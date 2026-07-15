package releaseverifyadapter

import (
	"context"
	"errors"
	"testing"

	appreleaseverify "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001NativePublisherPolicyAuthorizesOnlyExactEmbeddedBindings(t *testing.T) {
	t.Parallel()
	input := NativePublisherPolicyInput{
		"apple-developer-id-notarized-v1": {"agentmemory.publisher", "docker.publisher"},
	}
	verifier, err := NewNativePublisherPolicyVerifier(input)
	if err != nil {
		t.Fatal(err)
	}
	input["apple-developer-id-notarized-v1"][0] = "attacker"
	resource := nativePublisherResource(t, "docker.publisher", "apple-developer-id-notarized-v1")
	if err := verifier.VerifyNativePublisher(t.Context(), resource); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []releaseinventory.Resource{
		nativePublisherResource(t, "agentmemory.publisher", "other-policy"),
		nativePublisherResource(t, "foreign.publisher", "apple-developer-id-notarized-v1"),
		{},
	} {
		if err := verifier.VerifyNativePublisher(t.Context(), candidate); !errors.Is(err, appreleaseverify.ErrNativePublisherInvalid) {
			t.Fatalf("unexpected rejection %v", err)
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifier.VerifyNativePublisher(canceled, resource); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error=%v", err)
	}
	wsl := nativePublisherResourceKind(
		t, releaseinventory.ResourceKindRuntimeInstaller, "microsoft.publisher", "apple-developer-id-notarized-v1",
	)
	inputVerifier, err := NewNativePublisherPolicyVerifier(NativePublisherPolicyInput{
		"apple-developer-id-notarized-v1": {"microsoft.publisher"},
	})
	if err != nil || inputVerifier.VerifyNativePublisher(t.Context(), wsl) != nil {
		t.Fatalf("runtime installer publisher error=%v", err)
	}
}

func TestPF001NativePublisherPolicyRejectsIncompleteOrAmbiguousPolicy(t *testing.T) {
	t.Parallel()
	for _, input := range []NativePublisherPolicyInput{
		nil,
		{"": {"publisher"}},
		{"policy": nil},
		{"policy": {"publisher", "publisher"}},
		{"policy": {"bad publisher"}},
	} {
		if verifier, err := NewNativePublisherPolicyVerifier(input); verifier != nil || !errors.Is(err, appreleaseverify.ErrNativePublisherInvalid) {
			t.Fatalf("accepted policy %#v", input)
		}
	}
	var absent *NativePublisherPolicyVerifier
	if err := absent.VerifyNativePublisher(t.Context(), releaseinventory.Resource{}); !errors.Is(err, appreleaseverify.ErrNativePublisherInvalid) {
		t.Fatalf("nil receiver error=%v", err)
	}
}

func nativePublisherResource(t testing.TB, identity, policy string) releaseinventory.Resource {
	return nativePublisherResourceKind(t, releaseinventory.ResourceKindLauncher, identity, policy)
}

func nativePublisherResourceKind(
	t testing.TB,
	kind releaseinventory.ResourceKind,
	identity string,
	policy string,
) releaseinventory.Resource {
	t.Helper()
	platform, err := releaseinventory.NewPlatform("darwin", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("launcher")
	input := releaseinventory.ResourceInput{
		ID: "native-subject", Kind: kind,
		Purpose: map[releaseinventory.ResourceKind]releaseinventory.ResourcePurpose{
			releaseinventory.ResourceKindLauncher:         releaseinventory.ResourcePurposeNativeLauncher,
			releaseinventory.ResourceKindRuntimeInstaller: releaseinventory.ResourcePurposeRuntimeInstaller,
		}[kind],
		MediaType: map[releaseinventory.ResourceKind]string{
			releaseinventory.ResourceKindLauncher:         releaseinventory.MediaTypeNativeExecutable,
			releaseinventory.ResourceKindRuntimeInstaller: releaseinventory.MediaTypeRuntimeInstaller,
		}[kind],
		Platform: platform, Digest: releaseinventory.DigestBytes(raw), Size: uint64(len(raw)),
		SourceRef: "bundle://launcher", SourceAllowlist: []string{"bundle://launcher"},
		CycloneDXSBOMResourceID: "launcher-cyclonedx", SPDXSBOMResourceID: "launcher-spdx",
		ProvenanceResourceID: "launcher-provenance", LicenseResourceID: "launcher-license",
		VulnerabilityResourceID: "launcher-vulnerability", NativePublisherIdentity: identity,
		NativePublisherPolicyID: policy,
	}
	resource, err := releaseinventory.NewResource(input)
	if err != nil {
		t.Fatal(err)
	}
	return resource
}
