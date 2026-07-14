package launcher

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF006RuntimeExecutionReverifiesCatalogAndPersistedSelection(t *testing.T) {
	t.Parallel()
	request, authority, catalog := nativeRuntimeExecutionFixture(t)
	outer := authority.CatalogResourceEvidenceDigest()
	loader := &runtimeEnvelopeLoaderStub{envelope: nativeRuntimeCatalogEnvelope{ResourceDigest: outer}}
	policy := &runtimeCatalogPolicyStub{verified: nativeVerifiedRuntimeCatalog{
		runtime: catalog, manifestDigest: runtimecatalog.Digest(catalog.CatalogDigest()),
	}}
	verifier, err := newNativeRuntimeExecutionVerifier(loader, policy)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifier.verifyAuthenticated(t.Context(), request, authority)
	if err != nil || loader.calls != 1 || policy.calls != 1 ||
		!verified.authority.Equal(authority) || verified.runtime.CatalogDigest() != catalog.CatalogDigest() ||
		verified.manifestDigest.Hex() != authority.SignedCatalogEvidenceDigest().String() {
		t.Fatalf("verified=%+v error=%v calls=%d/%d", verified, err, loader.calls, policy.calls)
	}
}

func TestPF006RuntimeExecutionRejectsCatalogAndEnvelopeSubstitution(t *testing.T) {
	t.Parallel()
	request, authority, catalog := nativeRuntimeExecutionFixture(t)
	foreign, err := runtimeinstall.NewCertifiedRuntime(
		catalog.Platform(), catalog.Architecture(), catalog.Product(), "28.3.3", catalog.Channel(),
		catalog.CatalogSequence(), catalog.CatalogDigest(), runtimeinstall.RuntimeTermsInput{
			ID: catalog.TermsID(), Version: catalog.TermsVersion(), URL: catalog.TermsURL(),
			Digest: catalog.TermsDigest(), Presentation: catalog.TermsPresentation(),
		}, catalog.DownloadBytes(), catalog.ExpandedBytes(),
	)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		loader nativeRuntimeCatalogEnvelopeLoader
		policy nativeRuntimeCatalogPolicyVerifier
	}{
		{name: "outer envelope", loader: &runtimeEnvelopeLoaderStub{envelope: nativeRuntimeCatalogEnvelope{
			ResourceDigest: install.DigestBytes([]byte("foreign outer")),
		}}, policy: &runtimeCatalogPolicyStub{verified: nativeVerifiedRuntimeCatalog{
			runtime: catalog, manifestDigest: runtimecatalog.Digest(catalog.CatalogDigest()),
		}}},
		{name: "inner manifest", loader: &runtimeEnvelopeLoaderStub{envelope: nativeRuntimeCatalogEnvelope{
			ResourceDigest: authority.CatalogResourceEvidenceDigest(),
		}}, policy: &runtimeCatalogPolicyStub{verified: nativeVerifiedRuntimeCatalog{
			runtime: catalog, manifestDigest: runtimecatalog.DigestBytes([]byte("foreign inner")),
		}}},
		{name: "runtime selection", loader: &runtimeEnvelopeLoaderStub{envelope: nativeRuntimeCatalogEnvelope{
			ResourceDigest: authority.CatalogResourceEvidenceDigest(),
		}}, policy: &runtimeCatalogPolicyStub{verified: nativeVerifiedRuntimeCatalog{
			runtime: foreign, manifestDigest: runtimecatalog.Digest(foreign.CatalogDigest()),
		}}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			verifier, constructError := newNativeRuntimeExecutionVerifier(test.loader, test.policy)
			if constructError != nil {
				t.Fatal(constructError)
			}
			if result, verifyError := verifier.verifyAuthenticated(t.Context(), request, authority); !errors.Is(verifyError, installplanapp.ErrRuntimeEvidenceUnavailable) ||
				!result.authority.OperationID().IsZero() {
				t.Fatalf("result=%+v error=%v", result, verifyError)
			}
		})
	}
}

func TestPF006RuntimeExecutionVerifierFailsClosedWithoutAuthority(t *testing.T) {
	t.Parallel()
	request, authority, catalog := nativeRuntimeExecutionFixture(t)
	loader := &runtimeEnvelopeLoaderStub{envelope: nativeRuntimeCatalogEnvelope{
		ResourceDigest: authority.CatalogResourceEvidenceDigest(),
	}}
	policy := &runtimeCatalogPolicyStub{verified: nativeVerifiedRuntimeCatalog{
		runtime: catalog, manifestDigest: runtimecatalog.Digest(catalog.CatalogDigest()),
	}}
	for _, input := range []struct {
		loader nativeRuntimeCatalogEnvelopeLoader
		policy nativeRuntimeCatalogPolicyVerifier
	}{{policy: policy}, {loader: loader}} {
		if verifier, err := newNativeRuntimeExecutionVerifier(input.loader, input.policy); verifier != nil || err == nil {
			t.Fatalf("incomplete verifier=%+v error=%v", verifier, err)
		}
	}
	verifier, _ := newNativeRuntimeExecutionVerifier(loader, policy)
	if _, err := verifier.VerifyRuntimeExecution(t.Context(), installplanapp.RuntimeExecutionAuthority{}); !errors.Is(err, installplanapp.ErrRuntimeEvidenceUnavailable) {
		t.Fatalf("zero authority error=%v", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := verifier.verifyAuthenticated(cancelled, request, authority); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
	var absent *nativeRuntimeExecutionVerifier
	if _, err := absent.verifyAuthenticated(t.Context(), request, authority); !errors.Is(err, installplanapp.ErrRuntimeEvidenceUnavailable) {
		t.Fatalf("nil verifier error=%v", err)
	}
}

func nativeRuntimeExecutionFixture(
	t testing.TB,
) (installplanapp.RuntimeEvidenceRequest, installplanapp.RuntimePlanAuthority, runtimeinstall.CertifiedRuntime) {
	t.Helper()
	request := nativeRuntimeEvidenceRequest(t)
	catalog := nativeRuntimeCertifiedCatalog(t)
	plan, err := runtimeinstall.NewPlanV1(nativeRuntimeHost(t), runtimeinstall.NewAbsentRuntimeDiscovery(), catalog)
	if err != nil {
		t.Fatal(err)
	}
	resource := nativeRuntimeCatalogResource(t, []byte("outer signed runtime catalog"))
	outer, err := install.ParseDigest(resource.Digest().Hex())
	if err != nil {
		t.Fatal(err)
	}
	inner, err := install.ParseDigest(catalog.CatalogDigest().String())
	if err != nil {
		t.Fatal(err)
	}
	authority, err := installplanapp.NewRuntimePlanAuthority(
		request.OperationID, request.ParentPlanDigest, plan, request.HostEvidenceDigest,
		install.DigestBytes([]byte("discovery")), outer, inner,
	)
	if err != nil {
		t.Fatal(err)
	}
	request.RuntimeCatalogID = "runtime-catalog"
	request.RuntimeCatalogDigest = outer
	request.RuntimeCatalogResource = resource
	return request, authority, catalog
}
