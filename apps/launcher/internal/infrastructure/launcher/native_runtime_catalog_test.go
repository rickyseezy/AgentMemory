package launcher

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
)

func TestPF001NativeRuntimeCatalogLoaderAuthenticatesExactReleaseResourceBeforeDecode(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"signed":"runtime-catalog"}`)
	resource := nativeRuntimeCatalogResource(t, raw)
	verifier := &nativeRuntimeCatalogVerifierStub{}
	source := &nativeRuntimeCatalogSourceStub{raw: raw}
	decoded := false
	loader, err := newNativeRuntimeCatalogLoaderWithDependencies(
		verifier, source, func(candidate []byte) (runtimecatalog.SignedManifest, error) {
			decoded = bytes.Equal(candidate, raw)
			return runtimecatalog.SignedManifest{}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	request := nativeRuntimeCatalogRequest(t, resource)
	envelope, err := loader.Load(t.Context(), request)
	if err != nil || !decoded || verifier.calls != 1 || source.calls != 1 ||
		!envelope.ResourceDigest.Equal(request.RuntimeCatalogDigest) {
		t.Fatalf("envelope=%+v error=%v decoded=%v verifier=%d source=%d", envelope, err, decoded, verifier.calls, source.calls)
	}
}

func TestPF001NativeRuntimeCatalogLoaderRejectsReleaseContentAndBindingSubstitution(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"signed":"runtime-catalog"}`)
	resource := nativeRuntimeCatalogResource(t, raw)
	request := nativeRuntimeCatalogRequest(t, resource)
	for name, configure := range map[string]func(*nativeRuntimeCatalogVerifierStub, *nativeRuntimeCatalogSourceStub, *installplanapp.RuntimeEvidenceRequest){
		"release": func(verifier *nativeRuntimeCatalogVerifierStub, _ *nativeRuntimeCatalogSourceStub, _ *installplanapp.RuntimeEvidenceRequest) {
			verifier.err = errors.New("private verification error")
		},
		"content": func(_ *nativeRuntimeCatalogVerifierStub, source *nativeRuntimeCatalogSourceStub, _ *installplanapp.RuntimeEvidenceRequest) {
			source.raw = []byte("substituted")
		},
		"resource id": func(_ *nativeRuntimeCatalogVerifierStub, _ *nativeRuntimeCatalogSourceStub, request *installplanapp.RuntimeEvidenceRequest) {
			request.RuntimeCatalogID = "foreign"
		},
		"resource digest": func(_ *nativeRuntimeCatalogVerifierStub, _ *nativeRuntimeCatalogSourceStub, request *installplanapp.RuntimeEvidenceRequest) {
			request.RuntimeCatalogDigest = install.DigestBytes([]byte("foreign"))
		},
	} {
		verifier := &nativeRuntimeCatalogVerifierStub{}
		source := &nativeRuntimeCatalogSourceStub{raw: raw}
		candidate := request
		configure(verifier, source, &candidate)
		loader, err := newNativeRuntimeCatalogLoaderWithDependencies(
			verifier, source, func([]byte) (runtimecatalog.SignedManifest, error) {
				return runtimecatalog.SignedManifest{}, nil
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		if envelope, loadError := loader.Load(t.Context(), candidate); !errors.Is(loadError, installplanapp.ErrRuntimeEvidenceUnavailable) || !envelope.ResourceDigest.IsZero() {
			t.Fatalf("%s envelope=%+v error=%v", name, envelope, loadError)
		}
	}
	if loader, err := newNativeRuntimeCatalogLoaderWithDependencies(nil, nil, nil); loader != nil || err == nil {
		t.Fatalf("incomplete loader=(%v,%v)", loader, err)
	}
}

func nativeRuntimeCatalogRequest(t testing.TB, resource releaseinventory.Resource) installplanapp.RuntimeEvidenceRequest {
	t.Helper()
	operationID, err := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := install.BindPlan([]byte("canonical parent"))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := install.ParseDigest(resource.Digest().Hex())
	if err != nil {
		t.Fatal(err)
	}
	return installplanapp.RuntimeEvidenceRequest{
		OperationID: operationID, ParentPlanDigest: plan,
		RuntimeCatalogID: resource.ID(), RuntimeCatalogDigest: digest,
		RuntimeCatalogResource: resource,
	}
}

func nativeRuntimeCatalogResource(t testing.TB, raw []byte) releaseinventory.Resource {
	t.Helper()
	platform, err := releaseinventory.NewPlatform("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	resource, err := releaseinventory.NewResource(releaseinventory.ResourceInput{
		ID: "runtime-catalog", Kind: releaseinventory.ResourceKindRuntimeCatalog,
		Purpose: releaseinventory.ResourcePurposeRuntimeCatalog, MediaType: releaseinventory.MediaTypeRuntimeCatalog,
		Platform: platform, Digest: releaseinventory.DigestBytes(raw), Size: uint64(len(raw)),
		SourceRef: "bundle://runtime-catalog", SourceAllowlist: []string{"bundle://runtime-catalog"},
		CycloneDXSBOMResourceID: "runtime-catalog-cyclonedx", SPDXSBOMResourceID: "runtime-catalog-spdx",
		ProvenanceResourceID: "runtime-catalog-provenance", LicenseResourceID: "runtime-catalog-license",
		VulnerabilityResourceID: "runtime-catalog-vulnerability",
	})
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

type nativeRuntimeCatalogVerifierStub struct {
	calls int
	err   error
}

func (v *nativeRuntimeCatalogVerifierStub) VerifyReleaseResource(
	context.Context,
	releaseinventory.SignedManifest,
	releaseinventory.Resource,
) error {
	v.calls++
	return v.err
}

type nativeRuntimeCatalogSourceStub struct {
	raw   []byte
	calls int
}

func (s *nativeRuntimeCatalogSourceStub) OpenResource(context.Context, releaseinventory.Resource) (io.ReadCloser, error) {
	s.calls++
	return io.NopCloser(bytes.NewReader(s.raw)), nil
}
