package releaseverify

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

type bootstrapCatalogSourceStub struct {
	reader io.ReadCloser
	err    error
}

func (s *bootstrapCatalogSourceStub) OpenResource(context.Context, releaseinventory.Resource) (io.ReadCloser, error) {
	return s.reader, s.err
}

type bootstrapCatalogReadCloser struct {
	reader   io.Reader
	closeErr error
}

func (r *bootstrapCatalogReadCloser) Read(buffer []byte) (int, error) { return r.reader.Read(buffer) }
func (r *bootstrapCatalogReadCloser) Close() error                    { return r.closeErr }

type bootstrapCatalogErrorReader struct{ err error }

func (r bootstrapCatalogErrorReader) Read([]byte) (int, error) { return 0, r.err }

func TestPF001BootstrapCatalogRejectsPartialCompositionAndInvalidAuthority(t *testing.T) {
	t.Parallel()
	var typedNil *bootstrapCatalogSourceStub
	for _, source := range []BootstrapCatalogSource{nil, typedNil} {
		if catalog, err := NewBootstrapCatalog(source); catalog != nil || !errors.Is(err, ErrBootstrapCatalogIntegrity) {
			t.Fatalf("expected closed constructor rejection, got %#v, %v", catalog, err)
		}
	}
	catalog, err := NewBootstrapCatalog(&bootstrapCatalogSourceStub{})
	if err != nil {
		t.Fatal(err)
	}
	var absent *BootstrapCatalog
	if _, err := absent.Resolve(t.Context(), VerifiedInventory{}, releaseinventory.SignedManifest{}); !errors.Is(err, ErrBootstrapCatalogIntegrity) {
		t.Fatalf("nil catalog error=%v", err)
	}
	//lint:ignore SA1012 Deliberate absent-context security boundary.
	if _, err := catalog.Resolve(nil, VerifiedInventory{}, releaseinventory.SignedManifest{}); !errors.Is(err, ErrBootstrapCatalogIntegrity) { //nolint:staticcheck
		t.Fatalf("nil context error=%v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := catalog.Resolve(canceled, VerifiedInventory{}, releaseinventory.SignedManifest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context error=%v", err)
	}
	if _, err := catalog.Resolve(t.Context(), VerifiedInventory{}, releaseinventory.SignedManifest{}); !errors.Is(err, ErrBootstrapCatalogIntegrity) {
		t.Fatalf("empty authority error=%v", err)
	}
	if nilBootstrapCatalogCapability(1) || !nilBootstrapCatalogCapability(nil) || !nilBootstrapCatalogCapability(typedNil) {
		t.Fatal("bootstrap catalog nil classifier is inconsistent")
	}
	zero := VerifiedBootstrapTemplate{}
	if zero.Resource().ID() != "" || len(zero.CanonicalPlan()) != 0 ||
		!zero.DistributionManifestDigest().IsZero() || zero.Valid() {
		t.Fatal("zero verified template exposed authority")
	}
	_ = zero.ProductManifest()
}

func TestPF001BootstrapCatalogSelectsOneExactTemplateAndProduct(t *testing.T) {
	t.Parallel()
	platform, err := releaseinventory.NewPlatform("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := releaseinventory.NewPlatform("darwin", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	template := bootstrapSubjectResource(t, "install-plan", releaseinventory.ResourceKindInstallPlanTemplate, platform, []byte("plan"))
	product := bootstrapSubjectResource(t, "product-manifest", releaseinventory.ResourceKindProductManifest, releaseinventory.Platform{}, []byte("product"))
	selectedTemplate, selectedProduct, err := selectBootstrapResources([]releaseinventory.Resource{product, template}, platform)
	if err != nil || selectedTemplate.ID() != template.ID() || selectedProduct.ID() != product.ID() {
		t.Fatalf("unexpected selection %#v %#v %v", selectedTemplate, selectedProduct, err)
	}
	for _, resources := range [][]releaseinventory.Resource{
		nil,
		{template},
		{product},
		{template, template, product},
		{template, product, product},
		{bootstrapSubjectResource(t, "foreign-plan", releaseinventory.ResourceKindInstallPlanTemplate, foreign, []byte("foreign")), product},
	} {
		if _, _, err := selectBootstrapResources(resources, platform); !errors.Is(err, ErrBootstrapCatalogIntegrity) {
			t.Fatalf("expected ambiguous or missing selection to fail, got %v", err)
		}
	}
	inventory := VerifiedInventory{resources: []VerifiedResource{{
		id: template.ID(), kind: template.Kind(), purpose: template.Purpose(), mediaType: template.MediaType(),
		digest: template.Digest(), size: template.Size(), platform: template.Platform(), sourceRef: template.SourceRef(),
	}}}
	if !inventoryAuthorizes(inventory, template) || inventoryAuthorizes(inventory, product) {
		t.Fatal("verified inventory authorization escaped its exact descriptor")
	}
}

func TestPF001BootstrapCatalogReadsExactBoundBytesAndSanitizesFailures(t *testing.T) {
	t.Parallel()
	raw := []byte("authenticated plan bytes")
	resource := bootstrapSubjectResource(t, "install-plan", releaseinventory.ResourceKindInstallPlanTemplate,
		mustReleasePlatform(t, "linux", "amd64"), raw)
	source := &bootstrapCatalogSourceStub{reader: io.NopCloser(strings.NewReader(string(raw)))}
	got, err := readBootstrapCatalogResource(t.Context(), source, resource)
	if err != nil || string(got) != string(raw) {
		t.Fatalf("read=%q error=%v", got, err)
	}
	private := errors.New("private path")
	for _, test := range []struct {
		name   string
		source BootstrapCatalogSource
		value  releaseinventory.Resource
		want   error
	}{
		{name: "source error", source: &bootstrapCatalogSourceStub{err: private}, value: resource, want: ErrBootstrapCatalogUnavailable},
		{name: "source canceled", source: &bootstrapCatalogSourceStub{err: context.Canceled}, value: resource, want: context.Canceled},
		{name: "nil reader", source: &bootstrapCatalogSourceStub{}, value: resource, want: ErrBootstrapCatalogUnavailable},
		{name: "read error", source: &bootstrapCatalogSourceStub{reader: &bootstrapCatalogReadCloser{reader: bootstrapCatalogErrorReader{err: private}}}, value: resource, want: ErrBootstrapCatalogUnavailable},
		{name: "read canceled", source: &bootstrapCatalogSourceStub{reader: &bootstrapCatalogReadCloser{reader: bootstrapCatalogErrorReader{err: context.Canceled}}}, value: resource, want: context.Canceled},
		{name: "close error", source: &bootstrapCatalogSourceStub{reader: &bootstrapCatalogReadCloser{reader: strings.NewReader(string(raw)), closeErr: private}}, value: resource, want: ErrBootstrapCatalogUnavailable},
		{name: "short bytes", source: &bootstrapCatalogSourceStub{reader: io.NopCloser(strings.NewReader("short"))}, value: resource, want: ErrBootstrapCatalogIntegrity},
		{name: "long bytes", source: &bootstrapCatalogSourceStub{reader: io.NopCloser(strings.NewReader(string(raw) + "x"))}, value: resource, want: ErrBootstrapCatalogIntegrity},
		{name: "wrong digest", source: &bootstrapCatalogSourceStub{reader: io.NopCloser(strings.NewReader(string(raw)))}, value: bootstrapSubjectResource(t, "wrong", releaseinventory.ResourceKindInstallPlanTemplate, mustReleasePlatform(t, "linux", "amd64"), []byte(strings.Repeat("x", len(raw)))), want: ErrBootstrapCatalogIntegrity},
		{name: "zero resource", source: source, want: ErrBootstrapCatalogIntegrity},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := readBootstrapCatalogResource(t.Context(), test.source, test.value)
			if !errors.Is(err, test.want) || errors.Is(err, private) {
				t.Fatalf("error=%v, want %v", err, test.want)
			}
		})
	}
}

func bootstrapSubjectResource(
	t testing.TB,
	id string,
	kind releaseinventory.ResourceKind,
	platform releaseinventory.Platform,
	raw []byte,
) releaseinventory.Resource {
	t.Helper()
	purpose := releasePurpose(kind)
	mediaType := releaseMediaType(kind)
	if kind == releaseinventory.ResourceKindProductManifest {
		purpose = releaseinventory.ResourcePurposeProductManifest
		mediaType = releaseinventory.MediaTypeProductManifest
	}
	input := releaseinventory.ResourceInput{
		ID: id, Kind: kind, Purpose: purpose, MediaType: mediaType, Platform: platform,
		Digest: releaseinventory.DigestBytes(raw), Size: uint64(len(raw)), SourceRef: "bundle://" + id,
		SourceAllowlist: []string{"bundle://" + id}, CycloneDXSBOMResourceID: id + "-cyclonedx",
		SPDXSBOMResourceID: id + "-spdx", ProvenanceResourceID: id + "-provenance",
		LicenseResourceID: id + "-licenses", VulnerabilityResourceID: id + "-vulnerabilities",
	}
	resource, err := releaseinventory.NewResource(input)
	if err != nil {
		t.Fatal(err)
	}
	return resource
}
