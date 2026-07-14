package firststart

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/firststartapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001VerifiedTemplateSourcePinsCurrentAndExactSignedResources(t *testing.T) {
	t.Parallel()
	canonical := []byte(`{"schema":"signed-install-plan-template"}`)
	packaged := packagedTemplateFixture(t, canonical)
	catalog := &templateCatalogStub{packaged: packaged}
	source, err := NewVerifiedTemplateSource(catalog)
	if err != nil {
		t.Fatal(err)
	}
	current, err := source.Current(t.Context())
	if err != nil || !current.Digest().Equal(packaged.Template().Digest()) {
		t.Fatalf("Current()=%+v,%v", current, err)
	}
	exact, err := source.Exact(t.Context(), current.Digest())
	if err != nil || !exact.Digest().Equal(current.Digest()) || catalog.exact != packaged.Resource().Digest() {
		t.Fatalf("Exact()=%+v,%v selected=%s", exact, err, catalog.exact.Hex())
	}
	copyBytes := exact.Canonical()
	copyBytes[0] = 'X'
	if !exact.Valid() || string(exact.Canonical()) != string(canonical) {
		t.Fatal("template bytes aliased the caller")
	}
}

func TestPF001PackagedTemplateRejectsUnsignedPurposeAndByteSubstitution(t *testing.T) {
	t.Parallel()
	canonical := []byte(`{"schema":"signed-install-plan-template"}`)
	valid := packagedTemplateResource(t, canonical, releaseinventory.ResourceKindInstallPlanTemplate)
	for name, run := range map[string]func() error{
		"zero resource": func() error {
			_, err := NewPackagedTemplate(releaseinventory.Resource{}, canonical)
			return err
		},
		"wrong purpose": func() error {
			resource := packagedTemplateResource(t, canonical, releaseinventory.ResourceKindRuntimeCatalog)
			_, err := NewPackagedTemplate(resource, canonical)
			return err
		},
		"changed bytes": func() error {
			_, err := NewPackagedTemplate(valid, append(append([]byte(nil), canonical...), 'x'))
			return err
		},
		"empty bytes": func() error {
			_, err := NewPackagedTemplate(valid, nil)
			return err
		},
	} {
		if err := run(); !errors.Is(err, firststartapp.ErrIntegrity) {
			t.Fatalf("%s error=%v", name, err)
		}
	}
}

func TestPF001VerifiedTemplateSourceFailsClosedAtEveryCatalogBoundary(t *testing.T) {
	t.Parallel()
	canonical := []byte(`{"schema":"signed-install-plan-template"}`)
	packaged := packagedTemplateFixture(t, canonical)
	var typedNil *templateCatalogStub
	if source, err := NewVerifiedTemplateSource(typedNil); source != nil || !errors.Is(err, firststartapp.ErrIntegrity) {
		t.Fatalf("typed nil source=%+v error=%v", source, err)
	}
	source, _ := NewVerifiedTemplateSource(&templateCatalogStub{packaged: packaged})
	//lint:ignore SA1012 Deliberate absent-context boundary test.
	if _, err := source.Current(nil); !errors.Is(err, firststartapp.ErrIntegrity) { //nolint:staticcheck // Security fixture.
		t.Fatalf("nil Current error=%v", err)
	}
	//lint:ignore SA1012 Deliberate absent-context boundary test.
	if _, err := source.Exact(nil, packaged.Template().Digest()); !errors.Is(err, firststartapp.ErrIntegrity) { //nolint:staticcheck // Security fixture.
		t.Fatalf("nil Exact error=%v", err)
	}
	if _, err := source.Exact(t.Context(), install.PlanDigest{}); !errors.Is(err, firststartapp.ErrIntegrity) {
		t.Fatalf("zero Exact error=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Current(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Current error=%v", err)
	}
	for name, catalogErr := range map[string]error{
		"private": errors.New("private"), "integrity": firststartapp.ErrIntegrity,
		"deadline": context.DeadlineExceeded,
	} {
		candidate, _ := NewVerifiedTemplateSource(&templateCatalogStub{packaged: packaged, err: catalogErr})
		_, err := candidate.Current(t.Context())
		if name == "private" && !errors.Is(err, firststartapp.ErrUnavailable) ||
			name == "integrity" && !errors.Is(err, firststartapp.ErrIntegrity) ||
			name == "deadline" && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("%s mapped error=%v", name, err)
		}
	}
	foreign := packagedTemplateFixture(t, []byte(`{"schema":"foreign-template"}`))
	foreignSource, _ := NewVerifiedTemplateSource(&templateCatalogStub{packaged: foreign})
	if _, err := foreignSource.Exact(t.Context(), packaged.Template().Digest()); !errors.Is(err, firststartapp.ErrIntegrity) {
		t.Fatalf("foreign exact error=%v", err)
	}
}

type templateCatalogStub struct {
	packaged PackagedTemplate
	exact    releaseinventory.Digest
	err      error
}

func (c *templateCatalogStub) Current(context.Context) (PackagedTemplate, error) {
	return c.packaged, c.err
}

func (c *templateCatalogStub) Exact(_ context.Context, digest releaseinventory.Digest) (PackagedTemplate, error) {
	c.exact = digest
	return c.packaged, c.err
}

func packagedTemplateFixture(t *testing.T, canonical []byte) PackagedTemplate {
	t.Helper()
	packaged, err := NewPackagedTemplate(
		packagedTemplateResource(t, canonical, releaseinventory.ResourceKindInstallPlanTemplate), canonical,
	)
	if err != nil {
		t.Fatal(err)
	}
	return packaged
}

func packagedTemplateResource(
	t *testing.T,
	canonical []byte,
	kind releaseinventory.ResourceKind,
) releaseinventory.Resource {
	t.Helper()
	platform, err := releaseinventory.NewPlatform("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	digest := releaseinventory.DigestBytes(canonical)
	purpose := releaseinventory.ResourcePurposeInstallPlanTemplate
	mediaType := releaseinventory.MediaTypeInstallPlanTemplate
	if kind == releaseinventory.ResourceKindRuntimeCatalog {
		purpose = releaseinventory.ResourcePurposeRuntimeCatalog
		mediaType = releaseinventory.MediaTypeRuntimeCatalog
	}
	resource, err := releaseinventory.NewResource(releaseinventory.ResourceInput{
		ID: "install-plan", Kind: kind, Purpose: purpose, MediaType: mediaType,
		Platform: platform, Digest: digest, Size: uint64(len(canonical)),
		SourceRef: "bundle://install-plan", SourceAllowlist: []string{"bundle://install-plan"},
		CycloneDXSBOMResourceID: "install-plan-cyclonedx", SPDXSBOMResourceID: "install-plan-spdx",
		ProvenanceResourceID: "install-plan-provenance", LicenseResourceID: "install-plan-license",
		VulnerabilityResourceID: "install-plan-vulnerability",
	})
	if err != nil {
		t.Fatal(err)
	}
	return resource
}
