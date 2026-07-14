package installplanfs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	firststartadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/firststart"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/firststartapp"
	appreleaseverify "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001OuterDistributionCatalogAuthorizesExactInnerProductPlan(t *testing.T) {
	t.Parallel()
	fixture := bootstrapCatalogFixture(t)
	application, err := appreleaseverify.NewApplication(appreleaseverify.Dependencies{
		Clock: fixture.ports, Platform: fixture.ports, Protocol: fixture.ports,
		Signature: fixture.ports, TrustEvidence: fixture.ports, ResourceDigest: fixture.ports,
		SBOM: fixture.ports, Provenance: fixture.ports, License: fixture.ports,
		Vulnerability: fixture.ports, NativePublisher: fixture.ports, OCIIndex: fixture.ports,
		AntiRollback: fixture.ports,
	})
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := application.Verify(t.Context(), fixture.distribution)
	if err != nil {
		var verificationError *appreleaseverify.VerificationError
		if errors.As(err, &verificationError) {
			t.Fatalf("verify outer distribution: code=%s reason=%s error=%v", verificationError.Code(), verificationError.Reason(), err)
		}
		t.Fatalf("verify outer distribution: %v", err)
	}
	catalog, err := appreleaseverify.NewBootstrapCatalog(fixture.source)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := catalog.Resolve(t.Context(), inventory, fixture.distribution)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.Valid() || !bytes.Equal(verified.CanonicalPlan(), fixture.template) ||
		!verified.ProductManifest().Manifest().Digest().Equal(fixture.product.Manifest().Digest()) ||
		!verified.DistributionManifestDigest().Equal(fixture.distribution.Manifest().Digest()) ||
		verified.Resource().Kind() != releaseinventory.ResourceKindInstallPlanTemplate {
		t.Fatal("verified bootstrap template lost a two-level catalog binding")
	}
	retained, err := appreleaseverify.NewVerifiedDistributionCatalog(fixture.source, application, catalog)
	if err != nil {
		t.Fatal(err)
	}
	packagedCatalog, err := firststartadapter.NewDistributionTemplateCatalog(retained)
	if err != nil {
		t.Fatal(err)
	}
	packaged, err := packagedCatalog.Current(t.Context())
	if err != nil || !packaged.Valid() || !packaged.Resource().Digest().Equal(verified.Resource().Digest()) {
		t.Fatalf("retained current template=%+v error=%v", packaged, err)
	}
	exact, err := packagedCatalog.Exact(t.Context(), verified.Resource().Digest())
	if err != nil || !exact.Valid() || !bytes.Equal(exact.Template().Canonical(), fixture.template) {
		t.Fatalf("retained exact template=%+v error=%v", exact, err)
	}
	if _, err := packagedCatalog.Exact(t.Context(), releaseinventory.DigestBytes([]byte("foreign"))); !errors.Is(err, firststartapp.ErrIntegrity) {
		t.Fatalf("retained catalog fell forward: %v", err)
	}
	copyBytes := verified.CanonicalPlan()
	copyBytes[0] ^= 0xff
	if !verified.Valid() || bytes.Equal(copyBytes, verified.CanonicalPlan()) {
		t.Fatal("verified template exposed mutable canonical storage")
	}
}

func TestPF001OuterDistributionCatalogRejectsSubstitutionAndPartialComposition(t *testing.T) {
	t.Parallel()
	var typedNil *bootstrapCatalogSource
	if catalog, err := appreleaseverify.NewBootstrapCatalog(typedNil); catalog != nil ||
		!errors.Is(err, appreleaseverify.ErrBootstrapCatalogIntegrity) {
		t.Fatalf("typed nil catalog=%v error=%v", catalog, err)
	}
	fixture := bootstrapCatalogFixture(t)
	catalog, _ := appreleaseverify.NewBootstrapCatalog(fixture.source)
	//lint:ignore SA1012 Deliberate absent-context boundary test.
	if _, err := catalog.Resolve(nil, appreleaseverify.VerifiedInventory{}, fixture.distribution); !errors.Is(err, appreleaseverify.ErrBootstrapCatalogIntegrity) { //nolint:staticcheck
		t.Fatalf("nil context error=%v", err)
	}
	if _, err := catalog.Resolve(t.Context(), appreleaseverify.VerifiedInventory{}, fixture.distribution); !errors.Is(err, appreleaseverify.ErrBootstrapCatalogIntegrity) {
		t.Fatalf("zero inventory error=%v", err)
	}
	var absent *appreleaseverify.BootstrapCatalog
	if _, err := absent.Resolve(t.Context(), appreleaseverify.VerifiedInventory{}, fixture.distribution); !errors.Is(err, appreleaseverify.ErrBootstrapCatalogIntegrity) {
		t.Fatalf("nil catalog error=%v", err)
	}

	application, _ := appreleaseverify.NewApplication(appreleaseverify.Dependencies{
		Clock: fixture.ports, Platform: fixture.ports, Protocol: fixture.ports,
		Signature: fixture.ports, TrustEvidence: fixture.ports, ResourceDigest: fixture.ports,
		SBOM: fixture.ports, Provenance: fixture.ports, License: fixture.ports,
		Vulnerability: fixture.ports, NativePublisher: fixture.ports, OCIIndex: fixture.ports,
		AntiRollback: fixture.ports,
	})
	inventory, verifyError := application.Verify(t.Context(), fixture.distribution)
	if verifyError != nil {
		var verificationFailure *appreleaseverify.VerificationError
		if errors.As(verifyError, &verificationFailure) {
			t.Fatalf("verify outer distribution: code=%s reason=%s error=%v", verificationFailure.Code(), verificationFailure.Reason(), verifyError)
		}
		t.Fatalf("verify outer distribution: %v", verifyError)
	}
	fixture.source.contents["install-plan"] = append([]byte(nil), fixture.template...)
	fixture.source.contents["install-plan"][0] ^= 0xff
	if _, err := catalog.Resolve(t.Context(), inventory, fixture.distribution); !errors.Is(err, appreleaseverify.ErrBootstrapCatalogIntegrity) {
		t.Fatalf("changed template error=%v", err)
	}
	fixture.source.contents["install-plan"] = append([]byte(nil), fixture.template...)
	fixture.source.err = errors.New("private path")
	if _, err := catalog.Resolve(t.Context(), inventory, fixture.distribution); !errors.Is(err, appreleaseverify.ErrBootstrapCatalogUnavailable) || strings.Contains(err.Error(), "private") {
		t.Fatalf("private source error=%v", err)
	}
}

type bootstrapCatalogTestFixture struct {
	distribution releaseinventory.SignedManifest
	product      releaseinventory.SignedManifest
	template     []byte
	source       *bootstrapCatalogSource
	ports        *bootstrapCatalogPorts
}

func bootstrapCatalogFixture(t testing.TB) bootstrapCatalogTestFixture {
	t.Helper()
	plan := ownerSelectedTemplatePlan(t)
	product := plan.SignedRelease()
	productRaw, err := releaseinventory.EncodeSignedManifestV1(product)
	if err != nil {
		t.Fatal(err)
	}
	templateRaw := plan.CanonicalBytes()
	platform, _ := releaseinventory.NewPlatform("linux", "amd64")
	template := bootstrapCatalogSubject(t, releaseinventory.ResourceInput{
		ID: "install-plan", Kind: releaseinventory.ResourceKindInstallPlanTemplate,
		Purpose:   releaseinventory.ResourcePurposeInstallPlanTemplate,
		MediaType: releaseinventory.MediaTypeInstallPlanTemplate, Platform: platform,
		Digest: releaseinventory.DigestBytes(templateRaw), Size: uint64(len(templateRaw)),
		SourceRef: "bundle://install-plan", SourceAllowlist: []string{"bundle://install-plan"},
	})
	productResource := bootstrapCatalogSubject(t, releaseinventory.ResourceInput{
		ID: "product-manifest", Kind: releaseinventory.ResourceKindProductManifest,
		Purpose:   releaseinventory.ResourcePurposeProductManifest,
		MediaType: releaseinventory.MediaTypeProductManifest, Platform: platform,
		Digest: releaseinventory.DigestBytes(productRaw), Size: uint64(len(productRaw)),
		SourceRef: "bundle://product-manifest", SourceAllowlist: []string{"bundle://product-manifest"},
	})
	inner := product.Manifest()
	resources := append([]releaseinventory.Resource(nil), inner.Resources()...)
	resources = append(resources, template, productResource)
	resources = append(resources, filesystemEvidence(t, template)...)
	resources = append(resources, filesystemEvidence(t, productResource)...)
	distributionManifest, err := releaseinventory.NewManifest(releaseinventory.ManifestInput{
		SchemaVersion: inner.SchemaVersion(), ReleaseID: "agentmemory-distribution-1.0.0",
		Version: inner.Version(), BuildID: "distribution-20260701-1", SourceCommit: inner.SourceCommit(),
		BuildTimestamp: inner.BuildTimestamp(), Channel: inner.Channel(), Sequence: inner.Sequence() + 1,
		DataGeneration: inner.DataGeneration(), ValidFrom: inner.ValidFrom(), ValidUntil: inner.ValidUntil(),
		Protocol: inner.Protocol(), Compatibility: inner.Compatibility(), TrustPolicy: inner.TrustPolicy(),
		ReleaseHistory: inner.ReleaseHistory(), LicensePolicyDigest: inner.LicensePolicyDigest(),
		VulnerabilityPolicyDigest: inner.VulnerabilityPolicyDigest(), DockerTopology: inner.DockerTopology(),
		Resources: resources,
	})
	if err != nil {
		t.Fatal(err)
	}
	distribution, err := releaseinventory.NewSignedManifest(distributionManifest, releaseinventory.SignatureBundleInput{
		SchemaVersion: releaseinventory.SupportedSignatureBundleSchemaMajor,
		TrustMode:     releaseinventory.SignatureTrustModeKeyID, TrustRootID: product.TrustRootID(),
		Signature:     bytes.Repeat([]byte{0x62}, releaseinventory.ManifestSignatureSize),
		RevocationSet: product.RevocationSet(), TrustedTimeEvidence: product.TrustedTimeEvidence(),
	})
	if err != nil {
		t.Fatal(err)
	}
	distributionRaw, err := releaseinventory.EncodeSignedManifestV1(distribution)
	if err != nil {
		t.Fatal(err)
	}
	return bootstrapCatalogTestFixture{
		distribution: distribution, product: product, template: templateRaw,
		source: &bootstrapCatalogSource{envelope: distributionRaw, contents: map[string][]byte{
			"install-plan": templateRaw, "product-manifest": productRaw,
		}},
		ports: &bootstrapCatalogPorts{platform: platform, now: time.Date(2026, time.July, 2, 0, 0, 0, 0, time.UTC)},
	}
}

func bootstrapCatalogSubject(t testing.TB, input releaseinventory.ResourceInput) releaseinventory.Resource {
	t.Helper()
	input.CycloneDXSBOMResourceID = input.ID + "-cyclonedx"
	input.SPDXSBOMResourceID = input.ID + "-spdx"
	input.ProvenanceResourceID = input.ID + "-provenance"
	input.LicenseResourceID = input.ID + "-licenses"
	input.VulnerabilityResourceID = input.ID + "-vulnerabilities"
	resource, err := releaseinventory.NewResource(input)
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

type bootstrapCatalogSource struct {
	envelope []byte
	contents map[string][]byte
	err      error
}

func (s *bootstrapCatalogSource) ReadDistributionEnvelope(_ context.Context) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	return append([]byte(nil), s.envelope...), nil
}

func (s *bootstrapCatalogSource) OpenResource(_ context.Context, resource releaseinventory.Resource) (io.ReadCloser, error) {
	if s.err != nil {
		return nil, s.err
	}
	return io.NopCloser(bytes.NewReader(s.contents[resource.ID()])), nil
}

type bootstrapCatalogPorts struct {
	platform releaseinventory.Platform
	now      time.Time
}

func (p *bootstrapCatalogPorts) Now() time.Time { return p.now }
func (p *bootstrapCatalogPorts) CurrentPlatform(context.Context) (releaseinventory.Platform, error) {
	return p.platform, nil
}
func (p *bootstrapCatalogPorts) CurrentProtocol(context.Context) (uint32, error) { return 1, nil }
func (p *bootstrapCatalogPorts) VerifyManifestSignature(context.Context, releaseinventory.SignedManifest) error {
	return nil
}
func (p *bootstrapCatalogPorts) VerifyOfflineTrustEvidence(context.Context, releaseinventory.SignedManifest) error {
	return nil
}
func (p *bootstrapCatalogPorts) VerifyResourceDigest(context.Context, releaseinventory.Resource) error {
	return nil
}
func (p *bootstrapCatalogPorts) VerifySBOMs(context.Context, releaseinventory.Resource, releaseinventory.Resource, releaseinventory.Resource) error {
	return nil
}
func (p *bootstrapCatalogPorts) VerifyProvenance(context.Context, releaseinventory.Manifest, releaseinventory.Resource, releaseinventory.Resource) error {
	return nil
}
func (p *bootstrapCatalogPorts) VerifyLicense(context.Context, releaseinventory.Resource, releaseinventory.Resource) error {
	return nil
}
func (p *bootstrapCatalogPorts) VerifyVulnerabilities(context.Context, releaseinventory.Resource, releaseinventory.Resource) error {
	return nil
}
func (p *bootstrapCatalogPorts) VerifyNativePublisher(context.Context, releaseinventory.Resource) error {
	return nil
}
func (p *bootstrapCatalogPorts) VerifyOCIIndex(context.Context, releaseinventory.Resource, releaseinventory.Resource) error {
	return nil
}
func (p *bootstrapCatalogPorts) LoadReleaseAnchor(context.Context, releaseinventory.ReleaseChannel) (appreleaseverify.ReleaseAnchor, error) {
	return appreleaseverify.ReleaseAnchor{}, appreleaseverify.ErrReleaseAnchorNotFound
}
func (p *bootstrapCatalogPorts) CompareAndSwapReleaseAnchor(context.Context, *appreleaseverify.ReleaseAnchor, appreleaseverify.ReleaseAnchor) error {
	return nil
}
