package launcher

import (
	"context"
	"crypto/sha256"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeprovision"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	appreleaseverify "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

// nativeDesktopReleaseAuthority is the exact release-verified catalog/helper
// pair selected by the untrusted helper envelope. Both resources must belong
// to one desktop platform cell.
type nativeDesktopReleaseAuthority struct {
	manifestDigest releaseinventory.Digest
	catalog        releaseinventory.Resource
	helper         releaseinventory.Resource
	prerequisites  []releaseinventory.Resource
	certificates   map[string]releaseinventory.Digest
}

func newNativeDesktopReleaseAuthority(
	manifestDigest releaseinventory.Digest,
	catalog releaseinventory.Resource,
	helper releaseinventory.Resource,
	prerequisites []releaseinventory.Resource,
	certificates map[string]releaseinventory.Digest,
) (nativeDesktopReleaseAuthority, error) {
	authority := nativeDesktopReleaseAuthority{
		manifestDigest: manifestDigest, catalog: catalog, helper: helper,
		prerequisites: append([]releaseinventory.Resource(nil), prerequisites...),
		certificates:  copyNativeHelperCertificateBindings(certificates),
	}
	if !authority.valid() {
		return nativeDesktopReleaseAuthority{}, runtimeport.ErrDesktopMutationIntegrity
	}
	return authority, nil
}

func (a nativeDesktopReleaseAuthority) valid() bool {
	platform := a.catalog.Platform()
	if a.manifestDigest.IsZero() ||
		a.catalog.ID() == "" || a.catalog.Kind() != releaseinventory.ResourceKindRuntimeCatalog ||
		a.catalog.Purpose() != releaseinventory.ResourcePurposeRuntimeCatalog ||
		a.catalog.MediaType() != releaseinventory.MediaTypeRuntimeCatalog || platform.IsAny() ||
		(platform.OS() != runtimeinstall.PlatformDarwin.String() &&
			platform.OS() != runtimeinstall.PlatformWindows.String()) ||
		a.catalog.Digest().IsZero() || a.catalog.Size() == 0 ||
		a.helper.ID() == "" || a.helper.Kind() != releaseinventory.ResourceKindHelper ||
		a.helper.Purpose() != releaseinventory.ResourcePurposeNativeHelper ||
		a.helper.MediaType() != releaseinventory.MediaTypeNativeExecutable ||
		a.helper.Platform().IsAny() || a.helper.Platform().OS() != platform.OS() ||
		a.helper.Platform().Architecture() != platform.Architecture() ||
		a.helper.Digest().IsZero() || a.helper.Size() == 0 ||
		a.helper.NativePublisherIdentity() == "" || a.helper.NativePublisherPolicyID() == "" ||
		a.certificates[a.helper.ID()].IsZero() {
		return false
	}
	if platform.OS() == runtimeinstall.PlatformDarwin.String() {
		return len(a.prerequisites) == 0 && len(a.certificates) == 1
	}
	if len(a.prerequisites) != 2 || len(a.certificates) != 2 {
		return false
	}
	seen := map[releaseinventory.ResourceKind]bool{}
	for _, resource := range a.prerequisites {
		if resource.ID() == "" || resource.Platform().OS() != platform.OS() ||
			resource.Platform().Architecture() != platform.Architecture() || seen[resource.Kind()] {
			return false
		}
		seen[resource.Kind()] = true
		switch resource.Kind() {
		case releaseinventory.ResourceKindRuntimeInstaller:
			if resource.Purpose() != releaseinventory.ResourcePurposeRuntimeInstaller ||
				resource.MediaType() != releaseinventory.MediaTypeRuntimeInstaller ||
				resource.NativePublisherIdentity() == "" || resource.NativePublisherPolicyID() == "" ||
				a.certificates[resource.ID()].IsZero() {
				return false
			}
		case releaseinventory.ResourceKindRuntimeDistribution:
			if resource.Purpose() != releaseinventory.ResourcePurposeRuntimeDistribution ||
				resource.MediaType() != releaseinventory.MediaTypeRuntimeDistribution ||
				resource.NativePublisherIdentity() != "" || resource.NativePublisherPolicyID() != "" {
				return false
			}
		default:
			return false
		}
	}
	return seen[releaseinventory.ResourceKindRuntimeInstaller] &&
		seen[releaseinventory.ResourceKindRuntimeDistribution]
}

type nativeDesktopReleaseAuthorityVerifier interface {
	VerifyDesktopReleaseAuthority(
		context.Context,
		[]byte,
		string,
		string,
	) (nativeDesktopReleaseAuthority, error)
}

type nativeDesktopReleaseInventoryVerifier interface {
	Verify(context.Context, releaseinventory.SignedManifest) (appreleaseverify.VerifiedInventory, error)
}

// nativeVerifiedDesktopReleaseAuthority repeats complete release verification
// inside the elevated helper and accepts only inventory-authorized resources.
type nativeVerifiedDesktopReleaseAuthority struct {
	application  nativeDesktopReleaseInventoryVerifier
	certificates map[string]releaseinventory.Digest
}

func newNativeVerifiedDesktopReleaseAuthority(
	application nativeDesktopReleaseInventoryVerifier,
	certificates map[string]releaseinventory.Digest,
) (*nativeVerifiedDesktopReleaseAuthority, error) {
	if nilAny(application) || !validNativeHelperCertificateBindings(certificates) {
		return nil, errors.New("verified release application is required")
	}
	return &nativeVerifiedDesktopReleaseAuthority{
		application: application, certificates: copyNativeHelperCertificateBindings(certificates),
	}, nil
}

func (v *nativeVerifiedDesktopReleaseAuthority) VerifyDesktopReleaseAuthority(
	ctx context.Context,
	raw []byte,
	catalogID string,
	helperID string,
) (nativeDesktopReleaseAuthority, error) {
	if v == nil || ctx == nil || nilAny(v.application) || !validNativeHelperCertificateBindings(v.certificates) || len(raw) == 0 ||
		catalogID == "" || helperID == "" || catalogID == helperID {
		return nativeDesktopReleaseAuthority{}, runtimeport.ErrDesktopMutationIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nativeDesktopReleaseAuthority{}, err
	}
	signed, err := releaseinventory.DecodeSignedManifestV1(raw)
	if err != nil {
		return nativeDesktopReleaseAuthority{}, runtimeport.ErrDesktopMutationIntegrity
	}
	inventory, err := v.application.Verify(ctx, signed)
	if err != nil {
		return nativeDesktopReleaseAuthority{}, nativeDesktopHelperContextOrIntegrity(ctx)
	}
	authority, err := selectNativeDesktopReleaseAuthority(
		signed.Manifest().Digest(), signed.Manifest().Resources(), catalogID, helperID,
		v.certificates, nativeVerifiedDesktopResourceAuthorizer{inventory: inventory},
	)
	if err != nil {
		return nativeDesktopReleaseAuthority{}, runtimeport.ErrDesktopMutationIntegrity
	}
	return authority, nil
}

type nativeDesktopResourceAuthorizer interface {
	Authorizes(releaseinventory.Resource) bool
}

type nativeVerifiedDesktopResourceAuthorizer struct {
	inventory appreleaseverify.VerifiedInventory
}

func (a nativeVerifiedDesktopResourceAuthorizer) Authorizes(resource releaseinventory.Resource) bool {
	verified, present := a.inventory.Resource(resource.ID())
	return present && verified.Authorizes(resource)
}

func selectNativeDesktopReleaseAuthority(
	manifestDigest releaseinventory.Digest,
	resources []releaseinventory.Resource,
	catalogID string,
	helperID string,
	certificates map[string]releaseinventory.Digest,
	authorizer nativeDesktopResourceAuthorizer,
) (nativeDesktopReleaseAuthority, error) {
	if manifestDigest.IsZero() || catalogID == "" || helperID == "" || catalogID == helperID ||
		nilAny(authorizer) || !validNativeHelperCertificateBindings(certificates) {
		return nativeDesktopReleaseAuthority{}, runtimeport.ErrDesktopMutationIntegrity
	}
	var catalog releaseinventory.Resource
	var helper releaseinventory.Resource
	for _, resource := range resources {
		if resource.ID() == catalogID {
			if catalog.ID() != "" {
				return nativeDesktopReleaseAuthority{}, runtimeport.ErrDesktopMutationIntegrity
			}
			catalog = resource
		}
		if resource.ID() == helperID {
			if helper.ID() != "" {
				return nativeDesktopReleaseAuthority{}, runtimeport.ErrDesktopMutationIntegrity
			}
			helper = resource
		}
	}
	if catalog.ID() == "" || helper.ID() == "" || !authorizer.Authorizes(catalog) || !authorizer.Authorizes(helper) {
		return nativeDesktopReleaseAuthority{}, runtimeport.ErrDesktopMutationIntegrity
	}
	prerequisites := make([]releaseinventory.Resource, 0, 2)
	selectedCertificates := map[string]releaseinventory.Digest{helper.ID(): certificates[helper.ID()]}
	for _, resource := range resources {
		if resource.Platform().OS() != catalog.Platform().OS() ||
			resource.Platform().Architecture() != catalog.Platform().Architecture() ||
			(resource.Kind() != releaseinventory.ResourceKindRuntimeInstaller &&
				resource.Kind() != releaseinventory.ResourceKindRuntimeDistribution) {
			continue
		}
		if !authorizer.Authorizes(resource) {
			return nativeDesktopReleaseAuthority{}, runtimeport.ErrDesktopMutationIntegrity
		}
		prerequisites = append(prerequisites, resource)
		if resource.Kind() == releaseinventory.ResourceKindRuntimeInstaller {
			selectedCertificates[resource.ID()] = certificates[resource.ID()]
		}
	}
	authority, err := newNativeDesktopReleaseAuthority(
		manifestDigest, catalog, helper, prerequisites, selectedCertificates,
	)
	if err != nil {
		return nativeDesktopReleaseAuthority{}, runtimeport.ErrDesktopMutationIntegrity
	}
	return authority, nil
}

type nativeDesktopCatalogAuthorityVerifier interface {
	VerifyDesktopCatalogAuthority(
		context.Context,
		[]byte,
		releaseinventory.Resource,
		[]byte,
	) (runtimeport.DesktopAuthority, error)
}

type nativeDesktopCatalogApplicationVerifier interface {
	Verify(context.Context, runtimecatalogapp.Request) (runtimecatalogapp.VerifiedCatalog, error)
}

// nativeVerifiedDesktopCatalogAuthority repeats signature, anti-rollback,
// native-publisher, host, and canonical-plan projection in the helper.
type nativeVerifiedDesktopCatalogAuthority struct {
	application nativeDesktopCatalogApplicationVerifier
	host        runtimeprovision.DesktopHostBindingProvider
	trust       runtimeprovision.CatalogPublisherTrustResolver
}

func newNativeVerifiedDesktopCatalogAuthority(
	application nativeDesktopCatalogApplicationVerifier,
	host runtimeprovision.DesktopHostBindingProvider,
	trust runtimeprovision.CatalogPublisherTrustResolver,
) (*nativeVerifiedDesktopCatalogAuthority, error) {
	if nilAny(application) || nilAny(host) || nilAny(trust) {
		return nil, errors.New("verified desktop catalog, protected host, and native trust are required")
	}
	return &nativeVerifiedDesktopCatalogAuthority{application: application, host: host, trust: trust}, nil
}

func (v *nativeVerifiedDesktopCatalogAuthority) VerifyDesktopCatalogAuthority(
	ctx context.Context,
	raw []byte,
	resource releaseinventory.Resource,
	canonicalPlan []byte,
) (runtimeport.DesktopAuthority, error) {
	if v == nil || ctx == nil || nilAny(v.application) || nilAny(v.host) || nilAny(v.trust) ||
		len(raw) == 0 || len(canonicalPlan) == 0 ||
		resource.Kind() != releaseinventory.ResourceKindRuntimeCatalog ||
		resource.Purpose() != releaseinventory.ResourcePurposeRuntimeCatalog ||
		resource.MediaType() != releaseinventory.MediaTypeRuntimeCatalog || resource.Platform().IsAny() ||
		resource.Size() == 0 || uint64(len(raw)) != resource.Size() {
		return runtimeport.DesktopAuthority{}, runtimeport.ErrDesktopMutationIntegrity
	}
	if err := ctx.Err(); err != nil {
		return runtimeport.DesktopAuthority{}, err
	}
	digest := sha256.Sum256(raw)
	if releaseinventory.Digest(digest) != resource.Digest() {
		return runtimeport.DesktopAuthority{}, runtimeport.ErrDesktopMutationIntegrity
	}
	signed, err := runtimecatalog.DecodeSignedManifestV1(raw)
	if err != nil {
		return runtimeport.DesktopAuthority{}, runtimeport.ErrDesktopMutationIntegrity
	}
	mode, source, err := nativeRuntimeCatalogSourceSelection(signed.Manifest())
	if err != nil {
		return runtimeport.DesktopAuthority{}, runtimeport.ErrDesktopMutationIntegrity
	}
	verified, err := v.application.Verify(ctx, runtimecatalogapp.Request{
		SignedManifest: signed, ExpectedManifestDigest: signed.Manifest().Digest(),
		SourceMode: mode, OnlineSource: source,
	})
	if err != nil || verified.ManifestDigest() != signed.Manifest().Digest() {
		return runtimeport.DesktopAuthority{}, nativeDesktopHelperContextOrIntegrity(ctx)
	}
	execution, present := verified.Manifest().DesktopExecution()
	if !present || execution.ArtifactFileName() == "" {
		return runtimeport.DesktopAuthority{}, runtimeport.ErrDesktopMutationIntegrity
	}
	host, err := v.host.CurrentDesktopHostBinding(
		ctx, verified.ManifestDigest(), execution.ArtifactFileName(),
	)
	if err != nil {
		return runtimeport.DesktopAuthority{}, nativeDesktopHelperContextOrIntegrity(ctx)
	}
	trust, err := v.trust.NativeTrustDigest(verified.Manifest().Artifact().Publisher())
	if err != nil || trust.IsZero() {
		return runtimeport.DesktopAuthority{}, runtimeport.ErrDesktopMutationIntegrity
	}
	authority, err := verified.DesktopAuthority(canonicalPlan, host, trust)
	if err != nil || !authority.Valid() || resource.Platform().OS() != authority.Platform().String() ||
		resource.Platform().Architecture() != authority.Architecture().String() {
		return runtimeport.DesktopAuthority{}, runtimeport.ErrDesktopMutationIntegrity
	}
	return authority, nil
}

type nativeDesktopHelperSelfVerifier interface {
	VerifyDesktopHelperSelf(
		context.Context,
		releaseinventory.Resource,
		runtimeport.DesktopAuthority,
	) (runtimeinstall.Hash, error)
}

// nativeDesktopMutationAuthorityVerifier is the desktop helper's complete
// trust join. Inbound digests and paths remain data until every verifier agrees.
type nativeDesktopMutationAuthorityVerifier struct {
	releases nativeDesktopReleaseAuthorityVerifier
	catalogs nativeDesktopCatalogAuthorityVerifier
	self     nativeDesktopHelperSelfVerifier
}

func newNativeDesktopMutationAuthorityVerifier(
	releases nativeDesktopReleaseAuthorityVerifier,
	catalogs nativeDesktopCatalogAuthorityVerifier,
	self nativeDesktopHelperSelfVerifier,
) (*nativeDesktopMutationAuthorityVerifier, error) {
	if nilAny(releases) || nilAny(catalogs) || nilAny(self) {
		return nil, errors.New("complete native desktop helper authority dependencies are required")
	}
	return &nativeDesktopMutationAuthorityVerifier{releases: releases, catalogs: catalogs, self: self}, nil
}

func (v *nativeDesktopMutationAuthorityVerifier) VerifyDesktopMutationAuthority(
	ctx context.Context,
	envelope runtimeprovision.DesktopMutationRequestEnvelope,
) (runtimeprovision.DesktopMutationAuthorityEvidence, error) {
	if v == nil || ctx == nil || nilAny(envelope) || nilAny(v.releases) || nilAny(v.catalogs) || nilAny(v.self) {
		return runtimeprovision.DesktopMutationAuthorityEvidence{}, runtimeport.ErrDesktopMutationIntegrity
	}
	if err := ctx.Err(); err != nil {
		return runtimeprovision.DesktopMutationAuthorityEvidence{}, err
	}
	releaseRaw := envelope.SignedRelease()
	catalogRaw := envelope.SignedRuntimeCatalog()
	planRaw := envelope.CanonicalPlan()
	if len(releaseRaw) == 0 || len(catalogRaw) == 0 || len(planRaw) == 0 ||
		envelope.RuntimeCatalogResourceID() == "" || envelope.HelperResourceID() == "" {
		return runtimeprovision.DesktopMutationAuthorityEvidence{}, runtimeport.ErrDesktopMutationIntegrity
	}
	release, err := v.releases.VerifyDesktopReleaseAuthority(
		ctx, releaseRaw, envelope.RuntimeCatalogResourceID(), envelope.HelperResourceID(),
	)
	if err != nil || !release.valid() {
		return runtimeprovision.DesktopMutationAuthorityEvidence{}, nativeDesktopHelperContextOrIntegrity(ctx)
	}
	authority, err := v.catalogs.VerifyDesktopCatalogAuthority(ctx, catalogRaw, release.catalog, planRaw)
	if err != nil || !authority.Valid() ||
		release.catalog.Platform().OS() != authority.Platform().String() ||
		release.catalog.Platform().Architecture() != authority.Architecture().String() ||
		release.helper.Platform().OS() != authority.Platform().String() ||
		release.helper.Platform().Architecture() != authority.Architecture().String() {
		return runtimeprovision.DesktopMutationAuthorityEvidence{}, nativeDesktopHelperContextOrIntegrity(ctx)
	}
	helperDigest, err := v.self.VerifyDesktopHelperSelf(ctx, release.helper, authority)
	if err != nil || helperDigest.IsZero() || releaseinventory.Digest(helperDigest) != release.helper.Digest() {
		return runtimeprovision.DesktopMutationAuthorityEvidence{}, nativeDesktopHelperContextOrIntegrity(ctx)
	}
	certificates := make(map[string]runtimeinstall.Hash, len(release.prerequisites))
	for _, resource := range release.prerequisites {
		if certificate := release.certificates[resource.ID()]; !certificate.IsZero() {
			certificates[resource.ID()] = runtimeinstall.Hash(certificate)
		}
	}
	evidence, err := runtimeprovision.NewDesktopMutationAuthorityEvidenceWithPrerequisites(
		authority, helperDigest, runtimeinstall.Hash(release.manifestDigest),
		release.prerequisites, certificates,
	)
	if err != nil {
		return runtimeprovision.DesktopMutationAuthorityEvidence{}, runtimeport.ErrDesktopMutationIntegrity
	}
	return evidence, nil
}

func nativeDesktopHelperContextOrIntegrity(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return runtimeport.ErrDesktopMutationIntegrity
}

var (
	_ nativeDesktopReleaseAuthorityVerifier             = (*nativeVerifiedDesktopReleaseAuthority)(nil)
	_ nativeDesktopCatalogAuthorityVerifier             = (*nativeVerifiedDesktopCatalogAuthority)(nil)
	_ runtimeprovision.DesktopMutationAuthorityVerifier = (*nativeDesktopMutationAuthorityVerifier)(nil)
)
