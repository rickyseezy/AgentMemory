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

type nativePrivilegeReleaseAuthority struct {
	manifestDigest releaseinventory.Digest
	catalog        releaseinventory.Resource
	helper         releaseinventory.Resource
}

func newNativePrivilegeReleaseAuthority(
	manifestDigest releaseinventory.Digest,
	catalog releaseinventory.Resource,
	helper releaseinventory.Resource,
) (nativePrivilegeReleaseAuthority, error) {
	authority := nativePrivilegeReleaseAuthority{
		manifestDigest: manifestDigest, catalog: catalog, helper: helper,
	}
	if !authority.valid() {
		return nativePrivilegeReleaseAuthority{}, runtimeport.ErrPrivilegeIntegrity
	}
	return authority, nil
}

func (a nativePrivilegeReleaseAuthority) valid() bool {
	return !a.manifestDigest.IsZero() &&
		a.catalog.ID() != "" && a.catalog.Kind() == releaseinventory.ResourceKindRuntimeCatalog &&
		a.catalog.Purpose() == releaseinventory.ResourcePurposeRuntimeCatalog &&
		a.catalog.MediaType() == releaseinventory.MediaTypeRuntimeCatalog &&
		!a.catalog.Platform().IsAny() && a.catalog.Platform().OS() == runtimeinstall.PlatformLinux.String() &&
		!a.catalog.Digest().IsZero() && a.catalog.Size() != 0 &&
		a.helper.ID() != "" && a.helper.Kind() == releaseinventory.ResourceKindHelper &&
		a.helper.Purpose() == releaseinventory.ResourcePurposeNativeHelper &&
		a.helper.MediaType() == releaseinventory.MediaTypeNativeExecutable &&
		!a.helper.Platform().IsAny() && a.helper.Platform().OS() == runtimeinstall.PlatformLinux.String() &&
		!a.helper.Digest().IsZero() && a.helper.Size() != 0 &&
		a.helper.NativePublisherIdentity() != "" && a.helper.NativePublisherPolicyID() != ""
}

type nativePrivilegeReleaseAuthorityVerifier interface {
	VerifyPrivilegeReleaseAuthority(
		context.Context,
		[]byte,
		string,
		string,
	) (nativePrivilegeReleaseAuthority, error)
}

type nativePrivilegeReleaseInventoryVerifier interface {
	Verify(context.Context, releaseinventory.SignedManifest) (appreleaseverify.VerifiedInventory, error)
}

type nativeVerifiedPrivilegeReleaseAuthority struct {
	application nativePrivilegeReleaseInventoryVerifier
}

func newNativeVerifiedPrivilegeReleaseAuthority(
	application nativePrivilegeReleaseInventoryVerifier,
) (*nativeVerifiedPrivilegeReleaseAuthority, error) {
	if nilAny(application) {
		return nil, errors.New("verified release application is required")
	}
	return &nativeVerifiedPrivilegeReleaseAuthority{application: application}, nil
}

func (v *nativeVerifiedPrivilegeReleaseAuthority) VerifyPrivilegeReleaseAuthority(
	ctx context.Context,
	raw []byte,
	catalogID string,
	helperID string,
) (nativePrivilegeReleaseAuthority, error) {
	if v == nil || ctx == nil || nilAny(v.application) || len(raw) == 0 ||
		catalogID == "" || helperID == "" || catalogID == helperID {
		return nativePrivilegeReleaseAuthority{}, runtimeport.ErrPrivilegeIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nativePrivilegeReleaseAuthority{}, err
	}
	signed, err := releaseinventory.DecodeSignedManifestV1(raw)
	if err != nil {
		return nativePrivilegeReleaseAuthority{}, runtimeport.ErrPrivilegeIntegrity
	}
	inventory, err := v.application.Verify(ctx, signed)
	if err != nil {
		return nativePrivilegeReleaseAuthority{}, nativePrivilegeContextOrIntegrity(ctx)
	}
	catalog, catalogFound := releaseResourceByID(signed.Manifest(), catalogID)
	helper, helperFound := releaseResourceByID(signed.Manifest(), helperID)
	verifiedCatalog, catalogVerified := inventory.Resource(catalogID)
	verifiedHelper, helperVerified := inventory.Resource(helperID)
	if !catalogFound || !helperFound || !catalogVerified || !helperVerified ||
		!verifiedCatalog.Authorizes(catalog) || !verifiedHelper.Authorizes(helper) ||
		inventory.ManifestDigest() != signed.Manifest().Digest() {
		return nativePrivilegeReleaseAuthority{}, runtimeport.ErrPrivilegeIntegrity
	}
	authority, err := newNativePrivilegeReleaseAuthority(inventory.ManifestDigest(), catalog, helper)
	if err != nil {
		return nativePrivilegeReleaseAuthority{}, runtimeport.ErrPrivilegeIntegrity
	}
	return authority, nil
}

func releaseResourceByID(
	manifest releaseinventory.Manifest,
	resourceID string,
) (releaseinventory.Resource, bool) {
	if resourceID == "" {
		return releaseinventory.Resource{}, false
	}
	var selected releaseinventory.Resource
	for _, resource := range manifest.Resources() {
		if resource.ID() != resourceID {
			continue
		}
		if selected.ID() != "" {
			return releaseinventory.Resource{}, false
		}
		selected = resource
	}
	return selected, selected.ID() != ""
}

type nativePrivilegeCatalogAuthorityVerifier interface {
	VerifyPrivilegeCatalogAuthority(
		context.Context,
		[]byte,
		releaseinventory.Resource,
		[]byte,
	) (runtimeport.LinuxAuthority, error)
}

type nativePrivilegeCatalogApplicationVerifier interface {
	Verify(context.Context, runtimecatalogapp.Request) (runtimecatalogapp.VerifiedCatalog, error)
}

type nativeVerifiedPrivilegeCatalogAuthority struct {
	application nativePrivilegeCatalogApplicationVerifier
	host        runtimeprovision.LinuxHostBindingProvider
}

func newNativeVerifiedPrivilegeCatalogAuthority(
	application nativePrivilegeCatalogApplicationVerifier,
	host runtimeprovision.LinuxHostBindingProvider,
) (*nativeVerifiedPrivilegeCatalogAuthority, error) {
	if nilAny(application) || nilAny(host) {
		return nil, errors.New("verified catalog application and protected host binding are required")
	}
	return &nativeVerifiedPrivilegeCatalogAuthority{application: application, host: host}, nil
}

func (v *nativeVerifiedPrivilegeCatalogAuthority) VerifyPrivilegeCatalogAuthority(
	ctx context.Context,
	raw []byte,
	resource releaseinventory.Resource,
	canonicalPlan []byte,
) (runtimeport.LinuxAuthority, error) {
	if v == nil || ctx == nil || nilAny(v.application) || nilAny(v.host) ||
		len(raw) == 0 || len(canonicalPlan) == 0 ||
		resource.Kind() != releaseinventory.ResourceKindRuntimeCatalog ||
		resource.Purpose() != releaseinventory.ResourcePurposeRuntimeCatalog ||
		resource.MediaType() != releaseinventory.MediaTypeRuntimeCatalog ||
		resource.Size() == 0 || uint64(len(raw)) != resource.Size() {
		return runtimeport.LinuxAuthority{}, runtimeport.ErrPrivilegeIntegrity
	}
	if err := ctx.Err(); err != nil {
		return runtimeport.LinuxAuthority{}, err
	}
	digest := sha256.Sum256(raw)
	if releaseinventory.Digest(digest) != resource.Digest() {
		return runtimeport.LinuxAuthority{}, runtimeport.ErrPrivilegeIntegrity
	}
	signed, err := runtimecatalog.DecodeSignedManifestV1(raw)
	if err != nil {
		return runtimeport.LinuxAuthority{}, runtimeport.ErrPrivilegeIntegrity
	}
	mode, source, err := nativeRuntimeCatalogSourceSelection(signed.Manifest())
	if err != nil {
		return runtimeport.LinuxAuthority{}, runtimeport.ErrPrivilegeIntegrity
	}
	verified, err := v.application.Verify(ctx, runtimecatalogapp.Request{
		SignedManifest: signed, ExpectedManifestDigest: signed.Manifest().Digest(),
		SourceMode: mode, OnlineSource: source,
	})
	if err != nil {
		return runtimeport.LinuxAuthority{}, nativePrivilegeContextOrIntegrity(ctx)
	}
	host, err := v.host.CurrentLinuxHostBinding(ctx)
	if err != nil {
		return runtimeport.LinuxAuthority{}, nativePrivilegeContextOrIntegrity(ctx)
	}
	authority, err := verified.LinuxAuthority(canonicalPlan, host)
	if err != nil || !authority.Valid() {
		return runtimeport.LinuxAuthority{}, runtimeport.ErrPrivilegeIntegrity
	}
	return authority, nil
}

type nativePrivilegeHelperSelfVerifier interface {
	VerifyPrivilegeHelperSelf(
		context.Context,
		releaseinventory.Resource,
		runtimeport.LinuxAuthority,
	) (runtimeinstall.Hash, error)
}

// nativePrivilegeAuthorityVerifier is the helper-side trust join. No inbound
// descriptor, authority projection, or executable digest is accepted as proof.
type nativePrivilegeAuthorityVerifier struct {
	releases nativePrivilegeReleaseAuthorityVerifier
	catalogs nativePrivilegeCatalogAuthorityVerifier
	self     nativePrivilegeHelperSelfVerifier
}

func newNativePrivilegeAuthorityVerifier(
	releases nativePrivilegeReleaseAuthorityVerifier,
	catalogs nativePrivilegeCatalogAuthorityVerifier,
	self nativePrivilegeHelperSelfVerifier,
) (*nativePrivilegeAuthorityVerifier, error) {
	if nilAny(releases) || nilAny(catalogs) || nilAny(self) {
		return nil, errors.New("complete native privilege authority dependencies are required")
	}
	return &nativePrivilegeAuthorityVerifier{releases: releases, catalogs: catalogs, self: self}, nil
}

func (v *nativePrivilegeAuthorityVerifier) VerifyPrivilegeAuthority(
	ctx context.Context,
	envelope runtimeprovision.PrivilegeRequestEnvelope,
) (runtimeprovision.PrivilegeAuthorityEvidence, error) {
	if v == nil || ctx == nil || nilAny(envelope) || nilAny(v.releases) ||
		nilAny(v.catalogs) || nilAny(v.self) {
		return runtimeprovision.PrivilegeAuthorityEvidence{}, runtimeport.ErrPrivilegeIntegrity
	}
	if err := ctx.Err(); err != nil {
		return runtimeprovision.PrivilegeAuthorityEvidence{}, err
	}
	releaseRaw := envelope.SignedRelease()
	catalogRaw := envelope.SignedRuntimeCatalog()
	planRaw := envelope.CanonicalPlan()
	if len(releaseRaw) == 0 || len(catalogRaw) == 0 || len(planRaw) == 0 ||
		envelope.RuntimeCatalogResourceID() == "" || envelope.HelperResourceID() == "" {
		return runtimeprovision.PrivilegeAuthorityEvidence{}, runtimeport.ErrPrivilegeIntegrity
	}
	release, err := v.releases.VerifyPrivilegeReleaseAuthority(
		ctx, releaseRaw, envelope.RuntimeCatalogResourceID(), envelope.HelperResourceID(),
	)
	if err != nil || !release.valid() {
		return runtimeprovision.PrivilegeAuthorityEvidence{}, nativePrivilegeContextOrIntegrity(ctx)
	}
	authority, err := v.catalogs.VerifyPrivilegeCatalogAuthority(ctx, catalogRaw, release.catalog, planRaw)
	if err != nil || !authority.Valid() ||
		release.catalog.Platform().Architecture() != authority.Architecture().String() ||
		release.helper.Platform().Architecture() != authority.Architecture().String() {
		return runtimeprovision.PrivilegeAuthorityEvidence{}, nativePrivilegeContextOrIntegrity(ctx)
	}
	helperDigest, err := v.self.VerifyPrivilegeHelperSelf(ctx, release.helper, authority)
	if err != nil || helperDigest.IsZero() || releaseinventory.Digest(helperDigest) != release.helper.Digest() {
		return runtimeprovision.PrivilegeAuthorityEvidence{}, nativePrivilegeContextOrIntegrity(ctx)
	}
	evidence, err := runtimeprovision.NewPrivilegeAuthorityEvidence(authority, helperDigest)
	if err != nil {
		return runtimeprovision.PrivilegeAuthorityEvidence{}, runtimeport.ErrPrivilegeIntegrity
	}
	return evidence, nil
}

func nativePrivilegeContextOrIntegrity(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return runtimeport.ErrPrivilegeIntegrity
}

var _ runtimeprovision.PrivilegeAuthorityVerifier = (*nativePrivilegeAuthorityVerifier)(nil)

var (
	_ nativePrivilegeReleaseAuthorityVerifier = (*nativeVerifiedPrivilegeReleaseAuthority)(nil)
	_ nativePrivilegeCatalogAuthorityVerifier = (*nativeVerifiedPrivilegeCatalogAuthority)(nil)
)
