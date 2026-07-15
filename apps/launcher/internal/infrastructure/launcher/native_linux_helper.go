package launcher

import (
	"context"
	"crypto/sha256"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeprovision"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const nativeLinuxRuntimeHelperPath = "/usr/libexec/agentmemory/agentmemory-runtime-helper"

type nativeLinuxHelperReleaseVerifier interface {
	VerifyReleaseResource(context.Context, releaseinventory.SignedManifest, releaseinventory.Resource) error
}

// nativeLinuxHelperAuthority is projected only from a helper resource that
// passed the complete signed release verifier for the current Linux cell.
type nativeLinuxHelperAuthority struct {
	resource       releaseinventory.Resource
	manifestDigest releaseinventory.Digest
}

func (a nativeLinuxHelperAuthority) ValidFor(authority runtimeport.LinuxAuthority) bool {
	return authority.Valid() && !a.manifestDigest.IsZero() && a.resource.ID() != "" &&
		a.resource.Kind() == releaseinventory.ResourceKindHelper &&
		a.resource.Purpose() == releaseinventory.ResourcePurposeNativeHelper &&
		a.resource.MediaType() == releaseinventory.MediaTypeNativeExecutable &&
		a.resource.Platform().OS() == runtimeinstall.PlatformLinux.String() &&
		a.resource.Platform().Architecture() == authority.Architecture().String() &&
		!a.resource.Digest().IsZero() && a.resource.Size() != 0 &&
		a.resource.NativePublisherIdentity() != "" && a.resource.NativePublisherPolicyID() != ""
}

func (a nativeLinuxHelperAuthority) Resource() releaseinventory.Resource { return a.resource }
func (a nativeLinuxHelperAuthority) ResourceID() string                  { return a.resource.ID() }
func (a nativeLinuxHelperAuthority) CanonicalPath() string               { return nativeLinuxRuntimeHelperPath }
func (a nativeLinuxHelperAuthority) SHA256() runtimeinstall.Hash {
	return runtimeinstall.Hash(a.resource.Digest())
}
func (a nativeLinuxHelperAuthority) ReleaseManifestDigest() runtimeinstall.Hash {
	return runtimeinstall.Hash(a.manifestDigest)
}

type nativeLinuxHelperAuthorityResolver struct {
	releases       nativeLinuxHelperReleaseVerifier
	signed         releaseinventory.SignedManifest
	manifestDigest releaseinventory.Digest
	helpers        []releaseinventory.Resource
}

func newNativeLinuxHelperAuthorityResolver(
	releases nativeLinuxHelperReleaseVerifier,
	signed releaseinventory.SignedManifest,
	manifestDigest releaseinventory.Digest,
	resources []releaseinventory.Resource,
) (*nativeLinuxHelperAuthorityResolver, error) {
	helpers := make([]releaseinventory.Resource, 0, 2)
	for _, resource := range resources {
		if resource.Kind() != releaseinventory.ResourceKindHelper ||
			resource.Platform().OS() != runtimeinstall.PlatformLinux.String() {
			continue
		}
		if resource.Purpose() != releaseinventory.ResourcePurposeNativeHelper ||
			resource.MediaType() != releaseinventory.MediaTypeNativeExecutable ||
			resource.Platform().IsAny() || resource.Digest().IsZero() || resource.Size() == 0 ||
			resource.NativePublisherIdentity() == "" || resource.NativePublisherPolicyID() == "" {
			return nil, errNativeInstallerIntegrity
		}
		helpers = append(helpers, resource)
	}
	if nilAny(releases) || manifestDigest.IsZero() || len(helpers) == 0 {
		return nil, errNativeInstallerIntegrity
	}
	return &nativeLinuxHelperAuthorityResolver{
		releases: releases, signed: signed, manifestDigest: manifestDigest,
		helpers: append([]releaseinventory.Resource(nil), helpers...),
	}, nil
}

func (r *nativeLinuxHelperAuthorityResolver) ResolveLinuxHelperAuthority(
	ctx context.Context,
	authority runtimeport.LinuxAuthority,
) (nativeLinuxHelperAuthority, error) {
	if r == nil || ctx == nil || !authority.Valid() || nilAny(r.releases) || r.manifestDigest.IsZero() {
		return nativeLinuxHelperAuthority{}, errNativeInstallerIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nativeLinuxHelperAuthority{}, err
	}
	resource, err := r.helperFor(authority.Architecture())
	if err != nil || r.releases.VerifyReleaseResource(ctx, r.signed, resource) != nil {
		if contextError := ctx.Err(); contextError != nil {
			return nativeLinuxHelperAuthority{}, contextError
		}
		return nativeLinuxHelperAuthority{}, errNativeInstallerIntegrity
	}
	helper := nativeLinuxHelperAuthority{resource: resource, manifestDigest: r.manifestDigest}
	if !helper.ValidFor(authority) {
		return nativeLinuxHelperAuthority{}, errNativeInstallerIntegrity
	}
	return helper, nil
}

func (r *nativeLinuxHelperAuthorityResolver) helperFor(
	architecture runtimeinstall.Architecture,
) (releaseinventory.Resource, error) {
	if r == nil || architecture == runtimeinstall.ArchitectureUnknown {
		return releaseinventory.Resource{}, errNativeInstallerIntegrity
	}
	var selected releaseinventory.Resource
	for _, resource := range r.helpers {
		if resource.Platform().Architecture() != architecture.String() {
			continue
		}
		if selected.ID() != "" {
			return releaseinventory.Resource{}, errNativeInstallerIntegrity
		}
		selected = resource
	}
	if selected.ID() == "" {
		return releaseinventory.Resource{}, errNativeInstallerIntegrity
	}
	return selected, nil
}

type nativeReleaseManifestEncoder func(releaseinventory.SignedManifest) ([]byte, error)
type nativeRuntimeCatalogEncoder func(runtimecatalog.SignedManifest) ([]byte, error)

func buildNativeLinuxPrivilegeCodecWithEncoders(
	ctx context.Context,
	verified nativeVerifiedRuntimeExecution,
	authority runtimeport.LinuxAuthority,
	resolver *nativeLinuxHelperAuthorityResolver,
	releaseEncoder nativeReleaseManifestEncoder,
	catalogEncoder nativeRuntimeCatalogEncoder,
) (*runtimeprovision.CanonicalPrivilegeTransportCodec, nativeLinuxHelperAuthority, error) {
	plan := verified.authority.Plan()
	resource := verified.request.RuntimeCatalogResource
	if ctx == nil || !authority.ValidFor(plan) || verified.authority.BindingDigest().IsZero() ||
		resolver == nil || releaseEncoder == nil || catalogEncoder == nil ||
		verified.request.RuntimeCatalogID == "" || resource.ID() != verified.request.RuntimeCatalogID ||
		resource.Kind() != releaseinventory.ResourceKindRuntimeCatalog ||
		resource.Purpose() != releaseinventory.ResourcePurposeRuntimeCatalog ||
		resource.MediaType() != releaseinventory.MediaTypeRuntimeCatalog || resource.Digest().IsZero() || resource.Size() == 0 {
		return nil, nativeLinuxHelperAuthority{}, errNativeInstallerIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, nativeLinuxHelperAuthority{}, err
	}
	helper, err := resolver.ResolveLinuxHelperAuthority(ctx, authority)
	if err != nil || !helper.ValidFor(authority) {
		return nil, nativeLinuxHelperAuthority{}, errNativeInstallerIntegrity
	}
	releaseRaw, releaseError := releaseEncoder(verified.request.SignedRelease)
	catalogRaw, catalogError := catalogEncoder(verified.signedCatalog)
	actualCatalog := sha256.Sum256(catalogRaw)
	if releaseError != nil || catalogError != nil || uint64(len(catalogRaw)) != resource.Size() ||
		releaseinventory.Digest(actualCatalog) != resource.Digest() {
		return nil, nativeLinuxHelperAuthority{}, errNativeInstallerIntegrity
	}
	codec, err := runtimeprovision.NewCanonicalPrivilegeTransportCodec(runtimeprovision.PrivilegeEnvelopeInput{
		SignedRelease: releaseRaw, SignedRuntimeCatalog: catalogRaw, CanonicalPlan: plan.CanonicalBytes(),
		RuntimeCatalogResourceID: resource.ID(), HelperResourceID: helper.ResourceID(),
	})
	if err != nil {
		return nil, nativeLinuxHelperAuthority{}, errNativeInstallerIntegrity
	}
	return codec, helper, nil
}
