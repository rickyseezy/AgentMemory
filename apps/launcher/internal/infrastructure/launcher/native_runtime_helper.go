package launcher

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

type nativeDesktopHelperReleaseVerifier interface {
	VerifyReleaseResource(context.Context, releaseinventory.SignedManifest, releaseinventory.Resource) error
}

type nativeDesktopHelperAuthorityResolver struct {
	releases       nativeDesktopHelperReleaseVerifier
	signed         releaseinventory.SignedManifest
	manifestDigest releaseinventory.Digest
	certificates   map[string]releaseinventory.Digest
	helpers        []releaseinventory.Resource
}

// newNativeDesktopHelperTrust projects helper authority only from the signed
// release retained by the production release authority. Runtime catalogs do
// not get to name, locate, or authorize AgentMemory's elevated helper.
func newNativeDesktopHelperTrust(
	release *nativeReleaseAuthority,
	signed releaseinventory.SignedManifest,
) (runtimeport.DesktopHelperAuthorityResolver, runtimeport.DesktopHelperPublisherVerifier, error) {
	if release == nil || release.verifier() == nil {
		return nil, nil, errNativeInstallerIntegrity
	}
	resolver, err := newNativeDesktopHelperAuthorityResolver(
		&nativeVerifiedReleaseResource{application: release.verifier()}, signed,
		signed.Manifest().Digest(), release.runtimeHelperPublisherCertificates,
		signed.Manifest().Resources(),
	)
	if err != nil {
		return nil, nil, errNativeInstallerIntegrity
	}
	return resolver, &nativeDesktopHelperPublisherVerifier{resolver: resolver}, nil
}

func newNativeDesktopHelperAuthorityResolver(
	releases nativeDesktopHelperReleaseVerifier,
	signed releaseinventory.SignedManifest,
	manifestDigest releaseinventory.Digest,
	certificates map[string]releaseinventory.Digest,
	resources []releaseinventory.Resource,
) (*nativeDesktopHelperAuthorityResolver, error) {
	helpers := make([]releaseinventory.Resource, 0, 2)
	for _, resource := range resources {
		if resource.Kind() == releaseinventory.ResourceKindHelper {
			operatingSystem := resource.Platform().OS()
			if operatingSystem != runtimeinstall.PlatformDarwin.String() &&
				operatingSystem != runtimeinstall.PlatformWindows.String() {
				continue
			}
			if resource.Purpose() != releaseinventory.ResourcePurposeNativeHelper ||
				resource.MediaType() != releaseinventory.MediaTypeNativeExecutable ||
				resource.Platform().IsAny() || resource.Digest().IsZero() ||
				resource.NativePublisherIdentity() == "" || resource.NativePublisherPolicyID() == "" {
				return nil, errNativeInstallerIntegrity
			}
			if certificates[resource.ID()].IsZero() {
				return nil, errNativeInstallerIntegrity
			}
			helpers = append(helpers, resource)
		}
	}
	if nilAny(releases) || manifestDigest.IsZero() || !validNativeHelperCertificateBindings(certificates) || len(helpers) == 0 {
		return nil, errNativeInstallerIntegrity
	}
	return &nativeDesktopHelperAuthorityResolver{
		releases: releases, signed: signed, manifestDigest: manifestDigest,
		certificates: copyNativeHelperCertificateBindings(certificates),
		helpers:      append([]releaseinventory.Resource(nil), helpers...),
	}, nil
}

func (r *nativeDesktopHelperAuthorityResolver) ResolveDesktopHelperAuthority(
	ctx context.Context,
	desktop runtimeport.DesktopAuthority,
) (runtimeport.DesktopHelperAuthority, error) {
	if r == nil || ctx == nil || !desktop.Valid() || nilAny(r.releases) ||
		r.manifestDigest.IsZero() || !validNativeHelperCertificateBindings(r.certificates) {
		return runtimeport.DesktopHelperAuthority{}, runtimeport.ErrDesktopMutationIntegrity
	}
	if err := ctx.Err(); err != nil {
		return runtimeport.DesktopHelperAuthority{}, err
	}
	resource, err := r.helperFor(desktop.Platform(), desktop.Architecture())
	certificate := r.certificates[resource.ID()]
	if err != nil || certificate.IsZero() || r.releases.VerifyReleaseResource(ctx, r.signed, resource) != nil {
		return runtimeport.DesktopHelperAuthority{}, runtimeport.ErrDesktopMutationUnavailable
	}
	canonical, exchange, err := nativeDesktopHelperPaths(desktop)
	if err != nil {
		return runtimeport.DesktopHelperAuthority{}, runtimeport.ErrDesktopMutationIntegrity
	}
	helper, err := runtimeport.NewDesktopHelperAuthority(runtimeport.DesktopHelperAuthorityInput{
		Platform: desktop.Platform(), Architecture: desktop.Architecture(), PlanDigest: desktop.PlanDigest(),
		PrincipalID: desktop.PrincipalID(), MachineDigest: desktop.MachineDigest(),
		CanonicalPath: canonical, SHA256: runtimeinstall.Hash(resource.Digest()),
		PublisherIdentity:     resource.NativePublisherIdentity(),
		PublisherCertificate:  runtimeinstall.Hash(certificate),
		ReleaseManifestDigest: runtimeinstall.Hash(r.manifestDigest), ExchangeDirectory: exchange,
	})
	if err != nil || !helper.ValidFor(desktop) {
		return runtimeport.DesktopHelperAuthority{}, runtimeport.ErrDesktopMutationIntegrity
	}
	return helper, nil
}

func (r *nativeDesktopHelperAuthorityResolver) helperFor(
	platform runtimeinstall.Platform,
	architecture runtimeinstall.Architecture,
) (releaseinventory.Resource, error) {
	if r == nil {
		return releaseinventory.Resource{}, errNativeInstallerIntegrity
	}
	operatingSystem, processor := platform.String(), architecture.String()
	var selected releaseinventory.Resource
	for _, resource := range r.helpers {
		if resource.Platform().OS() == operatingSystem && resource.Platform().Architecture() == processor {
			if selected.ID() != "" {
				return releaseinventory.Resource{}, errNativeInstallerIntegrity
			}
			selected = resource
		}
	}
	if selected.ID() == "" {
		return releaseinventory.Resource{}, errNativeInstallerIntegrity
	}
	return selected, nil
}

func nativeDesktopHelperPaths(desktop runtimeport.DesktopAuthority) (string, string, error) {
	operation := desktop.PlanDigest().String()
	switch desktop.Platform() {
	case runtimeinstall.PlatformDarwin:
		return "/Library/PrivilegedHelperTools/com.rickyseezy.agentmemory.runtime-helper",
			filepath.Join(desktop.HomeDirectory(), "Library", "Application Support", "AgentMemory", "bootstrap", operation, "native"), nil
	case runtimeinstall.PlatformWindows:
		home := strings.TrimRight(desktop.HomeDirectory(), `\`)
		return `C:\Program Files\AgentMemory\bin\agentmemory-runtime-helper.exe`,
			home + `\AppData\Local\AgentMemory\bootstrap\` + operation + `\native`, nil
	case runtimeinstall.PlatformUnknown, runtimeinstall.PlatformLinux:
		return "", "", errNativeInstallerIntegrity
	}
	return "", "", errNativeInstallerIntegrity
}

type nativeDesktopHelperPublisherVerifier struct {
	resolver *nativeDesktopHelperAuthorityResolver
}

func (v *nativeDesktopHelperPublisherVerifier) VerifyDesktopHelperPublisher(
	ctx context.Context,
	helper runtimeport.DesktopHelperAuthority,
) error {
	if v == nil || v.resolver == nil || ctx == nil || !helper.Valid() {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	resource, err := v.resolver.helperFor(helper.Platform(), helper.Architecture())
	certificate := v.resolver.certificates[resource.ID()]
	if err != nil || helper.SHA256() != runtimeinstall.Hash(resource.Digest()) ||
		helper.PublisherIdentity() != resource.NativePublisherIdentity() ||
		certificate.IsZero() || helper.PublisherCertificate() != runtimeinstall.Hash(certificate) ||
		helper.ReleaseManifestDigest() != runtimeinstall.Hash(v.resolver.manifestDigest) {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	if err := v.resolver.releases.VerifyReleaseResource(ctx, v.resolver.signed, resource); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return runtimeport.ErrDesktopMutationIntegrity
	}
	return nil
}

var (
	_ runtimeport.DesktopHelperAuthorityResolver = (*nativeDesktopHelperAuthorityResolver)(nil)
	_ runtimeport.DesktopHelperPublisherVerifier = (*nativeDesktopHelperPublisherVerifier)(nil)
)
