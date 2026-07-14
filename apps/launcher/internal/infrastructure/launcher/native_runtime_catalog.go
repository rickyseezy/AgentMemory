package launcher

import (
	"context"
	"crypto/sha256"
	"io"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
	appreleaseverify "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
)

const maximumNativeRuntimeCatalogBytes = 8 * 1024 * 1024

type nativeRuntimeCatalogReleaseVerifier interface {
	VerifyReleaseResource(context.Context, releaseinventory.SignedManifest, releaseinventory.Resource) error
}

type nativeRuntimeCatalogSource interface {
	OpenResource(context.Context, releaseinventory.Resource) (io.ReadCloser, error)
}

type nativeRuntimeCatalogDecoder func([]byte) (runtimecatalog.SignedManifest, error)

type nativeRuntimeCatalogEnvelope struct {
	Signed         runtimecatalog.SignedManifest
	ResourceDigest install.Digest
}

type nativeRuntimeCatalogLoader struct {
	releases nativeRuntimeCatalogReleaseVerifier
	source   nativeRuntimeCatalogSource
	decode   nativeRuntimeCatalogDecoder
}

func newNativeRuntimeCatalogLoader(
	release *nativeReleaseAuthority,
) (*nativeRuntimeCatalogLoader, error) {
	if release == nil || release.verifier() == nil || release.source == nil {
		return nil, errNativeInstallerIntegrity
	}
	return newNativeRuntimeCatalogLoaderWithDependencies(
		&nativeVerifiedReleaseResource{application: release.verifier()},
		release.source, runtimecatalog.DecodeSignedManifestV1,
	)
}

func newNativeRuntimeCatalogLoaderWithDependencies(
	releases nativeRuntimeCatalogReleaseVerifier,
	source nativeRuntimeCatalogSource,
	decode nativeRuntimeCatalogDecoder,
) (*nativeRuntimeCatalogLoader, error) {
	if nilAny(releases) || nilAny(source) || decode == nil {
		return nil, errNativeInstallerIntegrity
	}
	return &nativeRuntimeCatalogLoader{releases: releases, source: source, decode: decode}, nil
}

func (l *nativeRuntimeCatalogLoader) Load(
	ctx context.Context,
	request installplanapp.RuntimeEvidenceRequest,
) (nativeRuntimeCatalogEnvelope, error) {
	resource := request.RuntimeCatalogResource
	resourceDigest, digestError := install.ParseDigest(resource.Digest().Hex())
	if l == nil || ctx == nil || request.OperationID.IsZero() || request.ParentPlanDigest.IsZero() ||
		request.RuntimeCatalogID == "" || request.RuntimeCatalogDigest.IsZero() || digestError != nil ||
		resource.ID() != request.RuntimeCatalogID || !resourceDigest.Equal(request.RuntimeCatalogDigest) ||
		resource.Kind() != releaseinventory.ResourceKindRuntimeCatalog ||
		resource.Purpose() != releaseinventory.ResourcePurposeRuntimeCatalog ||
		resource.MediaType() != releaseinventory.MediaTypeRuntimeCatalog || resource.Size() == 0 ||
		resource.Size() > maximumNativeRuntimeCatalogBytes || nilAny(l.releases) || nilAny(l.source) || l.decode == nil {
		return nativeRuntimeCatalogEnvelope{}, installplanapp.ErrRuntimeEvidenceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nativeRuntimeCatalogEnvelope{}, err
	}
	if err := l.releases.VerifyReleaseResource(ctx, request.SignedRelease, resource); err != nil {
		return nativeRuntimeCatalogEnvelope{}, installplanapp.ErrRuntimeEvidenceUnavailable
	}
	reader, err := l.source.OpenResource(ctx, resource)
	if err != nil || reader == nil {
		return nativeRuntimeCatalogEnvelope{}, installplanapp.ErrRuntimeEvidenceUnavailable
	}
	defer func() { _ = reader.Close() }()
	// G115: the resource size was bounded to 8 MiB above before conversion.
	raw, err := io.ReadAll(io.LimitReader(reader, int64(resource.Size())+1)) //nolint:gosec
	if err != nil || uint64(len(raw)) != resource.Size() {
		return nativeRuntimeCatalogEnvelope{}, installplanapp.ErrRuntimeEvidenceUnavailable
	}
	defer clear(raw)
	actual := sha256.Sum256(raw)
	if !releaseinventory.Digest(actual).Equal(resource.Digest()) {
		return nativeRuntimeCatalogEnvelope{}, installplanapp.ErrRuntimeEvidenceUnavailable
	}
	signed, err := l.decode(raw)
	if err != nil {
		return nativeRuntimeCatalogEnvelope{}, installplanapp.ErrRuntimeEvidenceUnavailable
	}
	return nativeRuntimeCatalogEnvelope{Signed: signed, ResourceDigest: resourceDigest}, nil
}

type nativeVerifiedReleaseResource struct {
	application *appreleaseverify.Application
}

func (v *nativeVerifiedReleaseResource) VerifyReleaseResource(
	ctx context.Context,
	signed releaseinventory.SignedManifest,
	resource releaseinventory.Resource,
) error {
	if v == nil || v.application == nil || ctx == nil {
		return installplanapp.ErrRuntimeEvidenceUnavailable
	}
	inventory, err := v.application.Verify(ctx, signed)
	if err != nil {
		return installplanapp.ErrRuntimeEvidenceUnavailable
	}
	verified, found := inventory.Resource(resource.ID())
	if !found || !verified.Authorizes(resource) {
		return installplanapp.ErrRuntimeEvidenceUnavailable
	}
	return nil
}
