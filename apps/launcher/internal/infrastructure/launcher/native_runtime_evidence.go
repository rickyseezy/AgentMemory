package launcher

import (
	"context"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

type nativeRuntimeCatalogEnvelopeLoader interface {
	Load(context.Context, installplanapp.RuntimeEvidenceRequest) (nativeRuntimeCatalogEnvelope, error)
}

type nativeVerifiedRuntimeCatalog struct {
	runtime        runtimeinstall.CertifiedRuntime
	manifestDigest runtimecatalog.Digest
	verified       runtimecatalogapp.VerifiedCatalog
}

type nativeRuntimeCatalogPolicyVerifier interface {
	VerifyRuntimeCatalog(
		context.Context,
		installplanapp.RuntimeEvidenceRequest,
		nativeRuntimeCatalogEnvelope,
	) (nativeVerifiedRuntimeCatalog, error)
}

type nativeRuntimeObservationResolver interface {
	ObserveRuntime(
		context.Context,
		installplanapp.RuntimeEvidenceRequest,
		runtimecatalogapp.VerifiedCatalog,
		runtimeinstall.CertifiedRuntime,
	) (runtimeinstall.HostCapabilities, runtimeinstall.RuntimeDiscovery, install.Digest, error)
}

// nativeRuntimeEvidenceResolver is the sole bridge from authenticated parent
// evidence to a persisted PF-006 runtime plan.
type nativeRuntimeEvidenceResolver struct {
	loader       nativeRuntimeCatalogEnvelopeLoader
	catalog      nativeRuntimeCatalogPolicyVerifier
	observations nativeRuntimeObservationResolver
}

func newNativeRuntimeEvidenceResolver(
	loader nativeRuntimeCatalogEnvelopeLoader,
	catalog nativeRuntimeCatalogPolicyVerifier,
	observations nativeRuntimeObservationResolver,
) (*nativeRuntimeEvidenceResolver, error) {
	if nilAny(loader) || nilAny(catalog) || nilAny(observations) {
		return nil, errNativeInstallerIntegrity
	}
	return &nativeRuntimeEvidenceResolver{loader: loader, catalog: catalog, observations: observations}, nil
}

func (r *nativeRuntimeEvidenceResolver) ResolveRuntimeEvidence(
	ctx context.Context,
	request installplanapp.RuntimeEvidenceRequest,
) (installplanapp.RuntimeEvidence, error) {
	if r == nil || ctx == nil || nilAny(r.loader) || nilAny(r.catalog) || nilAny(r.observations) ||
		request.OperationID.IsZero() || request.ParentPlanDigest.IsZero() || !request.SignedHostPlan.Valid() ||
		request.HostEvidenceDigest.IsZero() || request.HostStorageTarget == "" || request.RuntimeEndpoint == "" {
		return installplanapp.RuntimeEvidence{}, installplanapp.ErrRuntimeEvidenceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return installplanapp.RuntimeEvidence{}, err
	}
	envelope, err := r.loader.Load(ctx, request)
	if err != nil || envelope.ResourceDigest.IsZero() {
		return installplanapp.RuntimeEvidence{}, installplanapp.ErrRuntimeEvidenceUnavailable
	}
	verified, err := r.catalog.VerifyRuntimeCatalog(ctx, request, envelope)
	if err != nil || verified.runtime.CatalogDigest().IsZero() || verified.manifestDigest.IsZero() ||
		!runtimecatalog.Digest(verified.runtime.CatalogDigest()).Equal(verified.manifestDigest) {
		return installplanapp.RuntimeEvidence{}, installplanapp.ErrRuntimeEvidenceUnavailable
	}
	host, discovery, discoveryEvidence, err := r.observations.ObserveRuntime(
		ctx, request, verified.verified, verified.runtime,
	)
	if err != nil || discoveryEvidence.IsZero() {
		return installplanapp.RuntimeEvidence{}, installplanapp.ErrRuntimeEvidenceUnavailable
	}
	signedCatalogEvidence, err := install.ParseDigest(verified.manifestDigest.Hex())
	if err != nil {
		return installplanapp.RuntimeEvidence{}, installplanapp.ErrRuntimeEvidenceUnavailable
	}
	evidence, err := installplanapp.NewRuntimeEvidence(
		host, discovery, verified.runtime, request.HostEvidenceDigest, discoveryEvidence,
		envelope.ResourceDigest, signedCatalogEvidence,
	)
	if err != nil {
		return installplanapp.RuntimeEvidence{}, installplanapp.ErrRuntimeEvidenceUnavailable
	}
	return evidence, nil
}

type nativeRuntimeCatalogPolicy struct {
	clock     runtimecatalogapp.Clock
	signature runtimecatalogapp.ManifestSignatureVerifier
	publisher runtimecatalogapp.NativePublisherVerifier
	anchors   runtimecatalogapp.AntiRollbackRepository
}

func newNativeRuntimeCatalogPolicy(
	clock runtimecatalogapp.Clock,
	signature runtimecatalogapp.ManifestSignatureVerifier,
	publisher runtimecatalogapp.NativePublisherVerifier,
	anchors runtimecatalogapp.AntiRollbackRepository,
) (*nativeRuntimeCatalogPolicy, error) {
	policy := &nativeRuntimeCatalogPolicy{clock: clock, signature: signature, publisher: publisher, anchors: anchors}
	if nilAny(clock) || nilAny(signature) || nilAny(publisher) || nilAny(anchors) {
		return nil, errNativeInstallerIntegrity
	}
	return policy, nil
}

func (p *nativeRuntimeCatalogPolicy) VerifyRuntimeCatalog(
	ctx context.Context,
	request installplanapp.RuntimeEvidenceRequest,
	envelope nativeRuntimeCatalogEnvelope,
) (nativeVerifiedRuntimeCatalog, error) {
	if p == nil || ctx == nil || !request.SignedHostPlan.Valid() || request.HostEvidenceDigest.IsZero() ||
		!envelope.Signed.Valid() || envelope.ResourceDigest.IsZero() || nilAny(p.clock) || nilAny(p.signature) ||
		nilAny(p.publisher) || nilAny(p.anchors) {
		return nativeVerifiedRuntimeCatalog{}, installplanapp.ErrRuntimeEvidenceUnavailable
	}
	host, err := runtimeprovision.NewCertifiedCatalogHostProvider(request.SignedHostPlan, request.HostEvidenceDigest)
	if err != nil {
		return nativeVerifiedRuntimeCatalog{}, installplanapp.ErrRuntimeEvidenceUnavailable
	}
	application, err := runtimecatalogapp.NewApplication(runtimecatalogapp.Dependencies{
		Clock: p.clock, Host: host, Signature: p.signature, NativePublisher: p.publisher, AntiRollback: p.anchors,
	})
	if err != nil {
		return nativeVerifiedRuntimeCatalog{}, installplanapp.ErrRuntimeEvidenceUnavailable
	}
	manifest := envelope.Signed.Manifest()
	mode, source, err := nativeRuntimeCatalogSourceSelection(manifest)
	if err != nil {
		return nativeVerifiedRuntimeCatalog{}, installplanapp.ErrRuntimeEvidenceUnavailable
	}
	verified, err := application.Verify(ctx, runtimecatalogapp.Request{
		SignedManifest: envelope.Signed, ExpectedManifestDigest: manifest.Digest(),
		SourceMode: mode, OnlineSource: source,
	})
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nativeVerifiedRuntimeCatalog{}, err
		}
		return nativeVerifiedRuntimeCatalog{}, installplanapp.ErrRuntimeEvidenceUnavailable
	}
	certified, err := verified.CertifiedRuntime()
	if err != nil {
		return nativeVerifiedRuntimeCatalog{}, installplanapp.ErrRuntimeEvidenceUnavailable
	}
	return nativeVerifiedRuntimeCatalog{
		runtime: certified, manifestDigest: verified.ManifestDigest(), verified: verified,
	}, nil
}

func nativeRuntimeCatalogSourceSelection(
	manifest runtimecatalog.Manifest,
) (runtimecatalog.SourceMode, runtimecatalog.SourceLocation, error) {
	if !manifest.Valid() {
		return runtimecatalog.SourceModeUnknown, runtimecatalog.SourceLocation{}, errors.New("runtime catalog is invalid")
	}
	artifact := manifest.Artifact()
	if artifact.OfflinePolicy() == runtimecatalog.OfflinePolicyBundled && artifact.RedistributionPermitted() {
		return runtimecatalog.SourceModeOfflineBundle, runtimecatalog.SourceLocation{}, nil
	}
	sources := artifact.Sources()
	if len(sources) == 0 {
		return runtimecatalog.SourceModeUnknown, runtimecatalog.SourceLocation{}, errors.New("runtime source is unavailable")
	}
	return runtimecatalog.SourceModeOnline, sources[0], nil
}

var (
	_ installplanapp.RuntimeEvidenceResolver = (*nativeRuntimeEvidenceResolver)(nil)
	_ nativeRuntimeCatalogPolicyVerifier     = (*nativeRuntimeCatalogPolicy)(nil)
)
