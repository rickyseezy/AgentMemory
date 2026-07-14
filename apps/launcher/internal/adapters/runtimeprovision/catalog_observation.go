package runtimeprovision

import (
	"context"
	"errors"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

// CatalogPublisherTrustResolver returns the independently embedded native
// certificate/key digest for an already verified publisher tuple.
type CatalogPublisherTrustResolver interface {
	NativeTrustDigest(runtimecatalog.PublisherPolicy) (runtimecatalog.Digest, error)
}

// CatalogObservationInput is immutable authority for a native read-only probe.
type CatalogObservationInput struct {
	Catalog              runtimecatalogapp.VerifiedCatalog
	CertifiedRuntime     runtimeinstall.CertifiedRuntime
	HostStorageTarget    string
	RuntimeEndpoint      string
	NativePublisherTrust runtimecatalog.Digest
}

// CatalogObservationResult binds exact host/runtime facts to native evidence.
type CatalogObservationResult struct {
	Host      runtimeinstall.HostCapabilities
	Discovery runtimeinstall.RuntimeDiscovery
	Evidence  runtimeinstall.Hash
}

type catalogObservationBackend interface {
	ObserveCatalogRuntime(context.Context, CatalogObservationInput) (CatalogObservationResult, error)
}

// NativeCatalogObserver joins independently embedded publisher trust to the
// build-tag-selected native observation backend.
type NativeCatalogObserver struct {
	publishers CatalogPublisherTrustResolver
	backend    catalogObservationBackend
}

// NewNativeCatalogObserver constructs the production platform observer.
func NewNativeCatalogObserver(publishers CatalogPublisherTrustResolver) (*NativeCatalogObserver, error) {
	return newNativeCatalogObserver(publishers, newNativeCatalogObservationBackend())
}

func newNativeCatalogObserver(
	publishers CatalogPublisherTrustResolver,
	backend catalogObservationBackend,
) (*NativeCatalogObserver, error) {
	if nilDependency(publishers) || nilDependency(backend) {
		return nil, ErrProvisionIntegrity
	}
	return &NativeCatalogObserver{publishers: publishers, backend: backend}, nil
}

// ObserveRuntime implements the infrastructure observation port without
// accepting paths, endpoints, publishers, or versions from an inbound caller.
func (o *NativeCatalogObserver) ObserveRuntime(
	ctx context.Context,
	request installplanapp.RuntimeEvidenceRequest,
	catalog runtimecatalogapp.VerifiedCatalog,
	certified runtimeinstall.CertifiedRuntime,
) (runtimeinstall.HostCapabilities, runtimeinstall.RuntimeDiscovery, install.Digest, error) {
	if o == nil || ctx == nil || nilDependency(o.publishers) || nilDependency(o.backend) ||
		!catalog.Manifest().Valid() || catalog.VerifiedAt().IsZero() || catalog.VerifiedAt().Location() != time.UTC ||
		certified.CatalogDigest().IsZero() || runtimecatalog.Digest(certified.CatalogDigest()) != catalog.ManifestDigest() ||
		request.OperationID.IsZero() || request.ParentPlanDigest.IsZero() || !request.SignedHostPlan.Valid() ||
		request.HostEvidenceDigest.IsZero() ||
		request.HostStorageTarget == "" || request.RuntimeEndpoint == "" {
		return runtimeinstall.HostCapabilities{}, runtimeinstall.RuntimeDiscovery{}, install.Digest{}, ErrProvisionIntegrity
	}
	if err := ctx.Err(); err != nil {
		return runtimeinstall.HostCapabilities{}, runtimeinstall.RuntimeDiscovery{}, install.Digest{}, err
	}
	trust, err := o.publishers.NativeTrustDigest(catalog.Manifest().Artifact().Publisher())
	if err != nil || trust.IsZero() {
		return runtimeinstall.HostCapabilities{}, runtimeinstall.RuntimeDiscovery{}, install.Digest{}, ErrProvisionIntegrity
	}
	result, err := o.backend.ObserveCatalogRuntime(ctx, CatalogObservationInput{
		Catalog: catalog, CertifiedRuntime: certified, HostStorageTarget: request.HostStorageTarget,
		RuntimeEndpoint: request.RuntimeEndpoint, NativePublisherTrust: trust,
	})
	if err != nil || result.Evidence.IsZero() {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return runtimeinstall.HostCapabilities{}, runtimeinstall.RuntimeDiscovery{}, install.Digest{}, err
		}
		return runtimeinstall.HostCapabilities{}, runtimeinstall.RuntimeDiscovery{}, install.Digest{}, ErrProbeFailed
	}
	if _, err := runtimeinstall.NewPlanV1(result.Host, result.Discovery, certified); err != nil {
		return runtimeinstall.HostCapabilities{}, runtimeinstall.RuntimeDiscovery{}, install.Digest{}, ErrProbeFailed
	}
	evidence, err := install.ParseDigest(result.Evidence.String())
	if err != nil {
		return runtimeinstall.HostCapabilities{}, runtimeinstall.RuntimeDiscovery{}, install.Digest{}, ErrProbeFailed
	}
	return result.Host, result.Discovery, evidence, nil
}

var _ interface {
	ObserveRuntime(context.Context, installplanapp.RuntimeEvidenceRequest, runtimecatalogapp.VerifiedCatalog, runtimeinstall.CertifiedRuntime) (runtimeinstall.HostCapabilities, runtimeinstall.RuntimeDiscovery, install.Digest, error)
} = (*NativeCatalogObserver)(nil)
