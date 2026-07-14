package runtimeprovision

import (
	"context"
	"errors"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
)

// DesktopHostBindingProvider observes the current native principal, machine,
// home, endpoint, and operation-owned artifact path without receiving command
// or publisher authority from an inbound caller.
type DesktopHostBindingProvider interface {
	CurrentDesktopHostBinding(
		context.Context,
		runtimecatalog.Digest,
		string,
	) (runtimecatalogapp.DesktopHostBinding, error)
}

type desktopAuthorityProjector interface {
	ProjectDesktopAuthority(
		[]byte,
		runtimecatalogapp.DesktopHostBinding,
		runtimecatalog.Digest,
	) (runtimeport.DesktopAuthority, error)
}

type verifiedCatalogDesktopProjector struct {
	catalog runtimecatalogapp.VerifiedCatalog
}

func (p verifiedCatalogDesktopProjector) ProjectDesktopAuthority(
	canonicalPlan []byte,
	host runtimecatalogapp.DesktopHostBinding,
	nativeTrust runtimecatalog.Digest,
) (runtimeport.DesktopAuthority, error) {
	return p.catalog.DesktopAuthority(canonicalPlan, host, nativeTrust)
}

// CatalogDesktopAuthorityResolver joins a verified desktop catalog to current
// native identity and independently embedded publisher trust on every phase.
type CatalogDesktopAuthorityResolver struct {
	projector desktopAuthorityProjector
	host      DesktopHostBindingProvider
	trust     CatalogPublisherTrustResolver
	publisher runtimecatalog.PublisherPolicy
	catalog   runtimecatalog.Digest
	artifact  string
}

// NewCatalogDesktopAuthorityResolver constructs the production desktop
// authority resolver. The catalog cannot self-authorize its signer digest.
func NewCatalogDesktopAuthorityResolver(
	catalog runtimecatalogapp.VerifiedCatalog,
	host DesktopHostBindingProvider,
	trust CatalogPublisherTrustResolver,
) (*CatalogDesktopAuthorityResolver, error) {
	manifest := catalog.Manifest()
	if !manifest.Valid() || catalog.VerifiedAt().IsZero() || catalog.VerifiedAt().Location() != time.UTC ||
		nilDependency(host) || nilDependency(trust) {
		return nil, errors.New("verified desktop runtime authority dependencies are required")
	}
	execution, present := manifest.DesktopExecution()
	if !present {
		return nil, errors.New("verified catalog does not contain desktop execution authority")
	}
	return newCatalogDesktopAuthorityResolver(
		verifiedCatalogDesktopProjector{catalog: catalog}, host, trust, manifest.Artifact().Publisher(),
		manifest.Digest(), execution.ArtifactFileName(),
	)
}

func newCatalogDesktopAuthorityResolver(
	projector desktopAuthorityProjector,
	host DesktopHostBindingProvider,
	trust CatalogPublisherTrustResolver,
	publisher runtimecatalog.PublisherPolicy,
	catalog runtimecatalog.Digest,
	artifact string,
) (*CatalogDesktopAuthorityResolver, error) {
	if nilDependency(projector) || nilDependency(host) || nilDependency(trust) ||
		!validDesktopCatalogPublisher(publisher) || catalog.IsZero() || artifact == "" {
		return nil, errors.New("verified desktop runtime authority dependencies are required")
	}
	return &CatalogDesktopAuthorityResolver{
		projector: projector, host: host, trust: trust, publisher: publisher,
		catalog: catalog, artifact: artifact,
	}, nil
}

// ResolveDesktopAuthority accepts only canonical PF-006 plan bytes. Native
// binding and signer failures are deliberately collapsed to public errors.
func (r *CatalogDesktopAuthorityResolver) ResolveDesktopAuthority(
	ctx context.Context,
	canonicalPlan []byte,
) (runtimeport.DesktopAuthority, error) {
	if r == nil || ctx == nil || nilDependency(r.projector) || nilDependency(r.host) ||
		nilDependency(r.trust) || !validDesktopCatalogPublisher(r.publisher) || r.catalog.IsZero() || r.artifact == "" {
		return runtimeport.DesktopAuthority{}, runtimeport.ErrDesktopAuthorityUnavailable
	}
	if err := ctx.Err(); err != nil {
		return runtimeport.DesktopAuthority{}, err
	}
	host, err := r.host.CurrentDesktopHostBinding(ctx, r.catalog, r.artifact)
	if err != nil {
		if contextError := ctx.Err(); contextError != nil {
			return runtimeport.DesktopAuthority{}, contextError
		}
		return runtimeport.DesktopAuthority{}, runtimeport.ErrDesktopAuthorityUnavailable
	}
	nativeTrust, err := r.trust.NativeTrustDigest(r.publisher)
	if err != nil || nativeTrust.IsZero() {
		return runtimeport.DesktopAuthority{}, runtimeport.ErrDesktopAuthorityUnavailable
	}
	authority, err := r.projector.ProjectDesktopAuthority(canonicalPlan, host, nativeTrust)
	if err != nil {
		if errors.Is(err, runtimeport.ErrDesktopAuthorityUnavailable) {
			return runtimeport.DesktopAuthority{}, err
		}
		return runtimeport.DesktopAuthority{}, runtimeport.ErrDesktopAuthorityIntegrity
	}
	return authority, nil
}

func validDesktopCatalogPublisher(publisher runtimecatalog.PublisherPolicy) bool {
	verification := publisher.Verification()
	if verification != runtimecatalog.NativeVerificationAppleNotarized &&
		verification != runtimecatalog.NativeVerificationAuthenticode {
		return false
	}
	return validRuntimePublisherIdentity(runtimePublisherIdentity{
		verification: verification, identity: publisher.Identity(),
		signingKeyIdentity: publisher.SigningKeyIdentity(), packageIdentity: publisher.PackageIdentity(),
	})
}

var _ runtimeport.DesktopAuthorityResolver = (*CatalogDesktopAuthorityResolver)(nil)
