package runtimeprovision

import (
	"context"
	"errors"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
)

// LinuxHostBindingProvider observes invocation and machine identity without
// receiving any package, source, publisher, or command authority.
type LinuxHostBindingProvider interface {
	CurrentLinuxHostBinding(context.Context) (runtimecatalogapp.LinuxHostBinding, error)
}

type linuxAuthorityProjector interface {
	ProjectLinuxAuthority([]byte, runtimecatalogapp.LinuxHostBinding) (runtimeport.LinuxAuthority, error)
}

type verifiedCatalogLinuxProjector struct {
	catalog runtimecatalogapp.VerifiedCatalog
}

func (p verifiedCatalogLinuxProjector) ProjectLinuxAuthority(
	canonicalPlan []byte,
	host runtimecatalogapp.LinuxHostBinding,
) (runtimeport.LinuxAuthority, error) {
	return p.catalog.LinuxAuthority(canonicalPlan, host)
}

// CatalogLinuxAuthorityResolver joins one verified catalog cell to the native
// invocation identity for each resolution. It never decodes an unsigned
// execution projection supplied by an inbound caller.
type CatalogLinuxAuthorityResolver struct {
	projector linuxAuthorityProjector
	host      LinuxHostBindingProvider
}

// NewCatalogLinuxAuthorityResolver constructs the production PF-006 resolver.
func NewCatalogLinuxAuthorityResolver(
	catalog runtimecatalogapp.VerifiedCatalog,
	host LinuxHostBindingProvider,
) (*CatalogLinuxAuthorityResolver, error) {
	if !catalog.Manifest().Valid() || catalog.VerifiedAt().IsZero() ||
		catalog.VerifiedAt().Location() != time.UTC || nilDependency(host) {
		return nil, errors.New("verified Linux runtime authority dependencies are required")
	}
	if _, present := catalog.Manifest().LinuxExecution(); !present {
		return nil, errors.New("verified catalog does not contain Linux execution authority")
	}
	return newCatalogLinuxAuthorityResolver(verifiedCatalogLinuxProjector{catalog: catalog}, host)
}

func newCatalogLinuxAuthorityResolver(
	projector linuxAuthorityProjector,
	host LinuxHostBindingProvider,
) (*CatalogLinuxAuthorityResolver, error) {
	if nilDependency(projector) || nilDependency(host) {
		return nil, errors.New("verified Linux runtime authority dependencies are required")
	}
	return &CatalogLinuxAuthorityResolver{projector: projector, host: host}, nil
}

// ResolveLinuxAuthority resolves only the exact canonical plan supplied by the
// PF-006 application. Host-bound failures remain closed and privacy-safe.
func (r *CatalogLinuxAuthorityResolver) ResolveLinuxAuthority(
	ctx context.Context,
	canonicalPlan []byte,
) (runtimeport.LinuxAuthority, error) {
	if r == nil || ctx == nil || nilDependency(r.projector) || nilDependency(r.host) {
		return runtimeport.LinuxAuthority{}, runtimeport.ErrAuthorityUnavailable
	}
	if err := ctx.Err(); err != nil {
		return runtimeport.LinuxAuthority{}, err
	}
	host, err := r.host.CurrentLinuxHostBinding(ctx)
	if err != nil {
		if contextError := ctx.Err(); contextError != nil {
			return runtimeport.LinuxAuthority{}, contextError
		}
		return runtimeport.LinuxAuthority{}, runtimeport.ErrAuthorityUnavailable
	}
	authority, err := r.projector.ProjectLinuxAuthority(canonicalPlan, host)
	if err != nil {
		if errors.Is(err, runtimeport.ErrAuthorityUnavailable) {
			return runtimeport.LinuxAuthority{}, err
		}
		return runtimeport.LinuxAuthority{}, runtimeport.ErrAuthorityInvalid
	}
	return authority, nil
}

var _ runtimeport.AuthorityResolver = (*CatalogLinuxAuthorityResolver)(nil)
