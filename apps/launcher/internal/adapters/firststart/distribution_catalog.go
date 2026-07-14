package firststart

import (
	"context"
	"errors"
	"reflect"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/firststartapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

type verifiedDistributionCatalog interface {
	Current(context.Context) (releaseverify.VerifiedBootstrapTemplate, error)
	Exact(context.Context, releaseinventory.Digest) (releaseverify.VerifiedBootstrapTemplate, error)
}

// DistributionTemplateCatalog narrows the release-verified outer catalog to
// the first-start adapter contract without allowing callers to construct a
// PackagedTemplate from an arbitrary manifest resource.
type DistributionTemplateCatalog struct{ catalog verifiedDistributionCatalog }

// NewDistributionTemplateCatalog rejects partial and typed-nil composition.
func NewDistributionTemplateCatalog(catalog verifiedDistributionCatalog) (*DistributionTemplateCatalog, error) {
	if nilDistributionCatalog(catalog) {
		return nil, firststartapp.ErrIntegrity
	}
	return &DistributionTemplateCatalog{catalog: catalog}, nil
}

// Current returns only a release-verified, reauthenticated packaged template.
func (c *DistributionTemplateCatalog) Current(ctx context.Context) (PackagedTemplate, error) {
	if c == nil || ctx == nil || nilDistributionCatalog(c.catalog) {
		return PackagedTemplate{}, firststartapp.ErrIntegrity
	}
	template, err := c.catalog.Current(ctx)
	return packagedDistributionTemplate(template, err)
}

// Exact delegates the no-fall-forward digest to the verified catalog.
func (c *DistributionTemplateCatalog) Exact(
	ctx context.Context,
	digest releaseinventory.Digest,
) (PackagedTemplate, error) {
	if c == nil || ctx == nil || digest.IsZero() || nilDistributionCatalog(c.catalog) {
		return PackagedTemplate{}, firststartapp.ErrIntegrity
	}
	template, err := c.catalog.Exact(ctx, digest)
	return packagedDistributionTemplate(template, err)
}

func packagedDistributionTemplate(
	template releaseverify.VerifiedBootstrapTemplate,
	err error,
) (PackagedTemplate, error) {
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return PackagedTemplate{}, err
		}
		if errors.Is(err, releaseverify.ErrBootstrapCatalogIntegrity) {
			return PackagedTemplate{}, firststartapp.ErrIntegrity
		}
		return PackagedTemplate{}, firststartapp.ErrUnavailable
	}
	if !template.Valid() {
		return PackagedTemplate{}, firststartapp.ErrIntegrity
	}
	return NewPackagedTemplate(template.Resource(), template.CanonicalPlan())
}

func nilDistributionCatalog(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Every non-nilable concrete kind is a valid catalog.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ VerifiedTemplateCatalog = (*DistributionTemplateCatalog)(nil)
