package firststart

import (
	"context"
	"errors"
	"reflect"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/firststartapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

const maximumInstallPlanTemplateBytes = 16 << 20

// PackagedTemplate is one exact install-plan template resource selected from
// an already verified release inventory. NewPackagedTemplate repeats the
// resource digest and length checks at this use boundary so a catalog cannot
// substitute bytes after release verification.
type PackagedTemplate struct {
	resource releaseinventory.Resource
	template firststartapp.Template
}

// NewPackagedTemplate binds verified release metadata to exact template bytes.
// Production callers may pass only a resource selected from releaseverify's
// closed VerifiedInventory; accepting an arbitrary manifest resource is not a
// production composition authority.
func NewPackagedTemplate(
	resource releaseinventory.Resource,
	canonical []byte,
) (PackagedTemplate, error) {
	if resource.Kind() != releaseinventory.ResourceKindInstallPlanTemplate ||
		resource.Purpose() != releaseinventory.ResourcePurposeInstallPlanTemplate ||
		resource.MediaType() != releaseinventory.MediaTypeInstallPlanTemplate ||
		resource.Platform().IsAny() || resource.Size() == 0 ||
		resource.Size() > maximumInstallPlanTemplateBytes || uint64(len(canonical)) != resource.Size() ||
		!releaseinventory.DigestBytes(canonical).Equal(resource.Digest()) {
		return PackagedTemplate{}, firststartapp.ErrIntegrity
	}
	template, err := firststartapp.NewTemplate(canonical)
	if err != nil || template.Digest().String() != resource.Digest().Hex() {
		return PackagedTemplate{}, firststartapp.ErrIntegrity
	}
	return PackagedTemplate{resource: resource, template: template}, nil
}

// Template returns an immutable exact-template authority.
func (p PackagedTemplate) Template() firststartapp.Template { return p.template }

// Resource returns the signed release descriptor used for this template.
func (p PackagedTemplate) Resource() releaseinventory.Resource { return p.resource }

// Valid reauthenticates the resource-to-template binding.
func (p PackagedTemplate) Valid() bool {
	if !p.template.Valid() {
		return false
	}
	canonical := p.template.Canonical()
	return p.resource.Kind() == releaseinventory.ResourceKindInstallPlanTemplate &&
		p.resource.Purpose() == releaseinventory.ResourcePurposeInstallPlanTemplate &&
		p.resource.MediaType() == releaseinventory.MediaTypeInstallPlanTemplate &&
		!p.resource.Platform().IsAny() && p.resource.Size() == uint64(len(canonical)) &&
		p.resource.Size() <= maximumInstallPlanTemplateBytes &&
		releaseinventory.DigestBytes(canonical).Equal(p.resource.Digest()) &&
		p.template.Digest().String() == p.resource.Digest().Hex()
}

// VerifiedTemplateCatalog retains every template selected by a durable
// preparation. Its production implementation must first run the complete
// release verifier and select the install-plan resource from VerifiedInventory.
type VerifiedTemplateCatalog interface {
	Current(context.Context) (PackagedTemplate, error)
	Exact(context.Context, releaseinventory.Digest) (PackagedTemplate, error)
}

// VerifiedTemplateSource adapts a retained verified release catalog to the
// pristine-start application port.
type VerifiedTemplateSource struct{ catalog VerifiedTemplateCatalog }

// NewVerifiedTemplateSource rejects partial and typed-nil composition.
func NewVerifiedTemplateSource(catalog VerifiedTemplateCatalog) (*VerifiedTemplateSource, error) {
	if nilTemplateCatalog(catalog) {
		return nil, firststartapp.ErrIntegrity
	}
	return &VerifiedTemplateSource{catalog: catalog}, nil
}

// Current returns the current verified template without granting authority to
// fall forward after a preparation has persisted its exact digest.
func (s *VerifiedTemplateSource) Current(ctx context.Context) (firststartapp.Template, error) {
	if s == nil || ctx == nil || nilTemplateCatalog(s.catalog) {
		return firststartapp.Template{}, firststartapp.ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return firststartapp.Template{}, err
	}
	packaged, err := s.catalog.Current(ctx)
	return validatedTemplate(packaged, install.PlanDigest{}, err)
}

// Exact resolves only the retained resource whose SHA-256 equals the durable
// preparation digest.
func (s *VerifiedTemplateSource) Exact(
	ctx context.Context,
	digest install.PlanDigest,
) (firststartapp.Template, error) {
	if s == nil || ctx == nil || digest.IsZero() || nilTemplateCatalog(s.catalog) {
		return firststartapp.Template{}, firststartapp.ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return firststartapp.Template{}, err
	}
	resourceDigest, err := releaseinventory.ParseDigest(digest.String())
	if err != nil {
		return firststartapp.Template{}, firststartapp.ErrIntegrity
	}
	packaged, err := s.catalog.Exact(ctx, resourceDigest)
	return validatedTemplate(packaged, digest, err)
}

func validatedTemplate(
	packaged PackagedTemplate,
	expected install.PlanDigest,
	err error,
) (firststartapp.Template, error) {
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return firststartapp.Template{}, err
		}
		if errors.Is(err, firststartapp.ErrIntegrity) {
			return firststartapp.Template{}, firststartapp.ErrIntegrity
		}
		return firststartapp.Template{}, firststartapp.ErrUnavailable
	}
	if !packaged.Valid() || (!expected.IsZero() && !packaged.Template().Digest().Equal(expected)) {
		return firststartapp.Template{}, firststartapp.ErrIntegrity
	}
	return packaged.Template(), nil
}

func nilTemplateCatalog(value any) bool {
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

var _ firststartapp.VerifiedTemplateSource = (*VerifiedTemplateSource)(nil)
