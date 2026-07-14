package releaseverify

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"reflect"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/installplan"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

const maximumBootstrapCatalogResourceBytes = 32 * 1024 * 1024

var (
	// ErrBootstrapCatalogIntegrity rejects substitution, ambiguity, or a
	// product manifest that escaped the verified outer catalog.
	ErrBootstrapCatalogIntegrity = errors.New("bootstrap catalog integrity violation")
	// ErrBootstrapCatalogUnavailable sanitizes local retained-content failures.
	ErrBootstrapCatalogUnavailable = errors.New("bootstrap catalog unavailable")
)

// BootstrapCatalogSource opens exact retained bytes from the already verified
// outer distribution catalog.
type BootstrapCatalogSource interface {
	OpenResource(context.Context, releaseinventory.Resource) (io.ReadCloser, error)
}

// VerifiedBootstrapTemplate is emitted only after the outer inventory,
// separately encoded product manifest, and embedded plan authority all agree.
type VerifiedBootstrapTemplate struct {
	resource     releaseinventory.Resource
	canonical    []byte
	product      releaseinventory.SignedManifest
	distribution releaseinventory.Digest
}

// Resource returns the verified outer descriptor.
func (v VerifiedBootstrapTemplate) Resource() releaseinventory.Resource { return v.resource }

// CanonicalPlan returns caller-owned template bytes.
func (v VerifiedBootstrapTemplate) CanonicalPlan() []byte {
	return append([]byte(nil), v.canonical...)
}

// ProductManifest returns the independently signed inner product manifest.
func (v VerifiedBootstrapTemplate) ProductManifest() releaseinventory.SignedManifest {
	return v.product
}

// DistributionManifestDigest returns the outer catalog binding.
func (v VerifiedBootstrapTemplate) DistributionManifestDigest() releaseinventory.Digest {
	return v.distribution
}

// Valid reauthenticates every immutable cross-manifest binding.
func (v VerifiedBootstrapTemplate) Valid() bool {
	if v.resource.Kind() != releaseinventory.ResourceKindInstallPlanTemplate ||
		v.resource.Purpose() != releaseinventory.ResourcePurposeInstallPlanTemplate ||
		v.resource.MediaType() != releaseinventory.MediaTypeInstallPlanTemplate ||
		v.resource.Platform().IsAny() || v.distribution.IsZero() ||
		v.resource.Size() != uint64(len(v.canonical)) ||
		!releaseinventory.DigestBytes(v.canonical).Equal(v.resource.Digest()) {
		return false
	}
	plan, err := installplan.DecodeV1(v.canonical)
	if err != nil {
		return false
	}
	encoded, err := releaseinventory.EncodeSignedManifestV1(plan.SignedRelease())
	if err != nil {
		return false
	}
	expected, err := releaseinventory.EncodeSignedManifestV1(v.product)
	return err == nil && string(encoded) == string(expected)
}

// BootstrapCatalog resolves one exact platform template from a fully verified
// outer distribution inventory.
type BootstrapCatalog struct{ source BootstrapCatalogSource }

// NewBootstrapCatalog refuses partial or typed-nil composition.
func NewBootstrapCatalog(source BootstrapCatalogSource) (*BootstrapCatalog, error) {
	if nilBootstrapCatalogCapability(source) {
		return nil, ErrBootstrapCatalogIntegrity
	}
	return &BootstrapCatalog{source: source}, nil
}

// Resolve proves the two-level catalog without trusting a hand-built resource.
func (c *BootstrapCatalog) Resolve(
	ctx context.Context,
	inventory VerifiedInventory,
	distribution releaseinventory.SignedManifest,
) (VerifiedBootstrapTemplate, error) {
	if c == nil || ctx == nil || nilBootstrapCatalogCapability(c.source) {
		return VerifiedBootstrapTemplate{}, ErrBootstrapCatalogIntegrity
	}
	if err := ctx.Err(); err != nil {
		return VerifiedBootstrapTemplate{}, err
	}
	outer := distribution.Manifest()
	if inventory.ReleaseID() == "" || inventory.Sequence() == 0 || !inventory.Platform().Valid() ||
		outer.ReleaseID() != inventory.ReleaseID() || outer.Sequence() != inventory.Sequence() ||
		!outer.Digest().Equal(inventory.ManifestDigest()) {
		return VerifiedBootstrapTemplate{}, ErrBootstrapCatalogIntegrity
	}
	resources, err := outer.ResourcesFor(inventory.Platform())
	if err != nil {
		return VerifiedBootstrapTemplate{}, ErrBootstrapCatalogIntegrity
	}
	templateResource, productResource, err := selectBootstrapResources(resources, inventory.Platform())
	if err != nil || !inventoryAuthorizes(inventory, templateResource) ||
		!inventoryAuthorizes(inventory, productResource) {
		return VerifiedBootstrapTemplate{}, ErrBootstrapCatalogIntegrity
	}
	templateRaw, err := readBootstrapCatalogResource(ctx, c.source, templateResource)
	if err != nil {
		return VerifiedBootstrapTemplate{}, err
	}
	productRaw, err := readBootstrapCatalogResource(ctx, c.source, productResource)
	if err != nil {
		return VerifiedBootstrapTemplate{}, err
	}
	product, err := releaseinventory.DecodeSignedManifestV1(productRaw)
	if err != nil || product.Manifest().Digest().Equal(outer.Digest()) ||
		!productResourcesAuthorized(inventory, product.Manifest(), inventory.Platform()) {
		return VerifiedBootstrapTemplate{}, ErrBootstrapCatalogIntegrity
	}
	plan, err := installplan.DecodeV1(templateRaw)
	if err != nil {
		return VerifiedBootstrapTemplate{}, ErrBootstrapCatalogIntegrity
	}
	embedded, err := releaseinventory.EncodeSignedManifestV1(plan.SignedRelease())
	if err != nil || string(embedded) != string(productRaw) {
		return VerifiedBootstrapTemplate{}, ErrBootstrapCatalogIntegrity
	}
	verified := VerifiedBootstrapTemplate{
		resource: templateResource, canonical: append([]byte(nil), templateRaw...),
		product: product, distribution: outer.Digest(),
	}
	if !verified.Valid() {
		return VerifiedBootstrapTemplate{}, ErrBootstrapCatalogIntegrity
	}
	return verified, nil
}

func selectBootstrapResources(
	resources []releaseinventory.Resource,
	platform releaseinventory.Platform,
) (releaseinventory.Resource, releaseinventory.Resource, error) {
	var template releaseinventory.Resource
	var product releaseinventory.Resource
	for _, resource := range resources {
		switch resource.Kind() {
		case releaseinventory.ResourceKindInstallPlanTemplate:
			if template.ID() != "" || resource.Platform() != platform {
				return releaseinventory.Resource{}, releaseinventory.Resource{}, ErrBootstrapCatalogIntegrity
			}
			template = resource
		case releaseinventory.ResourceKindProductManifest:
			if product.ID() != "" || (!resource.Platform().IsAny() && resource.Platform() != platform) {
				return releaseinventory.Resource{}, releaseinventory.Resource{}, ErrBootstrapCatalogIntegrity
			}
			product = resource
		default:
		}
	}
	if template.ID() == "" || product.ID() == "" {
		return releaseinventory.Resource{}, releaseinventory.Resource{}, ErrBootstrapCatalogIntegrity
	}
	return template, product, nil
}

func inventoryAuthorizes(inventory VerifiedInventory, resource releaseinventory.Resource) bool {
	verified, exists := inventory.Resource(resource.ID())
	return exists && verified.Authorizes(resource)
}

func productResourcesAuthorized(
	inventory VerifiedInventory,
	manifest releaseinventory.Manifest,
	platform releaseinventory.Platform,
) bool {
	resources, err := manifest.ResourcesFor(platform)
	if err != nil {
		return false
	}
	for _, resource := range resources {
		if resource.Kind() == releaseinventory.ResourceKindInstallPlanTemplate ||
			resource.Kind() == releaseinventory.ResourceKindProductManifest ||
			!inventoryAuthorizes(inventory, resource) {
			return false
		}
	}
	return true
}

func readBootstrapCatalogResource(
	ctx context.Context,
	source BootstrapCatalogSource,
	resource releaseinventory.Resource,
) ([]byte, error) {
	if resource.Size() == 0 || resource.Size() > maximumBootstrapCatalogResourceBytes {
		return nil, ErrBootstrapCatalogIntegrity
	}
	reader, err := source.OpenResource(ctx, resource)
	if err != nil || nilBootstrapCatalogCapability(reader) {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, ErrBootstrapCatalogUnavailable
	}
	hash := sha256.New()
	limited := &io.LimitedReader{R: reader, N: int64(resource.Size()) + 1} // #nosec G115 -- resource size is bounded above.
	raw, readError := io.ReadAll(io.TeeReader(limited, hash))
	closeError := reader.Close()
	if readError != nil || closeError != nil {
		if errors.Is(readError, context.Canceled) || errors.Is(readError, context.DeadlineExceeded) {
			return nil, readError
		}
		return nil, ErrBootstrapCatalogUnavailable
	}
	if uint64(len(raw)) != resource.Size() || limited.N == 0 ||
		!releaseinventory.Digest(hash.Sum(nil)).Equal(resource.Digest()) {
		return nil, ErrBootstrapCatalogIntegrity
	}
	return raw, nil
}

func nilBootstrapCatalogCapability(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Every non-nilable concrete kind is a valid capability.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
