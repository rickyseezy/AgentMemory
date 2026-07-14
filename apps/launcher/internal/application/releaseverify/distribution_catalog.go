package releaseverify

import (
	"context"
	"errors"
	"reflect"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

// DistributionEnvelopeSource reads the fixed retained outer signed manifest.
// It supplies bytes only; it grants no trust authority.
type DistributionEnvelopeSource interface {
	ReadDistributionEnvelope(context.Context) ([]byte, error)
}

type distributionVerifier interface {
	Verify(context.Context, releaseinventory.SignedManifest) (VerifiedInventory, error)
}

type bootstrapTemplateResolver interface {
	Resolve(context.Context, VerifiedInventory, releaseinventory.SignedManifest) (VerifiedBootstrapTemplate, error)
}

// VerifiedDistributionCatalog composes retained bytes, strict envelope
// decoding, complete release verification, and the two-level bootstrap
// binding. It deliberately re-verifies on every resolution so a process never
// treats an earlier successful read as authority after bundle state changes.
type VerifiedDistributionCatalog struct {
	source   DistributionEnvelopeSource
	verifier distributionVerifier
	resolver bootstrapTemplateResolver
}

// NewVerifiedDistributionCatalog refuses any partial or typed-nil trust path.
func NewVerifiedDistributionCatalog(
	source DistributionEnvelopeSource,
	verifier distributionVerifier,
	resolver bootstrapTemplateResolver,
) (*VerifiedDistributionCatalog, error) {
	if nilDistributionCapability(source) || nilDistributionCapability(verifier) ||
		nilDistributionCapability(resolver) {
		return nil, ErrBootstrapCatalogIntegrity
	}
	return &VerifiedDistributionCatalog{source: source, verifier: verifier, resolver: resolver}, nil
}

// Current returns the exact template selected by the currently retained,
// fully verified distribution catalog.
func (c *VerifiedDistributionCatalog) Current(ctx context.Context) (VerifiedBootstrapTemplate, error) {
	return c.resolve(ctx, releaseinventory.Digest{})
}

// Exact refuses fall-forward by requiring the selected template digest to
// equal the digest already persisted in first-start preparation state.
func (c *VerifiedDistributionCatalog) Exact(
	ctx context.Context,
	digest releaseinventory.Digest,
) (VerifiedBootstrapTemplate, error) {
	if digest.IsZero() {
		return VerifiedBootstrapTemplate{}, ErrBootstrapCatalogIntegrity
	}
	return c.resolve(ctx, digest)
}

func (c *VerifiedDistributionCatalog) resolve(
	ctx context.Context,
	expected releaseinventory.Digest,
) (VerifiedBootstrapTemplate, error) {
	if c == nil || ctx == nil || nilDistributionCapability(c.source) ||
		nilDistributionCapability(c.verifier) || nilDistributionCapability(c.resolver) {
		return VerifiedBootstrapTemplate{}, ErrBootstrapCatalogIntegrity
	}
	if err := ctx.Err(); err != nil {
		return VerifiedBootstrapTemplate{}, err
	}
	raw, err := c.source.ReadDistributionEnvelope(ctx)
	if err != nil {
		return VerifiedBootstrapTemplate{}, distributionBoundaryError(ctx, err)
	}
	distribution, err := releaseinventory.DecodeSignedManifestV1(raw)
	clear(raw)
	if err != nil {
		return VerifiedBootstrapTemplate{}, ErrBootstrapCatalogIntegrity
	}
	inventory, err := c.verifier.Verify(ctx, distribution)
	if err != nil {
		return VerifiedBootstrapTemplate{}, distributionVerificationError(err)
	}
	template, err := c.resolver.Resolve(ctx, inventory, distribution)
	if err != nil {
		return VerifiedBootstrapTemplate{}, distributionBoundaryError(ctx, err)
	}
	if !template.Valid() || (!expected.IsZero() && !template.Resource().Digest().Equal(expected)) {
		return VerifiedBootstrapTemplate{}, ErrBootstrapCatalogIntegrity
	}
	return template, nil
}

func distributionVerificationError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var verification *VerificationError
	if errors.As(err, &verification) {
		if verification.Code() == ErrorCodeDependencyUnavailable ||
			verification.Code() == ErrorCodeDeadlineExceeded {
			return ErrBootstrapCatalogUnavailable
		}
		return ErrBootstrapCatalogIntegrity
	}
	return ErrBootstrapCatalogUnavailable
}

func distributionBoundaryError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, ErrBootstrapCatalogIntegrity) {
		return ErrBootstrapCatalogIntegrity
	}
	return ErrBootstrapCatalogUnavailable
}

func nilDistributionCapability(value any) bool {
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
