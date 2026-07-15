package launcher

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

// nativeRuntimeExecutionVerifier re-opens both signed catalog envelopes before
// constructing any platform mutation capability. Planning-time verification
// is evidence, never durable executable authority by itself.
type nativeRuntimeExecutionVerifier struct {
	loader  nativeRuntimeCatalogEnvelopeLoader
	catalog nativeRuntimeCatalogPolicyVerifier
}

func newNativeRuntimeExecutionVerifier(
	loader nativeRuntimeCatalogEnvelopeLoader,
	catalog nativeRuntimeCatalogPolicyVerifier,
) (*nativeRuntimeExecutionVerifier, error) {
	if nilAny(loader) || nilAny(catalog) {
		return nil, errNativeInstallerIntegrity
	}
	return &nativeRuntimeExecutionVerifier{loader: loader, catalog: catalog}, nil
}

// VerifyRuntimeExecution re-verifies the outer release resource, inner signed
// catalog, native publisher policy, rollback anchor, and exact persisted plan
// selection on every process lifetime.
func (v *nativeRuntimeExecutionVerifier) VerifyRuntimeExecution(
	ctx context.Context,
	execution installplanapp.RuntimeExecutionAuthority,
) (nativeVerifiedRuntimeExecution, error) {
	request := execution.Request()
	authority := execution.RuntimeAuthority()
	if _, err := installplanapp.NewRuntimeExecutionAuthority(request, authority); err != nil {
		return nativeVerifiedRuntimeExecution{}, installplanapp.ErrRuntimeEvidenceUnavailable
	}
	return v.verifyAuthenticated(ctx, request, authority)
}

func (v *nativeRuntimeExecutionVerifier) verifyAuthenticated(
	ctx context.Context,
	request installplanapp.RuntimeEvidenceRequest,
	authority installplanapp.RuntimePlanAuthority,
) (nativeVerifiedRuntimeExecution, error) {
	if v == nil || ctx == nil || nilAny(v.loader) || nilAny(v.catalog) {
		return nativeVerifiedRuntimeExecution{}, installplanapp.ErrRuntimeEvidenceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nativeVerifiedRuntimeExecution{}, err
	}
	envelope, err := v.loader.Load(ctx, request)
	if err != nil || envelope.ResourceDigest.IsZero() ||
		!envelope.ResourceDigest.Equal(authority.CatalogResourceEvidenceDigest()) {
		return nativeVerifiedRuntimeExecution{}, installplanapp.ErrRuntimeEvidenceUnavailable
	}
	verified, err := v.catalog.VerifyRuntimeCatalog(ctx, request, envelope)
	if err != nil || verified.manifestDigest.IsZero() || verified.runtime.CatalogDigest().IsZero() ||
		verified.manifestDigest.Hex() != authority.SignedCatalogEvidenceDigest().String() ||
		!runtimeSelectionMatches(authority.Plan(), verified.runtime) {
		return nativeVerifiedRuntimeExecution{}, installplanapp.ErrRuntimeEvidenceUnavailable
	}
	return nativeVerifiedRuntimeExecution{
		authority: authority, catalog: verified.verified, runtime: verified.runtime, request: request,
		manifestDigest: verified.manifestDigest, signedCatalog: envelope.Signed,
	}, nil
}

type nativeVerifiedRuntimeExecution struct {
	authority      installplanapp.RuntimePlanAuthority
	catalog        runtimecatalogapp.VerifiedCatalog
	runtime        runtimeinstall.CertifiedRuntime
	manifestDigest runtimecatalog.Digest
	signedCatalog  runtimecatalog.SignedManifest
	request        installplanapp.RuntimeEvidenceRequest
}

func runtimeSelectionMatches(plan runtimeinstall.Plan, catalog runtimeinstall.CertifiedRuntime) bool {
	return len(plan.CanonicalBytes()) != 0 && plan.CatalogDigest() == catalog.CatalogDigest() &&
		plan.Platform() == catalog.Platform() && plan.Architecture() == catalog.Architecture() &&
		plan.Product() == catalog.Product() && plan.Version() == catalog.Version() &&
		plan.Channel() == catalog.Channel() && plan.CatalogSequence() == catalog.CatalogSequence() &&
		plan.TermsDigest() == catalog.TermsDigest() && plan.TermsID() == catalog.TermsID() &&
		plan.TermsVersion() == catalog.TermsVersion() && plan.TermsURL() == catalog.TermsURL() &&
		plan.TermsPresentation() == catalog.TermsPresentation() &&
		plan.DownloadBytes() == catalog.DownloadBytes() && plan.ExpandedBytes() == catalog.ExpandedBytes()
}
