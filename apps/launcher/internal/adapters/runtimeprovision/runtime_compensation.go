package runtimeprovision

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeinstallapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

// RuntimeArtifactCompensationCAS releases the reservation, slot, and partial
// identities owned by one exact runtime artifact aggregate. Verified final CAS
// objects remain reusable and are never deleted by cancellation.
type RuntimeArtifactCompensationCAS interface {
	ReleaseReservationIfPresent(
		context.Context,
		artifactapp.Command,
		artifactacquisition.ReleaseReason,
	) (artifactapp.ReleaseResult, error)
}

// LinuxRuntimeCompensator is the production cancellation adapter for the
// signed Linux runtime acquisition path.
type LinuxRuntimeCompensator struct {
	projector linuxArtifactPlanProjector
	authority runtimeport.AuthorityResolver
	runtime   RuntimeInspector
	cas       RuntimeArtifactCompensationCAS
}

// NewLinuxRuntimeCompensator constructs only from the same verified catalog,
// host-bound authority, inspector, and CAS used by provisioning.
func NewLinuxRuntimeCompensator(
	catalog runtimecatalogapp.VerifiedCatalog,
	authority runtimeport.AuthorityResolver,
	runtime RuntimeInspector,
	cas RuntimeArtifactCompensationCAS,
) (*LinuxRuntimeCompensator, error) {
	if !catalog.Manifest().Valid() || catalog.VerifiedAt().IsZero() {
		return nil, ErrProvisionIntegrity
	}
	if _, present := catalog.Manifest().LinuxExecution(); !present {
		return nil, ErrProvisionIntegrity
	}
	return newLinuxRuntimeCompensator(verifiedCatalogArtifactProjector{catalog: catalog}, authority, runtime, cas)
}

func newLinuxRuntimeCompensator(
	projector linuxArtifactPlanProjector,
	authority runtimeport.AuthorityResolver,
	runtime RuntimeInspector,
	cas RuntimeArtifactCompensationCAS,
) (*LinuxRuntimeCompensator, error) {
	if nilArtifactDependency(projector) || nilDependency(authority) || nilDependency(runtime) ||
		nilArtifactDependency(cas) {
		return nil, ErrProvisionIntegrity
	}
	return &LinuxRuntimeCompensator{projector: projector, authority: authority, runtime: runtime, cas: cas}, nil
}

// CompensateRuntime releases only operation-owned acquisition state and proves
// the explicitly addressed runtime observation did not change.
func (c *LinuxRuntimeCompensator) CompensateRuntime(
	ctx context.Context,
	request runtimeinstallapp.RuntimeCompensationRequest,
) (runtimeinstallapp.RuntimeCompensationReceipt, error) {
	if c == nil || ctx == nil || nilArtifactDependency(c.projector) || nilDependency(c.authority) ||
		nilDependency(c.runtime) || nilArtifactDependency(c.cas) {
		return runtimeinstallapp.RuntimeCompensationReceipt{}, ErrProvisionIntegrity
	}
	if err := ctx.Err(); err != nil {
		return runtimeinstallapp.RuntimeCompensationReceipt{}, err
	}
	canonicalPlan := request.CanonicalPlan()
	plan, err := runtimeinstall.DecodePlanV1(canonicalPlan)
	if err != nil || plan.Platform() != runtimeinstall.PlatformLinux || plan.Digest() != request.PlanDigest() {
		return runtimeinstallapp.RuntimeCompensationReceipt{}, ErrProvisionIntegrity
	}
	authority, err := c.authority.ResolveLinuxAuthority(ctx, canonicalPlan)
	if err != nil || !authority.ValidFor(plan) || !runtimeOwnershipMatchesLinux(ctx, canonicalPlan, request, c.authority) {
		return runtimeinstallapp.RuntimeCompensationReceipt{}, sanitizedContextError(ctx, ErrProvisionIntegrity)
	}
	artifactPlan, err := c.projector.ProjectLinuxArtifactPlan(authority)
	if err != nil || !artifactPlan.Digest().Equal(releaseDigest(authority.CatalogDigest())) {
		return runtimeinstallapp.RuntimeCompensationReceipt{}, ErrProvisionIntegrity
	}
	before, err := c.runtime.Inspect(ctx, plan, authority)
	if err != nil || before.Digest().IsZero() {
		return runtimeinstallapp.RuntimeCompensationReceipt{}, sanitizedContextError(ctx, ErrProbeFailed)
	}
	release, err := c.cas.ReleaseReservationIfPresent(ctx, artifactapp.Command{
		OperationID: linuxArtifactOperationID(authority), Plan: artifactPlan,
	}, artifactacquisition.ReleaseReasonCancelled)
	if err != nil || !validCompensationRelease(release) {
		return runtimeinstallapp.RuntimeCompensationReceipt{}, sanitizedContextError(ctx, ErrProvisionIntegrity)
	}
	after, err := c.runtime.Inspect(ctx, plan, authority)
	if err != nil || after.Digest().IsZero() || before.Digest() != after.Digest() {
		return runtimeinstallapp.RuntimeCompensationReceipt{}, sanitizedContextError(ctx, ErrProvisionIntegrity)
	}
	cleanupDigest, err := runtimeCleanupDigest(
		"linux", request, authority.Digest(), linuxArtifactOperationID(authority), release,
		before.Digest(), after.Digest(),
	)
	if err != nil {
		return runtimeinstallapp.RuntimeCompensationReceipt{}, ErrProvisionIntegrity
	}
	return runtimeinstallapp.NewRuntimeCompensationReceipt(request, runtimeinstallapp.RuntimeCompensationReceiptInput{
		RuntimeBeforeDigest: before.Digest(), RuntimeAfterDigest: after.Digest(),
		ArtifactCleanupDigest: cleanupDigest, RuntimePreserved: true,
	})
}

// DesktopRuntimeCompensator is the production cancellation adapter for the
// signed macOS and Windows Docker Desktop acquisition path.
type DesktopRuntimeCompensator struct {
	projector desktopArtifactPlanProjector
	authority runtimeport.DesktopAuthorityResolver
	runtime   runtimeport.DesktopRuntimeInspector
	cas       RuntimeArtifactCompensationCAS
}

// NewDesktopRuntimeCompensator constructs the desktop compensation boundary.
func NewDesktopRuntimeCompensator(
	catalog runtimecatalogapp.VerifiedCatalog,
	authority runtimeport.DesktopAuthorityResolver,
	runtime runtimeport.DesktopRuntimeInspector,
	cas RuntimeArtifactCompensationCAS,
) (*DesktopRuntimeCompensator, error) {
	if !catalog.Manifest().Valid() || catalog.VerifiedAt().IsZero() {
		return nil, ErrProvisionIntegrity
	}
	if _, present := catalog.Manifest().DesktopExecution(); !present {
		return nil, ErrProvisionIntegrity
	}
	return newDesktopRuntimeCompensator(
		verifiedCatalogDesktopArtifactProjector{catalog: catalog}, authority, runtime, cas,
	)
}

func newDesktopRuntimeCompensator(
	projector desktopArtifactPlanProjector,
	authority runtimeport.DesktopAuthorityResolver,
	runtime runtimeport.DesktopRuntimeInspector,
	cas RuntimeArtifactCompensationCAS,
) (*DesktopRuntimeCompensator, error) {
	if nilArtifactDependency(projector) || nilDependency(authority) || nilDependency(runtime) ||
		nilArtifactDependency(cas) {
		return nil, ErrProvisionIntegrity
	}
	return &DesktopRuntimeCompensator{projector: projector, authority: authority, runtime: runtime, cas: cas}, nil
}

// CompensateRuntime releases only desktop acquisition slots and partials. It
// does not invoke Docker Desktop's destructive uninstaller.
func (c *DesktopRuntimeCompensator) CompensateRuntime(
	ctx context.Context,
	request runtimeinstallapp.RuntimeCompensationRequest,
) (runtimeinstallapp.RuntimeCompensationReceipt, error) {
	if c == nil || ctx == nil || nilArtifactDependency(c.projector) || nilDependency(c.authority) ||
		nilDependency(c.runtime) || nilArtifactDependency(c.cas) {
		return runtimeinstallapp.RuntimeCompensationReceipt{}, ErrProvisionIntegrity
	}
	if err := ctx.Err(); err != nil {
		return runtimeinstallapp.RuntimeCompensationReceipt{}, err
	}
	canonicalPlan := request.CanonicalPlan()
	plan, err := runtimeinstall.DecodePlanV1(canonicalPlan)
	if err != nil || (plan.Platform() != runtimeinstall.PlatformDarwin &&
		plan.Platform() != runtimeinstall.PlatformWindows) || plan.Digest() != request.PlanDigest() {
		return runtimeinstallapp.RuntimeCompensationReceipt{}, ErrProvisionIntegrity
	}
	authority, err := c.authority.ResolveDesktopAuthority(ctx, canonicalPlan)
	if err != nil || !authority.ValidFor(plan) || !runtimeOwnershipMatchesDesktop(ctx, canonicalPlan, request, c.authority) {
		return runtimeinstallapp.RuntimeCompensationReceipt{}, sanitizeDesktopBoundary(ctx, err, ErrProvisionIntegrity)
	}
	artifactPlan, err := c.projector.ProjectDesktopArtifactPlan(authority)
	if err != nil || !artifactPlan.Digest().Equal(releaseDigest(authority.CatalogDigest())) {
		return runtimeinstallapp.RuntimeCompensationReceipt{}, ErrProvisionIntegrity
	}
	before, err := c.runtime.InspectDesktopRuntime(ctx, plan, authority)
	if err != nil || before.Digest().IsZero() {
		return runtimeinstallapp.RuntimeCompensationReceipt{}, sanitizeDesktopBoundary(ctx, err, ErrProbeFailed)
	}
	release, err := c.cas.ReleaseReservationIfPresent(ctx, artifactapp.Command{
		OperationID: desktopArtifactOperationID(authority), Plan: artifactPlan,
	}, artifactacquisition.ReleaseReasonCancelled)
	if err != nil || !validCompensationRelease(release) {
		return runtimeinstallapp.RuntimeCompensationReceipt{}, sanitizeDesktopBoundary(ctx, err, ErrProvisionIntegrity)
	}
	after, err := c.runtime.InspectDesktopRuntime(ctx, plan, authority)
	if err != nil || after.Digest().IsZero() || before.Digest() != after.Digest() {
		return runtimeinstallapp.RuntimeCompensationReceipt{}, sanitizeDesktopBoundary(ctx, err, ErrProvisionIntegrity)
	}
	cleanupDigest, err := runtimeCleanupDigest(
		plan.Platform().String(), request, authority.Digest(), desktopArtifactOperationID(authority), release,
		before.Digest(), after.Digest(),
	)
	if err != nil {
		return runtimeinstallapp.RuntimeCompensationReceipt{}, ErrProvisionIntegrity
	}
	return runtimeinstallapp.NewRuntimeCompensationReceipt(request, runtimeinstallapp.RuntimeCompensationReceiptInput{
		RuntimeBeforeDigest: before.Digest(), RuntimeAfterDigest: after.Digest(),
		ArtifactCleanupDigest: cleanupDigest, RuntimePreserved: true,
	})
}

func runtimeOwnershipMatchesLinux(
	ctx context.Context,
	canonicalPlan []byte,
	request runtimeinstallapp.RuntimeCompensationRequest,
	resolver runtimeport.AuthorityResolver,
) bool {
	projector, err := NewLinuxOwnershipAuthorityResolver(resolver)
	if err != nil {
		return false
	}
	authority, err := projector.ResolveRuntimeOwnershipAuthority(ctx, canonicalPlan)
	return err == nil && ownershipAuthorityMatches(authority, request.OwnershipRecord())
}

func runtimeOwnershipMatchesDesktop(
	ctx context.Context,
	canonicalPlan []byte,
	request runtimeinstallapp.RuntimeCompensationRequest,
	resolver runtimeport.DesktopAuthorityResolver,
) bool {
	projector, err := NewDesktopOwnershipAuthorityResolver(resolver)
	if err != nil {
		return false
	}
	authority, err := projector.ResolveRuntimeOwnershipAuthority(ctx, canonicalPlan)
	return err == nil && ownershipAuthorityMatches(authority, request.OwnershipRecord())
}

func ownershipAuthorityMatches(
	authority runtimeinstall.RuntimeOwnershipAuthority,
	record runtimeinstall.RuntimeOwnershipRecord,
) bool {
	want := authority.Snapshot()
	got := record.Snapshot()
	return want.Vendor == got.Vendor && want.Version == got.Version && want.Channel == got.Channel &&
		want.Endpoint == got.Endpoint && want.Context == got.Context && want.Publisher == got.Publisher &&
		want.PublisherDigest == got.PublisherDigest && want.ArtifactDigest == got.ArtifactDigest &&
		slices.Equal(want.Components, got.Components) && slices.Equal(want.Settings, got.Settings)
}

func validCompensationRelease(result artifactapp.ReleaseResult) bool {
	return result.Reason == artifactacquisition.ReleaseReasonCancelled &&
		(!result.Released || result.Version != 0 && !result.AggregateEvidence.IsZero()) &&
		(result.Version == 0 || !result.AggregateEvidence.IsZero())
}

type runtimeCleanupReceiptV1 struct {
	Schema            string `json:"schema"`
	Platform          string `json:"platform"`
	OperationID       string `json:"operation_id"`
	PlanDigest        string `json:"plan_digest"`
	OwnershipDigest   string `json:"ownership_digest"`
	AuthorityDigest   string `json:"authority_digest"`
	ArtifactOperation string `json:"artifact_operation"`
	ReleaseVersion    uint64 `json:"release_version"`
	ReleaseReason     string `json:"release_reason"`
	Released          bool   `json:"released"`
	AggregateEvidence string `json:"aggregate_evidence"`
	RuntimeBefore     string `json:"runtime_before"`
	RuntimeAfter      string `json:"runtime_after"`
}

func runtimeCleanupDigest(
	platform string,
	request runtimeinstallapp.RuntimeCompensationRequest,
	authorityDigest runtimeinstall.Hash,
	artifactOperation string,
	release artifactapp.ReleaseResult,
	before runtimeinstall.Hash,
	after runtimeinstall.Hash,
) (runtimeinstall.Hash, error) {
	document := runtimeCleanupReceiptV1{
		Schema: "agentmemory.runtime-acquisition-cleanup.v1", Platform: platform,
		OperationID: request.OperationID(), PlanDigest: request.PlanDigest().String(),
		OwnershipDigest: request.OwnershipRecord().Digest().String(), AuthorityDigest: authorityDigest.String(),
		ArtifactOperation: artifactOperation, ReleaseVersion: release.Version,
		ReleaseReason: string(release.Reason), Released: release.Released,
		AggregateEvidence: release.AggregateEvidence.Hex(), RuntimeBefore: before.String(), RuntimeAfter: after.String(),
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return runtimeinstall.Hash{}, errors.Join(ErrProvisionIntegrity, err)
	}
	digest := runtimeinstall.Sum(encoded)
	if digest.IsZero() {
		return runtimeinstall.Hash{}, ErrProvisionIntegrity
	}
	return digest, nil
}

func releaseDigest(value runtimeinstall.Hash) [32]byte { return [32]byte(value) }

var _ runtimeinstallapp.RuntimeCompensator = (*LinuxRuntimeCompensator)(nil)
var _ runtimeinstallapp.RuntimeCompensator = (*DesktopRuntimeCompensator)(nil)
