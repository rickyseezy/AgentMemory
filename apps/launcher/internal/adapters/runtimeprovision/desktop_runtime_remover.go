package runtimeprovision

import (
	"context"
	"encoding/json"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeremovalapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeremoval"
)

// DesktopRuntimeRemoverDependencies are the complete signed-helper boundary
// required after the separate destructive operation has been consented and
// exhaustively re-scanned.
type DesktopRuntimeRemoverDependencies struct {
	Authority             runtimeport.DesktopAuthorityResolver
	Mutation              runtimeport.DesktopMutationBroker
	MutationAuthenticator runtimeport.DesktopMutationAuthenticator
	MutationReplay        runtimeport.DesktopMutationReplayLedger
	Nonces                runtimeport.NonceSource
	Clock                 runtimeport.Clock
}

// DesktopRuntimeRemover invokes only the closed vendor uninstall capability
// through the same signed, elevated helper used for installation.
type DesktopRuntimeRemover struct {
	authority             runtimeport.DesktopAuthorityResolver
	mutation              runtimeport.DesktopMutationBroker
	mutationAuthenticator runtimeport.DesktopMutationAuthenticator
	mutationReplay        runtimeport.DesktopMutationReplayLedger
	nonces                runtimeport.NonceSource
	clock                 runtimeport.Clock
}

var _ runtimeremovalapp.NativeRemover = (*DesktopRuntimeRemover)(nil)

// NewDesktopRuntimeRemover rejects any composition that could bypass signed
// authority, authenticated receipts, or replay protection.
func NewDesktopRuntimeRemover(
	dependencies DesktopRuntimeRemoverDependencies,
) (*DesktopRuntimeRemover, error) {
	values := []any{
		dependencies.Authority, dependencies.Mutation, dependencies.MutationAuthenticator,
		dependencies.MutationReplay, dependencies.Nonces, dependencies.Clock,
	}
	for _, value := range values {
		if desktopNilDependency(value) {
			return nil, ErrProvisionIntegrity
		}
	}
	return &DesktopRuntimeRemover{
		authority: dependencies.Authority, mutation: dependencies.Mutation,
		mutationAuthenticator: dependencies.MutationAuthenticator,
		mutationReplay:        dependencies.MutationReplay, nonces: dependencies.Nonces, clock: dependencies.Clock,
	}, nil
}

// RemoveManagedRuntime consumes the application-issued authorization without
// widening it into ambient command or path authority.
func (r *DesktopRuntimeRemover) RemoveManagedRuntime(
	ctx context.Context,
	authorization runtimeremovalapp.RemovalAuthorization,
) (runtimeremovalapp.NativeRemovalResult, error) {
	return r.removeAuthorizedDesktopRuntime(
		ctx, authorization.Plan(), authorization.Ownership(), authorization.Scan(), authorization.ConsentReceipt(),
	)
}

func (r *DesktopRuntimeRemover) removeAuthorizedDesktopRuntime(
	ctx context.Context,
	plan runtimeremoval.Plan,
	ownership runtimeinstall.RuntimeOwnershipRecord,
	scan runtimeremoval.DependencyScan,
	consent runtimeinstall.Hash,
) (runtimeremovalapp.NativeRemovalResult, error) {
	if r == nil || ctx == nil || desktopNilDependency(r.authority) || desktopNilDependency(r.mutation) ||
		desktopNilDependency(r.mutationAuthenticator) || desktopNilDependency(r.mutationReplay) ||
		desktopNilDependency(r.nonces) || desktopNilDependency(r.clock) || !plan.Valid() || consent.IsZero() ||
		(plan.Platform() != runtimeinstall.PlatformDarwin && plan.Platform() != runtimeinstall.PlatformWindows) ||
		ownership.Digest() != plan.OwnershipRecordDigest() ||
		ownership.Status() != runtimeinstall.OwnershipStatusFinalized ||
		ownership.Disposition() != runtimeinstall.OwnershipProvisionedByAgentMemory ||
		scan.Digest().IsZero() ||
		scan.OwnershipRecordDigest() != ownership.Digest() || scan.Endpoint() != plan.Endpoint() || !scan.SafeToRemove() {
		return runtimeremovalapp.NativeRemovalResult{}, ErrProvisionIntegrity
	}
	if err := ctx.Err(); err != nil {
		return runtimeremovalapp.NativeRemovalResult{}, err
	}
	runtimePlan, err := runtimeinstall.DecodePlanV1(plan.CanonicalRuntimePlan())
	if err != nil || runtimePlan.Digest() != plan.RuntimePlanDigest() || runtimePlan.Platform() != plan.Platform() ||
		runtimePlan.Product() != plan.Product() || runtimePlan.Version() != plan.Version() {
		return runtimeremovalapp.NativeRemovalResult{}, ErrProvisionIntegrity
	}
	authority, err := r.authority.ResolveDesktopAuthority(ctx, runtimePlan.CanonicalBytes())
	if err != nil || !authority.ValidFor(runtimePlan) || authority.Platform() != plan.Platform() ||
		authority.RuntimeVersion() != plan.Version() || authority.Endpoint() != plan.Endpoint() ||
		authority.ArtifactSHA256() != plan.ArtifactDigest() {
		return runtimeremovalapp.NativeRemovalResult{}, sanitizedContextError(ctx, ErrProvisionIntegrity)
	}
	now := r.clock.Now()
	if now.IsZero() || now.Location() != time.UTC {
		return runtimeremovalapp.NativeRemovalResult{}, ErrProvisionIntegrity
	}
	nonce, err := r.nonces.NewPrivilegeNonce(ctx)
	if err != nil || nonce.IsZero() {
		return runtimeremovalapp.NativeRemovalResult{}, sanitizedContextError(ctx, ErrProvisionIntegrity)
	}
	request, err := runtimeport.NewDesktopMutationRequest(
		plan.OperationID().String(), 1, runtimeport.DesktopMutationRemoveRuntime, authority,
		consent, plan.ArtifactDigest(), nonce, now, now.Add(desktopMutationRequestLifetime),
	)
	if err != nil {
		return runtimeremovalapp.NativeRemovalResult{}, ErrProvisionIntegrity
	}
	receipt, err := r.mutation.ExecuteDesktopMutation(ctx, request)
	if err != nil {
		return runtimeremovalapp.NativeRemovalResult{}, sanitizedContextError(ctx, ErrProvisionIntegrity)
	}
	if !receipt.Matches(request, r.clock.Now()) ||
		r.mutationAuthenticator.VerifyDesktopMutation(ctx, request, receipt) != nil ||
		!receipt.Matches(request, r.clock.Now()) ||
		r.mutationReplay.ConsumeDesktopMutation(ctx, request.Nonce(), receipt.Digest()) != nil ||
		!receipt.Matches(request, r.clock.Now()) {
		return runtimeremovalapp.NativeRemovalResult{}, ErrProvisionIntegrity
	}
	before, err := json.Marshal(struct {
		Schema    string `json:"schema"`
		Plan      string `json:"plan"`
		Ownership string `json:"ownership"`
		Scan      string `json:"scan"`
		Consent   string `json:"consent"`
		Authority string `json:"authority"`
		Request   string `json:"request"`
	}{
		Schema: "agentmemory.desktop-runtime-removal-before.v1", Plan: plan.Digest().String(),
		Ownership: ownership.Digest().String(), Scan: scan.Digest().String(), Consent: consent.String(),
		Authority: authority.Digest().String(), Request: request.Digest().String(),
	})
	if err != nil {
		return runtimeremovalapp.NativeRemovalResult{}, ErrProvisionIntegrity
	}
	return runtimeremovalapp.NativeRemovalResult{
		PlanDigest: plan.Digest(), OwnershipDigest: ownership.Digest(), ExecutionScan: scan.Digest(),
		BeforeDigest: runtimeinstall.Sum(before), EffectDigest: receipt.Digest(),
	}, nil
}
