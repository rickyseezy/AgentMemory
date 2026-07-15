//go:build darwin || linux

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

// LinuxRuntimeRemoverDependencies are the complete signed privilege-helper
// boundary required after separate consent and a fresh exhaustive empty scan.
type LinuxRuntimeRemoverDependencies struct {
	Authority     runtimeport.AuthorityResolver
	Privilege     runtimeport.PrivilegeBroker
	Authenticator runtimeport.ReceiptAuthenticator
	Replay        runtimeport.ReplayLedger
	Nonces        runtimeport.NonceSource
	Clock         runtimeport.Clock
}

// LinuxRuntimeRemover invokes only the closed package-removal capability and
// preserves local Docker/containerd data, repository configuration, user-unit
// bytes, linger policy, subordinate IDs, and distribution prerequisites.
type LinuxRuntimeRemover struct {
	authority     runtimeport.AuthorityResolver
	privilege     runtimeport.PrivilegeBroker
	authenticator runtimeport.ReceiptAuthenticator
	replay        runtimeport.ReplayLedger
	nonces        runtimeport.NonceSource
	clock         runtimeport.Clock
}

var _ runtimeremovalapp.NativeRemover = (*LinuxRuntimeRemover)(nil)

// NewLinuxRuntimeRemover rejects any composition that could bypass signed
// authority, receipt authentication, or one-use replay consumption.
func NewLinuxRuntimeRemover(dependencies LinuxRuntimeRemoverDependencies) (*LinuxRuntimeRemover, error) {
	values := []any{
		dependencies.Authority, dependencies.Privilege, dependencies.Authenticator,
		dependencies.Replay, dependencies.Nonces, dependencies.Clock,
	}
	for _, value := range values {
		if nilArtifactDependency(value) {
			return nil, ErrProvisionIntegrity
		}
	}
	return &LinuxRuntimeRemover{
		authority: dependencies.Authority, privilege: dependencies.Privilege,
		authenticator: dependencies.Authenticator, replay: dependencies.Replay,
		nonces: dependencies.Nonces, clock: dependencies.Clock,
	}, nil
}

// RemoveManagedRuntime consumes only the application-issued authorization.
func (r *LinuxRuntimeRemover) RemoveManagedRuntime(
	ctx context.Context,
	authorization runtimeremovalapp.RemovalAuthorization,
) (runtimeremovalapp.NativeRemovalResult, error) {
	return r.removeAuthorizedLinuxRuntime(
		ctx, authorization.Plan(), authorization.Ownership(), authorization.Scan(), authorization.ConsentReceipt(),
	)
}

func (r *LinuxRuntimeRemover) removeAuthorizedLinuxRuntime(
	ctx context.Context,
	plan runtimeremoval.Plan,
	ownership runtimeinstall.RuntimeOwnershipRecord,
	scan runtimeremoval.DependencyScan,
	consent runtimeinstall.Hash,
) (runtimeremovalapp.NativeRemovalResult, error) {
	if r == nil || ctx == nil || nilArtifactDependency(r.authority) || nilArtifactDependency(r.privilege) ||
		nilArtifactDependency(r.authenticator) || nilArtifactDependency(r.replay) || nilArtifactDependency(r.nonces) ||
		nilArtifactDependency(r.clock) || !plan.Valid() || plan.Platform() != runtimeinstall.PlatformLinux || consent.IsZero() ||
		ownership.Digest() != plan.OwnershipRecordDigest() || ownership.Status() != runtimeinstall.OwnershipStatusFinalized ||
		ownership.Disposition() != runtimeinstall.OwnershipProvisionedByAgentMemory || scan.Digest().IsZero() ||
		scan.OwnershipRecordDigest() != ownership.Digest() || scan.Endpoint() != plan.Endpoint() || !scan.SafeToRemove() {
		return runtimeremovalapp.NativeRemovalResult{}, ErrProvisionIntegrity
	}
	if err := ctx.Err(); err != nil {
		return runtimeremovalapp.NativeRemovalResult{}, err
	}
	authority, err := resolveLinuxRemovalAuthority(ctx, r.authority, plan)
	if err != nil {
		return runtimeremovalapp.NativeRemovalResult{}, err
	}
	authorizationDigest, err := linuxRemovalAuthorizationDigest(plan, ownership, scan, consent)
	if err != nil || authorizationDigest.IsZero() {
		return runtimeremovalapp.NativeRemovalResult{}, ErrProvisionIntegrity
	}
	now := r.clock.Now()
	if now.IsZero() || now.Location() != time.UTC {
		return runtimeremovalapp.NativeRemovalResult{}, ErrProvisionIntegrity
	}
	nonce, err := r.nonces.NewPrivilegeNonce(ctx)
	if err != nil || nonce.IsZero() {
		return runtimeremovalapp.NativeRemovalResult{}, sanitizedContextError(ctx, ErrProvisionIntegrity)
	}
	expected, err := runtimeport.ExpectedPrivilegeState(authority, runtimeport.PrivilegeRemoveManagedPackages)
	if err != nil {
		return runtimeremovalapp.NativeRemovalResult{}, ErrProvisionIntegrity
	}
	request, err := runtimeport.NewPrivilegeRequest(runtimeport.PrivilegeRequestInput{
		OperationID: plan.OperationID().String(), Attempt: 1, Operation: runtimeport.PrivilegeRemoveManagedPackages,
		Authority: authority, AuthorizationDigest: authorizationDigest, Nonce: nonce, IssuedAt: now,
		ExpiresAt: now.Add(privilegeRequestLifetime), ExpectedState: expected,
	})
	if err != nil {
		return runtimeremovalapp.NativeRemovalResult{}, ErrProvisionIntegrity
	}
	receipt, err := r.privilege.Execute(ctx, request)
	if err != nil {
		return runtimeremovalapp.NativeRemovalResult{}, sanitizedContextError(ctx, ErrProvisionIntegrity)
	}
	if !receipt.Matches(request, r.clock.Now()) ||
		r.authenticator.VerifyPrivilegeReceipt(ctx, request, receipt) != nil ||
		!receipt.Matches(request, r.clock.Now()) ||
		r.replay.ConsumePrivilegeReceipt(ctx, request.Nonce(), receipt.Digest()) != nil ||
		!receipt.Matches(request, r.clock.Now()) {
		return runtimeremovalapp.NativeRemovalResult{}, ErrProvisionIntegrity
	}
	before, err := json.Marshal(struct {
		Schema        string `json:"schema"`
		Authorization string `json:"authorization"`
		Request       string `json:"request"`
	}{
		Schema:        "agentmemory.linux-runtime-removal-before.v1",
		Authorization: authorizationDigest.String(), Request: request.Digest().String(),
	})
	if err != nil {
		return runtimeremovalapp.NativeRemovalResult{}, ErrProvisionIntegrity
	}
	return runtimeremovalapp.NativeRemovalResult{
		PlanDigest: plan.Digest(), OwnershipDigest: ownership.Digest(), ExecutionScan: scan.Digest(),
		BeforeDigest: runtimeinstall.Sum(before), EffectDigest: receipt.Digest(),
	}, nil
}

func linuxRemovalAuthorizationDigest(
	plan runtimeremoval.Plan,
	ownership runtimeinstall.RuntimeOwnershipRecord,
	scan runtimeremoval.DependencyScan,
	consent runtimeinstall.Hash,
) (runtimeinstall.Hash, error) {
	if !plan.Valid() || ownership.Digest() != plan.OwnershipRecordDigest() || scan.Digest().IsZero() ||
		scan.OwnershipRecordDigest() != ownership.Digest() || scan.Endpoint() != plan.Endpoint() ||
		!scan.SafeToRemove() || consent.IsZero() {
		return runtimeinstall.Hash{}, ErrProvisionIntegrity
	}
	encoded, err := json.Marshal(struct {
		Schema        string `json:"schema"`
		Plan          string `json:"plan"`
		Ownership     string `json:"ownership"`
		ExecutionScan string `json:"execution_scan"`
		Consent       string `json:"consent"`
		Impact        string `json:"impact"`
	}{
		Schema: "agentmemory.linux-runtime-removal-authorization.v1", Plan: plan.Digest().String(),
		Ownership: ownership.Digest().String(), ExecutionScan: scan.Digest().String(), Consent: consent.String(),
		Impact: plan.ImpactConfirmation(),
	})
	if err != nil {
		return runtimeinstall.Hash{}, ErrProvisionIntegrity
	}
	return runtimeinstall.Sum(encoded), nil
}
