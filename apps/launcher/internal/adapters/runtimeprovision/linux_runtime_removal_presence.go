//go:build darwin || linux

package runtimeprovision

import (
	"context"
	"encoding/json"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeremovalapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeremoval"
)

// LinuxRuntimeRemovalPresenceVerifier re-resolves signed Linux authority and
// distinguishes only the exact managed package set from complete absence.
// Mixed, mismatched, or unreadable native package state fails closed.
type LinuxRuntimeRemovalPresenceVerifier struct {
	resolver runtimeport.AuthorityResolver
	packages PrivilegePackageStateProbe
}

var _ runtimeremovalapp.RuntimePresenceVerifier = (*LinuxRuntimeRemovalPresenceVerifier)(nil)

// NewLinuxRuntimeRemovalPresenceVerifier requires both signed authority and an
// independently authenticated native package database probe.
func NewLinuxRuntimeRemovalPresenceVerifier(
	resolver runtimeport.AuthorityResolver,
	packages PrivilegePackageStateProbe,
) (*LinuxRuntimeRemovalPresenceVerifier, error) {
	if nilArtifactDependency(resolver) || nilArtifactDependency(packages) {
		return nil, ErrProvisionIntegrity
	}
	return &LinuxRuntimeRemovalPresenceVerifier{resolver: resolver, packages: packages}, nil
}

// InspectManagedRuntime returns absent only when every signed vendor-runtime
// package is independently proved absent.
func (v *LinuxRuntimeRemovalPresenceVerifier) InspectManagedRuntime(
	ctx context.Context,
	removalPlan runtimeremoval.Plan,
) (runtimeremovalapp.PresenceProof, error) {
	if v == nil || ctx == nil || nilArtifactDependency(v.resolver) || nilArtifactDependency(v.packages) ||
		!removalPlan.Valid() || removalPlan.Platform() != runtimeinstall.PlatformLinux {
		return runtimeremovalapp.PresenceProof{}, ErrProvisionIntegrity
	}
	if err := ctx.Err(); err != nil {
		return runtimeremovalapp.PresenceProof{}, err
	}
	authority, err := resolveLinuxRemovalAuthority(ctx, v.resolver, removalPlan)
	if err != nil {
		return runtimeremovalapp.PresenceProof{}, err
	}
	present, err := v.packages.PrivilegeManagedPackageStateMatches(ctx, authority)
	if err != nil {
		return runtimeremovalapp.PresenceProof{}, sanitizedContextError(ctx, ErrProvisionIntegrity)
	}
	absent := false
	if !present {
		absent, err = v.packages.PrivilegeManagedPackagesAbsent(ctx, authority)
		if err != nil || !absent {
			return runtimeremovalapp.PresenceProof{}, sanitizedContextError(ctx, ErrProvisionIntegrity)
		}
	}
	state, err := linuxRemovalPackageStateDigest(authority, absent)
	if err != nil {
		return runtimeremovalapp.PresenceProof{}, ErrProvisionIntegrity
	}
	evidence, err := json.Marshal(struct {
		Schema    string `json:"schema"`
		Plan      string `json:"plan"`
		Authority string `json:"authority"`
		Packages  string `json:"packages"`
		Absent    bool   `json:"absent"`
	}{
		Schema: "agentmemory.linux-runtime-removal-presence.v1", Plan: removalPlan.Digest().String(),
		Authority: authority.Digest().String(), Packages: state.String(), Absent: absent,
	})
	if err != nil {
		return runtimeremovalapp.PresenceProof{}, ErrProvisionIntegrity
	}
	return runtimeremovalapp.PresenceProof{
		PlanDigest: removalPlan.Digest(), OwnershipDigest: removalPlan.OwnershipRecordDigest(),
		EvidenceDigest: runtimeinstall.Sum(evidence), Absent: absent,
	}, nil
}

func linuxRemovalPackageStateDigest(
	authority runtimeport.LinuxAuthority,
	absent bool,
) (runtimeinstall.Hash, error) {
	if absent {
		return runtimeport.ExpectedRemovedPackageStateDigest(authority)
	}
	managed, err := runtimeport.ManagedRuntimePackages(authority)
	if err != nil {
		return runtimeinstall.Hash{}, runtimeport.ErrPrivilegeIntegrity
	}
	type packageState struct {
		Name       string `json:"name"`
		Version    string `json:"version"`
		Repository string `json:"repository"`
		Receipt    string `json:"receipt"`
	}
	document := struct {
		Schema   string         `json:"schema"`
		Present  bool           `json:"present"`
		Packages []packageState `json:"packages"`
	}{Schema: "agentmemory.linux-managed-runtime-package-presence.v1", Present: true}
	for _, pkg := range managed {
		document.Packages = append(document.Packages, packageState{
			Name: pkg.Name(), Version: pkg.Version(), Repository: pkg.RepositoryID(),
			Receipt: pkg.NativeReceiptDigest().String(),
		})
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return runtimeinstall.Hash{}, runtimeport.ErrPrivilegeIntegrity
	}
	return runtimeinstall.Sum(encoded), nil
}

func resolveLinuxRemovalAuthority(
	ctx context.Context,
	resolver runtimeport.AuthorityResolver,
	removalPlan runtimeremoval.Plan,
) (runtimeport.LinuxAuthority, error) {
	runtimePlan, err := runtimeinstall.DecodePlanV1(removalPlan.CanonicalRuntimePlan())
	if err != nil || runtimePlan.Digest() != removalPlan.RuntimePlanDigest() ||
		runtimePlan.Platform() != runtimeinstall.PlatformLinux || runtimePlan.Platform() != removalPlan.Platform() ||
		runtimePlan.Product() != removalPlan.Product() || runtimePlan.Version() != removalPlan.Version() {
		return runtimeport.LinuxAuthority{}, ErrProvisionIntegrity
	}
	authority, err := resolver.ResolveLinuxAuthority(ctx, runtimePlan.CanonicalBytes())
	if err != nil || !authority.ValidFor(runtimePlan) || authority.RuntimeVersion() != removalPlan.Version() ||
		authority.Endpoint() != removalPlan.Endpoint() || authority.ArtifactDigest() != removalPlan.ArtifactDigest() {
		return runtimeport.LinuxAuthority{}, sanitizedContextError(ctx, ErrProvisionIntegrity)
	}
	return authority, nil
}
