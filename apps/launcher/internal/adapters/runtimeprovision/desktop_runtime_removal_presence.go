package runtimeprovision

import (
	"context"
	"encoding/json"
	"errors"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeremovalapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeremoval"
)

// DesktopRuntimeRemovalPresenceVerifier re-resolves signed desktop authority
// and re-proves native installed-application identity on every observation.
type DesktopRuntimeRemovalPresenceVerifier struct {
	resolver  runtimeport.DesktopAuthorityResolver
	installed runtimeport.DesktopInstalledApplicationProbe
}

var _ runtimeremovalapp.RuntimePresenceVerifier = (*DesktopRuntimeRemovalPresenceVerifier)(nil)

// NewDesktopRuntimeRemovalPresenceVerifier rejects missing signed/native boundaries.
func NewDesktopRuntimeRemovalPresenceVerifier(
	resolver runtimeport.DesktopAuthorityResolver,
	installed runtimeport.DesktopInstalledApplicationProbe,
) (*DesktopRuntimeRemovalPresenceVerifier, error) {
	if desktopNilDependency(resolver) || desktopNilDependency(installed) {
		return nil, ErrProvisionIntegrity
	}
	return &DesktopRuntimeRemovalPresenceVerifier{resolver: resolver, installed: installed}, nil
}

// InspectManagedRuntime accepts absence only from the same native application
// probe that verifies path, signed version, and publisher while present.
func (v *DesktopRuntimeRemovalPresenceVerifier) InspectManagedRuntime(
	ctx context.Context,
	removalPlan runtimeremoval.Plan,
) (runtimeremovalapp.PresenceProof, error) {
	if v == nil || ctx == nil || desktopNilDependency(v.resolver) || desktopNilDependency(v.installed) ||
		!removalPlan.Valid() || (removalPlan.Platform() != runtimeinstall.PlatformDarwin &&
		removalPlan.Platform() != runtimeinstall.PlatformWindows) {
		return runtimeremovalapp.PresenceProof{}, ErrProvisionIntegrity
	}
	if err := ctx.Err(); err != nil {
		return runtimeremovalapp.PresenceProof{}, err
	}
	runtimePlan, err := runtimeinstall.DecodePlanV1(removalPlan.CanonicalRuntimePlan())
	if err != nil {
		return runtimeremovalapp.PresenceProof{}, ErrProvisionIntegrity
	}
	authority, err := v.resolver.ResolveDesktopAuthority(ctx, runtimePlan.CanonicalBytes())
	if err != nil || !authority.ValidFor(runtimePlan) || authority.Platform() != removalPlan.Platform() ||
		authority.RuntimeVersion() != removalPlan.Version() || authority.Endpoint() != removalPlan.Endpoint() ||
		authority.ArtifactSHA256() != removalPlan.ArtifactDigest() {
		return runtimeremovalapp.PresenceProof{}, sanitizedContextError(ctx, ErrProvisionIntegrity)
	}
	evidence, err := v.installed.ProbeDesktopInstalledApplication(ctx, authority)
	if err != nil || !evidence.VerifiedFor(authority) {
		return runtimeremovalapp.PresenceProof{}, sanitizedContextError(ctx, ErrProvisionIntegrity)
	}
	document := struct {
		Schema      string `json:"schema"`
		Plan        string `json:"plan"`
		Authority   string `json:"authority"`
		Application string `json:"application"`
		Absent      bool   `json:"absent"`
	}{
		Schema: "agentmemory.desktop-runtime-removal-presence.v1", Plan: removalPlan.Digest().String(),
		Authority: authority.Digest().String(), Application: evidence.Digest().String(), Absent: !evidence.Present(),
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return runtimeremovalapp.PresenceProof{}, errors.Join(ErrProvisionIntegrity, err)
	}
	return runtimeremovalapp.PresenceProof{
		PlanDigest: removalPlan.Digest(), OwnershipDigest: removalPlan.OwnershipRecordDigest(),
		EvidenceDigest: runtimeinstall.Sum(encoded), Absent: !evidence.Present(),
	}, nil
}
