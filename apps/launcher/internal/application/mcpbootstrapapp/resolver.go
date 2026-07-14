package mcpbootstrapapp

import (
	"context"
	"errors"

	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

var (
	// ErrBootstrapNotFound means no protected current installation binding exists.
	ErrBootstrapNotFound = errors.New("bootstrap binding not found")
	// ErrBootstrapConflict means a compare-and-swap or host-selection authority changed.
	ErrBootstrapConflict = errors.New("bootstrap binding conflict")
	// ErrBootstrapIntegrity means protected state is malformed, substituted, or contradictory.
	ErrBootstrapIntegrity = errors.New("bootstrap binding integrity violation")
	// ErrBootstrapUnavailable means protected state could not be read durably.
	ErrBootstrapUnavailable = errors.New("bootstrap binding unavailable")
)

// BootstrapResolver discovers the one protected local installation selected for
// an agent host. Implementations must authenticate the binding, canonical plan,
// and current operation before returning it.
type BootstrapResolver interface {
	ResolveBootstrap(context.Context, agentconfigdomain.AgentHost) (ResolvedBootstrap, error)
}

// ResolvedBootstrap is the minimal immutable authority needed to construct the
// pre-Ready MCP surface. Canonical plan bytes are always copied at the boundary.
type ResolvedBootstrap struct {
	installationID string
	operationID    install.OperationID
	planDigest     install.PlanDigest
	canonicalPlan  []byte
}

// NewResolvedBootstrap constructs a binding only from exact canonical bytes.
func NewResolvedBootstrap(
	installationID string,
	operationID install.OperationID,
	planDigest install.PlanDigest,
	canonicalPlan []byte,
) (ResolvedBootstrap, error) {
	bound, err := install.BindPlan(canonicalPlan)
	if !validInstallationID(installationID) || operationID.IsZero() || planDigest.IsZero() ||
		err != nil || !bound.Equal(planDigest) {
		return ResolvedBootstrap{}, ErrBootstrapIntegrity
	}
	return ResolvedBootstrap{
		installationID: installationID,
		operationID:    operationID,
		planDigest:     planDigest,
		canonicalPlan:  append([]byte(nil), canonicalPlan...),
	}, nil
}

// InstallationID returns the selected local installation.
func (r ResolvedBootstrap) InstallationID() string { return r.installationID }

// OperationID returns the exact resumable installation operation.
func (r ResolvedBootstrap) OperationID() install.OperationID { return r.operationID }

// PlanDigest returns the immutable canonical-plan binding.
func (r ResolvedBootstrap) PlanDigest() install.PlanDigest { return r.planDigest }

// CanonicalPlan returns a caller-owned copy.
func (r ResolvedBootstrap) CanonicalPlan() []byte { return append([]byte(nil), r.canonicalPlan...) }

// Valid reports whether the value was constructed with all required authority.
func (r ResolvedBootstrap) Valid() bool {
	bound, err := install.BindPlan(r.canonicalPlan)
	return validInstallationID(r.installationID) && !r.operationID.IsZero() &&
		!r.planDigest.IsZero() && err == nil && bound.Equal(r.planDigest)
}
