// Package installphase adapts typed PF-001 sub-use cases to InstallApplication
// phase capabilities without weakening their authenticated plan bindings.
package installphase

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/activereleaseapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/hostverifyapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/brainbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productinstall"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productstack"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/readinessapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/resourceapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeinstallapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

// HostVerificationPlan is an authenticated parent projection carrying the
// independently signed exact host policy.
type HostVerificationPlan struct {
	ParentPlanDigest install.PlanDigest
	SignedHostPlan   hostverification.SignedPlan
	RuntimeOwnership install.RuntimeOwnership
}

// HostVerificationPlanQuery resolves host authority by exact parent digest.
type HostVerificationPlanQuery interface {
	ResolveHostVerificationPlan(context.Context, install.PlanDigest) (HostVerificationPlan, error)
}

// HostVerifier is implemented by hostverifyapp.Application.
type HostVerifier interface {
	Verify(context.Context, hostverifyapp.Command) (hostverifyapp.Verification, error)
}

var _ HostVerifier = (*hostverifyapp.Application)(nil)

// ArtifactAcquisitionPlan is an authenticated parent-plan projection. The
// query implementation must derive every field from the canonical plan and
// its already verified signed release inventory.
type ArtifactAcquisitionPlan struct {
	ParentPlanDigest      install.PlanDigest
	InstallationID        string
	ReleaseID             string
	GenerationID          string
	AcquisitionPlanDigest install.Digest
	AcquisitionPlan       artifactacquisition.Plan
	ComposeArtifactID     string
	RuntimeOwnership      install.RuntimeOwnership
	SecretProjections     []artifactapp.SecretProjectionCapacity
	HostCASCapacity       artifactapp.CapacityTarget
	HostReleaseCapacity   artifactapp.CapacityTarget
	DockerEngineCapacity  artifactapp.CapacityTarget
	DockerVolumeCapacity  artifactapp.CapacityTarget
}

// ArtifactAcquisitionPlanQuery resolves the exact acquisition projection
// authorized by the immutable parent installation plan.
type ArtifactAcquisitionPlanQuery interface {
	ResolveArtifactAcquisitionPlan(context.Context, install.PlanDigest) (ArtifactAcquisitionPlan, error)
}

// ArtifactApplication is implemented by artifactapp.Application. Keeping one
// capability ensures reservation and acquisition share one aggregate journal.
type ArtifactApplication interface {
	ReserveSpace(context.Context, artifactapp.Command) (artifactapp.ReserveResult, error)
	Acquire(context.Context, artifactapp.Command) (artifactapp.AcquireResult, error)
	ReleaseReservation(context.Context, artifactapp.Command, artifactacquisition.ReleaseReason) (artifactapp.ReleaseResult, error)
	ReleaseReservationIfPresent(context.Context, artifactapp.Command, artifactacquisition.ReleaseReason) (artifactapp.ReleaseResult, error)
}

// ArtifactCapacityApplication is the mandatory per-pool lease coordinator.
type ArtifactCapacityApplication interface {
	ReserveCapacity(context.Context, artifactapp.CapacityCommand) (artifactapp.CapacityResult, error)
	ConsumeArtifactExpansion(context.Context, artifactapp.CapacityCommand, string) (artifactapp.CapacityResult, error)
	PrepareSecretProjectionCapacity(context.Context, artifactapp.CapacityCommand, string) (artifactapp.CapacityResult, error)
	TransferActivationCapacity(context.Context, artifactapp.CapacityCommand, string, string) (artifactapp.CapacityResult, error)
	ReleaseOperationCapacity(context.Context, artifactapp.CapacityCommand) (artifactapp.CapacityResult, error)
	CompensateOperationCapacity(context.Context, artifactapp.CapacityCommand) (artifactapp.CapacityResult, error)
	ReleaseActivatedCapacity(context.Context, artifactapp.CapacityCommand, string, string) (artifactapp.CapacityResult, error)
}

// RuntimePlanQuery resolves an authenticated, signed nested runtime plan
// projection that is cryptographically bound to the parent installation plan.
type RuntimePlanQuery interface {
	ResolveRuntimePlan(context.Context, install.PlanDigest, install.OperationID) (RuntimePlan, error)
}

// RuntimeEnsurer is the narrow PF-006 use-case boundary implemented by
// runtimeinstallapp.Application.
type RuntimeEnsurer interface {
	Ensure(context.Context, runtimeinstallapp.Command) (runtimeinstallapp.Result, error)
}

var _ RuntimeEnsurer = (*runtimeinstallapp.Application)(nil)

// ReleaseVerificationPlan is the exact signed release projection authorized
// by the parent installation plan. The verifier must distrust every field in
// SignedManifest until its complete trust policy succeeds.
type ReleaseVerificationPlan struct {
	PlanDigest       install.PlanDigest
	ReleaseID        string
	ManifestDigest   install.Digest
	ReleaseSequence  uint64
	SignedManifest   releaseinventory.SignedManifest
	RuntimeOwnership install.RuntimeOwnership
}

// VerifiedRelease is the minimal privacy-safe projection needed to advance
// PF-001 after the complete release verifier succeeds.
type VerifiedRelease struct {
	ReleaseID       string
	ManifestDigest  install.Digest
	ReleaseSequence uint64
}

// ReleasePlanQuery resolves an authenticated canonical-plan projection.
type ReleasePlanQuery interface {
	ResolveReleasePlan(context.Context, install.PlanDigest) (ReleaseVerificationPlan, error)
}

// ReleaseVerifier verifies the signed release and returns only its trusted
// identity. A production implementation delegates to releaseverify.Application.
type ReleaseVerifier interface {
	VerifyRelease(context.Context, releaseinventory.SignedManifest) (VerifiedRelease, error)
}

// ReadinessPlan is the verified plan projection required by the gate.
type ReadinessPlan struct {
	PlanDigest        install.PlanDigest
	ReleaseID         string
	GenerationID      string
	ManifestDigest    install.Digest
	ComposeDigest     install.Digest
	CoreEndpoint      string
	APICredentialPath string
	RuntimeOwnership  install.RuntimeOwnership
}

// ActivationPlan is the verified plan/resource projection required to make a
// readiness-authorized release active.
type ActivationPlan struct {
	PlanDigest               install.PlanDigest
	InstallationID           string
	ReleaseID                string
	GenerationID             string
	ManifestDigest           install.Digest
	ComposeDigest            install.Digest
	ReadinessReceiptDigest   install.Digest
	RuntimeEndpoint          string
	ReleaseSequence          uint64
	ResourceInventoryVersion uint64
	ResourceInventoryDigest  install.Digest
	SecurityEpoch            uint64
	RuntimeOwnership         install.RuntimeOwnership
	CapacityCommand          artifactapp.CapacityCommand
}

// ReadinessPlanQuery resolves an authenticated canonical-plan projection.
type ReadinessPlanQuery interface {
	ResolveReadinessPlan(context.Context, install.PlanDigest) (ReadinessPlan, error)
}

// ActivationPlanQuery resolves an authenticated activation-plan projection.
type ActivationPlanQuery interface {
	ResolveActivationPlan(context.Context, install.PlanDigest, install.OperationID) (ActivationPlan, error)
}

// ReadinessVerifier is implemented by readinessapp.Application.
type ReadinessVerifier interface {
	Verify(context.Context, readinessapp.Command) (readinessapp.Verification, error)
}

// ActiveReleaseCommitter is implemented by activereleaseapp.Application.
type ActiveReleaseCommitter interface {
	Commit(context.Context, activereleaseapp.Command) (activereleaseapp.Result, error)
}

// NetworkVolumePlan is the exact signed projection needed to reconcile Docker
// ownership resources.
type NetworkVolumePlan struct {
	PlanDigest        install.PlanDigest
	InstallationID    string
	GenerationID      string
	Release           string
	CreationOperation string
	Endpoint          containerengine.Endpoint
	RuntimeOwnership  install.RuntimeOwnership
	CapacityCommand   artifactapp.CapacityCommand
}

// NetworkVolumePlanQuery resolves an authenticated resource-plan projection.
type NetworkVolumePlanQuery interface {
	ResolveNetworkVolumePlan(context.Context, install.PlanDigest) (NetworkVolumePlan, error)
}

// ManagedResourceEnsurer is implemented by resourceapp.Application.
type ManagedResourceEnsurer interface {
	EnsureNetworkAndVolumes(context.Context, resourceapp.Command) (resourceapp.Result, error)
}

// DirectoryPlanQuery derives the exact operation/attempt-bound directory
// authorization from the immutable canonical installation plan.
type DirectoryPlanQuery interface {
	ResolveDirectoryCommand(
		context.Context,
		install.PlanDigest,
		install.OperationID,
		uint32,
	) (productinstall.DirectoryCommand, error)
}

// SecretPlanQuery derives the exact operation/attempt-bound protected-secret
// authorization from the immutable canonical installation plan.
type SecretPlanQuery interface {
	ResolveSecretCommand(
		context.Context,
		install.PlanDigest,
		install.OperationID,
		uint32,
	) (productinstall.SecretCommand, error)
}

// StackPlanQuery derives one operation/attempt-bound Docker stack authority
// exclusively from the immutable canonical installation plan.
type StackPlanQuery interface {
	ResolveStackAuthorization(
		context.Context,
		install.PlanDigest,
		install.OperationID,
		uint32,
		productstack.Operation,
	) (productstack.Authorization, error)
}

// BrainBootstrapPlanQuery derives the exact authenticated first-Brain command
// from the immutable canonical installation plan.
type BrainBootstrapPlanQuery interface {
	ResolveBrainBootstrapAuthorization(
		context.Context,
		install.PlanDigest,
		install.OperationID,
		uint32,
	) (brainbootstrap.Authorization, error)
}
