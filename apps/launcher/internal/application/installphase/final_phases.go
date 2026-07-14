package installphase

import (
	"context"
	"errors"
	"reflect"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/activereleaseapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/readinessapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

// ReadinessPhase is the concrete InstallApplication VerifyReadiness adapter.
type ReadinessPhase struct {
	plans    ReadinessPlanQuery
	verifier ReadinessVerifier
}

// NewReadinessPhase requires both authenticated plan resolution and the
// complete readiness use case.
func NewReadinessPhase(plans ReadinessPlanQuery, verifier ReadinessVerifier) (*ReadinessPhase, error) {
	if nilPort(plans) || nilPort(verifier) {
		return nil, errors.New("readiness phase capabilities are required")
	}
	return &ReadinessPhase{plans: plans, verifier: verifier}, nil
}

// VerifyReadiness runs the complete gate and returns a recoverable phase
// outcome for valid negative evidence. It never manufactures success.
func (p *ReadinessPhase) VerifyReadiness(
	ctx context.Context,
	request installapp.PhaseRequest,
) (installapp.PhaseOutput, error) {
	if !validRequest(request) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	plan, err := p.plans.ResolveReadinessPlan(ctx, request.PlanDigest())
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodePlanUnavailable)
	}
	if !plan.PlanDigest.Equal(request.PlanDigest()) || !plan.RuntimeOwnership.Resolved() {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	verification, err := p.verifier.Verify(ctx, readinessapp.Command{
		OperationID: request.OperationID(), PlanDigest: request.PlanDigest(),
		ReleaseID: plan.ReleaseID, GenerationID: plan.GenerationID,
		ManifestDigest: plan.ManifestDigest, ComposeDigest: plan.ComposeDigest,
		CoreEndpoint: plan.CoreEndpoint, APICredentialPath: plan.APICredentialPath,
	})
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeReadinessUnavailable)
	}
	if !verification.Ready() {
		if len(verification.Failures()) == 0 {
			return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
		}
		return expectedOutput(installapp.PhaseOutcomeFailedRecoverable, "installation.readiness_retry")
	}
	receipt := verification.Receipt()
	if receipt.IsZero() || receipt.OperationID() != request.OperationID() ||
		!receipt.PlanDigest().Equal(request.PlanDigest()) || receipt.ReleaseID() != plan.ReleaseID ||
		receipt.GenerationID() != plan.GenerationID || !receipt.ManifestDigest().Equal(plan.ManifestDigest) ||
		!receipt.ComposeDigest().Equal(plan.ComposeDigest) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	return completedOutput(
		request.PlanDigest(),
		receipt.Digest(),
		plan.RuntimeOwnership,
		"preserve.previous_active_release",
		"installation.continue",
		"readiness",
		"verified",
	)
}

// ActiveReleasePhase is the concrete CommitActiveRelease phase adapter.
type ActiveReleasePhase struct {
	plans     ActivationPlanQuery
	committer ActiveReleaseCommitter
	capacity  ArtifactCapacityApplication
}

// NewActiveReleasePhase requires an authenticated activation projection and
// the crash-resumable host/Core committer.
func NewActiveReleasePhase(plans ActivationPlanQuery, committer ActiveReleaseCommitter, capacity ArtifactCapacityApplication) (*ActiveReleasePhase, error) {
	if nilPort(plans) || nilPort(committer) || nilPort(capacity) {
		return nil, errors.New("active release phase capabilities are required")
	}
	return &ActiveReleasePhase{plans: plans, committer: committer, capacity: capacity}, nil
}

// CommitActiveRelease passes only the exact persisted readiness receipt and
// signed monotonic resource tuple into the activation transaction.
func (p *ActiveReleasePhase) CommitActiveRelease(
	ctx context.Context,
	request installapp.PhaseRequest,
) (installapp.PhaseOutput, error) {
	if !validRequest(request) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	plan, err := p.plans.ResolveActivationPlan(ctx, request.PlanDigest(), request.OperationID())
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodePlanUnavailable)
	}
	if !plan.PlanDigest.Equal(request.PlanDigest()) || !plan.RuntimeOwnership.Resolved() ||
		plan.ReadinessReceiptDigest.IsZero() || plan.CapacityCommand.OperationID != request.OperationID().String() ||
		plan.CapacityCommand.Plan.Digest().IsZero() {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	capacityResult, capacityError := p.capacity.TransferActivationCapacity(ctx, plan.CapacityCommand, plan.GenerationID, plan.InstallationID)
	if capacityError != nil || !validActivationCapacity(capacityResult, plan.CapacityCommand, plan.GenerationID, plan.InstallationID) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeActivationUnavailable)
	}
	result, err := p.committer.Commit(ctx, activereleaseapp.Command{
		OperationID: request.OperationID(), PlanDigest: request.PlanDigest(),
		InstallationID: plan.InstallationID, ReleaseID: plan.ReleaseID, GenerationID: plan.GenerationID,
		ManifestDigest: plan.ManifestDigest, ComposeDigest: plan.ComposeDigest,
		ReadinessReceiptDigest: plan.ReadinessReceiptDigest, RuntimeEndpoint: plan.RuntimeEndpoint,
		ReleaseSequence: plan.ReleaseSequence, ResourceInventoryVersion: plan.ResourceInventoryVersion,
		ResourceInventoryDigest: plan.ResourceInventoryDigest, SecurityEpoch: plan.SecurityEpoch,
	})
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeActivationUnavailable)
	}
	if result.Status != activereleaseapp.StatusCommitted || result.PointerDigest.IsZero() {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	return completedOutput(
		plan.ReadinessReceiptDigest,
		result.PointerDigest,
		plan.RuntimeOwnership,
		"retain.prior_generation",
		"installation.ready",
		"activation",
		"committed",
	)
}

func validActivationCapacity(
	result artifactapp.CapacityResult,
	command artifactapp.CapacityCommand,
	generationID string,
	installationID string,
) bool {
	if result.Version == 0 || command.OperationID == "" || command.ParentPlanDigest.IsZero() || command.ReleaseID == "" ||
		command.Plan.Digest().IsZero() || generationID == "" || installationID == "" {
		return false
	}
	expanded := make(map[string]artifactacquisition.Artifact)
	for _, artifact := range command.Plan.Artifacts() {
		if artifact.ExpandedBytes() != 0 {
			expanded[artifact.ID()] = artifact
		}
	}
	projections := make(map[string]artifactapp.SecretProjectionCapacity, len(command.SecretProjections))
	for _, projection := range command.SecretProjections {
		if projection.Name == "" || projection.Purpose == "" || projection.ReservedBytes == 0 {
			return false
		}
		if _, duplicate := projections[projection.Name]; duplicate {
			return false
		}
		projections[projection.Name] = projection
	}
	if len(projections) != 6 || len(result.Leases) != len(expanded)+len(projections)+2 {
		return false
	}
	seenLeases := make(map[string]struct{}, len(result.Leases))
	seenExpanded := make(map[string]struct{}, len(expanded))
	seenProjections := make(map[string]struct{}, len(projections))
	rollbackSeen, safetySeen := false, false
	for _, lease := range result.Leases {
		if lease.LeaseID == "" || lease.Owner != command.OperationID || lease.PlanDigest != command.ParentPlanDigest.String() ||
			lease.PoolID == "" || lease.PoolKind == "" || lease.Bytes == 0 || lease.ReceiptToken == "" ||
			lease.State != string(artifactacquisition.LeaseTransferred) || lease.ReleaseFrom != "" ||
			lease.ReleaseKind != "" || lease.ReleaseReceiptToken != "" {
			return false
		}
		if _, duplicate := seenLeases[lease.LeaseID]; duplicate {
			return false
		}
		seenLeases[lease.LeaseID] = struct{}{}
		switch artifactacquisition.LeasePurpose(lease.Purpose) {
		case artifactacquisition.LeaseExpanded:
			artifact, exists := expanded[lease.ArtifactID]
			if !exists || lease.NewOwner != generationID || lease.Bytes != artifact.ExpandedBytes() ||
				lease.ExpectedTargetDigest != artifact.ExpandedDigest().Hex() || lease.TargetDigest != artifact.ExpandedDigest().Hex() ||
				lease.UsageBytes == 0 || lease.UsageBytes > lease.Bytes {
				return false
			}
			if _, duplicate := seenExpanded[lease.ArtifactID]; duplicate {
				return false
			}
			seenExpanded[lease.ArtifactID] = struct{}{}
		case artifactacquisition.LeaseSecretProjection:
			projection, exists := projections[lease.ArtifactID]
			if !exists || lease.ResourcePurpose != projection.Purpose || lease.Bytes != projection.ReservedBytes ||
				lease.ProjectionInstallationID != command.InstallationID || lease.ProjectionReleaseID != command.ReleaseID ||
				lease.ProjectionGenerationID != command.GenerationID ||
				lease.NewOwner != generationID || lease.SourceDigest != "" || lease.SourceBytes != 0 ||
				lease.ExpectedTargetDigest != "" || lease.TargetDigest != "" || lease.UsageBytes != 0 ||
				lease.TargetKind != "" || lease.TargetStorageID != "" || lease.TargetAuthorityDigest != "" || lease.TargetRoot != "" {
				return false
			}
			if _, duplicate := seenProjections[lease.ArtifactID]; duplicate {
				return false
			}
			seenProjections[lease.ArtifactID] = struct{}{}
		case artifactacquisition.LeaseRollback:
			if rollbackSeen || lease.ArtifactID != "" || lease.ResourcePurpose != "" || lease.NewOwner != generationID ||
				lease.Bytes != command.Plan.Totals().RollbackHeadroomBytes() || lease.ExpectedTargetDigest != "" ||
				lease.TargetDigest != "" || lease.UsageBytes != 0 {
				return false
			}
			rollbackSeen = true
		case artifactacquisition.LeaseSafety:
			if safetySeen || lease.ArtifactID != "" || lease.NewOwner != installationID ||
				lease.Bytes != command.Plan.Totals().SafetyHeadroomBytes() || lease.ExpectedTargetDigest != "" ||
				lease.TargetDigest != "" || lease.UsageBytes != 0 {
				return false
			}
			safetySeen = true
		default:
			return false
		}
	}
	return rollbackSeen && safetySeen && len(seenExpanded) == len(expanded) && len(seenProjections) == len(projections)
}

func validRequest(request installapp.PhaseRequest) bool {
	return !request.OperationID().IsZero() && !request.PlanDigest().IsZero() && request.Attempt() > 0 &&
		len(request.CanonicalPlan()) > 0
}

func completedOutput(
	inputBinding interface{ String() string },
	output install.Digest,
	ownership install.RuntimeOwnership,
	compensationKey string,
	nextActionKey string,
	factName string,
	factValue string,
) (installapp.PhaseOutput, error) {
	input, err := install.ParseDigest(inputBinding.String())
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	compensation, err := install.NewCompensationBoundary(compensationKey)
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	nextAction, err := install.NewSafeAction(nextActionKey)
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	fact, err := install.NewNonSecretFact(factName, factValue)
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	return installapp.NewCompletedPhaseOutput(installapp.CompletionOutput{
		InputDigest: input, OutputDigest: output, Facts: []install.NonSecretFact{fact},
		RuntimeOwnership: ownership, CompensationBoundary: compensation, NextSafeAction: nextAction,
	})
}

func expectedOutput(outcome installapp.PhaseOutcome, nextActionKey string) (installapp.PhaseOutput, error) {
	nextAction, err := install.NewSafeAction(nextActionKey)
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	return installapp.NewExpectedPhaseOutput(outcome, nextAction)
}

func nilPort(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid,
		reflect.Bool,
		reflect.Int,
		reflect.Int8,
		reflect.Int16,
		reflect.Int32,
		reflect.Int64,
		reflect.Uint,
		reflect.Uint8,
		reflect.Uint16,
		reflect.Uint32,
		reflect.Uint64,
		reflect.Uintptr,
		reflect.Float32,
		reflect.Float64,
		reflect.Complex64,
		reflect.Complex128,
		reflect.Array,
		reflect.String,
		reflect.Struct,
		reflect.UnsafePointer:
		return false
	}
	return false
}

var _ installapp.ReadinessPort = (*ReadinessPhase)(nil)
var _ installapp.ActiveReleasePort = (*ActiveReleasePhase)(nil)
