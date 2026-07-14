package installphase

import (
	"context"
	"errors"
	"strconv"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

// SpaceReservationPhase adapts the exact reservation use case to PF-001.
type SpaceReservationPhase struct {
	plans     ArtifactAcquisitionPlanQuery
	artifacts ArtifactApplication
	capacity  ArtifactCapacityApplication
}

// NewSpaceReservationPhase requires an authenticated parent-plan projection
// and the complete artifact application.
func NewSpaceReservationPhase(
	plans ArtifactAcquisitionPlanQuery,
	artifacts ArtifactApplication,
	capacity ArtifactCapacityApplication,
) (*SpaceReservationPhase, error) {
	if nilPort(plans) || nilPort(artifacts) || nilPort(capacity) {
		return nil, errors.New("space reservation phase capabilities are required")
	}
	return &SpaceReservationPhase{plans: plans, artifacts: artifacts, capacity: capacity}, nil
}

// ReserveSpace records only the aggregate's durable exact reservation proof.
func (p *SpaceReservationPhase) ReserveSpace(
	ctx context.Context,
	request installapp.PhaseRequest,
) (installapp.PhaseOutput, error) {
	if !validRequest(request) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	projection, err := p.resolve(ctx, request)
	if err != nil {
		return installapp.PhaseOutput{}, err
	}
	capacityResult, err := p.capacity.ReserveCapacity(ctx, capacityCommand(request, projection))
	if err != nil || capacityResult.Version == 0 || len(capacityResult.Leases) == 0 {
		return reservationFailure(err)
	}
	result, err := p.artifacts.ReserveSpace(ctx, artifactapp.Command{
		OperationID: request.OperationID().String(), Plan: projection.AcquisitionPlan,
	})
	if err != nil {
		return reservationFailure(err)
	}
	expectedID, idError := projection.AcquisitionPlan.ReservationID(request.OperationID().String())
	if idError != nil || result.Version == 0 || result.ReservationID != expectedID ||
		result.ReservedBytes != projection.AcquisitionPlan.Totals().DownloadBytes() || result.AggregateEvidence.IsZero() {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	evidence, err := install.ParseDigest(result.AggregateEvidence.Hex())
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	return completedOutput(
		request.PlanDigest(), evidence, projection.RuntimeOwnership,
		"release.space_reservation", "installation.continue", "reserved_bytes",
		strconv.FormatUint(projection.AcquisitionPlan.Totals().RequiredBytes(), 10),
	)
}

// ReleaseSpace settles any aggregate-owned reservation after the parent saga
// has durably recorded cancellation or rollback. An absent/pristine aggregate
// is an idempotent no-op; an allocating or active aggregate must complete its
// journal-authorized release protocol before this method succeeds.
func (p *SpaceReservationPhase) ReleaseSpace(
	ctx context.Context,
	request installapp.PhaseRequest,
	reason installapp.ReservationReleaseReason,
) error {
	if !validRequest(request) {
		return phaseError(ErrorCodeInvalidBinding)
	}
	projection, err := p.resolve(ctx, request)
	if err != nil {
		return err
	}
	artifactReason := artifactacquisition.ReleaseReason("")
	switch reason {
	case installapp.ReservationReleaseCompleted:
		artifactReason = artifactacquisition.ReleaseReasonCompleted
	case installapp.ReservationReleaseCancelled:
		artifactReason = artifactacquisition.ReleaseReasonCancelled
	case installapp.ReservationReleaseRollback:
		artifactReason = artifactacquisition.ReleaseReasonRollback
	case installapp.ReservationReleaseUnknown:
		return phaseError(ErrorCodeInvalidBinding)
	default:
		return phaseError(ErrorCodeInvalidBinding)
	}
	capacity := capacityCommand(request, projection)
	var capacityError error
	if reason == installapp.ReservationReleaseCompleted {
		_, capacityError = p.capacity.ReleaseOperationCapacity(ctx, capacity)
	} else {
		_, capacityError = p.capacity.CompensateOperationCapacity(ctx, capacity)
	}
	if capacityError != nil {
		return phaseError(ErrorCodeReservationUnavailable)
	}
	_, err = p.artifacts.ReleaseReservationIfPresent(ctx, artifactapp.Command{
		OperationID: request.OperationID().String(), Plan: projection.AcquisitionPlan,
	}, artifactReason)
	if err != nil {
		return phaseError(ErrorCodeReservationUnavailable)
	}
	return nil
}

func (p *SpaceReservationPhase) resolve(
	ctx context.Context,
	request installapp.PhaseRequest,
) (ArtifactAcquisitionPlan, error) {
	projection, err := p.plans.ResolveArtifactAcquisitionPlan(ctx, request.PlanDigest())
	if err != nil {
		return ArtifactAcquisitionPlan{}, phaseError(ErrorCodePlanUnavailable)
	}
	if !validArtifactProjection(projection, request.PlanDigest()) {
		return ArtifactAcquisitionPlan{}, phaseError(ErrorCodeInvalidBinding)
	}
	return projection, nil
}

// ComposeBundlePhase acquires and re-verifies every plan artifact before it
// emits the exact Compose CAS digest as installation evidence.
type ComposeBundlePhase struct {
	plans     ArtifactAcquisitionPlanQuery
	artifacts ArtifactApplication
	capacity  ArtifactCapacityApplication
}

// NewComposeBundlePhase requires the same authenticated projection and
// aggregate-backed artifact application as ReserveSpace.
func NewComposeBundlePhase(
	plans ArtifactAcquisitionPlanQuery,
	artifacts ArtifactApplication,
	capacity ArtifactCapacityApplication,
) (*ComposeBundlePhase, error) {
	if nilPort(plans) || nilPort(artifacts) || nilPort(capacity) {
		return nil, errors.New("compose bundle phase capabilities are required")
	}
	return &ComposeBundlePhase{plans: plans, artifacts: artifacts, capacity: capacity}, nil
}

// EnsureComposeBundle can succeed only after artifactapp restores a durable
// reservation and verifies every final CAS object against the signed plan.
func (p *ComposeBundlePhase) EnsureComposeBundle(
	ctx context.Context,
	request installapp.PhaseRequest,
) (installapp.PhaseOutput, error) {
	if !validRequest(request) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	projection, err := p.plans.ResolveArtifactAcquisitionPlan(ctx, request.PlanDigest())
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodePlanUnavailable)
	}
	if !validArtifactProjection(projection, request.PlanDigest()) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	composeArtifact, exists := projection.AcquisitionPlan.Artifact(projection.ComposeArtifactID)
	if !exists {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	result, err := p.artifacts.Acquire(ctx, artifactapp.Command{
		OperationID: request.OperationID().String(), Plan: projection.AcquisitionPlan,
	})
	if err != nil {
		return acquisitionFailure(err)
	}
	if !validAcquisitionEvidence(projection.AcquisitionPlan, result) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	for _, artifact := range projection.AcquisitionPlan.Artifacts() {
		if artifact.ExpandedBytes() == 0 {
			continue
		}
		capacityResult, capacityError := p.capacity.ConsumeArtifactExpansion(ctx, capacityCommand(request, projection), artifact.ID())
		if capacityError != nil || capacityResult.Version == 0 {
			return installapp.PhaseOutput{}, phaseError(ErrorCodeArtifactUnavailable)
		}
	}
	aggregateEvidence, aggregateError := install.ParseDigest(result.AggregateEvidence.Hex())
	composeDigest, composeError := install.ParseDigest(composeArtifact.Digest().Hex())
	if aggregateError != nil || composeError != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	fact, err := install.NewNonSecretFact("artifacts_verified", strconv.FormatUint(uint64(result.CompletedArtifacts), 10))
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	compensation, err := install.NewCompensationBoundary("retain.verified_bundle")
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	nextAction, err := install.NewSafeAction("installation.continue")
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	input, err := install.ParseDigest(request.PlanDigest().String())
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	return installapp.NewCompletedPhaseOutput(installapp.CompletionOutput{
		InputDigest: input, OutputDigest: aggregateEvidence, VerifiedArtifactDigest: composeDigest,
		Facts: []install.NonSecretFact{fact}, RuntimeOwnership: projection.RuntimeOwnership,
		CompensationBoundary: compensation, NextSafeAction: nextAction,
	})
}

func validArtifactProjection(projection ArtifactAcquisitionPlan, parent install.PlanDigest) bool {
	if !projection.ParentPlanDigest.Equal(parent) || projection.AcquisitionPlanDigest.IsZero() ||
		!projection.RuntimeOwnership.Resolved() || projection.ComposeArtifactID == "" ||
		projection.InstallationID == "" || projection.ReleaseID == "" || projection.GenerationID == "" || len(projection.SecretProjections) != 6 ||
		projection.HostCASCapacity.Kind != artifactapp.CapacityHostCAS ||
		projection.HostReleaseCapacity.Kind != artifactapp.CapacityHostRelease ||
		projection.DockerEngineCapacity.Kind != artifactapp.CapacityDockerEngine ||
		projection.DockerVolumeCapacity.Kind != artifactapp.CapacityDockerDataVolume {
		return false
	}
	digest, err := install.ParseDigest(projection.AcquisitionPlan.Digest().Hex())
	if err != nil || !digest.Equal(projection.AcquisitionPlanDigest) {
		return false
	}
	_, exists := projection.AcquisitionPlan.Artifact(projection.ComposeArtifactID)
	return exists
}

func capacityCommand(request installapp.PhaseRequest, projection ArtifactAcquisitionPlan) artifactapp.CapacityCommand {
	return artifactapp.CapacityCommand{OperationID: request.OperationID().String(), ParentPlanDigest: request.PlanDigest(),
		InstallationID: projection.InstallationID, ReleaseID: projection.ReleaseID, GenerationID: projection.GenerationID,
		Plan: projection.AcquisitionPlan, SecretProjections: append([]artifactapp.SecretProjectionCapacity(nil), projection.SecretProjections...),
		HostCAS: projection.HostCASCapacity, HostRelease: projection.HostReleaseCapacity,
		DockerEngine:     projection.DockerEngineCapacity,
		DockerDataVolume: projection.DockerVolumeCapacity}
}

func validAcquisitionEvidence(plan artifactacquisition.Plan, result artifactapp.AcquireResult) bool {
	artifacts := plan.Artifacts()
	if result.Version == 0 || result.AggregateEvidence.IsZero() || !result.ReservationRetained ||
		uint64(result.CompletedArtifacts) != uint64(len(artifacts)) || len(result.VerifiedArtifacts) != len(artifacts) {
		return false
	}
	seen := make(map[string]struct{}, len(result.VerifiedArtifacts))
	for _, evidence := range result.VerifiedArtifacts {
		expected, exists := plan.Artifact(evidence.ID)
		if !exists || evidence.Digest != expected.Digest() || evidence.Size != expected.Size() ||
			evidence.ContentKey != expected.ContentKey() {
			return false
		}
		if _, duplicate := seen[evidence.ID]; duplicate {
			return false
		}
		seen[evidence.ID] = struct{}{}
	}
	return true
}

func reservationFailure(err error) (installapp.PhaseOutput, error) {
	if errors.Is(err, artifactapp.ErrReservationUnsupported) {
		return expectedOutput(installapp.PhaseOutcomeUnsupportedHost, "installation.select_supported_host")
	}
	var typed *artifactapp.Error
	if errors.As(err, &typed) && typed.Code == artifactapp.ErrorReservation {
		return expectedOutput(installapp.PhaseOutcomeFailedRecoverable, "installation.free_local_space")
	}
	return installapp.PhaseOutput{}, phaseError(ErrorCodeReservationUnavailable)
}

func acquisitionFailure(err error) (installapp.PhaseOutput, error) {
	var typed *artifactapp.Error
	if !errors.As(err, &typed) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeArtifactUnavailable)
	}
	switch typed.Code {
	case artifactapp.ErrorSource, artifactapp.ErrorStore:
		return expectedOutput(installapp.PhaseOutcomeFailedRecoverable, "installation.retry_artifact_acquisition")
	case artifactapp.ErrorIntegrity:
		return expectedOutput(installapp.PhaseOutcomeFailedRecoverable, "installation.obtain_verified_release")
	case artifactapp.ErrorInvalidCommand, artifactapp.ErrorReservation, artifactapp.ErrorRepository, artifactapp.ErrorCompensation:
		return installapp.PhaseOutput{}, phaseError(ErrorCodeArtifactUnavailable)
	}
	return installapp.PhaseOutput{}, phaseError(ErrorCodeArtifactUnavailable)
}

var _ installapp.SpaceReservationPort = (*SpaceReservationPhase)(nil)
var _ installapp.ComposeBundlePort = (*ComposeBundlePhase)(nil)
