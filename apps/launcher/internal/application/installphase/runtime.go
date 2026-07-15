package installphase

import (
	"context"
	"encoding/hex"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeinstallapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const runtimeParentBindingDomain = "agentmemory.runtime-parent-binding.v1"

// RuntimePlan is an immutable-by-copy authenticated projection. The signed
// catalog evidence digest proves the resolver validated the manifest; this
// adapter does not claim signature-verification capability of its own.
type RuntimePlan struct {
	parentPlanDigest      install.PlanDigest
	canonicalPlan         []byte
	planDigest            runtimeinstall.Hash
	signedCatalogEvidence install.Digest
	parentBindingDigest   install.Digest
}

// NewRuntimePlan binds exact nested canonical bytes and authenticated catalog
// evidence to one parent PF-001 plan.
func NewRuntimePlan(
	parentPlanDigest install.PlanDigest,
	canonicalPlan []byte,
	signedCatalogEvidence install.Digest,
) (RuntimePlan, error) {
	decoded, err := runtimeinstall.DecodePlanV1(canonicalPlan)
	if parentPlanDigest.IsZero() || err != nil || len(decoded.CanonicalBytes()) == 0 || signedCatalogEvidence.IsZero() {
		return RuntimePlan{}, errors.New("runtime plan binding is incomplete")
	}
	plan := RuntimePlan{
		parentPlanDigest:      parentPlanDigest,
		canonicalPlan:         decoded.CanonicalBytes(),
		planDigest:            decoded.Digest(),
		signedCatalogEvidence: signedCatalogEvidence,
	}
	plan.parentBindingDigest = runtimeParentBinding(
		plan.parentPlanDigest,
		plan.planDigest,
		plan.signedCatalogEvidence,
	)
	return plan, nil
}

// ParentPlanDigest returns the authorized parent installation binding.
func (p RuntimePlan) ParentPlanDigest() install.PlanDigest { return p.parentPlanDigest }

// CanonicalPlan returns a caller-owned copy of the exact nested plan bytes.
func (p RuntimePlan) CanonicalPlan() []byte { return append([]byte(nil), p.canonicalPlan...) }

// PlanDigest returns the nested runtime plan binding.
func (p RuntimePlan) PlanDigest() runtimeinstall.Hash { return p.planDigest }

// SignedCatalogEvidenceDigest returns the authenticated manifest proof binding.
func (p RuntimePlan) SignedCatalogEvidenceDigest() install.Digest { return p.signedCatalogEvidence }

// ParentBindingDigest binds the nested signed runtime plan into PF-001 evidence.
func (p RuntimePlan) ParentBindingDigest() install.Digest { return p.parentBindingDigest }

func (p RuntimePlan) validFor(parent install.PlanDigest) bool {
	if parent.IsZero() || !p.parentPlanDigest.Equal(parent) || len(p.canonicalPlan) == 0 ||
		p.planDigest.IsZero() || p.signedCatalogEvidence.IsZero() || p.parentBindingDigest.IsZero() {
		return false
	}
	decoded, err := runtimeinstall.DecodePlanV1(p.canonicalPlan)
	return err == nil && decoded.Digest() == p.planDigest &&
		p.parentBindingDigest.Equal(runtimeParentBinding(parent, p.planDigest, p.signedCatalogEvidence))
}

func runtimeParentBinding(
	parent install.PlanDigest,
	nested runtimeinstall.Hash,
	signedEvidence install.Digest,
) install.Digest {
	canonical := []byte(runtimeParentBindingDomain + "\x00" + parent.String() + "\x00" +
		nested.String() + "\x00" + signedEvidence.String())
	return install.DigestBytes(canonical)
}

// ContainerRuntimePhase is the concrete EnsureContainerRuntime adapter.
type ContainerRuntimePhase struct {
	plans   RuntimePlanQuery
	runtime RuntimeEnsurer
}

// NewContainerRuntimePhase requires authenticated plan resolution and the
// complete resumable PF-006 runtime use case.
func NewContainerRuntimePhase(
	plans RuntimePlanQuery,
	runtime RuntimeEnsurer,
) (*ContainerRuntimePhase, error) {
	if nilPort(plans) || nilPort(runtime) {
		return nil, errors.New("container runtime phase capabilities are required")
	}
	return &ContainerRuntimePhase{plans: plans, runtime: runtime}, nil
}

// EnsureContainerRuntime translates only aggregate-authenticated PF-006
// outcomes. It never infers ownership or completion from runtime availability.
func (p *ContainerRuntimePhase) EnsureContainerRuntime(
	ctx context.Context,
	request installapp.PhaseRequest,
) (installapp.PhaseOutput, error) {
	if !validRequest(request) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	plan, err := p.plans.ResolveRuntimePlan(ctx, request.PlanDigest(), request.OperationID())
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodePlanUnavailable)
	}
	if !plan.validFor(request.PlanDigest()) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}

	command := runtimeinstallapp.Command{
		OperationID:   request.OperationID().String(),
		CanonicalPlan: plan.CanonicalPlan(),
	}
	if receipt, ok := request.ResumeReceipt(); ok {
		runtimeReceipt, conversionError := runtimeHashFromInstallDigest(receipt)
		if conversionError != nil {
			return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
		}
		command.ResumeReceipt = &runtimeReceipt
	}
	result, runtimeError := p.runtime.Ensure(ctx, command)
	if runtimeError != nil && result.Outcome == runtimeinstallapp.OutcomeUnknown {
		if (result.OperationID != "" && result.OperationID != request.OperationID().String()) ||
			(!result.PlanDigest().IsZero() && result.PlanDigest() != plan.PlanDigest()) {
			return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
		}
		return installapp.PhaseOutput{}, phaseError(ErrorCodeRuntimeUnavailable)
	}
	if result.OperationID != request.OperationID().String() || result.PlanDigest() != plan.PlanDigest() ||
		result.Attempt == 0 {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}

	switch result.Outcome {
	case runtimeinstallapp.OutcomeCompleted:
		if runtimeError != nil || result.State != runtimeinstall.OperationStateReady ||
			result.CurrentPhase != runtimeinstall.PhaseUnknown || result.ErrorCode != runtimeinstallapp.ErrorCodeNone {
			return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
		}
		return p.completedOutput(request, plan, result)
	case runtimeinstallapp.OutcomeRebootRequired:
		if runtimeError != nil || result.State != runtimeinstall.OperationStateRebootPending ||
			result.ErrorCode != runtimeinstallapp.ErrorCodeRebootRequired ||
			(result.CurrentPhase != runtimeinstall.PhaseInstallPrerequisites &&
				result.CurrentPhase != runtimeinstall.PhaseInstallRuntime) {
			return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
		}
		receipt, ok := result.RebootReceipt()
		if !ok {
			return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
		}
		converted, conversionError := install.ParseDigest(receipt.String())
		if conversionError != nil {
			return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
		}
		action, actionError := install.NewSafeAction("installation.resume_after_restart")
		if actionError != nil {
			return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
		}
		return installapp.NewRebootRequiredPhaseOutput(converted, action)
	case runtimeinstallapp.OutcomeFailedRecoverable:
		if result.State != runtimeinstall.OperationStateFailedRecoverable || !recoverableRuntimeCode(result.ErrorCode) {
			return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
		}
		if runtimeError != nil {
			var applicationError *runtimeinstallapp.ApplicationError
			if !errors.As(runtimeError, &applicationError) {
				return installapp.PhaseOutput{}, phaseError(ErrorCodeRuntimeUnavailable)
			}
			if applicationError.Code() != result.ErrorCode {
				return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
			}
		}
		return expectedOutput(installapp.PhaseOutcomeFailedRecoverable, "installation.runtime_retry")
	case runtimeinstallapp.OutcomeAdministratorRequired:
		return expectedRuntimeOutcome(runtimeError, result, runtimeinstall.OperationStatePausedForAdministrator,
			runtimeinstallapp.ErrorCodeAdministratorRequired, installapp.PhaseOutcomeAdministratorRequired,
			"installation.runtime_administrator_required")
	case runtimeinstallapp.OutcomeCancelled:
		if !result.CompensationSettled {
			return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
		}
		return expectedRuntimeOutcome(runtimeError, result, runtimeinstall.OperationStateCancelled,
			runtimeinstallapp.ErrorCodeCancelled, installapp.PhaseOutcomeCancelled,
			"installation.runtime_cancelled")
	case runtimeinstallapp.OutcomeUnsupportedHost:
		return expectedRuntimeOutcome(runtimeError, result, runtimeinstall.OperationStateUnsupportedHost,
			runtimeinstallapp.ErrorCodeUnsupportedHost, installapp.PhaseOutcomeUnsupportedHost,
			"installation.runtime_unsupported_host")
	case runtimeinstallapp.OutcomeRuntimeConflict:
		return expectedRuntimeOutcome(runtimeError, result, runtimeinstall.OperationStateRuntimeConflict,
			runtimeinstallapp.ErrorCodeRuntimeConflict, installapp.PhaseOutcomeRuntimeConflict,
			"installation.runtime_conflict")
	case runtimeinstallapp.OutcomeUnknown:
	}
	return installapp.PhaseOutput{}, phaseError(ErrorCodeRuntimeUnavailable)
}

// CancelContainerRuntime durably settles only the exact PF-006 child bound to
// this parent operation. A missing child is an authenticated no-op, while a
// concurrently completed child is preserved.
func (p *ContainerRuntimePhase) CancelContainerRuntime(
	ctx context.Context,
	request installapp.PhaseRequest,
) error {
	if !validRequest(request) {
		return phaseError(ErrorCodeInvalidBinding)
	}
	plan, err := p.plans.ResolveRuntimePlan(ctx, request.PlanDigest(), request.OperationID())
	if err != nil {
		return phaseError(ErrorCodePlanUnavailable)
	}
	if !plan.validFor(request.PlanDigest()) {
		return phaseError(ErrorCodeInvalidBinding)
	}
	result, runtimeError := p.runtime.Cancel(ctx, runtimeinstallapp.Command{
		OperationID: request.OperationID().String(), CanonicalPlan: plan.CanonicalPlan(),
	})
	if runtimeError != nil {
		return phaseError(ErrorCodeRuntimeUnavailable)
	}
	if result.OperationID != request.OperationID().String() || result.PlanDigest() != plan.PlanDigest() ||
		!result.CompensationSettled {
		return phaseError(ErrorCodeInvalidBinding)
	}
	switch result.State {
	case runtimeinstall.OperationStateCancelled:
		if result.Outcome != runtimeinstallapp.OutcomeCancelled ||
			result.ErrorCode != runtimeinstallapp.ErrorCodeCancelled {
			return phaseError(ErrorCodeInvalidBinding)
		}
		return nil
	case runtimeinstall.OperationStateReady:
		if result.Outcome != runtimeinstallapp.OutcomeCompleted ||
			result.ErrorCode != runtimeinstallapp.ErrorCodeNone || result.Attempt == 0 {
			return phaseError(ErrorCodeInvalidBinding)
		}
		return nil
	case runtimeinstall.OperationStateUnknown,
		runtimeinstall.OperationStateRunning,
		runtimeinstall.OperationStateRebootPending,
		runtimeinstall.OperationStatePausedForAdministrator,
		runtimeinstall.OperationStateUnsupportedHost,
		runtimeinstall.OperationStateRuntimeConflict,
		runtimeinstall.OperationStateFailedRecoverable:
		return phaseError(ErrorCodeInvalidBinding)
	}
	return phaseError(ErrorCodeInvalidBinding)
}

func (p *ContainerRuntimePhase) completedOutput(
	request installapp.PhaseRequest,
	plan RuntimePlan,
	result runtimeinstallapp.Result,
) (installapp.PhaseOutput, error) {
	receipt, ok := result.CompletionReceipt()
	if !ok || receipt.OperationID() != request.OperationID().String() ||
		receipt.PlanDigest() != plan.PlanDigest() || receipt.AggregateVersion() != result.Version ||
		receipt.OwnershipRecordDigest().IsZero() || !receipt.Valid() {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	outputDigest, err := install.ParseDigest(receipt.ReceiptDigest().String())
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	artifactDigest, err := install.ParseDigest(receipt.ArtifactDigest().String())
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	ownership, ok := installOwnership(receipt.Ownership())
	if !ok {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	compensation, err := install.NewCompensationBoundary("preserve.container_runtime")
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	action, err := install.NewSafeAction("installation.continue")
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	fact, err := install.NewNonSecretFact("runtime_status", "verified")
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	return installapp.NewCompletedPhaseOutput(installapp.CompletionOutput{
		InputDigest:            plan.ParentBindingDigest(),
		OutputDigest:           outputDigest,
		VerifiedArtifactDigest: artifactDigest,
		Facts:                  []install.NonSecretFact{fact},
		RuntimeOwnership:       ownership,
		CompensationBoundary:   compensation,
		NextSafeAction:         action,
	})
}

func expectedRuntimeOutcome(
	runtimeError error,
	result runtimeinstallapp.Result,
	state runtimeinstall.OperationState,
	code runtimeinstallapp.ErrorCode,
	outcome installapp.PhaseOutcome,
	action string,
) (installapp.PhaseOutput, error) {
	if runtimeError != nil || result.State != state || result.ErrorCode != code {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	return expectedOutput(outcome, action)
}

func recoverableRuntimeCode(code runtimeinstallapp.ErrorCode) bool {
	switch code {
	case runtimeinstallapp.ErrorCodeInternal,
		runtimeinstallapp.ErrorCodeDeadlineExceeded,
		runtimeinstallapp.ErrorCodeConflict,
		runtimeinstallapp.ErrorCodeIntegrityViolation:
		return true
	case runtimeinstallapp.ErrorCodeNone,
		runtimeinstallapp.ErrorCodeInvalidArgument,
		runtimeinstallapp.ErrorCodeAdministratorRequired,
		runtimeinstallapp.ErrorCodeCancelled,
		runtimeinstallapp.ErrorCodeUnsupportedHost,
		runtimeinstallapp.ErrorCodeRuntimeConflict,
		runtimeinstallapp.ErrorCodeRebootRequired:
		return false
	}
	return false
}

func installOwnership(value runtimeinstall.OwnershipDisposition) (install.RuntimeOwnership, bool) {
	switch value {
	case runtimeinstall.OwnershipReusedExternal:
		return install.RuntimeOwnershipReusedExternal, true
	case runtimeinstall.OwnershipProvisionedByAgentMemory:
		return install.RuntimeOwnershipProvisionedByAgentMemory, true
	case runtimeinstall.OwnershipUnknown:
		return install.RuntimeOwnershipUnknown, false
	}
	return install.RuntimeOwnershipUnknown, false
}

func runtimeHashFromInstallDigest(value install.Digest) (runtimeinstall.Hash, error) {
	decoded, err := hex.DecodeString(value.String())
	if err != nil || len(decoded) != len(runtimeinstall.Hash{}) {
		return runtimeinstall.Hash{}, errors.New("runtime receipt digest is invalid")
	}
	var result runtimeinstall.Hash
	copy(result[:], decoded)
	if result.IsZero() {
		return runtimeinstall.Hash{}, errors.New("runtime receipt digest is zero")
	}
	return result, nil
}

var _ installapp.ContainerRuntimePort = (*ContainerRuntimePhase)(nil)
