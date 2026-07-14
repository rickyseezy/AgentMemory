package installphase

import (
	"context"
	"errors"
	"strconv"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

// ReleaseVerificationPhase is the concrete InstallApplication VerifyRelease
// adapter. It cannot advance on a signature check alone: its delegate must run
// every digest, trust-evidence, SBOM, provenance, license, vulnerability,
// native-publisher, OCI-index, platform and anti-rollback gate.
type ReleaseVerificationPhase struct {
	plans    ReleasePlanQuery
	verifier ReleaseVerifier
}

// NewReleaseVerificationPhase rejects incomplete and typed-nil composition.
func NewReleaseVerificationPhase(
	plans ReleasePlanQuery,
	verifier ReleaseVerifier,
) (*ReleaseVerificationPhase, error) {
	if nilPort(plans) || nilPort(verifier) {
		return nil, errors.New("release verification phase capabilities are required")
	}
	return &ReleaseVerificationPhase{plans: plans, verifier: verifier}, nil
}

// VerifyRelease verifies and cross-checks the exact release authorized by the
// parent plan. Negative trust evidence never becomes successful phase output.
func (p *ReleaseVerificationPhase) VerifyRelease(
	ctx context.Context,
	request installapp.PhaseRequest,
) (installapp.PhaseOutput, error) {
	if !validRequest(request) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	plan, err := p.plans.ResolveReleasePlan(ctx, request.PlanDigest())
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodePlanUnavailable)
	}
	if !plan.PlanDigest.Equal(request.PlanDigest()) || plan.ReleaseID == "" ||
		plan.ManifestDigest.IsZero() || plan.ReleaseSequence == 0 || !plan.RuntimeOwnership.Resolved() {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}

	verified, err := p.verifier.VerifyRelease(ctx, plan.SignedManifest)
	if err != nil {
		return releaseFailureOutput(err)
	}
	if verified.ReleaseID != plan.ReleaseID ||
		!verified.ManifestDigest.Equal(plan.ManifestDigest) ||
		verified.ReleaseSequence != plan.ReleaseSequence {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}

	compensation, compensationErr := install.NewCompensationBoundary("retain.verified_release")
	nextAction, actionErr := install.NewSafeAction("installation.continue")
	fact, factErr := install.NewNonSecretFact("release_sequence", strconv.FormatUint(plan.ReleaseSequence, 10))
	if compensationErr != nil || actionErr != nil || factErr != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	return installapp.NewCompletedPhaseOutput(installapp.CompletionOutput{
		InputDigest:            install.DigestBytes(request.CanonicalPlan()),
		OutputDigest:           plan.ManifestDigest,
		VerifiedArtifactDigest: plan.ManifestDigest,
		Facts:                  []install.NonSecretFact{fact},
		RuntimeOwnership:       plan.RuntimeOwnership,
		CompensationBoundary:   compensation,
		NextSafeAction:         nextAction,
	})
}

func releaseFailureOutput(err error) (installapp.PhaseOutput, error) {
	var verificationError interface {
		Code() releaseverify.ErrorCode
	}
	if !errors.As(err, &verificationError) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeReleaseUnavailable)
	}
	switch verificationError.Code() {
	case releaseverify.ErrorCodeUnsupportedHost:
		return expectedOutput(installapp.PhaseOutcomeUnsupportedHost, "installation.select_supported_host")
	case releaseverify.ErrorCodeIntegrityViolation,
		releaseverify.ErrorCodeConflict,
		releaseverify.ErrorCodeSchemaUnsupported,
		releaseverify.ErrorCodeForbidden:
		return expectedOutput(installapp.PhaseOutcomeFailedRecoverable, "installation.obtain_verified_release")
	case releaseverify.ErrorCodeDependencyUnavailable,
		releaseverify.ErrorCodeDeadlineExceeded:
		return expectedOutput(installapp.PhaseOutcomeFailedRecoverable, "installation.retry_release_verification")
	case releaseverify.ErrorCodeInternal:
		return installapp.PhaseOutput{}, phaseError(ErrorCodeReleaseUnavailable)
	}
	return installapp.PhaseOutput{}, phaseError(ErrorCodeReleaseUnavailable)
}

// ReleaseApplicationAdapter narrows the complete release verifier to the
// projection consumed by the installation phase.
type ReleaseApplicationAdapter struct {
	application releaseVerificationApplication
}

type releaseVerificationApplication interface {
	Verify(context.Context, releaseinventory.SignedManifest) (releaseverify.VerifiedInventory, error)
}

// NewReleaseApplicationAdapter rejects incomplete and typed-nil composition.
func NewReleaseApplicationAdapter(application releaseVerificationApplication) (*ReleaseApplicationAdapter, error) {
	if nilPort(application) {
		return nil, errors.New("release verification application is required")
	}
	return &ReleaseApplicationAdapter{application: application}, nil
}

// VerifyRelease delegates every trust gate and maps only authenticated fields.
func (a *ReleaseApplicationAdapter) VerifyRelease(
	ctx context.Context,
	signed releaseinventory.SignedManifest,
) (VerifiedRelease, error) {
	inventory, err := a.application.Verify(ctx, signed)
	if err != nil {
		return VerifiedRelease{}, err
	}
	return newVerifiedRelease(inventory.ReleaseID(), inventory.ManifestDigest().Hex(), inventory.Sequence())
}

func newVerifiedRelease(releaseID string, manifestDigest string, sequence uint64) (VerifiedRelease, error) {
	digest, err := install.ParseDigest(manifestDigest)
	if err != nil || releaseID == "" || sequence == 0 {
		return VerifiedRelease{}, phaseError(ErrorCodeInvalidBinding)
	}
	return VerifiedRelease{
		ReleaseID: releaseID, ManifestDigest: digest, ReleaseSequence: sequence,
	}, nil
}

var _ installapp.ReleaseVerificationPort = (*ReleaseVerificationPhase)(nil)
var _ ReleaseVerifier = (*ReleaseApplicationAdapter)(nil)
