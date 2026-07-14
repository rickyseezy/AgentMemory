package runtimeprovision

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeinstallapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const (
	desktopConsentRequestLifetime  = 5 * time.Minute
	desktopMutationRequestLifetime = 5 * time.Minute
	desktopStartDeadline           = 3 * time.Minute
)

// DesktopDependencies are mandatory macOS/Windows provisioning boundaries.
// Missing native signing, consent, elevation, or replay dependencies never
// produce a permissive fallback.
type DesktopDependencies struct {
	Authority             runtimeport.DesktopAuthorityResolver
	Host                  runtimeport.DesktopHostProbe
	Runtime               runtimeport.DesktopRuntimeInspector
	Consent               runtimeport.DesktopConsentBroker
	ConsentAuthenticator  runtimeport.DesktopConsentAuthenticator
	ConsentRepository     runtimeport.DesktopConsentRepository
	Artifacts             runtimeport.DesktopArtifactAcquirer
	ArtifactVerifier      runtimeport.DesktopArtifactVerifier
	Mutation              runtimeport.DesktopMutationBroker
	MutationAuthenticator runtimeport.DesktopMutationAuthenticator
	MutationReplay        runtimeport.DesktopMutationReplayLedger
	Terms                 runtimeport.DesktopTermsObserver
	Launcher              runtimeport.DesktopRuntimeLauncher
	Capabilities          runtimeport.DesktopCapabilityProbe
	Nonces                runtimeport.NonceSource
	Clock                 runtimeport.Clock
}

// DesktopProvisioner implements every PF-006 phase for certified macOS and
// Windows Docker Desktop installations.
type DesktopProvisioner struct {
	authority             runtimeport.DesktopAuthorityResolver
	host                  runtimeport.DesktopHostProbe
	runtime               runtimeport.DesktopRuntimeInspector
	consent               runtimeport.DesktopConsentBroker
	consentAuthenticator  runtimeport.DesktopConsentAuthenticator
	consentRepository     runtimeport.DesktopConsentRepository
	artifacts             runtimeport.DesktopArtifactAcquirer
	artifactVerifier      runtimeport.DesktopArtifactVerifier
	mutation              runtimeport.DesktopMutationBroker
	mutationAuthenticator runtimeport.DesktopMutationAuthenticator
	mutationReplay        runtimeport.DesktopMutationReplayLedger
	terms                 runtimeport.DesktopTermsObserver
	launcher              runtimeport.DesktopRuntimeLauncher
	capabilities          runtimeport.DesktopCapabilityProbe
	nonces                runtimeport.NonceSource
	clock                 runtimeport.Clock
}

// NewDesktopProvisioner constructs only a complete fail-closed provisioner.
func NewDesktopProvisioner(dependencies DesktopDependencies) (*DesktopProvisioner, error) {
	values := []any{
		dependencies.Authority, dependencies.Host, dependencies.Runtime, dependencies.Consent,
		dependencies.ConsentAuthenticator, dependencies.ConsentRepository, dependencies.Artifacts,
		dependencies.ArtifactVerifier, dependencies.Mutation, dependencies.MutationAuthenticator,
		dependencies.MutationReplay, dependencies.Terms, dependencies.Launcher, dependencies.Capabilities,
		dependencies.Nonces, dependencies.Clock,
	}
	for _, value := range values {
		if desktopNilDependency(value) {
			return nil, ErrProvisionIntegrity
		}
	}
	return &DesktopProvisioner{
		authority: dependencies.Authority, host: dependencies.Host, runtime: dependencies.Runtime,
		consent: dependencies.Consent, consentAuthenticator: dependencies.ConsentAuthenticator,
		consentRepository: dependencies.ConsentRepository, artifacts: dependencies.Artifacts,
		artifactVerifier: dependencies.ArtifactVerifier, mutation: dependencies.Mutation,
		mutationAuthenticator: dependencies.MutationAuthenticator, mutationReplay: dependencies.MutationReplay,
		terms: dependencies.Terms, launcher: dependencies.Launcher, capabilities: dependencies.Capabilities,
		nonces: dependencies.Nonces, clock: dependencies.Clock,
	}, nil
}

func desktopNilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Non-nilable dependency values are valid by construction.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid:
		return true
	default:
		return false
	}
}

// DetectHost re-proves platform, principal, machine, virtualization, storage,
// encryption, resource, feature, and WSL facts.
func (p *DesktopProvisioner) DetectHost(
	ctx context.Context,
	request runtimeinstallapp.Request,
) (runtimeinstallapp.Output, error) {
	plan, authority, err := p.resolve(ctx, request)
	if err != nil {
		return mapExpectedOrError(err)
	}
	if plan.Action() == runtimeinstall.PlanActionBlock && hostDecision(plan.DecisionCode()) {
		return expected(runtimeinstallapp.OutcomeUnsupportedHost)
	}
	evidence, err := p.host.ProbeDesktopHost(ctx, authority)
	if err != nil || evidence.Supports(authority) != nil {
		if err == nil {
			err = ErrUnsupportedHost
		}
		return mapExpectedOrError(sanitizeDesktopBoundary(ctx, err, ErrUnsupportedHost))
	}
	return p.completed(request, authority, evidence.Digest(), runtimeinstall.OwnershipUnknown)
}

// DetectRuntime inspects only the authority's explicit local endpoint and
// signed application identity.
func (p *DesktopProvisioner) DetectRuntime(
	ctx context.Context,
	request runtimeinstallapp.Request,
) (runtimeinstallapp.Output, error) {
	plan, authority, err := p.resolve(ctx, request)
	if err != nil {
		return mapExpectedOrError(err)
	}
	if plan.Action() == runtimeinstall.PlanActionBlock {
		return blockOutput(plan.DecisionCode())
	}
	evidence, err := p.runtime.InspectDesktopRuntime(ctx, plan, authority)
	if err != nil {
		return mapExpectedOrError(sanitizeDesktopBoundary(ctx, err, ErrProbeFailed))
	}
	valid := false
	switch plan.Action() {
	case runtimeinstall.PlanActionInstallCertified:
		valid = evidence.Condition() == runtimeinstall.RuntimeConditionAbsent && evidence.Workloads() == 0
	case runtimeinstall.PlanActionStartCompatible:
		valid = evidence.Condition() == runtimeinstall.RuntimeConditionStopped || evidence.Compatible(authority)
	case runtimeinstall.PlanActionAdoptCompatible:
		valid = evidence.Compatible(authority)
	case runtimeinstall.PlanActionRepairManaged:
		valid = evidence.Condition() == runtimeinstall.RuntimeConditionDamaged || evidence.Compatible(authority)
	case runtimeinstall.PlanActionBlock, runtimeinstall.PlanActionUnknown:
	}
	if !valid {
		return expected(runtimeinstallapp.OutcomeRuntimeConflict)
	}
	return p.completed(request, authority, evidence.Digest(), runtimeinstall.OwnershipUnknown)
}

// PlanRuntime binds the already-decoded canonical decision to signed desktop authority.
func (p *DesktopProvisioner) PlanRuntime(
	ctx context.Context,
	request runtimeinstallapp.Request,
) (runtimeinstallapp.Output, error) {
	plan, authority, err := p.resolve(ctx, request)
	if err != nil {
		return mapExpectedOrError(err)
	}
	if plan.Action() == runtimeinstall.PlanActionBlock {
		return blockOutput(plan.DecisionCode())
	}
	return p.completed(request, authority, combineDigests(authority.Digest(), authority.CatalogDigest()), runtimeinstall.OwnershipUnknown)
}

// AwaitRuntimeConsent obtains non-preselected plan, terms, authority, and
// entitlement confirmation before an installer can receive --accept-license.
func (p *DesktopProvisioner) AwaitRuntimeConsent(
	ctx context.Context,
	request runtimeinstallapp.Request,
) (runtimeinstallapp.Output, error) {
	plan, authority, err := p.resolve(ctx, request)
	if err != nil {
		return mapExpectedOrError(err)
	}
	if plan.Action() == runtimeinstall.PlanActionBlock {
		return blockOutput(plan.DecisionCode())
	}
	if passiveAction(plan.Action()) {
		return p.completed(request, authority, authority.Digest(), runtimeinstall.OwnershipUnknown)
	}
	now, nonce, err := p.freshNonce(ctx)
	if err != nil {
		return runtimeinstallapp.Output{}, err
	}
	consentRequest, err := runtimeport.NewDesktopConsentRequest(
		request.OperationID(), request.Attempt(), authority, nonce, now, now.Add(desktopConsentRequestLifetime),
	)
	if err != nil {
		return runtimeinstallapp.Output{}, ErrProvisionIntegrity
	}
	receipt, err := p.consent.AwaitDesktopConsent(ctx, consentRequest)
	if err != nil {
		switch {
		case errors.Is(err, runtimeport.ErrDesktopConsentDeclined):
			return expected(runtimeinstallapp.OutcomeCancelled)
		case errors.Is(err, runtimeport.ErrDesktopConsentUnavailable):
			return expected(runtimeinstallapp.OutcomeAdministratorRequired)
		default:
			return runtimeinstallapp.Output{}, sanitizeDesktopBoundary(ctx, err, ErrProvisionIntegrity)
		}
	}
	if !receipt.Matches(consentRequest, p.clock.Now()) ||
		p.consentAuthenticator.VerifyDesktopConsent(ctx, consentRequest, receipt) != nil ||
		!receipt.Matches(consentRequest, p.clock.Now()) ||
		p.consentRepository.StoreDesktopConsent(ctx, request.OperationID(), receipt) != nil {
		return runtimeinstallapp.Output{}, sanitizeDesktopBoundary(ctx, nil, ErrProvisionIntegrity)
	}
	return p.completed(request, authority, receipt.Digest(), runtimeinstall.OwnershipUnknown)
}

// AcquireRuntime performs exact allowlisted resumable acquisition.
func (p *DesktopProvisioner) AcquireRuntime(
	ctx context.Context,
	request runtimeinstallapp.Request,
) (runtimeinstallapp.Output, error) {
	plan, authority, err := p.resolve(ctx, request)
	if err != nil {
		return mapExpectedOrError(err)
	}
	if plan.Action() == runtimeinstall.PlanActionBlock {
		return blockOutput(plan.DecisionCode())
	}
	if passiveAction(plan.Action()) {
		return p.completed(request, authority, authority.ArtifactSHA256(), runtimeinstall.OwnershipUnknown)
	}
	evidence, err := p.artifacts.AcquireDesktopArtifact(ctx, authority)
	if err != nil || !evidence.AcquiredFor(authority) {
		return runtimeinstallapp.Output{}, sanitizeDesktopBoundary(ctx, err, ErrProbeFailed)
	}
	return p.completed(request, authority, evidence.Digest(), runtimeinstall.OwnershipUnknown)
}

// VerifyRuntimeArtifact reopens the exact artifact and proves digest plus
// Gatekeeper/notarization or WinVerifyTrust publisher identity.
func (p *DesktopProvisioner) VerifyRuntimeArtifact(
	ctx context.Context,
	request runtimeinstallapp.Request,
) (runtimeinstallapp.Output, error) {
	plan, authority, err := p.resolve(ctx, request)
	if err != nil {
		return mapExpectedOrError(err)
	}
	if plan.Action() == runtimeinstall.PlanActionBlock {
		return blockOutput(plan.DecisionCode())
	}
	if passiveAction(plan.Action()) {
		return p.completed(request, authority, authority.ArtifactSHA256(), runtimeinstall.OwnershipUnknown)
	}
	evidence, err := p.artifactVerifier.VerifyDesktopArtifact(ctx, authority)
	if err != nil || !evidence.VerifiedFor(authority) {
		return runtimeinstallapp.Output{}, sanitizeDesktopBoundary(ctx, err, ErrProvisionIntegrity)
	}
	return p.completed(request, authority, evidence.Digest(), runtimeinstall.OwnershipUnknown)
}

// InstallPrerequisites enables only exact signed Windows WSL prerequisites.
func (p *DesktopProvisioner) InstallPrerequisites(
	ctx context.Context,
	request runtimeinstallapp.Request,
) (runtimeinstallapp.Output, error) {
	plan, authority, err := p.resolve(ctx, request)
	if err != nil {
		return mapExpectedOrError(err)
	}
	if plan.Action() == runtimeinstall.PlanActionBlock {
		return blockOutput(plan.DecisionCode())
	}
	if passiveAction(plan.Action()) || authority.Platform() == runtimeinstall.PlatformDarwin {
		return p.completed(request, authority, authority.Digest(), runtimeinstall.OwnershipUnknown)
	}
	host, err := p.host.ProbeDesktopHost(ctx, authority)
	if err != nil || host.Supports(authority) != nil {
		return runtimeinstallapp.Output{}, sanitizeDesktopBoundary(ctx, err, ErrUnsupportedHost)
	}
	if host.PrerequisitesReady(authority) {
		return p.completed(request, authority, host.Digest(), runtimeinstall.OwnershipUnknown)
	}
	receipt, err := p.requireConsent(ctx, request, authority)
	if err != nil {
		return p.desktopConsentError(ctx, err)
	}
	mutation, output, err := p.executeMutation(
		ctx, request, authority, runtimeport.DesktopMutationInstallPrerequisites, receipt, runtimeport.DesktopArtifactEvidence{},
	)
	if err != nil || output != nil {
		return outputOrZero(output), err
	}
	return p.completed(request, authority, mutation, runtimeinstall.OwnershipUnknown)
}

// InstallRuntime re-verifies artifact and consent immediately before one fixed
// native helper invocation using the documented vendor arguments.
func (p *DesktopProvisioner) InstallRuntime(
	ctx context.Context,
	request runtimeinstallapp.Request,
) (runtimeinstallapp.Output, error) {
	plan, authority, err := p.resolve(ctx, request)
	if err != nil {
		return mapExpectedOrError(err)
	}
	if plan.Action() == runtimeinstall.PlanActionBlock {
		return blockOutput(plan.DecisionCode())
	}
	if passiveAction(plan.Action()) {
		return p.completed(request, authority, authority.ArtifactSHA256(), runtimeinstall.OwnershipUnknown)
	}
	consent, err := p.requireConsent(ctx, request, authority)
	if err != nil {
		return p.desktopConsentError(ctx, err)
	}
	artifact, err := p.artifactVerifier.VerifyDesktopArtifact(ctx, authority)
	if err != nil || !artifact.VerifiedFor(authority) {
		return runtimeinstallapp.Output{}, sanitizeDesktopBoundary(ctx, err, ErrProvisionIntegrity)
	}
	mutation, output, err := p.executeMutation(
		ctx, request, authority, runtimeport.DesktopMutationInstallRuntime, consent, artifact,
	)
	if err != nil || output != nil {
		return outputOrZero(output), err
	}
	return p.completed(request, authority, combineDigests(mutation, artifact.Digest()), runtimeinstall.OwnershipUnknown)
}

// AwaitThirdPartyTerms revalidates stored consent and observes any mandatory
// vendor surface without synthesizing a decision.
func (p *DesktopProvisioner) AwaitThirdPartyTerms(
	ctx context.Context,
	request runtimeinstallapp.Request,
) (runtimeinstallapp.Output, error) {
	plan, authority, err := p.resolve(ctx, request)
	if err != nil {
		return mapExpectedOrError(err)
	}
	if plan.Action() == runtimeinstall.PlanActionBlock {
		return blockOutput(plan.DecisionCode())
	}
	if passiveAction(plan.Action()) {
		return p.completed(request, authority, authority.Terms().Digest(), runtimeinstall.OwnershipUnknown)
	}
	consent, err := p.requireConsent(ctx, request, authority)
	if err != nil {
		return p.desktopConsentError(ctx, err)
	}
	if !authority.VendorUIMandatory() {
		return p.completed(request, authority, consent.Digest(), runtimeinstall.OwnershipUnknown)
	}
	observation, err := p.terms.ObserveDesktopTerms(ctx, authority, consent)
	if err != nil {
		if errors.Is(err, runtimeport.ErrDesktopConsentDeclined) {
			return expected(runtimeinstallapp.OutcomeCancelled)
		}
		return runtimeinstallapp.Output{}, sanitizeDesktopBoundary(ctx, err, ErrProbeFailed)
	}
	if observation.IsZero() {
		return runtimeinstallapp.Output{}, ErrProvisionIntegrity
	}
	return p.completed(request, authority, combineDigests(consent.Digest(), observation), runtimeinstall.OwnershipUnknown)
}

// StartRuntime launches the exact signed application path and waits on the
// exact local endpoint without changing global Docker context.
func (p *DesktopProvisioner) StartRuntime(
	ctx context.Context,
	request runtimeinstallapp.Request,
) (runtimeinstallapp.Output, error) {
	plan, authority, err := p.resolve(ctx, request)
	if err != nil {
		return mapExpectedOrError(err)
	}
	if plan.Action() == runtimeinstall.PlanActionBlock {
		return blockOutput(plan.DecisionCode())
	}
	launchReceipt, err := p.launcher.LaunchDesktopRuntime(ctx, authority)
	if err != nil || launchReceipt.IsZero() {
		return runtimeinstallapp.Output{}, sanitizeDesktopBoundary(ctx, err, ErrProbeFailed)
	}
	evidence, err := p.awaitDesktopRunning(ctx, plan, authority)
	if err != nil {
		return mapExpectedOrError(err)
	}
	return p.completed(request, authority, combineDigests(launchReceipt, evidence.Digest()), runtimeinstall.OwnershipUnknown)
}

// VerifyRuntimeCapabilities runs active capability and workload-preservation probes.
func (p *DesktopProvisioner) VerifyRuntimeCapabilities(
	ctx context.Context,
	request runtimeinstallapp.Request,
) (runtimeinstallapp.Output, error) {
	plan, authority, err := p.resolve(ctx, request)
	if err != nil {
		return mapExpectedOrError(err)
	}
	if plan.Action() == runtimeinstall.PlanActionBlock {
		return blockOutput(plan.DecisionCode())
	}
	evidence, err := p.runtime.InspectDesktopRuntime(ctx, plan, authority)
	if err != nil || !evidence.Compatible(authority) {
		return expected(runtimeinstallapp.OutcomeRuntimeConflict)
	}
	capabilities, err := p.capabilities.VerifyDesktopCapabilities(ctx, authority)
	if err != nil || capabilities.IsZero() {
		return runtimeinstallapp.Output{}, sanitizeDesktopBoundary(ctx, err, ErrProbeFailed)
	}
	ownership := runtimeinstall.OwnershipReusedExternal
	if plan.Action() == runtimeinstall.PlanActionInstallCertified || plan.Action() == runtimeinstall.PlanActionRepairManaged {
		ownership = runtimeinstall.OwnershipProvisionedByAgentMemory
	}
	return p.completed(request, authority, combineDigests(evidence.Digest(), capabilities), ownership)
}

func (p *DesktopProvisioner) resolve(
	ctx context.Context,
	request runtimeinstallapp.Request,
) (runtimeinstall.Plan, runtimeport.DesktopAuthority, error) {
	if p == nil || ctx == nil || desktopNilDependency(p.authority) {
		return runtimeinstall.Plan{}, runtimeport.DesktopAuthority{}, ErrProvisionIntegrity
	}
	if err := ctx.Err(); err != nil {
		return runtimeinstall.Plan{}, runtimeport.DesktopAuthority{}, err
	}
	canonical := request.CanonicalPlan()
	plan, err := runtimeinstall.DecodePlanV1(canonical)
	if err != nil || plan.Digest() != request.PlanDigest() {
		return runtimeinstall.Plan{}, runtimeport.DesktopAuthority{}, ErrProvisionIntegrity
	}
	authority, err := p.authority.ResolveDesktopAuthority(ctx, canonical)
	if err != nil {
		if errors.Is(err, runtimeport.ErrDesktopAuthorityUnavailable) {
			return runtimeinstall.Plan{}, runtimeport.DesktopAuthority{}, ErrAdministratorRequired
		}
		return runtimeinstall.Plan{}, runtimeport.DesktopAuthority{}, sanitizeDesktopBoundary(ctx, err, ErrProvisionIntegrity)
	}
	if !authority.ValidFor(plan) {
		return runtimeinstall.Plan{}, runtimeport.DesktopAuthority{}, ErrProvisionIntegrity
	}
	return plan, authority, nil
}

func (p *DesktopProvisioner) freshNonce(ctx context.Context) (time.Time, runtimeport.Nonce, error) {
	now := p.clock.Now()
	if now.Location() != time.UTC {
		return time.Time{}, runtimeport.Nonce{}, ErrProvisionIntegrity
	}
	nonce, err := p.nonces.NewPrivilegeNonce(ctx)
	if err != nil || nonce.IsZero() {
		return time.Time{}, runtimeport.Nonce{}, sanitizeDesktopBoundary(ctx, err, ErrProvisionIntegrity)
	}
	return now, nonce, nil
}

func (p *DesktopProvisioner) requireConsent(
	ctx context.Context,
	request runtimeinstallapp.Request,
	authority runtimeport.DesktopAuthority,
) (runtimeport.DesktopConsentReceipt, error) {
	receipt, err := p.consentRepository.LoadDesktopConsent(ctx, request.OperationID(), authority.PlanDigest())
	if err != nil || !receipt.Authorizes(authority, p.clock.Now()) ||
		p.consentAuthenticator.VerifyStoredDesktopConsent(ctx, authority, receipt) != nil ||
		!receipt.Authorizes(authority, p.clock.Now()) {
		return runtimeport.DesktopConsentReceipt{}, errors.Join(runtimeport.ErrDesktopConsentIntegrity, err)
	}
	return receipt, nil
}

func (p *DesktopProvisioner) desktopConsentError(ctx context.Context, err error) (runtimeinstallapp.Output, error) {
	if errors.Is(err, runtimeport.ErrDesktopConsentDeclined) {
		return expected(runtimeinstallapp.OutcomeCancelled)
	}
	if errors.Is(err, runtimeport.ErrDesktopConsentUnavailable) {
		return expected(runtimeinstallapp.OutcomeAdministratorRequired)
	}
	return runtimeinstallapp.Output{}, sanitizeDesktopBoundary(ctx, err, ErrProvisionIntegrity)
}

func (p *DesktopProvisioner) executeMutation(
	ctx context.Context,
	request runtimeinstallapp.Request,
	authority runtimeport.DesktopAuthority,
	operation runtimeport.DesktopMutationOperation,
	consent runtimeport.DesktopConsentReceipt,
	artifact runtimeport.DesktopArtifactEvidence,
) (runtimeinstall.Hash, *runtimeinstallapp.Output, error) {
	now, nonce, err := p.freshNonce(ctx)
	if err != nil {
		return runtimeinstall.Hash{}, nil, err
	}
	mutationRequest, err := runtimeport.NewDesktopMutationRequest(
		request.OperationID(), request.Attempt(), operation, authority, consent.Digest(), artifact.Digest(), nonce,
		now, now.Add(desktopMutationRequestLifetime),
	)
	if err != nil {
		return runtimeinstall.Hash{}, nil, ErrProvisionIntegrity
	}
	receipt, err := p.mutation.ExecuteDesktopMutation(ctx, mutationRequest)
	if err != nil {
		switch {
		case errors.Is(err, runtimeport.ErrDesktopMutationDenied):
			output, outputError := runtimeinstallapp.NewExpectedOutput(runtimeinstallapp.OutcomeCancelled)
			return runtimeinstall.Hash{}, &output, outputError
		case errors.Is(err, runtimeport.ErrDesktopMutationUnavailable), errors.Is(err, runtimeport.ErrDesktopMutationPolicy):
			output, outputError := runtimeinstallapp.NewExpectedOutput(runtimeinstallapp.OutcomeAdministratorRequired)
			return runtimeinstall.Hash{}, &output, outputError
		default:
			return runtimeinstall.Hash{}, nil, sanitizeDesktopBoundary(ctx, err, ErrProvisionIntegrity)
		}
	}
	if !receipt.Matches(mutationRequest, p.clock.Now()) ||
		p.mutationAuthenticator.VerifyDesktopMutation(ctx, mutationRequest, receipt) != nil ||
		!receipt.Matches(mutationRequest, p.clock.Now()) ||
		p.mutationReplay.ConsumeDesktopMutation(ctx, receipt) != nil ||
		!receipt.Matches(mutationRequest, p.clock.Now()) {
		return runtimeinstall.Hash{}, nil, ErrProvisionIntegrity
	}
	if reboot := receipt.RebootReceipt(); !reboot.IsZero() {
		output, outputError := runtimeinstallapp.NewRebootOutput(reboot)
		return runtimeinstall.Hash{}, &output, outputError
	}
	return receipt.Digest(), nil, nil
}

func (p *DesktopProvisioner) awaitDesktopRunning(
	ctx context.Context,
	plan runtimeinstall.Plan,
	authority runtimeport.DesktopAuthority,
) (runtimeport.DesktopRuntimeEvidence, error) {
	probeContext := ctx
	cancel := func() {}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		probeContext, cancel = context.WithTimeout(ctx, desktopStartDeadline)
	}
	defer cancel()
	ticker := time.NewTicker(runtimePollInterval)
	defer ticker.Stop()
	for {
		evidence, err := p.runtime.InspectDesktopRuntime(probeContext, plan, authority)
		if err == nil && evidence.Compatible(authority) {
			return evidence, nil
		}
		select {
		case <-probeContext.Done():
			return runtimeport.DesktopRuntimeEvidence{}, probeContext.Err()
		case <-ticker.C:
		}
	}
}

func (p *DesktopProvisioner) completed(
	request runtimeinstallapp.Request,
	authority runtimeport.DesktopAuthority,
	output runtimeinstall.Hash,
	ownership runtimeinstall.OwnershipDisposition,
) (runtimeinstallapp.Output, error) {
	if output.IsZero() {
		return runtimeinstallapp.Output{}, ErrProvisionIntegrity
	}
	artifact := runtimeinstall.Hash{}
	if request.Phase() >= runtimeinstall.PhaseVerifyRuntimeArtifact {
		artifact = authority.ArtifactSHA256()
	}
	return runtimeinstallapp.NewCompletedOutput(runtimeinstallapp.Completion{
		InputDigest: desktopPhaseInputDigest(request, authority), OutputDigest: output,
		ArtifactDigest: artifact, Ownership: ownership,
	})
}

func desktopPhaseInputDigest(
	request runtimeinstallapp.Request,
	authority runtimeport.DesktopAuthority,
) runtimeinstall.Hash {
	encoded, _ := json.Marshal(struct {
		Attempt   uint32 `json:"attempt"`
		Authority string `json:"authority_digest"`
		Operation string `json:"operation_id"`
		Phase     string `json:"phase"`
		Plan      string `json:"plan_digest"`
	}{
		Attempt: request.Attempt(), Authority: authority.Digest().String(), Operation: request.OperationID(),
		Phase: request.Phase().String(), Plan: request.PlanDigest().String(),
	})
	return runtimeinstall.Sum(encoded)
}

func sanitizeDesktopBoundary(ctx context.Context, err error, fallback error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	for _, safe := range []error{ErrUnsupportedHost, ErrAdministratorRequired, ErrRuntimeConflict, ErrProvisionIntegrity, ErrProbeFailed} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	return fallback
}

var (
	_ runtimeinstallapp.HostCapabilityProbe          = (*DesktopProvisioner)(nil)
	_ runtimeinstallapp.ContainerRuntimeDetector     = (*DesktopProvisioner)(nil)
	_ runtimeinstallapp.RuntimeReleaseCatalog        = (*DesktopProvisioner)(nil)
	_ runtimeinstallapp.RuntimeConsentPort           = (*DesktopProvisioner)(nil)
	_ runtimeinstallapp.RuntimeArtifactFetcher       = (*DesktopProvisioner)(nil)
	_ runtimeinstallapp.RuntimeArtifactVerifier      = (*DesktopProvisioner)(nil)
	_ runtimeinstallapp.RuntimePrerequisiteInstaller = (*DesktopProvisioner)(nil)
	_ runtimeinstallapp.ContainerRuntimeInstaller    = (*DesktopProvisioner)(nil)
	_ runtimeinstallapp.ThirdPartyTermsPort          = (*DesktopProvisioner)(nil)
	_ runtimeinstallapp.ContainerRuntimeController   = (*DesktopProvisioner)(nil)
	_ runtimeinstallapp.RuntimeCapabilityProbe       = (*DesktopProvisioner)(nil)
)
