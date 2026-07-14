package runtimeprovision

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeinstallapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const (
	privilegeRequestLifetime = 2 * time.Minute
	runtimeStartDeadline     = 60 * time.Second
	runtimePollInterval      = 100 * time.Millisecond
)

// RuntimeInspector is the read-only exact-endpoint discovery boundary.
type RuntimeInspector interface {
	Inspect(context.Context, runtimeinstall.Plan, runtimeport.LinuxAuthority) (RuntimeEvidence, error)
}

// Dependencies are mandatory production boundaries. No nil dependency enables
// a permissive fallback.
type Dependencies struct {
	Authority     runtimeport.AuthorityResolver
	Host          HostProbe
	Runtime       RuntimeInspector
	Capabilities  CapabilityProbe
	Privilege     runtimeport.PrivilegeBroker
	Authenticator runtimeport.ReceiptAuthenticator
	Replay        runtimeport.ReplayLedger
	Nonces        runtimeport.NonceSource
	Clock         runtimeport.Clock
	RootlessTool  argvprocess.Runner
}

// LinuxProvisioner implements all Linux-owned PF-006 phase ports.
type LinuxProvisioner struct {
	authority     runtimeport.AuthorityResolver
	host          HostProbe
	runtime       RuntimeInspector
	capabilities  CapabilityProbe
	privilege     runtimeport.PrivilegeBroker
	authenticator runtimeport.ReceiptAuthenticator
	replay        runtimeport.ReplayLedger
	nonces        runtimeport.NonceSource
	clock         runtimeport.Clock
	rootlessTool  argvprocess.Runner
}

// NewLinuxProvisioner constructs only a complete fail-closed provisioner.
func NewLinuxProvisioner(dependencies Dependencies) (*LinuxProvisioner, error) {
	values := []any{
		dependencies.Authority, dependencies.Host, dependencies.Runtime, dependencies.Capabilities,
		dependencies.Privilege, dependencies.Authenticator, dependencies.Replay,
		dependencies.Nonces, dependencies.Clock, dependencies.RootlessTool,
	}
	for _, value := range values {
		if nilDependency(value) {
			return nil, ErrProvisionIntegrity
		}
	}
	authority := dependencies.RootlessTool.ExecutableAuthority()
	if !authority.Valid() || authority.Role() != argvprocess.ExecutableRoleRootlessSetup ||
		authority.Platform() != "linux" || authority.OwnerIdentity() != "uid:0" ||
		authority.CanonicalPath() != "/usr/bin/dockerd-rootless-setuptool.sh" {
		return nil, ErrProvisionIntegrity
	}
	return &LinuxProvisioner{
		authority: dependencies.Authority, host: dependencies.Host, runtime: dependencies.Runtime,
		capabilities: dependencies.Capabilities, privilege: dependencies.Privilege,
		authenticator: dependencies.Authenticator, replay: dependencies.Replay,
		nonces: dependencies.Nonces, clock: dependencies.Clock, rootlessTool: dependencies.RootlessTool,
	}, nil
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // All non-nilable reflection kinds are intentionally accepted by default.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid:
		return true
	default:
		return false
	}
}

// DetectHost re-probes exact signed host, principal, rootless, resource, and policy facts.
func (p *LinuxProvisioner) DetectHost(
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
	evidence, err := p.host.ProbeLinuxHost(ctx, authority)
	if err != nil {
		return mapExpectedOrError(sanitizeBoundaryError(ctx, err, ErrProbeFailed))
	}
	if err := evidence.Supports(authority); err != nil {
		return mapExpectedOrError(err)
	}
	return p.completed(request, authority, evidence.Digest(), runtimeinstall.OwnershipUnknown, false)
}

// DetectRuntime explicitly addresses and inspects only the authorized local endpoint.
func (p *LinuxProvisioner) DetectRuntime(
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
	evidence, err := p.runtime.Inspect(ctx, plan, authority)
	if err != nil {
		return mapExpectedOrError(sanitizeBoundaryError(ctx, err, ErrProbeFailed))
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
	default:
	}
	if !valid {
		return expected(runtimeinstallapp.OutcomeRuntimeConflict)
	}
	return p.completed(request, authority, evidence.Digest(), runtimeinstall.OwnershipUnknown, false)
}

// InstallPrerequisites configures only repository state and subordinate IDs.
func (p *LinuxProvisioner) InstallPrerequisites(
	ctx context.Context,
	request runtimeinstallapp.Request,
) (runtimeinstallapp.Output, error) {
	plan, authority, err := p.resolve(ctx, request)
	if err != nil {
		return mapExpectedOrError(err)
	}
	if passiveAction(plan.Action()) {
		return p.completed(request, authority, authority.Digest(), runtimeinstall.OwnershipUnknown, true)
	}
	if plan.Action() == runtimeinstall.PlanActionBlock {
		return blockOutput(plan.DecisionCode())
	}
	if plan.Action() != runtimeinstall.PlanActionInstallCertified && plan.Action() != runtimeinstall.PlanActionRepairManaged {
		return runtimeinstallapp.Output{}, ErrProvisionIntegrity
	}
	repositoryReceipt, output, err := p.executePrivilege(ctx, request, authority, runtimeport.PrivilegeConfigureRepository)
	if err != nil || output != nil {
		return outputOrZero(output), err
	}
	subordinateReceipt, output, err := p.executePrivilege(ctx, request, authority, runtimeport.PrivilegeConfigureSubordinateIDs)
	if err != nil || output != nil {
		return outputOrZero(output), err
	}
	return p.completed(
		request, authority, combineDigests(repositoryReceipt, subordinateReceipt),
		runtimeinstall.OwnershipUnknown, true,
	)
}

// InstallRuntime installs exact packages, authenticates their receipt, then
// directly executes only the retained packaged rootless setup tool.
func (p *LinuxProvisioner) InstallRuntime(
	ctx context.Context,
	request runtimeinstallapp.Request,
) (runtimeinstallapp.Output, error) {
	plan, authority, err := p.resolve(ctx, request)
	if err != nil {
		return mapExpectedOrError(err)
	}
	if passiveAction(plan.Action()) {
		return p.completed(request, authority, authority.Digest(), runtimeinstall.OwnershipUnknown, true)
	}
	if plan.Action() == runtimeinstall.PlanActionBlock {
		return blockOutput(plan.DecisionCode())
	}
	packageReceipt, output, err := p.executePrivilege(ctx, request, authority, runtimeport.PrivilegeInstallPackages)
	if err != nil || output != nil {
		return outputOrZero(output), err
	}
	if !p.rootlessRunnerMatches(authority) {
		return runtimeinstallapp.Output{}, ErrProvisionIntegrity
	}
	invocation, err := argvprocess.NewRootlessSetupInvocation(
		authority.RootlessToolPath(), []string{"install"}, authority.HomeDirectory(),
		authority.RuntimeDirectory(), authority.InvokingUID(),
	)
	if err != nil {
		return runtimeinstallapp.Output{}, ErrProvisionIntegrity
	}
	result, err := p.rootlessTool.Run(ctx, invocation)
	if err != nil {
		return runtimeinstallapp.Output{}, sanitizedContextError(ctx, ErrProbeFailed)
	}
	if result.ExitCode != 0 || result.OutputTruncated {
		return runtimeinstallapp.Output{}, ErrProbeFailed
	}
	return p.completed(
		request, authority, combineDigests(packageReceipt, authority.RootlessToolDigest()),
		runtimeinstall.OwnershipUnknown, true,
	)
}

// StartRuntime authenticates exact package/service state and enables/starts
// only docker.service for the invoking user.
func (p *LinuxProvisioner) StartRuntime(
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
	var serviceReceipt runtimeinstall.Hash
	if plan.Action() != runtimeinstall.PlanActionAdoptCompatible {
		var output *runtimeinstallapp.Output
		var executeError error
		serviceReceipt, output, executeError = p.executePrivilege(
			ctx, request, authority, runtimeport.PrivilegeEnableUserService,
		)
		if executeError != nil || output != nil {
			return outputOrZero(output), executeError
		}
	}
	evidence, err := p.awaitRunning(ctx, plan, authority)
	if err != nil {
		return mapExpectedOrError(err)
	}
	return p.completed(
		request, authority, combineDigests(serviceReceipt, evidence.Digest()),
		runtimeinstall.OwnershipUnknown, true,
	)
}

// VerifyRuntimeCapabilities re-proves managed receipts, runtime compatibility,
// and every active bind/network/volume/publish/workload capability.
func (p *LinuxProvisioner) VerifyRuntimeCapabilities(
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
	stateReceipt, output, err := p.executePrivilege(ctx, request, authority, runtimeport.PrivilegeVerifyManagedState)
	if err != nil || output != nil {
		return outputOrZero(output), err
	}
	runtimeEvidence, err := p.runtime.Inspect(ctx, plan, authority)
	if err != nil || !runtimeEvidence.Compatible(authority) {
		if err == nil {
			err = ErrRuntimeConflict
		} else {
			err = sanitizeBoundaryError(ctx, err, ErrProbeFailed)
		}
		return mapExpectedOrError(err)
	}
	capabilities, err := p.capabilities.VerifyLinuxCapabilities(ctx, authority, runtimeEvidence, stateReceipt)
	if err != nil || capabilities.Digest().IsZero() {
		if err == nil {
			err = ErrProbeFailed
		} else {
			err = sanitizeBoundaryError(ctx, err, ErrProbeFailed)
		}
		return mapExpectedOrError(err)
	}
	ownership := runtimeinstall.OwnershipReusedExternal
	if plan.Action() == runtimeinstall.PlanActionInstallCertified || plan.Action() == runtimeinstall.PlanActionRepairManaged {
		ownership = runtimeinstall.OwnershipProvisionedByAgentMemory
	}
	return p.completed(
		request, authority, combineDigests(stateReceipt, runtimeEvidence.Digest(), capabilities.Digest()),
		ownership, true,
	)
}

func (p *LinuxProvisioner) resolve(
	ctx context.Context,
	request runtimeinstallapp.Request,
) (runtimeinstall.Plan, runtimeport.LinuxAuthority, error) {
	if p == nil || ctx == nil || nilDependency(p.authority) {
		return runtimeinstall.Plan{}, runtimeport.LinuxAuthority{}, ErrProvisionIntegrity
	}
	if err := ctx.Err(); err != nil {
		return runtimeinstall.Plan{}, runtimeport.LinuxAuthority{}, err
	}
	canonical := request.CanonicalPlan()
	plan, err := runtimeinstall.DecodePlanV1(canonical)
	if err != nil || plan.Digest() != request.PlanDigest() {
		return runtimeinstall.Plan{}, runtimeport.LinuxAuthority{}, ErrProvisionIntegrity
	}
	authority, err := p.authority.ResolveLinuxAuthority(ctx, canonical)
	if err != nil {
		if errors.Is(err, runtimeport.ErrAuthorityUnavailable) {
			return runtimeinstall.Plan{}, runtimeport.LinuxAuthority{}, ErrAdministratorRequired
		}
		return runtimeinstall.Plan{}, runtimeport.LinuxAuthority{}, sanitizedContextError(ctx, ErrProvisionIntegrity)
	}
	if !authority.ValidFor(plan) || !p.rootlessRunnerMatches(authority) {
		return runtimeinstall.Plan{}, runtimeport.LinuxAuthority{}, ErrProvisionIntegrity
	}
	return plan, authority, nil
}

func (p *LinuxProvisioner) executePrivilege(
	ctx context.Context,
	request runtimeinstallapp.Request,
	authority runtimeport.LinuxAuthority,
	operation runtimeport.PrivilegeOperation,
) (runtimeinstall.Hash, *runtimeinstallapp.Output, error) {
	now := p.clock.Now()
	if now.Location() != time.UTC {
		return runtimeinstall.Hash{}, nil, ErrProvisionIntegrity
	}
	nonce, err := p.nonces.NewPrivilegeNonce(ctx)
	if err != nil || nonce.IsZero() {
		return runtimeinstall.Hash{}, nil, sanitizedContextError(ctx, ErrProvisionIntegrity)
	}
	expectedState, err := runtimeport.ExpectedPrivilegeState(authority, operation)
	if err != nil {
		return runtimeinstall.Hash{}, nil, ErrProvisionIntegrity
	}
	helperRequest, err := runtimeport.NewPrivilegeRequest(runtimeport.PrivilegeRequestInput{
		OperationID: request.OperationID(), Attempt: request.Attempt(), Operation: operation,
		Authority: authority, Nonce: nonce, IssuedAt: now,
		ExpiresAt: now.Add(privilegeRequestLifetime), ExpectedState: expectedState,
	})
	if err != nil {
		return runtimeinstall.Hash{}, nil, ErrProvisionIntegrity
	}
	receipt, err := p.privilege.Execute(ctx, helperRequest)
	if err != nil {
		switch {
		case errors.Is(err, runtimeport.ErrPrivilegeDenied):
			output, outputError := runtimeinstallapp.NewExpectedOutput(runtimeinstallapp.OutcomeCancelled)
			return runtimeinstall.Hash{}, &output, outputError
		case errors.Is(err, runtimeport.ErrPrivilegeUnavailable), errors.Is(err, runtimeport.ErrPrivilegePolicy):
			output, outputError := runtimeinstallapp.NewExpectedOutput(runtimeinstallapp.OutcomeAdministratorRequired)
			return runtimeinstall.Hash{}, &output, outputError
		default:
			return runtimeinstall.Hash{}, nil, sanitizedContextError(ctx, ErrProvisionIntegrity)
		}
	}
	verificationTime := p.clock.Now()
	if !receipt.Matches(helperRequest, verificationTime) ||
		p.authenticator.VerifyPrivilegeReceipt(ctx, helperRequest, receipt) != nil ||
		!receipt.Matches(helperRequest, p.clock.Now()) {
		return runtimeinstall.Hash{}, nil, sanitizedContextError(ctx, ErrProvisionIntegrity)
	}
	if err := p.replay.ConsumePrivilegeReceipt(ctx, nonce, receipt.Digest()); err != nil {
		return runtimeinstall.Hash{}, nil, sanitizedContextError(ctx, ErrProvisionIntegrity)
	}
	if !receipt.Matches(helperRequest, p.clock.Now()) {
		return runtimeinstall.Hash{}, nil, ErrProvisionIntegrity
	}
	return receipt.Digest(), nil, nil
}

func (p *LinuxProvisioner) rootlessRunnerMatches(authority runtimeport.LinuxAuthority) bool {
	runnerAuthority := p.rootlessTool.ExecutableAuthority()
	return runnerAuthority.Valid() && runnerAuthority.Role() == argvprocess.ExecutableRoleRootlessSetup &&
		runnerAuthority.CanonicalPath() == authority.RootlessToolPath() &&
		runnerAuthority.SHA256() == [32]byte(authority.RootlessToolDigest()) &&
		runnerAuthority.Platform() == "linux" && runnerAuthority.Architecture() == authority.Architecture().String() &&
		runtimeinstall.Hash(runnerAuthority.RuntimePlanDigest()) == authority.PlanDigest()
}

func (p *LinuxProvisioner) awaitRunning(
	ctx context.Context,
	plan runtimeinstall.Plan,
	authority runtimeport.LinuxAuthority,
) (RuntimeEvidence, error) {
	probeContext := ctx
	cancel := func() {}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		probeContext, cancel = context.WithTimeout(ctx, runtimeStartDeadline)
	}
	defer cancel()
	ticker := time.NewTicker(runtimePollInterval)
	defer ticker.Stop()
	for {
		evidence, err := p.runtime.Inspect(probeContext, plan, authority)
		if err == nil && evidence.Compatible(authority) {
			return evidence, nil
		}
		if err != nil && !errors.Is(err, ErrRuntimeConflict) && !errors.Is(err, ErrProbeFailed) {
			return RuntimeEvidence{}, sanitizedContextError(probeContext, ErrProbeFailed)
		}
		select {
		case <-probeContext.Done():
			return RuntimeEvidence{}, probeContext.Err()
		case <-ticker.C:
		}
	}
}

func (p *LinuxProvisioner) completed(
	request runtimeinstallapp.Request,
	authority runtimeport.LinuxAuthority,
	output runtimeinstall.Hash,
	ownership runtimeinstall.OwnershipDisposition,
	includeArtifact bool,
) (runtimeinstallapp.Output, error) {
	if output.IsZero() {
		return runtimeinstallapp.Output{}, ErrProvisionIntegrity
	}
	input := phaseInputDigest(request, authority)
	artifact := runtimeinstall.Hash{}
	if includeArtifact {
		artifact = authority.ArtifactDigest()
	}
	return runtimeinstallapp.NewCompletedOutput(runtimeinstallapp.Completion{
		InputDigest: input, OutputDigest: output, ArtifactDigest: artifact, Ownership: ownership,
	})
}

func phaseInputDigest(
	request runtimeinstallapp.Request,
	authority runtimeport.LinuxAuthority,
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

func combineDigests(values ...runtimeinstall.Hash) runtimeinstall.Hash {
	combined := make([]byte, 0, len(values)*32)
	for _, value := range values {
		if !value.IsZero() {
			combined = append(combined, value[:]...)
		}
	}
	if len(combined) == 0 {
		return runtimeinstall.Hash{}
	}
	return runtimeinstall.Sum(combined)
}

func passiveAction(action runtimeinstall.PlanAction) bool {
	return action == runtimeinstall.PlanActionAdoptCompatible || action == runtimeinstall.PlanActionStartCompatible
}

func hostDecision(code runtimeinstall.DecisionCode) bool {
	return code >= runtimeinstall.DecisionUnsupportedPlatform && code <= runtimeinstall.DecisionInsufficientDisk ||
		code == runtimeinstall.DecisionCatalogMismatch
}

func blockOutput(code runtimeinstall.DecisionCode) (runtimeinstallapp.Output, error) {
	if hostDecision(code) {
		return expected(runtimeinstallapp.OutcomeUnsupportedHost)
	}
	return expected(runtimeinstallapp.OutcomeRuntimeConflict)
}

func expected(outcome runtimeinstallapp.Outcome) (runtimeinstallapp.Output, error) {
	return runtimeinstallapp.NewExpectedOutput(outcome)
}

func mapExpectedOrError(err error) (runtimeinstallapp.Output, error) {
	switch {
	case errors.Is(err, ErrUnsupportedHost):
		return expected(runtimeinstallapp.OutcomeUnsupportedHost)
	case errors.Is(err, ErrAdministratorRequired):
		return expected(runtimeinstallapp.OutcomeAdministratorRequired)
	case errors.Is(err, ErrRuntimeConflict):
		return expected(runtimeinstallapp.OutcomeRuntimeConflict)
	default:
		return runtimeinstallapp.Output{}, err
	}
}

func sanitizeBoundaryError(ctx context.Context, err error, fallback error) error {
	if ctx != nil {
		if contextError := ctx.Err(); contextError != nil {
			return contextError
		}
	}
	for _, safe := range []error{
		ErrUnsupportedHost,
		ErrAdministratorRequired,
		ErrRuntimeConflict,
		ErrProvisionIntegrity,
		ErrProbeFailed,
	} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	return fallback
}

func outputOrZero(output *runtimeinstallapp.Output) runtimeinstallapp.Output {
	if output == nil {
		return runtimeinstallapp.Output{}
	}
	return *output
}

var (
	_ runtimeinstallapp.HostCapabilityProbe          = (*LinuxProvisioner)(nil)
	_ runtimeinstallapp.ContainerRuntimeDetector     = (*LinuxProvisioner)(nil)
	_ runtimeinstallapp.RuntimePrerequisiteInstaller = (*LinuxProvisioner)(nil)
	_ runtimeinstallapp.ContainerRuntimeInstaller    = (*LinuxProvisioner)(nil)
	_ runtimeinstallapp.ContainerRuntimeController   = (*LinuxProvisioner)(nil)
	_ runtimeinstallapp.RuntimeCapabilityProbe       = (*LinuxProvisioner)(nil)
)
