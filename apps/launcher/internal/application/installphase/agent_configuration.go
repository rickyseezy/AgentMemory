package installphase

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"slices"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/agentconfigapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	agentconfigport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/agentconfig"
	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const agentConfigurationBindingDomain = "agentmemory.agent-configuration-parent-binding.v1"

// AgentConfigurationPlan is an immutable authenticated projection of the
// exact host mutation authorized by one parent installation-plan attempt.
// Its binding digest is safe to journal; host paths and commands are not.
type AgentConfigurationPlan struct {
	parentPlanDigest           install.PlanDigest
	operationID                install.OperationID
	attempt                    uint32
	location                   agentconfigport.ConfigLocation
	target                     agentconfigdomain.Target
	expectedManagedEntryDigest agentconfigdomain.Digest
	runtimeOwnership           install.RuntimeOwnership
	parentBindingDigest        install.Digest
}

// NewAgentConfigurationPlan validates and binds every parent-authorized merge
// input. Query implementations must construct projections from authenticated
// canonical-plan data, never from host discovery or agent-provided values.
func NewAgentConfigurationPlan(
	parentPlanDigest install.PlanDigest,
	operationID install.OperationID,
	attempt uint32,
	location agentconfigport.ConfigLocation,
	target agentconfigdomain.Target,
	expectedManagedEntryDigest agentconfigdomain.Digest,
	runtimeOwnership install.RuntimeOwnership,
) (AgentConfigurationPlan, error) {
	if parentPlanDigest.IsZero() || operationID.IsZero() || attempt == 0 ||
		location.String() == "" || target.InstallationID() == "" || target.EntryID() == "" ||
		target.Command() == "" || target.LauncherDigest().IsZero() || !runtimeOwnership.Resolved() {
		return AgentConfigurationPlan{}, errors.New("agent configuration plan binding is incomplete")
	}
	plan := AgentConfigurationPlan{
		parentPlanDigest:           parentPlanDigest,
		operationID:                operationID,
		attempt:                    attempt,
		location:                   location,
		target:                     target,
		expectedManagedEntryDigest: expectedManagedEntryDigest,
		runtimeOwnership:           runtimeOwnership,
	}
	plan.parentBindingDigest = agentConfigurationParentBinding(plan)
	return plan, nil
}

// ParentPlanDigest returns the canonical parent-plan binding.
func (p AgentConfigurationPlan) ParentPlanDigest() install.PlanDigest { return p.parentPlanDigest }

// OperationID returns the exact parent operation authorized to mutate.
func (p AgentConfigurationPlan) OperationID() install.OperationID { return p.operationID }

// Attempt returns the one-based phase attempt authorized to mutate.
func (p AgentConfigurationPlan) Attempt() uint32 { return p.attempt }

// Location returns the explicit host configuration location.
func (p AgentConfigurationPlan) Location() agentconfigport.ConfigLocation { return p.location }

// Target returns the exact signed-launcher MCP target.
func (p AgentConfigurationPlan) Target() agentconfigdomain.Target { return p.target }

// ExpectedManagedEntryDigest returns the protected prior managed-entry digest.
func (p AgentConfigurationPlan) ExpectedManagedEntryDigest() agentconfigdomain.Digest {
	return p.expectedManagedEntryDigest
}

// RuntimeOwnership returns the ownership proof carried from runtime setup.
func (p AgentConfigurationPlan) RuntimeOwnership() install.RuntimeOwnership {
	return p.runtimeOwnership
}

// ParentBindingDigest returns the privacy-safe digest of every authorized input.
func (p AgentConfigurationPlan) ParentBindingDigest() install.Digest { return p.parentBindingDigest }

func (p AgentConfigurationPlan) validFor(request installapp.PhaseRequest) bool {
	return !p.parentPlanDigest.IsZero() && p.parentPlanDigest.Equal(request.PlanDigest()) &&
		!p.operationID.IsZero() && p.operationID == request.OperationID() &&
		p.attempt > 0 && p.attempt == request.Attempt() && p.location.String() != "" &&
		p.target.InstallationID() != "" && p.target.EntryID() != "" && p.target.Command() != "" &&
		!p.target.LauncherDigest().IsZero() && p.runtimeOwnership.Resolved() &&
		!p.parentBindingDigest.IsZero() &&
		p.parentBindingDigest.Equal(agentConfigurationParentBinding(p))
}

func agentConfigurationParentBinding(plan AgentConfigurationPlan) install.Digest {
	canonical := make([]byte, 0, 640)
	fields := []string{
		agentConfigurationBindingDomain,
		plan.parentPlanDigest.String(),
		plan.operationID.String(),
		plan.location.String(),
		plan.target.InstallationID(),
		plan.target.EntryID(),
		plan.target.Command(),
		plan.target.LauncherDigest().String(),
		plan.expectedManagedEntryDigest.String(),
	}
	for _, field := range fields {
		canonical = appendAgentConfigurationField(canonical, field)
	}
	for _, argument := range plan.target.Arguments() {
		canonical = appendAgentConfigurationField(canonical, argument)
	}
	canonical = binary.BigEndian.AppendUint32(canonical, plan.attempt)
	canonical = append(canonical, byte(plan.runtimeOwnership))
	return install.DigestBytes(canonical)
}

func appendAgentConfigurationField(destination []byte, value string) []byte {
	destination = binary.BigEndian.AppendUint64(destination, uint64(len(value)))
	return append(destination, value...)
}

// AgentConfigurationPlanQuery resolves only the exact operation attempt bound
// to the authenticated canonical parent plan.
type AgentConfigurationPlanQuery interface {
	ResolveAgentConfigurationPlan(
		context.Context,
		install.PlanDigest,
		install.OperationID,
		uint32,
	) (AgentConfigurationPlan, error)
}

// AgentConfigurationMerger is the sole mutation capability required by this
// phase. agentconfigapp.Application implements it directly.
type AgentConfigurationMerger interface {
	Merge(context.Context, agentconfigapp.MergeRequest) (agentconfigapp.MergeResult, error)
}

// AgentConfigurationPhase adapts the verified owner-scoped merge use case to
// InstallApplication's MergeAgentConfiguration capability.
type AgentConfigurationPhase struct {
	plans  AgentConfigurationPlanQuery
	merger AgentConfigurationMerger
}

// NewAgentConfigurationPhase rejects incomplete and typed-nil composition.
func NewAgentConfigurationPhase(
	plans AgentConfigurationPlanQuery,
	merger AgentConfigurationMerger,
) (*AgentConfigurationPhase, error) {
	if nilPort(plans) || nilPort(merger) {
		return nil, errors.New("agent configuration phase capabilities are required")
	}
	return &AgentConfigurationPhase{plans: plans, merger: merger}, nil
}

// MergeAgentConfiguration executes only the exact parent-authorized mutation
// and independently validates the returned plan and durable receipt.
func (p *AgentConfigurationPhase) MergeAgentConfiguration(
	ctx context.Context,
	request installapp.PhaseRequest,
) (installapp.PhaseOutput, error) {
	if !validRequest(request) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	projection, err := p.plans.ResolveAgentConfigurationPlan(
		ctx,
		request.PlanDigest(),
		request.OperationID(),
		request.Attempt(),
	)
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodePlanUnavailable)
	}
	if !projection.validFor(request) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}

	result, err := p.merger.Merge(ctx, agentconfigapp.MergeRequest{
		Location:                   projection.location,
		Target:                     projection.target,
		ExpectedManagedEntryDigest: projection.expectedManagedEntryDigest,
	})
	if err != nil {
		return agentConfigurationFailure(err)
	}
	if !validAgentConfigurationResult(projection, result) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	return agentConfigurationCompletedOutput(projection, result.Plan())
}

func validAgentConfigurationResult(
	projection AgentConfigurationPlan,
	result agentconfigapp.MergeResult,
) bool {
	actual := result.Plan()
	expected, err := agentconfigdomain.PlanMerge(
		actual.BeforeContent(),
		actual.OriginalExisted(),
		projection.target,
		projection.expectedManagedEntryDigest,
	)
	if err != nil || result.Changed() != actual.Changed() ||
		!sameAgentConfigurationMergePlan(actual, expected) {
		return false
	}
	receipt := result.Receipt()
	if !actual.Changed() {
		return emptyAgentConfigurationReceipt(receipt)
	}
	return receipt.Valid() && receipt.Changed() &&
		receipt.OriginalExisted() == actual.OriginalExisted() &&
		receipt.BeforeDigest().Equal(actual.BeforeDigest()) &&
		receipt.AfterDigest().Equal(actual.AfterDigest()) &&
		receipt.ManagedEntryDigest().Equal(actual.ManagedEntryDigest()) &&
		validAgentConfigurationBackupReceipt(receipt, actual)
}

func sameAgentConfigurationMergePlan(left, right agentconfigdomain.MergePlan) bool {
	return left.Action() == right.Action() && left.OriginalExisted() == right.OriginalExisted() &&
		bytes.Equal(left.BeforeContent(), right.BeforeContent()) &&
		bytes.Equal(left.AfterContent(), right.AfterContent()) &&
		left.BeforeDigest().Equal(right.BeforeDigest()) &&
		left.AfterDigest().Equal(right.AfterDigest()) &&
		left.ManagedEntryDigest().Equal(right.ManagedEntryDigest()) &&
		sameAgentConfigurationTarget(left.Target(), right.Target())
}

func sameAgentConfigurationTarget(left, right agentconfigdomain.Target) bool {
	return left.Host() == right.Host() && left.InstallationID() == right.InstallationID() && left.EntryID() == right.EntryID() &&
		left.Command() == right.Command() && left.LauncherDigest().Equal(right.LauncherDigest()) &&
		slices.Equal(left.Arguments(), right.Arguments())
}

func emptyAgentConfigurationReceipt(receipt agentconfigport.ApplyReceipt) bool {
	return !receipt.Valid() && !receipt.Changed() && !receipt.OriginalExisted() &&
		receipt.BeforeDigest().IsZero() && receipt.AfterDigest().IsZero() &&
		receipt.ManagedEntryDigest().IsZero() && receipt.BackupLocation() == "" &&
		receipt.BackupDigest().IsZero()
}

func validAgentConfigurationBackupReceipt(
	receipt agentconfigport.ApplyReceipt,
	plan agentconfigdomain.MergePlan,
) bool {
	if plan.OriginalExisted() {
		return receipt.BackupLocation() != "" && receipt.BackupDigest().Equal(plan.BeforeDigest())
	}
	return receipt.BackupLocation() == "" && receipt.BackupDigest().IsZero()
}

func agentConfigurationCompletedOutput(
	projection AgentConfigurationPlan,
	plan agentconfigdomain.MergePlan,
) (installapp.PhaseOutput, error) {
	return completedOutput(
		projection.parentBindingDigest,
		install.DigestBytes(plan.AfterContent()),
		projection.runtimeOwnership,
		"preserve.agent_configuration",
		"installation.continue",
		"agent_configuration",
		plan.Action().String(),
	)
}

func agentConfigurationFailure(err error) (installapp.PhaseOutput, error) {
	switch {
	case errors.Is(err, agentconfigapp.ErrCompensationFailed),
		errors.Is(err, agentconfigport.ErrIntegrity):
		return expectedOutput(installapp.PhaseOutcomeFailedRecoverable, "installation.resolve_agent_configuration")
	case errors.Is(err, agentconfigapp.ErrInvalidReceipt),
		errors.Is(err, agentconfigport.ErrInvalidArgument),
		errors.Is(err, agentconfigdomain.ErrInvalidTarget):
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	case errors.Is(err, context.Canceled):
		return expectedOutput(installapp.PhaseOutcomeCancelled, "installation.cancelled")
	case errors.Is(err, agentconfigport.ErrUnsupportedPlatform):
		return expectedOutput(installapp.PhaseOutcomeUnsupportedHost, "installation.select_supported_host")
	case errors.Is(err, agentconfigdomain.ErrInvalidDocument),
		errors.Is(err, agentconfigdomain.ErrAmbiguousOwnership),
		errors.Is(err, agentconfigdomain.ErrManagedEntryConflict),
		errors.Is(err, agentconfigport.ErrConflict):
		return expectedOutput(installapp.PhaseOutcomeFailedRecoverable, "installation.resolve_agent_configuration")
	case errors.Is(err, agentconfigport.ErrUnsafePath):
		return expectedOutput(installapp.PhaseOutcomeFailedRecoverable, "installation.repair_agent_configuration_permissions")
	case errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, agentconfigapp.ErrInvocationVerification),
		errors.Is(err, agentconfigport.ErrNotFound),
		errors.Is(err, agentconfigport.ErrDurabilityAmbiguous),
		errors.Is(err, agentconfigport.ErrIO):
		return expectedOutput(installapp.PhaseOutcomeFailedRecoverable, "installation.retry_agent_configuration")
	}
	return installapp.PhaseOutput{}, phaseError(ErrorCodeAgentConfigurationUnavailable)
}

var _ AgentConfigurationMerger = (*agentconfigapp.Application)(nil)
var _ installapp.AgentConfigurationPort = (*AgentConfigurationPhase)(nil)
