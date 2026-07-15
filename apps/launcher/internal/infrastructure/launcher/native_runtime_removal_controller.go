package launcher

import (
	"context"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeconsent"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeremovalapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeremoval"
)

type nativePreparedRuntimeRemoval struct {
	public managedRuntimeRemovalPlan
	plan   runtimeremoval.Plan
	valid  bool
}

type nativeRuntimeRemovalUseCase interface {
	Prepare(context.Context, runtimeremovalapp.Command) (nativePreparedRuntimeRemoval, error)
	Remove(context.Context, runtimeremovalapp.Command) (runtimeremovalapp.Result, error)
}

type nativeRuntimeRemovalDecisionBroker interface {
	SubmitManagedRuntimeRemovalDecision(
		context.Context,
		runtimeremoval.Plan,
		runtimeconsent.ManagedRuntimeRemovalDecisionInput,
	) error
	DiscardManagedRuntimeRemovalDecision(runtimeremoval.Plan)
}

type nativeRuntimeRemovalApplicationPort interface {
	Prepare(context.Context, runtimeremovalapp.Command) (runtimeremovalapp.PreparedRemoval, error)
	Remove(context.Context, runtimeremovalapp.Command) (runtimeremovalapp.Result, error)
}

type nativeRuntimeRemovalApplication struct {
	application nativeRuntimeRemovalApplicationPort
}

func (a nativeRuntimeRemovalApplication) Prepare(
	ctx context.Context,
	command runtimeremovalapp.Command,
) (nativePreparedRuntimeRemoval, error) {
	if nilReadyCapability(a.application) {
		return nativePreparedRuntimeRemoval{}, errors.New("managed runtime removal application is unavailable")
	}
	prepared, err := a.application.Prepare(ctx, command)
	if err != nil || !prepared.Valid() {
		return nativePreparedRuntimeRemoval{}, errors.New("managed runtime removal plan is unavailable")
	}
	plan := prepared.RemovalPlan()
	return nativePreparedRuntimeRemoval{
		public: managedRuntimeRemovalPlan{
			OperationID: prepared.OperationID(), PlanDigest: prepared.PlanDigest().String(),
			Impact: prepared.Impact(), Platform: prepared.Platform().String(),
			Product: prepared.Product(), Version: prepared.Version(),
		},
		plan: plan, valid: plan.Valid(),
	}, nil
}

func (a nativeRuntimeRemovalApplication) Remove(
	ctx context.Context,
	command runtimeremovalapp.Command,
) (runtimeremovalapp.Result, error) {
	if nilReadyCapability(a.application) {
		return runtimeremovalapp.Result{}, errors.New("managed runtime removal application is unavailable")
	}
	return a.application.Remove(ctx, command)
}

type nativeManagedRuntimeRemovalController struct {
	command   runtimeremovalapp.Command
	useCase   nativeRuntimeRemovalUseCase
	decisions nativeRuntimeRemovalDecisionBroker
}

func newNativeManagedRuntimeRemovalController(
	command runtimeremovalapp.Command,
	useCase nativeRuntimeRemovalUseCase,
	decisions nativeRuntimeRemovalDecisionBroker,
) (*nativeManagedRuntimeRemovalController, error) {
	operationID, operationError := install.NewOperationID(command.OperationID)
	sourceID, sourceError := install.NewOperationID(command.SourceOperationID)
	if operationError != nil || sourceError != nil || operationID == sourceID ||
		len(command.CanonicalRuntimePlan) == 0 || nilReadyCapability(useCase) || nilReadyCapability(decisions) {
		return nil, errors.New("managed runtime removal controller authority is invalid")
	}
	command.CanonicalRuntimePlan = append([]byte(nil), command.CanonicalRuntimePlan...)
	return &nativeManagedRuntimeRemovalController{
		command: command, useCase: useCase, decisions: decisions,
	}, nil
}

func (c *nativeManagedRuntimeRemovalController) PrepareManagedRuntimeRemoval(
	ctx context.Context,
) (managedRuntimeRemovalPlan, error) {
	prepared, err := c.prepare(ctx)
	if err != nil {
		return managedRuntimeRemovalPlan{}, err
	}
	return prepared.public, nil
}

func (c *nativeManagedRuntimeRemovalController) DecideManagedRuntimeRemoval(
	ctx context.Context,
	input managedRuntimeRemovalDecision,
) (managedRuntimeRemovalResult, error) {
	if c == nil || ctx == nil || input.Approved != input.ExplicitConfirmation {
		return managedRuntimeRemovalResult{}, errors.New("managed runtime removal decision is invalid")
	}
	prepared, err := c.prepare(ctx)
	if err != nil || input.OperationID != prepared.public.OperationID ||
		input.PlanDigest != prepared.public.PlanDigest || input.Impact != prepared.public.Impact {
		return managedRuntimeRemovalResult{}, errors.New("managed runtime removal decision does not match the prepared plan")
	}
	digest, err := runtimeinstall.ParseHash(input.PlanDigest)
	if err != nil {
		return managedRuntimeRemovalResult{}, errors.New("managed runtime removal plan digest is invalid")
	}
	if err := c.decisions.SubmitManagedRuntimeRemovalDecision(
		ctx,
		prepared.plan,
		runtimeconsent.ManagedRuntimeRemovalDecisionInput{
			OperationID: input.OperationID, PlanDigest: digest, Impact: input.Impact,
			Approved: input.Approved, ExplicitConfirmation: input.ExplicitConfirmation,
		},
	); err != nil {
		return managedRuntimeRemovalResult{}, errors.New("managed runtime removal consent could not be recorded")
	}
	defer c.decisions.DiscardManagedRuntimeRemovalDecision(prepared.plan)
	result, err := c.useCase.Remove(ctx, c.command)
	if err != nil || result.OperationID != prepared.public.OperationID || result.PlanDigest != digest {
		return managedRuntimeRemovalResult{}, errors.New("managed runtime removal did not complete")
	}
	outcome := ""
	switch result.Outcome {
	case runtimeremovalapp.OutcomeDeclined:
		outcome = "declined"
	case runtimeremovalapp.OutcomeRemoved:
		outcome = "removed"
	case runtimeremovalapp.OutcomeUnknown:
	}
	if outcome == "" {
		return managedRuntimeRemovalResult{}, errors.New("managed runtime removal result is invalid")
	}
	return managedRuntimeRemovalResult{
		OperationID: result.OperationID, PlanDigest: result.PlanDigest.String(), Outcome: outcome,
	}, nil
}

func (c *nativeManagedRuntimeRemovalController) prepare(
	ctx context.Context,
) (nativePreparedRuntimeRemoval, error) {
	if c == nil || ctx == nil || nilReadyCapability(c.useCase) || nilReadyCapability(c.decisions) {
		return nativePreparedRuntimeRemoval{}, errors.New("managed runtime removal controller is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nativePreparedRuntimeRemoval{}, err
	}
	prepared, err := c.useCase.Prepare(ctx, c.command)
	if err != nil || !prepared.valid || !prepared.public.valid() ||
		prepared.public.OperationID != c.command.OperationID {
		return nativePreparedRuntimeRemoval{}, errors.New("managed runtime removal plan is unavailable")
	}
	if _, err := runtimeinstall.ParseHash(prepared.public.PlanDigest); err != nil {
		return nativePreparedRuntimeRemoval{}, errors.New("managed runtime removal plan is invalid")
	}
	return prepared, nil
}

var _ managedRuntimeRemovalController = (*nativeManagedRuntimeRemovalController)(nil)
