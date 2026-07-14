package launcher

import (
	"bytes"
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installphase"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeinstallapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

type nativeRuntimeExecutionQuery interface {
	ResolveRuntimeExecutionAuthority(
		context.Context,
		install.PlanDigest,
		install.OperationID,
	) (installplanapp.RuntimeExecutionAuthority, error)
}

type nativeRuntimeExecutionVerification interface {
	VerifyRuntimeExecution(
		context.Context,
		installplanapp.RuntimeExecutionAuthority,
	) (nativeVerifiedRuntimeExecution, error)
}

type nativePlatformRuntimeApplicationFactory interface {
	BuildRuntimeApplication(
		context.Context,
		nativeVerifiedRuntimeExecution,
	) (installphase.RuntimeEnsurer, error)
}

// nativeRuntimeEnsurer is the process-resume gate in front of PF-006. Every
// Ensure call reloads parent aggregate evidence and re-verifies both catalog
// envelopes before any platform phase can observe the command.
type nativeRuntimeEnsurer struct {
	parent    install.PlanDigest
	operation install.OperationID
	query     nativeRuntimeExecutionQuery
	verify    nativeRuntimeExecutionVerification
	platform  nativePlatformRuntimeApplicationFactory
}

func newNativeRuntimeEnsurer(
	parent install.PlanDigest,
	operation install.OperationID,
	query nativeRuntimeExecutionQuery,
	verify nativeRuntimeExecutionVerification,
	platform nativePlatformRuntimeApplicationFactory,
) (*nativeRuntimeEnsurer, error) {
	if parent.IsZero() || operation.IsZero() || nilAny(query) || nilAny(verify) || nilAny(platform) {
		return nil, errNativeInstallerIntegrity
	}
	return &nativeRuntimeEnsurer{
		parent: parent, operation: operation, query: query, verify: verify, platform: platform,
	}, nil
}

func (e *nativeRuntimeEnsurer) Ensure(
	ctx context.Context,
	command runtimeinstallapp.Command,
) (runtimeinstallapp.Result, error) {
	operationID, operationError := install.NewOperationID(command.OperationID)
	commandPlan, planError := runtimeinstall.DecodePlanV1(command.CanonicalPlan)
	if e == nil || ctx == nil || operationError != nil || planError != nil ||
		operationID != e.operation || e.parent.IsZero() || nilAny(e.query) || nilAny(e.verify) || nilAny(e.platform) {
		return runtimeinstallapp.Result{}, errNativeInstallerIntegrity
	}
	if err := ctx.Err(); err != nil {
		return runtimeinstallapp.Result{}, err
	}
	execution, err := e.query.ResolveRuntimeExecutionAuthority(ctx, e.parent, e.operation)
	if err != nil {
		return runtimeinstallapp.Result{}, errNativeInstallerIntegrity
	}
	authority := execution.RuntimeAuthority()
	if authority.OperationID() != e.operation || !authority.ParentPlanDigest().Equal(e.parent) ||
		authority.Plan().Digest() != commandPlan.Digest() ||
		!bytes.Equal(authority.Plan().CanonicalBytes(), command.CanonicalPlan) {
		return runtimeinstallapp.Result{}, errNativeInstallerIntegrity
	}
	verified, err := e.verify.VerifyRuntimeExecution(ctx, execution)
	if err != nil || !verified.authority.Equal(authority) ||
		!runtimeSelectionMatches(commandPlan, verified.runtime) {
		return runtimeinstallapp.Result{}, errNativeInstallerIntegrity
	}
	application, err := e.platform.BuildRuntimeApplication(ctx, verified)
	if err != nil || nilAny(application) {
		return runtimeinstallapp.Result{}, errNativeInstallerIntegrity
	}
	return application.Ensure(ctx, command)
}

var _ installphase.RuntimeEnsurer = (*nativeRuntimeEnsurer)(nil)
