// Package runtimeremovalapp implements the separately planned, separately
// consented managed-runtime removal use case.
package runtimeremovalapp

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeremoval"
)

const saveTimeout = 5 * time.Second

// Dependencies lists every required boundary explicitly.
type Dependencies struct {
	Operations OperationRepository
	Ownership  RuntimeOwnershipRepository
	Scanner    DependencyScanner
	Consent    SecondConsentPort
	Presence   RuntimePresenceVerifier
	Remover    NativeRemover
}

// Application orchestrates the crash-safe destructive operation.
type Application struct {
	operations OperationRepository
	ownership  RuntimeOwnershipRepository
	scanner    DependencyScanner
	consent    SecondConsentPort
	presence   RuntimePresenceVerifier
	remover    NativeRemover
}

// New rejects incomplete production composition.
func New(dependencies Dependencies) (*Application, error) {
	values := []any{dependencies.Operations, dependencies.Ownership, dependencies.Scanner,
		dependencies.Consent, dependencies.Presence, dependencies.Remover}
	for _, value := range values {
		if nilBoundary(value) {
			return nil, errors.New("every managed runtime removal dependency is required")
		}
	}
	return &Application{
		operations: dependencies.Operations, ownership: dependencies.Ownership, scanner: dependencies.Scanner,
		consent: dependencies.Consent, presence: dependencies.Presence, remover: dependencies.Remover,
	}, nil
}

// Remove starts or resumes until a durable terminal result or a fail-closed refusal.
func (a *Application) Remove(ctx context.Context, command Command) (Result, error) {
	operationID, sourceID, runtimePlan, err := validateCommand(command)
	if err != nil {
		return Result{OperationID: command.OperationID}, err
	}
	operation, loadError := a.operations.Load(ctx, operationID.String())
	switch {
	case loadError == nil && operation == nil:
		return Result{OperationID: command.OperationID}, ErrIntegrity
	case loadError == nil:
		if !commandMatches(operation.Plan(), operationID, sourceID, runtimePlan) {
			return resultFor(operation, OutcomeUnknown), ErrIntegrity
		}
	case errors.Is(loadError, ErrOperationNotFound):
		operation, err = a.createOperation(ctx, operationID, sourceID, runtimePlan)
		if err != nil {
			return Result{OperationID: command.OperationID}, err
		}
	default:
		return Result{OperationID: command.OperationID}, loadError
	}

	plan := operation.Plan()
	if operation.State() == runtimeremoval.StateAwaitingConsent {
		decision, consentError := a.consent.AwaitManagedRuntimeRemovalConsent(ctx, plan)
		if consentError != nil {
			return resultFor(operation, OutcomeUnknown), consentError
		}
		if decision.PlanDigest != plan.Digest() || decision.Impact != runtimeremoval.ImpactConfirmation {
			return resultFor(operation, OutcomeUnknown), ErrIntegrity
		}
		if !decision.Approved {
			if decision.Explicit || !decision.Receipt.IsZero() || operation.Decline(plan.Digest()) != nil {
				return resultFor(operation, OutcomeUnknown), ErrIntegrity
			}
			if err := a.save(ctx, operation); err != nil {
				return resultFor(operation, OutcomeUnknown), err
			}
			return resultFor(operation, OutcomeDeclined), nil
		}
		if !decision.Explicit || decision.Receipt.IsZero() ||
			operation.AuthorizeRemoval(plan.Digest(), decision.Receipt) != nil {
			return resultFor(operation, OutcomeUnknown), ErrIntegrity
		}
		if err := a.save(ctx, operation); err != nil {
			return resultFor(operation, OutcomeUnknown), err
		}
	}

	if operation.State() == runtimeremoval.StateReadyToRemove {
		ownership, ownershipError := a.loadExactOwnership(ctx, plan)
		if ownershipError != nil {
			return resultFor(operation, OutcomeUnknown), ownershipError
		}
		scan, scanError := a.scanExact(ctx, plan, ownership)
		if scanError != nil {
			return resultFor(operation, OutcomeUnknown), scanError
		}
		if operation.BeginRemoval(plan.Digest(), scan.Digest()) != nil {
			return resultFor(operation, OutcomeUnknown), ErrIntegrity
		}
		if err := a.save(ctx, operation); err != nil {
			return resultFor(operation, OutcomeUnknown), err
		}
	}

	if operation.State() == runtimeremoval.StateRemoving {
		if err := a.finishRemoval(ctx, operation); err != nil {
			return resultFor(operation, OutcomeUnknown), err
		}
	}
	if operation.State() == runtimeremoval.StateRemoved {
		return resultFor(operation, OutcomeRemoved), nil
	}
	if operation.State() == runtimeremoval.StateDeclined {
		return resultFor(operation, OutcomeDeclined), nil
	}
	return resultFor(operation, OutcomeUnknown), ErrIntegrity
}

func (a *Application) createOperation(
	ctx context.Context,
	operationID, sourceID install.OperationID,
	runtimePlan runtimeinstall.Plan,
) (*runtimeremoval.Operation, error) {
	ownership, err := a.ownership.LoadRuntimeOwnership(ctx, sourceID.String())
	if err != nil || ownership.OperationID() != sourceID.String() {
		if err != nil {
			return nil, err
		}
		return nil, ErrIntegrity
	}
	scan, err := a.scanner.ScanRuntimeDependencies(ctx, ScanRequest{
		Endpoint: ownership.Endpoint(), Ownership: ownership,
	})
	if err != nil {
		return nil, err
	}
	plan, err := runtimeremoval.NewPlan(operationID, runtimePlan.CanonicalBytes(), ownership, scan)
	if err != nil {
		if scan.Digest().IsZero() {
			return nil, ErrScanUncertain
		}
		if !scan.SafeToRemove() {
			return nil, ErrDependenciesExist
		}
		return nil, ErrIntegrity
	}
	operation, err := runtimeremoval.NewOperation(plan)
	if err != nil {
		return nil, ErrIntegrity
	}
	if err := a.save(ctx, operation); err != nil {
		return nil, err
	}
	return operation, nil
}

func (a *Application) finishRemoval(ctx context.Context, operation *runtimeremoval.Operation) error {
	plan := operation.Plan()
	presence, err := a.presence.InspectManagedRuntime(ctx, plan)
	if err != nil || !presence.validFor(plan) {
		if err != nil {
			return err
		}
		return ErrScanUncertain
	}
	if presence.Absent {
		return a.complete(ctx, operation, alreadyAbsentReceipt(
			plan, presence, operation.ExecutionScanDigest(), operation.ConsentReceipt(),
		))
	}
	ownership, err := a.loadExactOwnership(ctx, plan)
	if err != nil {
		return err
	}
	scan, err := a.scanExact(ctx, plan, ownership)
	if err != nil {
		return err
	}
	if scan.Digest() != operation.ExecutionScanDigest() {
		return ErrScanUncertain
	}
	authorization := RemovalAuthorization{
		plan: plan, ownership: ownership, scan: scan, consentReceipt: operation.ConsentReceipt(),
	}
	if !authorization.valid() {
		return ErrIntegrity
	}
	result, err := a.remover.RemoveManagedRuntime(ctx, authorization)
	if err != nil {
		return err
	}
	if !result.validFor(authorization) {
		return ErrIntegrity
	}
	absence, err := a.presence.InspectManagedRuntime(ctx, plan)
	if err != nil || !absence.validFor(plan) || !absence.Absent {
		if err != nil {
			return err
		}
		return ErrScanUncertain
	}
	return a.complete(ctx, operation, removalReceipt(result, absence))
}

func (a *Application) complete(ctx context.Context, operation *runtimeremoval.Operation, receipt runtimeinstall.Hash) error {
	if receipt.IsZero() || operation.CompleteRemoval(operation.PlanDigest(), receipt) != nil {
		return ErrIntegrity
	}
	return a.save(ctx, operation)
}

func (a *Application) loadExactOwnership(
	ctx context.Context,
	plan runtimeremoval.Plan,
) (runtimeinstall.RuntimeOwnershipRecord, error) {
	ownership, err := a.ownership.LoadRuntimeOwnership(ctx, plan.SourceOperationID())
	if err != nil {
		return runtimeinstall.RuntimeOwnershipRecord{}, err
	}
	if ownership.Digest() != plan.OwnershipRecordDigest() || ownership.OperationID() != plan.SourceOperationID() ||
		ownership.Status() != runtimeinstall.OwnershipStatusFinalized ||
		ownership.Disposition() != runtimeinstall.OwnershipProvisionedByAgentMemory {
		return runtimeinstall.RuntimeOwnershipRecord{}, ErrIntegrity
	}
	return ownership, nil
}

func (a *Application) scanExact(
	ctx context.Context,
	plan runtimeremoval.Plan,
	ownership runtimeinstall.RuntimeOwnershipRecord,
) (runtimeremoval.DependencyScan, error) {
	scan, err := a.scanner.ScanRuntimeDependencies(ctx, ScanRequest{
		Endpoint: plan.Endpoint(), Ownership: ownership,
	})
	if err != nil {
		return runtimeremoval.DependencyScan{}, err
	}
	if scan.Digest().IsZero() || scan.OwnershipRecordDigest() != ownership.Digest() || scan.Endpoint() != plan.Endpoint() {
		return runtimeremoval.DependencyScan{}, ErrScanUncertain
	}
	if !scan.SafeToRemove() {
		return runtimeremoval.DependencyScan{}, ErrDependenciesExist
	}
	return scan, nil
}

func (a *Application) save(ctx context.Context, operation *runtimeremoval.Operation) error {
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), saveTimeout)
	defer cancel()
	return a.operations.Save(persistCtx, operation.Snapshot())
}

func validateCommand(command Command) (install.OperationID, install.OperationID, runtimeinstall.Plan, error) {
	operationID, operationError := install.NewOperationID(command.OperationID)
	sourceID, sourceError := install.NewOperationID(command.SourceOperationID)
	plan, planError := runtimeinstall.DecodePlanV1(command.CanonicalRuntimePlan)
	if operationError != nil || sourceError != nil || planError != nil || operationID == sourceID {
		return install.OperationID{}, install.OperationID{}, runtimeinstall.Plan{}, ErrIntegrity
	}
	return operationID, sourceID, plan, nil
}

func commandMatches(
	plan runtimeremoval.Plan,
	operationID, sourceID install.OperationID,
	runtimePlan runtimeinstall.Plan,
) bool {
	return plan.Valid() && plan.OperationID() == operationID && plan.SourceOperationID() == sourceID.String() &&
		plan.RuntimePlanDigest() == runtimePlan.Digest()
}

func resultFor(operation *runtimeremoval.Operation, outcome Outcome) Result {
	return Result{OperationID: operation.ID().String(), PlanDigest: operation.PlanDigest(), Outcome: outcome}
}

func nilBoundary(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid, reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128, reflect.Array,
		reflect.String, reflect.Struct, reflect.UnsafePointer:
		return false
	}
	return false
}
