package filesystem

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const (
	cancellationPollMinimum = 10 * time.Millisecond
	cancellationPollMaximum = 250 * time.Millisecond
)

// Request atomically appends cancellation intent to the same authenticated
// aggregate journal used by phase transitions. Ready and requested are thus a
// linearizable either/or decision under the short operation-state fence.
func (r *InstallOperationRepository) Request(
	ctx context.Context,
	request installapp.CancellationRequest,
) (installapp.CancellationIntent, error) {
	if ctx == nil || request.OperationID.IsZero() || request.PlanDigest.IsZero() {
		return installapp.CancellationIntent{}, installapp.ErrCancellationIntentIntegrity
	}
	var result installapp.CancellationIntent
	err := r.fence.WithExclusive(ctx, request.OperationID, func() error {
		operation, loadError := r.loadUnfenced(ctx, request.OperationID)
		if loadError != nil {
			return loadError
		}
		if operation == nil || operation.AggregateVersion() < request.ObservedAggregateVersion {
			return installapp.ErrCancellationIntentIntegrity
		}
		if bindingError := operation.VerifyPlanBinding(request.PlanDigest); bindingError != nil {
			return installapp.ErrCancellationIntentIntegrity
		}
		before := operation.AggregateVersion()
		if requestError := operation.RequestCancellation(request.PlanDigest); requestError != nil {
			return installapp.ErrCancellationIntentConflict
		}
		if operation.AggregateVersion() != before {
			if saveError := r.saveUnfenced(ctx, operation.Snapshot()); saveError != nil {
				return saveError
			}
		}
		intent, intentError := cancellationIntentFromOperation(operation)
		result = intent
		return intentError
	})
	if err != nil {
		return installapp.CancellationIntent{}, mapCancellationRepositoryError(err)
	}
	return result, nil
}

// Observe returns only authenticated aggregate-owned intent.
func (r *InstallOperationRepository) Observe(
	ctx context.Context,
	operationID install.OperationID,
	plan install.PlanDigest,
) (installapp.CancellationIntent, error) {
	if ctx == nil || operationID.IsZero() || plan.IsZero() {
		return installapp.CancellationIntent{}, installapp.ErrCancellationIntentIntegrity
	}
	operation, err := r.Load(ctx, operationID)
	if err != nil {
		return installapp.CancellationIntent{}, mapCancellationRepositoryError(err)
	}
	if operation == nil || operation.VerifyPlanBinding(plan) != nil {
		return installapp.CancellationIntent{}, installapp.ErrCancellationIntentIntegrity
	}
	return cancellationIntentFromOperation(operation)
}

// Wait polls the same durable authority with bounded exponential backoff. It
// allocates no goroutine and returns promptly when the phase context is done.
func (r *InstallOperationRepository) Wait(
	ctx context.Context,
	operationID install.OperationID,
	plan install.PlanDigest,
) (installapp.CancellationIntent, error) {
	if ctx == nil {
		return installapp.CancellationIntent{}, installapp.ErrCancellationIntentIntegrity
	}
	delay := cancellationPollMinimum
	for {
		intent, err := r.Observe(ctx, operationID, plan)
		if err == nil || !errors.Is(err, installapp.ErrCancellationIntentNotFound) {
			return intent, err
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return installapp.CancellationIntent{}, ctx.Err()
		case <-timer.C:
		}
		if delay < cancellationPollMaximum {
			delay *= 2
			if delay > cancellationPollMaximum {
				delay = cancellationPollMaximum
			}
		}
	}
}

// Acknowledge appends the final aggregate mutation only after the application
// has persisted StateCancelled and completed owned cleanup.
func (r *InstallOperationRepository) Acknowledge(
	ctx context.Context,
	intent installapp.CancellationIntent,
	state install.State,
) (installapp.CancellationIntent, error) {
	if ctx == nil || state != install.StateCancelled ||
		!intent.ValidFor(intent.OperationID, intent.PlanDigest) {
		return installapp.CancellationIntent{}, installapp.ErrCancellationIntentIntegrity
	}
	var result installapp.CancellationIntent
	err := r.fence.WithExclusive(ctx, intent.OperationID, func() error {
		operation, loadError := r.loadUnfenced(ctx, intent.OperationID)
		if loadError != nil {
			return loadError
		}
		if operation == nil || operation.VerifyPlanBinding(intent.PlanDigest) != nil ||
			operation.State() != install.StateCancelled {
			return installapp.ErrCancellationIntentIntegrity
		}
		persisted, ok := operation.CancellationIntent()
		if !ok || persisted.RequestedAtVersion() != intent.Revision {
			if ok && persisted.Status() == install.CancellationAcknowledged {
				converted, conversionError := cancellationIntentFromOperation(operation)
				result = converted
				return conversionError
			}
			return installapp.ErrCancellationIntentConflict
		}
		if acknowledgeError := operation.AcknowledgeCancellation(intent.PlanDigest); acknowledgeError != nil {
			return installapp.ErrCancellationIntentIntegrity
		}
		if saveError := r.saveUnfenced(ctx, operation.Snapshot()); saveError != nil {
			return saveError
		}
		converted, conversionError := cancellationIntentFromOperation(operation)
		result = converted
		return conversionError
	})
	if err != nil {
		return installapp.CancellationIntent{}, mapCancellationRepositoryError(err)
	}
	return result, nil
}

func cancellationIntentFromOperation(
	operation *install.Operation,
) (installapp.CancellationIntent, error) {
	if operation == nil {
		return installapp.CancellationIntent{}, installapp.ErrCancellationIntentIntegrity
	}
	persisted, ok := operation.CancellationIntent()
	if !ok {
		return installapp.CancellationIntent{}, installapp.ErrCancellationIntentNotFound
	}
	requested, err := installapp.NewRequestedCancellationIntentForAdapter(
		installapp.CancellationRequest{
			OperationID: operation.ID(), PlanDigest: operation.PlanDigest(),
			ObservedAggregateVersion: persisted.RequestedAtVersion() - 1,
		},
		persisted.RequestedAtVersion(),
	)
	if err != nil {
		return installapp.CancellationIntent{}, installapp.ErrCancellationIntentIntegrity
	}
	if persisted.Status() == install.CancellationRequested {
		return requested, nil
	}
	acknowledged, err := installapp.NewAcknowledgedCancellationIntentForAdapter(
		requested, persisted.AcknowledgedAtVersion(), install.StateCancelled,
	)
	if err != nil {
		return installapp.CancellationIntent{}, installapp.ErrCancellationIntentIntegrity
	}
	return acknowledged, nil
}

func mapCancellationRepositoryError(err error) error {
	switch {
	case errors.Is(err, installapp.ErrCancellationIntentNotFound),
		errors.Is(err, installapp.ErrCancellationIntentIntegrity),
		errors.Is(err, installapp.ErrCancellationIntentConflict):
		return err
	case errors.Is(err, installapp.ErrOperationNotFound):
		return installapp.ErrCancellationIntentNotFound
	case errors.Is(err, installapp.ErrOperationIntegrity):
		return fmt.Errorf("%w: operation authority rejected intent", installapp.ErrCancellationIntentIntegrity)
	case errors.Is(err, installapp.ErrOperationConflict):
		return fmt.Errorf("%w: operation authority changed", installapp.ErrCancellationIntentConflict)
	default:
		return err
	}
}
