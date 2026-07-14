package setupprogressapp

import (
	"context"
	"errors"
	"reflect"
	"sync"
)

// DecisionInput is the exact transport-neutral command body.
type DecisionInput struct {
	PlanDigest     string
	Decision       Decision
	IdempotencyKey string
}

// Application validates every call and every backend projection. It never
// creates state, advances progress, or derives Ready.
type Application struct {
	binding   Binding
	snapshots SnapshotAuthority
	decisions DecisionAuthority
	mu        sync.Mutex
	observed  Snapshot
	hasSeen   bool
}

// NewApplication rejects missing and typed-nil durable authorities.
func NewApplication(
	binding Binding,
	snapshots SnapshotAuthority,
	decisions DecisionAuthority,
) (*Application, error) {
	if !binding.Valid() || nilCapability(snapshots) || nilCapability(decisions) {
		return nil, errors.New("setup progress application dependencies are invalid")
	}
	return &Application{binding: binding, snapshots: snapshots, decisions: decisions}, nil
}

// Binding returns the operation and plan selected at composition time.
func (a *Application) Binding() Binding {
	if a == nil {
		return Binding{}
	}
	return a.binding
}

// Current returns only a complete backend-authoritative bound snapshot.
func (a *Application) Current(ctx context.Context) (Snapshot, error) {
	if err := a.validateCall(ctx); err != nil {
		return Snapshot{}, err
	}
	snapshot, err := a.snapshots.CurrentSnapshot(ctx, a.binding)
	if err != nil {
		return Snapshot{}, mapAuthorityError(err)
	}
	if err := a.observe(snapshot, 0, false); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

// WaitAfter blocks behind the durable snapshot port and accepts only an exact
// bound projection with a sequence strictly greater than the supplied cursor.
func (a *Application) WaitAfter(ctx context.Context, after uint64) (Snapshot, error) {
	if err := a.validateCall(ctx); err != nil || after > MaximumSafeInteger {
		if err != nil {
			return Snapshot{}, err
		}
		return Snapshot{}, newApplicationError(ErrorInvalidArgument)
	}
	snapshot, err := a.snapshots.WaitSnapshotAfter(ctx, a.binding, after)
	if err != nil {
		return Snapshot{}, mapAuthorityError(err)
	}
	if err := a.observe(snapshot, after, true); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

// Decide delegates the exact UUID and closed decision to the durable port,
// then rejects any receipt or snapshot substitution.
func (a *Application) Decide(ctx context.Context, input DecisionInput) (Snapshot, error) {
	if err := a.validateCall(ctx); err != nil {
		return Snapshot{}, err
	}
	if input.PlanDigest != a.binding.PlanDigest().String() || !input.Decision.Valid() ||
		!validUUID(input.IdempotencyKey) {
		return Snapshot{}, newApplicationError(ErrorInvalidArgument)
	}
	command := newDecisionCommand(a.binding, input.Decision, input.IdempotencyKey)
	receipt, err := a.decisions.ApplyDecision(ctx, command)
	if err != nil {
		return Snapshot{}, mapAuthorityError(err)
	}
	if receipt.IdempotencyKey() != input.IdempotencyKey || receipt.Decision() != input.Decision {
		return Snapshot{}, newApplicationError(ErrorIntegrity)
	}
	snapshot := receipt.Snapshot()
	if err := a.observe(snapshot, 0, false); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func (a *Application) validateCall(ctx context.Context) error {
	if a == nil || !a.binding.Valid() || nilCapability(a.snapshots) || nilCapability(a.decisions) || ctx == nil {
		return newApplicationError(ErrorInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return newApplicationError(ErrorDeadline)
	}
	return nil
}

func (a *Application) observe(snapshot Snapshot, minimum uint64, exclusive bool) error {
	if snapshot.OperationID() != a.binding.OperationID() || snapshot.PlanDigest() != a.binding.PlanDigest() {
		return newApplicationError(ErrorIntegrity)
	}
	if _, err := snapshot.CanonicalJSON(); err != nil || exclusive && snapshot.Sequence() <= minimum {
		return newApplicationError(ErrorIntegrity)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.hasSeen {
		if snapshot.Sequence() < a.observed.Sequence() ||
			snapshot.Sequence() == a.observed.Sequence() && !equalCanonicalSnapshot(snapshot, a.observed) {
			return newApplicationError(ErrorIntegrity)
		}
	}
	if !a.hasSeen || snapshot.Sequence() > a.observed.Sequence() {
		a.observed, a.hasSeen = snapshot, true
	}
	return nil
}

func mapAuthorityError(err error) *ApplicationError {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return newApplicationError(ErrorDeadline)
	case errors.Is(err, ErrAuthorityConflict):
		return newApplicationError(ErrorConflict)
	case errors.Is(err, ErrAuthorityIntegrity):
		return newApplicationError(ErrorIntegrity)
	default:
		return newApplicationError(ErrorUnavailable)
	}
}

func nilCapability(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Every non-nilable concrete kind is a valid non-nil dependency.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid:
		return true
	default:
		return false
	}
}
