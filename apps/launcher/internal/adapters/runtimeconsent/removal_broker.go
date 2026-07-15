package runtimeconsent

import (
	"context"
	"reflect"
	"sync"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeremovalapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeremoval"
)

// ManagedRuntimeRemovalDecisionInput is the exact two-step agent-host
// confirmation. ExplicitConfirmation is false by default and must be actively
// set only for approval; decline never obtains destructive authority.
type ManagedRuntimeRemovalDecisionInput struct {
	OperationID          string
	PlanDigest           runtimeinstall.Hash
	Impact               string
	Approved             bool
	ExplicitConfirmation bool
}

type managedRuntimeRemovalConsentSigner interface {
	SignManagedRuntimeRemovalConsent(
		context.Context,
		runtimeremoval.Plan,
		time.Time,
	) (runtimeinstall.Hash, error)
}

type trustedRemovalConsentClock interface{ Now() time.Time }

// RemovalBroker accepts one exact non-preselected agent-host decision and
// consumes it once through the application consent port. Approved decisions
// are authenticated by the owner/machine-bound protected consent key.
type RemovalBroker struct {
	signer managedRuntimeRemovalConsentSigner
	clock  trustedRemovalConsentClock

	mu      sync.Mutex
	pending map[runtimeinstall.Hash]runtimeremovalapp.ConsentDecision
}

var _ runtimeremovalapp.SecondConsentPort = (*RemovalBroker)(nil)

// NewRemovalBroker requires protected signing and trusted UTC time.
func NewRemovalBroker(
	signer managedRuntimeRemovalConsentSigner,
	clock trustedRemovalConsentClock,
) (*RemovalBroker, error) {
	if nilRemovalConsentDependency(signer) || nilRemovalConsentDependency(clock) {
		return nil, ErrIntegrity
	}
	return &RemovalBroker{
		signer: signer, clock: clock,
		pending: make(map[runtimeinstall.Hash]runtimeremovalapp.ConsentDecision),
	}, nil
}

// SubmitManagedRuntimeRemovalDecision binds the exact prepared plan and
// refuses a second queued decision, substituted impact, or implicit approval.
func (b *RemovalBroker) SubmitManagedRuntimeRemovalDecision(
	ctx context.Context,
	plan runtimeremoval.Plan,
	input ManagedRuntimeRemovalDecisionInput,
) error {
	if b == nil || ctx == nil || !plan.Valid() || nilRemovalConsentDependency(b.signer) ||
		nilRemovalConsentDependency(b.clock) || input.OperationID != plan.OperationID().String() ||
		input.PlanDigest != plan.Digest() || input.Impact != plan.ImpactConfirmation() ||
		input.Approved != input.ExplicitConfirmation {
		return ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	decision := runtimeremovalapp.ConsentDecision{
		Approved: input.Approved, Explicit: input.ExplicitConfirmation,
		PlanDigest: plan.Digest(), Impact: plan.ImpactConfirmation(),
	}
	if input.Approved {
		acceptedAt := b.clock.Now().UTC().Truncate(time.Microsecond)
		if acceptedAt.IsZero() {
			return ErrIntegrity
		}
		receipt, err := b.signer.SignManagedRuntimeRemovalConsent(ctx, plan, acceptedAt)
		if err != nil || receipt.IsZero() {
			return ErrIntegrity
		}
		decision.Receipt = receipt
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := b.pending[plan.Digest()]; exists {
		return ErrConflict
	}
	b.pending[plan.Digest()] = decision
	return nil
}

// AwaitManagedRuntimeRemovalConsent consumes exactly one previously submitted
// decision and never waits for an ambient or unrelated prompt.
func (b *RemovalBroker) AwaitManagedRuntimeRemovalConsent(
	ctx context.Context,
	plan runtimeremoval.Plan,
) (runtimeremovalapp.ConsentDecision, error) {
	if b == nil || ctx == nil || !plan.Valid() {
		return runtimeremovalapp.ConsentDecision{}, ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return runtimeremovalapp.ConsentDecision{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	decision, exists := b.pending[plan.Digest()]
	if !exists || decision.PlanDigest != plan.Digest() || decision.Impact != plan.ImpactConfirmation() {
		return runtimeremovalapp.ConsentDecision{}, ErrConflict
	}
	delete(b.pending, plan.Digest())
	return decision, nil
}

// DiscardManagedRuntimeRemovalDecision removes a still-unconsumed in-memory
// decision after the controller observes a terminal replay or failed effect.
// It is idempotent and never creates or persists destructive authority.
func (b *RemovalBroker) DiscardManagedRuntimeRemovalDecision(plan runtimeremoval.Plan) {
	if b == nil || !plan.Valid() {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.pending, plan.Digest())
}

func nilRemovalConsentDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Non-nilable concrete capabilities are valid dependencies.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
