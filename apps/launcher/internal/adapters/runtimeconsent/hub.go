// Package runtimeconsent coordinates the trusted local setup surface with a
// blocked PF-006 consent phase. It transports only a closed decision; platform
// adapters remain responsible for signed receipt construction and storage.
package runtimeconsent

import (
	"context"
	"errors"
	"sync"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/setupprogressapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

var (
	// ErrIntegrity rejects a missing, malformed, or substituted binding.
	ErrIntegrity = errors.New("runtime consent hub integrity violation")
	// ErrConflict rejects a second concurrent prompt or decision.
	ErrConflict = errors.New("runtime consent hub conflict")
)

// Decision is the only user choice transported to a runtime consent broker.
type Decision uint8

const (
	decisionUnknown Decision = iota
	// DecisionAccept records an explicit affirmative decision.
	DecisionAccept
	// DecisionDecline records an explicit negative decision.
	DecisionDecline
)

// Pending binds one prompt to the authenticated runtime plan and terms. These
// values are revalidated again by the platform consent receipt constructor.
type Pending struct {
	OperationID       string
	RuntimePlanDigest runtimeinstall.Hash
	TermsDigest       runtimeinstall.Hash
}

func (p Pending) valid() bool {
	if p.OperationID == "" || len(p.OperationID) > 128 ||
		p.RuntimePlanDigest.IsZero() || p.TermsDigest.IsZero() {
		return false
	}
	for _, character := range p.OperationID {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

type pendingDecision struct {
	input     Pending
	decisions chan Decision
	delivered bool
}

type operationEntry struct {
	binding setupprogressapp.Binding
	pending *pendingDecision
	changed chan struct{}
}

// Hub owns operation-scoped synchronization without a background goroutine.
// Context cancellation owns every wait and removes abandoned prompts.
type Hub struct {
	mu      sync.Mutex
	entries map[string]*operationEntry
}

// NewHub constructs an empty local decision authority.
func NewHub() (*Hub, error) {
	return &Hub{entries: make(map[string]*operationEntry)}, nil
}

// Bind registers the already authenticated parent setup binding. Rebinding is
// idempotent only when every binding field is identical.
func (h *Hub) Bind(binding setupprogressapp.Binding) error {
	if h == nil || !binding.Valid() {
		return ErrIntegrity
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	key := binding.OperationID().String()
	if existing, present := h.entries[key]; present {
		if existing == nil || !sameBinding(existing.binding, binding) {
			return ErrIntegrity
		}
		return nil
	}
	h.entries[key] = &operationEntry{binding: binding, changed: make(chan struct{})}
	return nil
}

// Await publishes one exact pending prompt and waits for the trusted setup
// surface. A second platform prompt for the operation is a conflict.
func (h *Hub) Await(ctx context.Context, input Pending) (Decision, error) {
	if h == nil || ctx == nil || !input.valid() {
		return decisionUnknown, ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return decisionUnknown, err
	}
	h.mu.Lock()
	entry := h.entries[input.OperationID]
	if entry == nil || !entry.binding.Valid() {
		h.mu.Unlock()
		return decisionUnknown, ErrIntegrity
	}
	if entry.pending != nil {
		h.mu.Unlock()
		return decisionUnknown, ErrConflict
	}
	pending := &pendingDecision{input: input, decisions: make(chan Decision, 1)}
	entry.pending = pending
	signal(entry)
	h.mu.Unlock()

	defer h.clear(input.OperationID, pending)
	select {
	case <-ctx.Done():
		return decisionUnknown, ctx.Err()
	case decision := <-pending.decisions:
		if decision != DecisionAccept && decision != DecisionDecline {
			return decisionUnknown, ErrIntegrity
		}
		return decision, nil
	}
}

// SubmitRuntimeConsent waits through the narrow child-save/prompt-register
// race, validates the exact parent binding, and delivers one closed decision.
func (h *Hub) SubmitRuntimeConsent(
	ctx context.Context,
	binding setupprogressapp.Binding,
	requested setupprogressapp.Decision,
	idempotencyKey string,
) error {
	var decision Decision
	switch requested {
	case setupprogressapp.DecisionAccept:
		decision = DecisionAccept
	case setupprogressapp.DecisionDecline:
		decision = DecisionDecline
	case setupprogressapp.DecisionCancel, setupprogressapp.DecisionRetry:
		return ErrIntegrity
	default:
		return ErrIntegrity
	}
	if h == nil || ctx == nil || !binding.Valid() || idempotencyKey == "" {
		return ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	key := binding.OperationID().String()
	for {
		h.mu.Lock()
		entry := h.entries[key]
		if entry == nil || !sameBinding(entry.binding, binding) {
			h.mu.Unlock()
			return ErrIntegrity
		}
		if entry.pending != nil {
			if entry.pending.delivered {
				h.mu.Unlock()
				return ErrConflict
			}
			entry.pending.delivered = true
			entry.pending.decisions <- decision
			h.mu.Unlock()
			return nil
		}
		changed := entry.changed
		h.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

func (h *Hub) clear(operationID string, pending *pendingDecision) {
	h.mu.Lock()
	defer h.mu.Unlock()
	entry := h.entries[operationID]
	if entry != nil && entry.pending == pending {
		entry.pending = nil
		signal(entry)
	}
}

func signal(entry *operationEntry) {
	close(entry.changed)
	entry.changed = make(chan struct{})
}

func sameBinding(left, right setupprogressapp.Binding) bool {
	return left.Valid() && right.Valid() && left.OperationID() == right.OperationID() &&
		left.PlanDigest().Equal(right.PlanDigest())
}
