package runtimeremoval

import (
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const operationSchemaVersion = uint16(1)

// State is the closed durable removal-operation lifecycle.
type State uint8

const (
	// StateUnknown is the invalid zero state.
	StateUnknown State = iota
	// StateAwaitingConsent precedes the impact-specific second decision.
	StateAwaitingConsent
	// StateReadyToRemove has durable second consent but no destructive intent.
	StateReadyToRemove
	// StateRemoving has durable consent and execution-scan intent.
	StateRemoving
	// StateRemoved has exact native absence evidence.
	StateRemoved
	// StateDeclined is the non-destructive terminal state.
	StateDeclined
)

// OperationSnapshot is the strict persistence representation.
type OperationSnapshot struct {
	SchemaVersion  uint16              `json:"schema_version"`
	OperationID    string              `json:"operation_id"`
	Plan           PlanSnapshot        `json:"plan"`
	State          State               `json:"state"`
	Version        uint64              `json:"version"`
	ConsentReceipt runtimeinstall.Hash `json:"consent_receipt"`
	ExecutionScan  runtimeinstall.Hash `json:"execution_scan"`
	RemovalReceipt runtimeinstall.Hash `json:"removal_receipt"`
}

// Operation owns the second-consent and destructive-side-effect transitions.
type Operation struct {
	id             install.OperationID
	plan           Plan
	state          State
	version        uint64
	consentReceipt runtimeinstall.Hash
	executionScan  runtimeinstall.Hash
	removalReceipt runtimeinstall.Hash
}

// NewOperation starts only after an exhaustive safe plan exists.
func NewOperation(plan Plan) (*Operation, error) {
	if !plan.Valid() {
		return nil, errors.New("managed runtime removal plan is invalid")
	}
	return &Operation{id: plan.OperationID(), plan: plan, state: StateAwaitingConsent}, nil
}

// ID returns the distinct removal operation identity.
func (o *Operation) ID() install.OperationID { return o.id }

// PlanDigest returns the immutable removal plan binding.
func (o *Operation) PlanDigest() runtimeinstall.Hash { return o.plan.Digest() }

// Plan returns the immutable removal authority retained for crash recovery.
func (o *Operation) Plan() Plan { return o.plan }

// State returns the durable lifecycle state.
func (o *Operation) State() State { return o.state }

// Version returns the optimistic aggregate version.
func (o *Operation) Version() uint64 { return o.version }

// ConsentReceipt returns the authenticated impact confirmation digest.
func (o *Operation) ConsentReceipt() runtimeinstall.Hash { return o.consentReceipt }

// ExecutionScanDigest returns the fresh empty scan durably recorded before the native effect.
func (o *Operation) ExecutionScanDigest() runtimeinstall.Hash { return o.executionScan }

// RemovalReceipt returns the native removal and absence-verification digest.
func (o *Operation) RemovalReceipt() runtimeinstall.Hash { return o.removalReceipt }

// AuthorizeRemoval durably records the non-preselected second confirmation.
func (o *Operation) AuthorizeRemoval(planDigest, receipt runtimeinstall.Hash) error {
	if planDigest != o.plan.Digest() || receipt.IsZero() || o.state != StateAwaitingConsent ||
		!o.consentReceipt.IsZero() || !o.executionScan.IsZero() || !o.removalReceipt.IsZero() {
		return errors.New("managed runtime removal consent transition is invalid")
	}
	o.consentReceipt = receipt
	o.state = StateReadyToRemove
	o.version++
	return nil
}

// Decline records an explicit user refusal without any removal authority.
func (o *Operation) Decline(planDigest runtimeinstall.Hash) error {
	if planDigest != o.plan.Digest() || o.state != StateAwaitingConsent ||
		!o.consentReceipt.IsZero() || !o.executionScan.IsZero() || !o.removalReceipt.IsZero() {
		return errors.New("managed runtime removal decline is invalid")
	}
	o.state = StateDeclined
	o.version++
	return nil
}

// BeginRemoval persists the destructive intent before invoking a native adapter.
func (o *Operation) BeginRemoval(planDigest, executionScan runtimeinstall.Hash) error {
	if planDigest != o.plan.Digest() || executionScan.IsZero() || o.state != StateReadyToRemove ||
		o.consentReceipt.IsZero() || !o.executionScan.IsZero() {
		return errors.New("managed runtime removal cannot begin")
	}
	o.executionScan = executionScan
	o.state = StateRemoving
	o.version++
	return nil
}

// CompleteRemoval records native absence proof. It is idempotent only for the
// exact same already-recorded receipt.
func (o *Operation) CompleteRemoval(planDigest, receipt runtimeinstall.Hash) error {
	if planDigest != o.plan.Digest() || receipt.IsZero() {
		return errors.New("managed runtime removal receipt is invalid")
	}
	if o.state == StateRemoved && o.removalReceipt == receipt {
		return nil
	}
	if o.state != StateRemoving || !o.removalReceipt.IsZero() || o.consentReceipt.IsZero() || o.executionScan.IsZero() {
		return errors.New("managed runtime removal completion is invalid")
	}
	o.removalReceipt = receipt
	o.state = StateRemoved
	o.version++
	return nil
}

// Snapshot returns an immutable persistence value.
func (o *Operation) Snapshot() OperationSnapshot {
	return OperationSnapshot{
		SchemaVersion: operationSchemaVersion, OperationID: o.id.String(), Plan: o.plan.Snapshot(),
		State: o.state, Version: o.version, ConsentReceipt: o.consentReceipt,
		ExecutionScan: o.executionScan, RemovalReceipt: o.removalReceipt,
	}
}

// RestoreOperation rejects impossible or substituted persisted state.
func RestoreOperation(snapshot OperationSnapshot) (*Operation, error) {
	id, err := install.NewOperationID(snapshot.OperationID)
	plan, planError := RestorePlan(snapshot.Plan)
	if err != nil || planError != nil || snapshot.SchemaVersion != operationSchemaVersion || plan.OperationID() != id {
		return nil, errors.New("managed runtime removal snapshot identity is invalid")
	}
	operation := &Operation{
		id: id, plan: plan, state: snapshot.State, version: snapshot.Version,
		consentReceipt: snapshot.ConsentReceipt, executionScan: snapshot.ExecutionScan,
		removalReceipt: snapshot.RemovalReceipt,
	}
	switch snapshot.State {
	case StateAwaitingConsent:
		if snapshot.Version != 0 || !snapshot.ConsentReceipt.IsZero() || !snapshot.ExecutionScan.IsZero() ||
			!snapshot.RemovalReceipt.IsZero() {
			return nil, errors.New("managed runtime removal consent state is invalid")
		}
	case StateReadyToRemove:
		if snapshot.Version != 1 || snapshot.ConsentReceipt.IsZero() || !snapshot.ExecutionScan.IsZero() ||
			!snapshot.RemovalReceipt.IsZero() {
			return nil, errors.New("managed runtime removal authorized state is invalid")
		}
	case StateRemoving:
		if snapshot.Version != 2 || snapshot.ConsentReceipt.IsZero() || snapshot.ExecutionScan.IsZero() ||
			!snapshot.RemovalReceipt.IsZero() {
			return nil, errors.New("managed runtime removal in-progress state is invalid")
		}
	case StateRemoved:
		if snapshot.Version != 3 || snapshot.ConsentReceipt.IsZero() || snapshot.ExecutionScan.IsZero() ||
			snapshot.RemovalReceipt.IsZero() {
			return nil, errors.New("managed runtime removal completion state is invalid")
		}
	case StateDeclined:
		if snapshot.Version != 1 || !snapshot.ConsentReceipt.IsZero() || !snapshot.ExecutionScan.IsZero() ||
			!snapshot.RemovalReceipt.IsZero() {
			return nil, errors.New("managed runtime removal declined state is invalid")
		}
	case StateUnknown:
		return nil, errors.New("managed runtime removal state is invalid")
	default:
		return nil, errors.New("managed runtime removal state is invalid")
	}
	return operation, nil
}
