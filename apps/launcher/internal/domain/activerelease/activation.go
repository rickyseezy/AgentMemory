package activerelease

import (
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const activationSchemaVersion = uint16(1)

// StageDigest independently binds Core's durable preparation receipt to the
// exact operation, pointer, and readiness authorization. Core and launcher
// implement these canonical bytes separately and must produce the same SHA-256.
func StageDigest(operationID install.OperationID, pointer Pointer) (install.Digest, error) {
	if operationID.IsZero() || pointer.IsZero() {
		return install.Digest{}, errors.New("core activation stage binding is invalid")
	}
	canonical := appendField(nil, "agentmemory.active-release-stage.v1")
	canonical = appendField(canonical, operationID.String())
	canonical = appendField(canonical, pointer.Digest().String())
	canonical = appendField(canonical, pointer.ReadinessReceiptDigest().String())
	return install.DigestBytes(canonical), nil
}

// State is the closed crash-recovery cursor for activation.
type State uint8

const (
	// StateUnknown is the invalid zero value.
	StateUnknown State = iota
	// StateCreated is durable before Core staging.
	StateCreated
	// StateCorePrepared records Core's idempotent staging receipt.
	StateCorePrepared
	// StateHostCommitted records a durable host pointer compare-and-swap.
	StateHostCommitted
	// StateCommitted records that Core mirrors the exact host pointer.
	StateCommitted
)

// ActivationSnapshot is the explicit versioned repository DTO.
type ActivationSnapshot struct {
	SchemaVersion      uint16
	OperationID        string
	PlanDigest         string
	ExpectedHostDigest string
	Target             PointerRecord
	State              State
	CoreStageDigest    string
	Version            uint64
}

// Activation owns the only legal host/Core pointer transition order.
type Activation struct {
	operationID        install.OperationID
	planDigest         install.PlanDigest
	expectedHostDigest install.Digest
	target             Pointer
	state              State
	coreStageDigest    install.Digest
	version            uint64
}

// NewActivation creates the durable intent that must be saved before Core or
// host pointer side effects. expectedHostDigest is zero only for first install.
func NewActivation(
	operationID install.OperationID,
	planDigest install.PlanDigest,
	expectedHostDigest install.Digest,
	target Pointer,
) (*Activation, error) {
	if operationID.IsZero() || planDigest.IsZero() || target.IsZero() {
		return nil, errors.New("active release activation intent is invalid")
	}
	return &Activation{
		operationID:        operationID,
		planDigest:         planDigest,
		expectedHostDigest: expectedHostDigest,
		target:             target,
		state:              StateCreated,
	}, nil
}

// RestoreActivation strictly rehydrates a repository snapshot and rejects
// unknown schemas or contradictory cursor/evidence combinations.
func RestoreActivation(snapshot ActivationSnapshot) (*Activation, error) {
	if snapshot.SchemaVersion != activationSchemaVersion {
		return nil, errors.New("active release activation schema is unsupported")
	}
	operationID, operationError := install.NewOperationID(snapshot.OperationID)
	planDigest, planError := install.ParsePlanDigest(snapshot.PlanDigest)
	target, targetError := RestorePointer(snapshot.Target)
	var expected install.Digest
	var expectedError error
	if snapshot.ExpectedHostDigest != "" {
		expected, expectedError = install.ParseDigest(snapshot.ExpectedHostDigest)
	}
	var stage install.Digest
	var stageError error
	if snapshot.CoreStageDigest != "" {
		stage, stageError = install.ParseDigest(snapshot.CoreStageDigest)
	}
	if operationError != nil || planError != nil || targetError != nil || expectedError != nil || stageError != nil {
		return nil, errors.New("active release activation snapshot is invalid")
	}
	expectedVersion := uint64(0)
	switch snapshot.State {
	case StateCreated:
		if !stage.IsZero() {
			return nil, errors.New("created activation contains a Core receipt")
		}
	case StateCorePrepared:
		expectedVersion = 1
	case StateHostCommitted:
		expectedVersion = 2
	case StateCommitted:
		expectedVersion = 3
	case StateUnknown:
		return nil, errors.New("active release activation state is invalid")
	}
	if snapshot.Version != expectedVersion || (snapshot.State >= StateCorePrepared && stage.IsZero()) {
		return nil, errors.New("active release activation cursor is contradictory")
	}
	return &Activation{
		operationID:        operationID,
		planDigest:         planDigest,
		expectedHostDigest: expected,
		target:             target,
		state:              snapshot.State,
		coreStageDigest:    stage,
		version:            snapshot.Version,
	}, nil
}

// RecordCorePrepared advances after Core durably stages the exact target.
func (a *Activation) RecordCorePrepared(stageDigest install.Digest) error {
	if stageDigest.IsZero() {
		return errors.New("core activation stage receipt is required")
	}
	if a.state == StateCorePrepared && a.coreStageDigest.Equal(stageDigest) {
		return nil
	}
	if a.state != StateCreated {
		return errors.New("core activation cannot be prepared at the current state")
	}
	a.coreStageDigest = stageDigest
	a.state = StateCorePrepared
	a.version++
	return nil
}

// RecordHostCommitted advances only for the exact target pointer digest.
func (a *Activation) RecordHostCommitted(pointerDigest install.Digest) error {
	if a.state == StateHostCommitted && a.target.Digest().Equal(pointerDigest) {
		return nil
	}
	if a.state != StateCorePrepared || !a.target.Digest().Equal(pointerDigest) {
		return errors.New("host activation receipt does not match the staged target")
	}
	a.state = StateHostCommitted
	a.version++
	return nil
}

// RecordCoreCommitted completes only when Core attests both the original
// stage receipt and the exact host pointer digest.
func (a *Activation) RecordCoreCommitted(stageDigest install.Digest, pointerDigest install.Digest) error {
	if a.state == StateCommitted && a.coreStageDigest.Equal(stageDigest) && a.target.Digest().Equal(pointerDigest) {
		return nil
	}
	if a.state != StateHostCommitted || !a.coreStageDigest.Equal(stageDigest) ||
		!a.target.Digest().Equal(pointerDigest) {
		return errors.New("core activation commit does not match durable host state")
	}
	a.state = StateCommitted
	a.version++
	return nil
}

// OperationID returns the parent PF-001 operation.
func (a *Activation) OperationID() install.OperationID { return a.operationID }

// PlanDigest returns the canonical installation-plan binding.
func (a *Activation) PlanDigest() install.PlanDigest { return a.planDigest }

// ExpectedHostDigest returns the compare-and-swap predecessor or zero.
func (a *Activation) ExpectedHostDigest() install.Digest { return a.expectedHostDigest }

// Pointer returns the immutable activation target.
func (a *Activation) Pointer() Pointer { return a.target }

// State returns the current crash-recovery cursor.
func (a *Activation) State() State { return a.state }

// CoreStageDigest returns Core's idempotent preparation receipt.
func (a *Activation) CoreStageDigest() install.Digest { return a.coreStageDigest }

// Version returns the optimistic repository revision.
func (a *Activation) Version() uint64 { return a.version }

// Snapshot returns a caller-owned persistence representation.
func (a *Activation) Snapshot() ActivationSnapshot {
	expected := ""
	if !a.expectedHostDigest.IsZero() {
		expected = a.expectedHostDigest.String()
	}
	stage := ""
	if !a.coreStageDigest.IsZero() {
		stage = a.coreStageDigest.String()
	}
	return ActivationSnapshot{
		SchemaVersion:      activationSchemaVersion,
		OperationID:        a.operationID.String(),
		PlanDigest:         a.planDigest.String(),
		ExpectedHostDigest: expected,
		Target:             a.target.Record(),
		State:              a.state,
		CoreStageDigest:    stage,
		Version:            a.version,
	}
}
