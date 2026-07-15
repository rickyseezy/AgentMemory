package runtimeinstallapp

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const (
	completionEvidenceDomain = "agentmemory.runtime-completion-evidence.v1"
	completionReceiptDomain  = "agentmemory.runtime-completion-receipt.v1"
)

// CompletionReceipt is the privacy-safe projection of a fully restored Ready
// aggregate. It contains bindings, not paths, platform output, or credentials.
type CompletionReceipt struct {
	operationID      string
	planDigest       runtimeinstall.Hash
	aggregateVersion uint64
	evidenceDigest   runtimeinstall.Hash
	inputDigest      runtimeinstall.Hash
	outputDigest     runtimeinstall.Hash
	artifactDigest   runtimeinstall.Hash
	ownership        runtimeinstall.OwnershipDisposition
	ownershipRecord  runtimeinstall.Hash
	seal             runtimeinstall.Hash
}

// NewCompletionReceipt validates and replays the complete aggregate before
// projecting final runtime authority for the parent installation saga.
func NewCompletionReceipt(
	snapshot runtimeinstall.OperationSnapshot,
	ownershipRecord runtimeinstall.RuntimeOwnershipRecord,
) (CompletionReceipt, error) {
	operation, err := runtimeinstall.RestoreOperation(snapshot)
	if err != nil {
		return CompletionReceipt{}, errors.New("runtime completion aggregate is invalid")
	}
	phases := runtimeinstall.OrderedPhases()
	if operation.State() != runtimeinstall.OperationStateReady ||
		operation.CurrentPhase() != runtimeinstall.PhaseUnknown ||
		len(snapshot.Evidence) != len(phases) {
		return CompletionReceipt{}, errors.New("runtime completion aggregate is not Ready")
	}
	finalEvidence := snapshot.Evidence[len(snapshot.Evidence)-1]
	if finalEvidence.Phase != runtimeinstall.PhaseVerifyRuntimeCapabilities ||
		finalEvidence.PlanDigest != snapshot.PlanDigest ||
		finalEvidence.InputDigest.IsZero() || finalEvidence.OutputDigest.IsZero() ||
		finalEvidence.ArtifactDigest.IsZero() || !resolvedOwnership(finalEvidence.Ownership) {
		return CompletionReceipt{}, errors.New("runtime completion evidence is incomplete")
	}
	if ownershipRecord.Status() != runtimeinstall.OwnershipStatusFinalized ||
		ownershipRecord.OperationState() != runtimeinstall.OperationStateReady ||
		ownershipRecord.OperationID() != snapshot.OperationID || ownershipRecord.PlanDigest() != snapshot.PlanDigest ||
		ownershipRecord.Revision() != snapshot.Version || ownershipRecord.Disposition() != finalEvidence.Ownership ||
		ownershipRecord.ArtifactDigest() != finalEvidence.ArtifactDigest ||
		ownershipRecord.CompatibilityDigest() != finalEvidence.OutputDigest || ownershipRecord.Digest().IsZero() {
		return CompletionReceipt{}, errors.New("runtime ownership completion evidence is incomplete")
	}

	receipt := CompletionReceipt{
		operationID:      snapshot.OperationID,
		planDigest:       snapshot.PlanDigest,
		aggregateVersion: snapshot.Version,
		evidenceDigest:   digestCompletionEvidence(snapshot),
		inputDigest:      finalEvidence.InputDigest,
		outputDigest:     finalEvidence.OutputDigest,
		artifactDigest:   finalEvidence.ArtifactDigest,
		ownership:        finalEvidence.Ownership,
		ownershipRecord:  ownershipRecord.Digest(),
	}
	receipt.seal = receipt.computeSeal()
	if !receipt.Valid() {
		return CompletionReceipt{}, errors.New("runtime completion receipt is invalid")
	}
	return receipt, nil
}

// OperationID returns the parent installation identifier.
func (r CompletionReceipt) OperationID() string { return r.operationID }

// PlanDigest returns the exact nested runtime plan digest.
func (r CompletionReceipt) PlanDigest() runtimeinstall.Hash { return r.planDigest }

// AggregateVersion returns the authenticated aggregate revision.
func (r CompletionReceipt) AggregateVersion() uint64 { return r.aggregateVersion }

// EvidenceDigest binds the complete ordered transition history.
func (r CompletionReceipt) EvidenceDigest() runtimeinstall.Hash { return r.evidenceDigest }

// InputDigest returns the final capability probe input binding.
func (r CompletionReceipt) InputDigest() runtimeinstall.Hash { return r.inputDigest }

// OutputDigest returns the final capability probe output binding.
func (r CompletionReceipt) OutputDigest() runtimeinstall.Hash { return r.outputDigest }

// ArtifactDigest returns the verified runtime artifact binding.
func (r CompletionReceipt) ArtifactDigest() runtimeinstall.Hash { return r.artifactDigest }

// Ownership returns the verified runtime ownership disposition.
func (r CompletionReceipt) Ownership() runtimeinstall.OwnershipDisposition { return r.ownership }

// OwnershipRecordDigest binds the finalized protected RuntimeOwnershipRecord.
func (r CompletionReceipt) OwnershipRecordDigest() runtimeinstall.Hash { return r.ownershipRecord }

// ReceiptDigest binds the full completion projection, including the finalized
// protected ownership record, for the parent PF-001 installation audit trail.
func (r CompletionReceipt) ReceiptDigest() runtimeinstall.Hash { return r.seal }

// Valid verifies both required fields and the immutable projection seal.
func (r CompletionReceipt) Valid() bool {
	return r.operationID != "" && !r.planDigest.IsZero() && r.aggregateVersion > 0 &&
		!r.evidenceDigest.IsZero() && !r.inputDigest.IsZero() && !r.outputDigest.IsZero() &&
		!r.artifactDigest.IsZero() && resolvedOwnership(r.ownership) &&
		!r.ownershipRecord.IsZero() &&
		!r.seal.IsZero() && r.seal == r.computeSeal()
}

// NewResultFromSnapshot is the validated projection used by persistence and
// adapter boundaries. Invalid snapshots cannot manufacture public outcomes.
func NewResultFromSnapshot(
	snapshot runtimeinstall.OperationSnapshot,
	ownershipRecords ...runtimeinstall.RuntimeOwnershipRecord,
) (Result, error) {
	operation, err := runtimeinstall.RestoreOperation(snapshot)
	if err != nil {
		return Result{}, errors.New("runtime operation snapshot is invalid")
	}
	if operation.State() == runtimeinstall.OperationStateReady {
		if len(ownershipRecords) != 1 {
			return Result{}, errors.New("ready runtime result requires one finalized ownership record")
		}
		return completedResult(operation, ownershipRecords[0])
	}
	if len(ownershipRecords) != 0 {
		return Result{}, errors.New("non-ready runtime result cannot carry ownership completion")
	}
	return resultFrom(operation, outcomeForState(operation.State()), codeForState(operation.State())), nil
}

func completedResult(
	operation *runtimeinstall.Operation,
	ownershipRecord runtimeinstall.RuntimeOwnershipRecord,
) (Result, error) {
	receipt, err := NewCompletionReceipt(operation.Snapshot(), ownershipRecord)
	if err != nil {
		return resultFrom(operation, OutcomeUnknown, ErrorCodeIntegrityViolation),
			applicationError(ErrorCodeIntegrityViolation, false)
	}
	result := resultFrom(operation, OutcomeCompleted, ErrorCodeNone)
	result.completionReceipt = receipt
	return result, nil
}

func resolvedOwnership(value runtimeinstall.OwnershipDisposition) bool {
	return value == runtimeinstall.OwnershipReusedExternal ||
		value == runtimeinstall.OwnershipProvisionedByAgentMemory
}

func digestCompletionEvidence(snapshot runtimeinstall.OperationSnapshot) runtimeinstall.Hash {
	payload := make([]byte, 0, 128+len(snapshot.Evidence)*140)
	payload = appendLengthPrefixed(payload, completionEvidenceDomain)
	payload = appendLengthPrefixed(payload, snapshot.OperationID)
	payload = append(payload, snapshot.PlanDigest[:]...)
	payload = appendUint64(payload, snapshot.Version)
	for _, evidence := range snapshot.Evidence {
		payload = append(payload, byte(evidence.Phase))
		payload = appendUint32(payload, evidence.Attempt)
		payload = append(payload, evidence.PlanDigest[:]...)
		payload = append(payload, evidence.InputDigest[:]...)
		payload = append(payload, evidence.OutputDigest[:]...)
		payload = append(payload, evidence.ArtifactDigest[:]...)
		payload = append(payload, byte(evidence.Ownership))
	}
	return sha256.Sum256(payload)
}

func (r CompletionReceipt) computeSeal() runtimeinstall.Hash {
	payload := make([]byte, 0, 256)
	payload = appendLengthPrefixed(payload, completionReceiptDomain)
	payload = appendLengthPrefixed(payload, r.operationID)
	payload = append(payload, r.planDigest[:]...)
	payload = appendUint64(payload, r.aggregateVersion)
	payload = append(payload, r.evidenceDigest[:]...)
	payload = append(payload, r.inputDigest[:]...)
	payload = append(payload, r.outputDigest[:]...)
	payload = append(payload, r.artifactDigest[:]...)
	payload = append(payload, byte(r.ownership))
	payload = append(payload, r.ownershipRecord[:]...)
	return sha256.Sum256(payload)
}

func appendLengthPrefixed(destination []byte, value string) []byte {
	destination = appendUint32(destination, uint32(len(value))) // #nosec G115 -- all inputs are bounded domain or aggregate identifiers.
	return append(destination, value...)
}

func appendUint32(destination []byte, value uint32) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	return append(destination, encoded[:]...)
}

func appendUint64(destination []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(destination, encoded[:]...)
}
