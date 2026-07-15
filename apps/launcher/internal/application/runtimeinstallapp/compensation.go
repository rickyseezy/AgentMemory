package runtimeinstallapp

import (
	"crypto/sha256"
	"errors"
	"slices"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const runtimeCompensationReceiptDomain = "agentmemory.runtime-compensation-receipt.v1"

// RuntimeCompensationRequest is aggregate- and ownership-derived authority to
// remove only runtime-acquisition state owned by one cancelled PF-006 operation.
type RuntimeCompensationRequest struct {
	operationID   string
	planDigest    runtimeinstall.Hash
	canonicalPlan []byte
	ownership     runtimeinstall.RuntimeOwnershipRecord
}

func newRuntimeCompensationRequest(
	canonicalPlan []byte,
	ownership runtimeinstall.RuntimeOwnershipRecord,
) (RuntimeCompensationRequest, error) {
	plan, err := runtimeinstall.DecodePlanV1(canonicalPlan)
	if err != nil || ownership.OperationID() == "" || ownership.PlanDigest() != plan.Digest() ||
		ownership.Status() != runtimeinstall.OwnershipStatusPrepared ||
		ownership.OperationState() != runtimeinstall.OperationStateCancelled ||
		!ownership.CompensationReceiptDigest().IsZero() {
		return RuntimeCompensationRequest{}, errors.New("runtime compensation authority is invalid")
	}
	return RuntimeCompensationRequest{
		operationID: ownership.OperationID(), planDigest: plan.Digest(),
		canonicalPlan: plan.CanonicalBytes(), ownership: ownership,
	}, nil
}

// OperationID returns the exact parent installation operation.
func (r RuntimeCompensationRequest) OperationID() string { return r.operationID }

// PlanDigest returns the exact canonical PF-006 plan binding.
func (r RuntimeCompensationRequest) PlanDigest() runtimeinstall.Hash { return r.planDigest }

// CanonicalPlan returns caller-owned execution authority.
func (r RuntimeCompensationRequest) CanonicalPlan() []byte {
	return append([]byte(nil), r.canonicalPlan...)
}

// OwnershipRecord returns an immutable-by-value ownership authority.
func (r RuntimeCompensationRequest) OwnershipRecord() runtimeinstall.RuntimeOwnershipRecord {
	restored, _ := runtimeinstall.RestoreRuntimeOwnershipRecord(r.ownership.Snapshot())
	return restored
}

func (r RuntimeCompensationRequest) valid() bool {
	restored, err := newRuntimeCompensationRequest(r.canonicalPlan, r.ownership)
	return err == nil && restored.operationID == r.operationID && restored.planDigest == r.planDigest
}

// RuntimeCompensationReceiptInput is the adapter-observed, non-secret result
// of releasing exact owned acquisition state without changing the runtime.
type RuntimeCompensationReceiptInput struct {
	RuntimeBeforeDigest    runtimeinstall.Hash
	RuntimeAfterDigest     runtimeinstall.Hash
	ArtifactCleanupDigest  runtimeinstall.Hash
	RemovedArtifactDigests []runtimeinstall.Hash
	RemovedSettings        []string
	RuntimePreserved       bool
}

// RuntimeCompensationReceipt binds exact cleanup evidence to one ownership record.
type RuntimeCompensationReceipt struct {
	operationID            string
	planDigest             runtimeinstall.Hash
	ownershipRecordDigest  runtimeinstall.Hash
	runtimeBeforeDigest    runtimeinstall.Hash
	runtimeAfterDigest     runtimeinstall.Hash
	artifactCleanupDigest  runtimeinstall.Hash
	removedArtifactDigests []runtimeinstall.Hash
	removedSettings        []string
	runtimePreserved       bool
	digest                 runtimeinstall.Hash
}

// NewRuntimeCompensationReceipt validates that an adapter removed only state
// authorized by the protected ownership record and left runtime state unchanged.
func NewRuntimeCompensationReceipt(
	request RuntimeCompensationRequest,
	input RuntimeCompensationReceiptInput,
) (RuntimeCompensationReceipt, error) {
	if !request.valid() || input.RuntimeBeforeDigest.IsZero() || input.RuntimeAfterDigest.IsZero() ||
		input.RuntimeBeforeDigest != input.RuntimeAfterDigest || input.ArtifactCleanupDigest.IsZero() ||
		!input.RuntimePreserved || !validRemovedArtifacts(input.RemovedArtifactDigests, request.ownership) ||
		!validRemovedSettings(input.RemovedSettings, request.ownership) {
		return RuntimeCompensationReceipt{}, errors.New("runtime compensation receipt is invalid")
	}
	receipt := RuntimeCompensationReceipt{
		operationID: request.operationID, planDigest: request.planDigest,
		ownershipRecordDigest: request.ownership.Digest(),
		runtimeBeforeDigest:   input.RuntimeBeforeDigest, runtimeAfterDigest: input.RuntimeAfterDigest,
		artifactCleanupDigest:  input.ArtifactCleanupDigest,
		removedArtifactDigests: append([]runtimeinstall.Hash(nil), input.RemovedArtifactDigests...),
		removedSettings:        append([]string(nil), input.RemovedSettings...),
		runtimePreserved:       true,
	}
	receipt.digest = receipt.computeDigest()
	if !receipt.ValidFor(request) {
		return RuntimeCompensationReceipt{}, errors.New("runtime compensation receipt is invalid")
	}
	return receipt, nil
}

func validRemovedArtifacts(values []runtimeinstall.Hash, ownership runtimeinstall.RuntimeOwnershipRecord) bool {
	if len(values) > 1 {
		return false
	}
	return len(values) == 0 || !values[0].IsZero() && values[0] == ownership.ArtifactDigest()
}

func validRemovedSettings(values []string, ownership runtimeinstall.RuntimeOwnershipRecord) bool {
	if len(values) > len(ownership.Settings()) || !slices.IsSorted(values) ||
		ownership.Disposition() == runtimeinstall.OwnershipReusedExternal && len(values) != 0 {
		return false
	}
	allowed := ownership.Settings()
	for index, value := range values {
		if value == "" || index > 0 && values[index-1] == value || !slices.Contains(allowed, value) {
			return false
		}
	}
	return true
}

// ValidFor revalidates all request bindings and the canonical receipt digest.
func (r RuntimeCompensationReceipt) ValidFor(request RuntimeCompensationRequest) bool {
	return request.valid() && r.operationID == request.operationID && r.planDigest == request.planDigest &&
		r.ownershipRecordDigest == request.ownership.Digest() && !r.runtimeBeforeDigest.IsZero() &&
		r.runtimeBeforeDigest == r.runtimeAfterDigest && !r.artifactCleanupDigest.IsZero() &&
		r.runtimePreserved && validRemovedArtifacts(r.removedArtifactDigests, request.ownership) &&
		validRemovedSettings(r.removedSettings, request.ownership) && !r.digest.IsZero() &&
		r.digest == r.computeDigest()
}

// Digest returns the canonical receipt digest persisted by the runtime aggregate.
func (r RuntimeCompensationReceipt) Digest() runtimeinstall.Hash { return r.digest }

// RemovedArtifactDigests returns caller-owned exact artifact identities.
func (r RuntimeCompensationReceipt) RemovedArtifactDigests() []runtimeinstall.Hash {
	return append([]runtimeinstall.Hash(nil), r.removedArtifactDigests...)
}

// RemovedSettings returns caller-owned exact settings restored by the adapter.
func (r RuntimeCompensationReceipt) RemovedSettings() []string {
	return append([]string(nil), r.removedSettings...)
}

func (r RuntimeCompensationReceipt) computeDigest() runtimeinstall.Hash {
	payload := make([]byte, 0, 384)
	payload = appendLengthPrefixed(payload, runtimeCompensationReceiptDomain)
	payload = appendLengthPrefixed(payload, r.operationID)
	payload = append(payload, r.planDigest[:]...)
	payload = append(payload, r.ownershipRecordDigest[:]...)
	payload = append(payload, r.runtimeBeforeDigest[:]...)
	payload = append(payload, r.runtimeAfterDigest[:]...)
	payload = append(payload, r.artifactCleanupDigest[:]...)
	payload = appendUint32(payload, uint32(len(r.removedArtifactDigests))) // #nosec G115 -- bounded to one.
	for _, digest := range r.removedArtifactDigests {
		payload = append(payload, digest[:]...)
	}
	payload = appendUint32(payload, uint32(len(r.removedSettings))) // #nosec G115 -- bounded by ownership settings.
	for _, setting := range r.removedSettings {
		payload = appendLengthPrefixed(payload, setting)
	}
	if r.runtimePreserved {
		payload = append(payload, 1)
	} else {
		payload = append(payload, 0)
	}
	return sha256.Sum256(payload)
}
