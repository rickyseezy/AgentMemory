package runtimeremovalapp

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeremoval"
)

// Command starts or resumes the separate destructive removal operation.
type Command struct {
	OperationID          string
	SourceOperationID    string
	CanonicalRuntimePlan []byte
}

// Outcome is the closed externally visible removal result.
type Outcome uint8

const (
	// OutcomeUnknown is never a successful terminal result.
	OutcomeUnknown Outcome = iota
	// OutcomeDeclined means the user durably refused the second confirmation.
	OutcomeDeclined
	// OutcomeRemoved means exact native absence proof is durable.
	OutcomeRemoved
)

// Result reports durable state without leaking native inventory details.
type Result struct {
	OperationID string
	PlanDigest  runtimeinstall.Hash
	Outcome     Outcome
}

// ConsentDecision is an exact-plan, exact-impact second decision. Explicit
// must be true only when the control was initially unselected and the user
// actively confirmed it.
type ConsentDecision struct {
	Approved   bool
	Explicit   bool
	PlanDigest runtimeinstall.Hash
	Impact     string
	Receipt    runtimeinstall.Hash
}

// ScanRequest gives a read-only scanner the minimum bound authority required
// to inspect the explicit endpoint.
type ScanRequest struct {
	Endpoint  string
	Ownership runtimeinstall.RuntimeOwnershipRecord
}

// RemovalAuthorization is created only after consent and a fresh exhaustive
// empty scan have both been durably recorded.
type RemovalAuthorization struct {
	plan           runtimeremoval.Plan
	ownership      runtimeinstall.RuntimeOwnershipRecord
	scan           runtimeremoval.DependencyScan
	consentReceipt runtimeinstall.Hash
}

// Plan returns the exact persisted removal authority.
func (a RemovalAuthorization) Plan() runtimeremoval.Plan { return a.plan }

// Ownership returns the exact finalized runtime ownership authority.
func (a RemovalAuthorization) Ownership() runtimeinstall.RuntimeOwnershipRecord { return a.ownership }

// Scan returns the exhaustive execution-time dependency proof.
func (a RemovalAuthorization) Scan() runtimeremoval.DependencyScan { return a.scan }

// ConsentReceipt returns the durable second-confirmation binding.
func (a RemovalAuthorization) ConsentReceipt() runtimeinstall.Hash { return a.consentReceipt }

func (a RemovalAuthorization) valid() bool {
	return a.plan.Valid() && a.ownership.Digest() == a.plan.OwnershipRecordDigest() &&
		a.scan.OwnershipRecordDigest() == a.ownership.Digest() && a.scan.Endpoint() == a.plan.Endpoint() &&
		a.scan.SafeToRemove() && !a.consentReceipt.IsZero()
}

// PresenceProof is a signed/native observation of the plan-bound runtime.
type PresenceProof struct {
	PlanDigest      runtimeinstall.Hash
	OwnershipDigest runtimeinstall.Hash
	EvidenceDigest  runtimeinstall.Hash
	Absent          bool
}

func (p PresenceProof) validFor(plan runtimeremoval.Plan) bool {
	return p.PlanDigest == plan.Digest() && p.OwnershipDigest == plan.OwnershipRecordDigest() &&
		!p.EvidenceDigest.IsZero()
}

// NativeRemovalResult binds the exact effect to the execution-time scan.
type NativeRemovalResult struct {
	PlanDigest      runtimeinstall.Hash
	OwnershipDigest runtimeinstall.Hash
	ExecutionScan   runtimeinstall.Hash
	BeforeDigest    runtimeinstall.Hash
	EffectDigest    runtimeinstall.Hash
}

func (r NativeRemovalResult) validFor(authorization RemovalAuthorization) bool {
	return authorization.valid() && r.PlanDigest == authorization.plan.Digest() &&
		r.OwnershipDigest == authorization.ownership.Digest() && r.ExecutionScan == authorization.scan.Digest() &&
		!r.BeforeDigest.IsZero() && !r.EffectDigest.IsZero()
}

func removalReceipt(result NativeRemovalResult, absence PresenceProof) runtimeinstall.Hash {
	document := struct {
		Schema          string `json:"schema"`
		Plan            string `json:"plan"`
		Ownership       string `json:"ownership"`
		ExecutionScan   string `json:"execution_scan"`
		Before          string `json:"before"`
		Effect          string `json:"effect"`
		AbsenceEvidence string `json:"absence_evidence"`
	}{
		Schema: "agentmemory.runtime-removal-receipt.v1", Plan: result.PlanDigest.String(),
		Ownership: result.OwnershipDigest.String(), ExecutionScan: result.ExecutionScan.String(),
		Before: result.BeforeDigest.String(), Effect: result.EffectDigest.String(),
		AbsenceEvidence: absence.EvidenceDigest.String(),
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return runtimeinstall.Hash{}
	}
	return sha256.Sum256(encoded)
}

func alreadyAbsentReceipt(
	plan runtimeremoval.Plan,
	proof PresenceProof,
	executionScan, consentReceipt runtimeinstall.Hash,
) runtimeinstall.Hash {
	document := struct {
		Schema        string `json:"schema"`
		Plan          string `json:"plan"`
		Ownership     string `json:"ownership"`
		ExecutionScan string `json:"execution_scan"`
		Consent       string `json:"consent"`
		Absence       string `json:"absence"`
	}{
		Schema: "agentmemory.runtime-removal-already-absent.v1", Plan: plan.Digest().String(),
		Ownership: plan.OwnershipRecordDigest().String(), ExecutionScan: executionScan.String(),
		Consent: consentReceipt.String(), Absence: proof.EvidenceDigest.String(),
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return runtimeinstall.Hash{}
	}
	return sha256.Sum256(encoded)
}
