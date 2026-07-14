package hostverifyapp

import (
	"bytes"
	"encoding/binary"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

// Command binds a signed nested host policy to one exact installation operation.
type Command struct {
	OperationID      install.OperationID
	ParentPlanDigest install.PlanDigest
	SignedPlan       hostverification.SignedPlan
	StorageTarget    string
}

// Verification is immutable certification evidence or one expected rejection.
type Verification struct {
	operationID      install.OperationID
	parentPlanDigest install.PlanDigest
	hostPlanDigest   install.Digest
	evidenceDigest   install.Digest
	certified        bool
	failure          hostverification.FailureReason
}

func newVerification(
	command Command,
	plan hostverification.Plan,
	observationDigest install.Digest,
	reason hostverification.FailureReason,
) Verification {
	var canonical bytes.Buffer
	writeString := func(value string) {
		_ = binary.Write(&canonical, binary.BigEndian, uint64(len(value)))
		canonical.WriteString(value)
	}
	writeString("agentmemory.host-verification-receipt.v1")
	writeString(command.OperationID.String())
	writeString(command.ParentPlanDigest.String())
	writeString(plan.Digest().String())
	writeString(command.StorageTarget)
	writeString(observationDigest.String())
	writeString(string(reason))
	return Verification{
		operationID: command.OperationID, parentPlanDigest: command.ParentPlanDigest,
		hostPlanDigest: plan.Digest(), evidenceDigest: install.DigestBytes(canonical.Bytes()),
		certified: reason == hostverification.FailureNone, failure: reason,
	}
}

// Certified reports whether every trust and host gate succeeded.
func (v Verification) Certified() bool { return v.certified }

// Failure returns the closed expected host rejection reason.
func (v Verification) Failure() hostverification.FailureReason { return v.failure }

// HostPlanDigest returns exact signed nested policy identity.
func (v Verification) HostPlanDigest() install.Digest { return v.hostPlanDigest }

// EvidenceDigest returns the operation-bound certification receipt.
func (v Verification) EvidenceDigest() install.Digest { return v.evidenceDigest }

// OperationID returns the operation authorized by this receipt.
func (v Verification) OperationID() install.OperationID { return v.operationID }

// ParentPlanDigest returns the PF-001 parent authority.
func (v Verification) ParentPlanDigest() install.PlanDigest { return v.parentPlanDigest }

// ValidFor prevents another operation or parent plan from reusing a receipt.
func (v Verification) ValidFor(operationID install.OperationID, parent install.PlanDigest) bool {
	if operationID.IsZero() || parent.IsZero() || v.operationID != operationID ||
		!v.parentPlanDigest.Equal(parent) || v.hostPlanDigest.IsZero() || v.evidenceDigest.IsZero() {
		return false
	}
	if v.certified {
		return v.failure == hostverification.FailureNone
	}
	return v.failure != hostverification.FailureNone
}
