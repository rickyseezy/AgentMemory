package runtimeprovision

import (
	"context"
	"encoding/json"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

// CapabilityEvidence contains every required PF-006 final proof. A partially
// successful exercise cannot construct it.
type CapabilityEvidence struct{ digest runtimeinstall.Hash }

// CapabilityEvidenceInput is the closed decision table for the final probe.
type CapabilityEvidenceInput struct {
	EngineAPI          bool
	Compose            bool
	Architecture       bool
	LinuxContainers    bool
	Rootless           bool
	NoTCPListener      bool
	BindReadOnly       bool
	NetworkIsolation   bool
	VolumePersistence  bool
	LoopbackPublish    bool
	WorkloadsPreserved bool
	LocalExecution     bool
	ManagedStateDigest runtimeinstall.Hash
	PolicyDigest       runtimeinstall.Hash
}

// NewCapabilityEvidence accepts only a complete signed-policy exercise.
func NewCapabilityEvidence(input CapabilityEvidenceInput) (CapabilityEvidence, error) {
	if !input.EngineAPI || !input.Compose || !input.Architecture || !input.LinuxContainers ||
		!input.Rootless || !input.NoTCPListener || !input.BindReadOnly || !input.NetworkIsolation ||
		!input.VolumePersistence || !input.LoopbackPublish || !input.WorkloadsPreserved ||
		!input.LocalExecution || input.ManagedStateDigest.IsZero() || input.PolicyDigest.IsZero() {
		return CapabilityEvidence{}, ErrProbeFailed
	}
	encoded, _ := json.Marshal(struct {
		Managed string `json:"managed_state_digest"`
		Policy  string `json:"policy_digest"`
		Valid   bool   `json:"all_capabilities_verified"`
	}{Managed: input.ManagedStateDigest.String(), Policy: input.PolicyDigest.String(), Valid: true})
	return CapabilityEvidence{digest: runtimeinstall.Sum(encoded)}, nil
}

// Digest returns the aggregate final capability binding.
func (e CapabilityEvidence) Digest() runtimeinstall.Hash { return e.digest }

// CapabilityProbe runs destructive-but-compensated, plan-bound probe objects
// through the exact local endpoint. Implementations must preserve the initial
// unrelated workload inventory byte-for-byte.
type CapabilityProbe interface {
	VerifyLinuxCapabilities(
		context.Context,
		runtimeport.LinuxAuthority,
		RuntimeEvidence,
		runtimeinstall.Hash,
	) (CapabilityEvidence, error)
}
