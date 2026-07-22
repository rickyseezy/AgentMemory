package provideradapterapp

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/provideradapter"
)

// SandboxPolicyInput is installation-owned policy; adapters cannot expand these ceilings.
type SandboxPolicyInput struct {
	AllowGateway               bool
	MaximumCPUsMilli           uint32
	MaximumMemoryBytes         uint64
	MaximumPIDs                uint32
	MaximumTimeoutMilliseconds uint32
	MaximumScratchBytes        uint64
}

// SandboxPermissionPolicy applies administrator ceilings after manifest validation.
type SandboxPermissionPolicy struct{ input SandboxPolicyInput }

// NewSandboxPermissionPolicy rejects incomplete or unbounded policy.
func NewSandboxPermissionPolicy(input SandboxPolicyInput) (*SandboxPermissionPolicy, error) {
	if input.MaximumCPUsMilli == 0 || input.MaximumMemoryBytes == 0 || input.MaximumPIDs == 0 ||
		input.MaximumTimeoutMilliseconds == 0 || input.MaximumScratchBytes == 0 {
		return nil, ErrPolicy
	}
	return &SandboxPermissionPolicy{input: input}, nil
}

// Authorize rejects gateway access or resources beyond installation policy.
func (p *SandboxPermissionPolicy) Authorize(ctx context.Context, manifest provideradapter.Manifest) error {
	if p == nil || ctx == nil || manifest.Digest().IsZero() {
		return ErrPolicy
	}
	limits := manifest.Limits()
	if (manifest.GatewayAccess() && !p.input.AllowGateway) || limits.CPUsMilli > p.input.MaximumCPUsMilli ||
		limits.MemoryBytes > p.input.MaximumMemoryBytes || limits.PIDs > p.input.MaximumPIDs ||
		limits.TimeoutMilliseconds > p.input.MaximumTimeoutMilliseconds || limits.ScratchBytes > p.input.MaximumScratchBytes {
		return ErrPolicy
	}
	return nil
}

var _ PermissionPolicy = (*SandboxPermissionPolicy)(nil)
