package provideradapterapp

import (
	"context"
	"errors"
	"testing"
)

func TestPRO002SandboxPermissionPolicyAppliesAllAdministrativeCeilings(t *testing.T) {
	t.Parallel()
	manifest, _ := verificationFixture(t)
	input := SandboxPolicyInput{AllowGateway: true, MaximumCPUsMilli: 500, MaximumMemoryBytes: 536870912, MaximumPIDs: 64, MaximumTimeoutMilliseconds: 30000, MaximumScratchBytes: 67108864}
	policy, err := NewSandboxPermissionPolicy(input)
	if err != nil || policy.Authorize(context.Background(), manifest) != nil {
		t.Fatalf("valid policy = %v", err)
	}
	tests := []func(*SandboxPolicyInput){
		func(value *SandboxPolicyInput) { value.AllowGateway = false },
		func(value *SandboxPolicyInput) { value.MaximumCPUsMilli-- },
		func(value *SandboxPolicyInput) { value.MaximumMemoryBytes-- },
		func(value *SandboxPolicyInput) { value.MaximumPIDs-- },
		func(value *SandboxPolicyInput) { value.MaximumTimeoutMilliseconds-- },
		func(value *SandboxPolicyInput) { value.MaximumScratchBytes-- },
	}
	for _, mutate := range tests {
		candidate := input
		mutate(&candidate)
		denied, _ := NewSandboxPermissionPolicy(candidate)
		if err := denied.Authorize(context.Background(), manifest); !errors.Is(err, ErrPolicy) {
			t.Fatalf("excess accepted: %#v %v", candidate, err)
		}
	}
}
