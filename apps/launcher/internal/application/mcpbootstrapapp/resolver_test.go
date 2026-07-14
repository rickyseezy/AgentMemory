package mcpbootstrapapp

import (
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001ResolvedBootstrapBindsAndCopiesCanonicalPlan(t *testing.T) {
	t.Parallel()
	operation, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	canonical := []byte("canonical plan")
	digest, _ := install.BindPlan(canonical)
	resolved, err := NewResolvedBootstrap(
		"019f5f20-1234-7abc-8123-0123456789ab", operation, digest, canonical,
	)
	if err != nil || !resolved.Valid() || resolved.InstallationID() == "" ||
		resolved.OperationID() != operation || !resolved.PlanDigest().Equal(digest) {
		t.Fatalf("resolved=%+v error=%v", resolved, err)
	}
	canonical[0] = 'X'
	first := resolved.CanonicalPlan()
	first[0] = 'Y'
	if string(resolved.CanonicalPlan()) != "canonical plan" {
		t.Fatal("resolved bootstrap leaked canonical plan ownership")
	}
}

func TestPF001ResolvedBootstrapRejectsEveryIncompleteOrContradictoryBinding(t *testing.T) {
	t.Parallel()
	operation, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	canonical := []byte("canonical plan")
	digest, _ := install.BindPlan(canonical)
	tests := []struct {
		name         string
		installation string
		operation    install.OperationID
		digest       install.PlanDigest
		plan         []byte
	}{
		{name: "installation", operation: operation, digest: digest, plan: canonical},
		{name: "operation", installation: "019f5f20-1234-7abc-8123-0123456789ab", digest: digest, plan: canonical},
		{name: "digest", installation: "019f5f20-1234-7abc-8123-0123456789ab", operation: operation, plan: canonical},
		{name: "plan", installation: "019f5f20-1234-7abc-8123-0123456789ab", operation: operation, digest: digest},
		{name: "substitution", installation: "019f5f20-1234-7abc-8123-0123456789ab", operation: operation, digest: digest, plan: []byte("other")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewResolvedBootstrap(test.installation, test.operation, test.digest, test.plan); !errors.Is(err, ErrBootstrapIntegrity) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}
