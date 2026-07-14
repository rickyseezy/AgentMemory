package runtimeprovision

import (
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeinstallapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestClosedDecisionAndConstructorEdges(t *testing.T) {
	t.Parallel()
	if _, err := NewLinuxProvisioner(Dependencies{}); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("NewLinuxProvisioner(empty) error = %v", err)
	}
	if _, err := NewDockerInspector(nil, nil, nil); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("NewDockerInspector(empty) error = %v", err)
	}
	if _, err := NewEndpointEvidence(true, 0, 0o600, true); !errors.Is(err, ErrProbeFailed) {
		t.Fatalf("NewEndpointEvidence(invalid) error = %v", err)
	}
	if _, err := NewRuntimeEvidence(RuntimeEvidenceInput{}); !errors.Is(err, ErrProbeFailed) {
		t.Fatalf("NewRuntimeEvidence(invalid) error = %v", err)
	}
	if _, err := NewHostEvidence(HostEvidenceInput{}); !errors.Is(err, ErrProbeFailed) {
		t.Fatalf("NewHostEvidence(invalid) error = %v", err)
	}
	if _, err := NewCapabilityEvidence(CapabilityEvidenceInput{}); !errors.Is(err, ErrProbeFailed) {
		t.Fatalf("NewCapabilityEvidence(invalid) error = %v", err)
	}
	if !hostDecision(runtimeinstall.DecisionUnsupportedPlatform) ||
		!hostDecision(runtimeinstall.DecisionCatalogMismatch) || hostDecision(runtimeinstall.DecisionRuntimeConflict) {
		t.Fatal("host decision taxonomy drifted")
	}
	if _, err := blockOutput(runtimeinstall.DecisionUnsupportedPlatform); err != nil {
		t.Fatal(err)
	}
	if _, err := blockOutput(runtimeinstall.DecisionRuntimeConflict); err != nil {
		t.Fatal(err)
	}
	for _, expectedError := range []error{ErrUnsupportedHost, ErrAdministratorRequired, ErrRuntimeConflict} {
		if _, err := mapExpectedOrError(expectedError); err != nil {
			t.Fatalf("mapExpectedOrError(%v) error = %v", expectedError, err)
		}
	}
	if _, err := mapExpectedOrError(ErrProbeFailed); !errors.Is(err, ErrProbeFailed) {
		t.Fatalf("probe failure mapping error = %v", err)
	}
	if !combineDigests().IsZero() || !combineDigests(runtimeinstall.Hash{}).IsZero() {
		t.Fatal("empty digest combination was not zero")
	}
	output, err := runtimeinstallapp.NewExpectedOutput(runtimeinstallapp.OutcomeCancelled)
	if err != nil || outputOrZero(&output) != output || outputOrZero(nil) != (runtimeinstallapp.Output{}) {
		t.Fatal("optional output projection failed")
	}
}
