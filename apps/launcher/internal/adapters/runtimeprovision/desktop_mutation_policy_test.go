package runtimeprovision

import (
	"testing"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
)

func TestWindowsDesktopMutationElevationPolicyKeepsPerUserInstallUnelevated(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		operation runtimeport.DesktopMutationOperation
		verb      string
		elevated  bool
		valid     bool
	}{
		{operation: runtimeport.DesktopMutationInstallPrerequisites, verb: "runas", elevated: true, valid: true},
		{operation: runtimeport.DesktopMutationInstallRuntime, verb: "open", valid: true},
		{operation: runtimeport.DesktopMutationOperation("foreign")},
	} {
		verb, elevated, valid := windowsDesktopMutationExecutionPolicy(test.operation)
		if verb != test.verb || elevated != test.elevated || valid != test.valid {
			t.Fatalf("operation=%q policy=(%q,%t,%t)", test.operation, verb, elevated, valid)
		}
	}
}
