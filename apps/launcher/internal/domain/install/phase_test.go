package install

import "testing"

func TestPF001OrderedPhasesAreStableAndDefensivelyCopied(t *testing.T) {
	first := OrderedPhases()
	if len(first) != 14 || first[0] != PhaseVerifyHost || first[len(first)-1] != PhaseCommitActiveRelease {
		t.Fatalf("unexpected phase sequence: %#v", first)
	}
	first[0] = PhaseCommitActiveRelease
	if OrderedPhases()[0] != PhaseVerifyHost {
		t.Fatal("OrderedPhases exposed mutable package state")
	}

	for index, phase := range OrderedPhases() {
		if !phase.Valid() || phase.String() == "Unknown" {
			t.Fatalf("phase %d is invalid: %d", index, phase)
		}
		next, exists := phase.Next()
		if index == len(OrderedPhases())-1 {
			if exists || next != PhaseUnknown {
				t.Fatalf("final phase has next %s", next)
			}
		} else if !exists || next != OrderedPhases()[index+1] {
			t.Fatalf("next after %s = (%s, %t)", phase, next, exists)
		}
	}
	if PhaseUnknown.Valid() || PhaseUnknown.String() != "Unknown" {
		t.Fatal("unknown phase was treated as valid")
	}
	if Phase(255).String() != "Unknown" {
		t.Fatal("out-of-range phase did not fail closed")
	}
}

func TestPF001StatesHaveStableNamesAndTerminalSemantics(t *testing.T) {
	tests := []struct {
		state    State
		name     string
		terminal bool
	}{
		{StateUnknown, "Unknown", false},
		{StateRunning, "Running", false},
		{StateRebootPending, "RebootPending", false},
		{StateResumeVerified, "ResumeVerified", false},
		{StateFailedRecoverable, "FailedRecoverable", false},
		{StatePausedForAdministrator, "PausedForAdministrator", false},
		{StateCancelled, "Cancelled", true},
		{StateUnsupportedHost, "UnsupportedHost", true},
		{StateRuntimeConflict, "RuntimeConflict", true},
		{StateReady, "Ready", true},
	}
	for _, test := range tests {
		if got := test.state.String(); got != test.name {
			t.Errorf("state %d = %q, want %q", test.state, got, test.name)
		}
		if got := test.state.Terminal(); got != test.terminal {
			t.Errorf("state %s terminal = %t, want %t", test.state, got, test.terminal)
		}
		if got, want := test.state.Valid(), test.state != StateUnknown; got != want {
			t.Errorf("state %s valid = %t, want %t", test.state, got, want)
		}
	}
	if State(255).String() != "Unknown" || State(255).Terminal() {
		t.Fatal("out-of-range state did not fail closed")
	}
	if RuntimeOwnership(255).String() != "unknown" {
		t.Fatal("out-of-range runtime ownership did not fail closed")
	}
}
