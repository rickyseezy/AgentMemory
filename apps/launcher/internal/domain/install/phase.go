package install

// Phase is one verified step in the PF-001 installation saga.
//
// Ready is an operation State, not a phase. An operation reaches StateReady
// only after every phase in OrderedPhases has verified evidence.
type Phase uint8

const (
	// PhaseUnknown is the zero value and never a runnable installation phase.
	PhaseUnknown Phase = iota
	// PhaseVerifyHost verifies the certified host and required resources.
	PhaseVerifyHost
	// PhaseEnsureContainerRuntime delegates the portable runtime lifecycle to PF-006.
	PhaseEnsureContainerRuntime
	// PhaseVerifyRelease authenticates the immutable AgentMemory release manifest.
	PhaseVerifyRelease
	// PhaseReserveSpace proves required acquisition and rollback capacity.
	PhaseReserveSpace
	// PhaseEnsureDirectories creates and verifies owner-protected local state roots.
	PhaseEnsureDirectories
	// PhaseEnsureKeys creates or recovers locally protected installation keys.
	PhaseEnsureKeys
	// PhaseEnsureComposeBundle materializes the verified immutable Compose bundle.
	PhaseEnsureComposeBundle
	// PhaseEnsureNetworkAndVolumes creates only labelled AgentMemory resources.
	PhaseEnsureNetworkAndVolumes
	// PhaseRunMigrations applies the exact release migration sequence.
	PhaseRunMigrations
	// PhaseEnsureCoreAndGraph starts and health-checks canonical and graph services.
	PhaseEnsureCoreAndGraph
	// PhaseBootstrapLocalBrain creates the first local Brain and owner binding.
	PhaseBootstrapLocalBrain
	// PhaseMergeAgentConfiguration safely adds the signed launcher MCP entry.
	PhaseMergeAgentConfiguration
	// PhaseVerifyReadiness runs the full local write, index, and recall proof.
	PhaseVerifyReadiness
	// PhaseCommitActiveRelease atomically activates the verified release generation.
	PhaseCommitActiveRelease
)

var orderedPhases = [...]Phase{
	PhaseVerifyHost,
	PhaseEnsureContainerRuntime,
	PhaseVerifyRelease,
	PhaseReserveSpace,
	PhaseEnsureDirectories,
	PhaseEnsureKeys,
	PhaseEnsureComposeBundle,
	PhaseEnsureNetworkAndVolumes,
	PhaseRunMigrations,
	PhaseEnsureCoreAndGraph,
	PhaseBootstrapLocalBrain,
	PhaseMergeAgentConfiguration,
	PhaseVerifyReadiness,
	PhaseCommitActiveRelease,
}

// OrderedPhases returns a copy of the normative PF-001 phase sequence.
func OrderedPhases() []Phase {
	result := make([]Phase, len(orderedPhases))
	copy(result, orderedPhases[:])
	return result
}

// Valid reports whether the phase belongs to the PF-001 phase sequence.
func (p Phase) Valid() bool {
	return p >= PhaseVerifyHost && p <= PhaseCommitActiveRelease
}

// Next returns the phase after p. The boolean is false for an invalid phase or
// after PhaseCommitActiveRelease.
func (p Phase) Next() (Phase, bool) {
	if !p.Valid() || p == PhaseCommitActiveRelease {
		return PhaseUnknown, false
	}
	return p + 1, true
}

func (p Phase) String() string {
	switch p {
	case PhaseUnknown:
		return "Unknown"
	case PhaseVerifyHost:
		return "VerifyHost"
	case PhaseEnsureContainerRuntime:
		return "EnsureContainerRuntime"
	case PhaseVerifyRelease:
		return "VerifyRelease"
	case PhaseReserveSpace:
		return "ReserveSpace"
	case PhaseEnsureDirectories:
		return "EnsureDirectories"
	case PhaseEnsureKeys:
		return "EnsureKeys"
	case PhaseEnsureComposeBundle:
		return "EnsureComposeBundle"
	case PhaseEnsureNetworkAndVolumes:
		return "EnsureNetworkAndVolumes"
	case PhaseRunMigrations:
		return "RunMigrations"
	case PhaseEnsureCoreAndGraph:
		return "EnsureCoreAndGraph"
	case PhaseBootstrapLocalBrain:
		return "BootstrapLocalBrain"
	case PhaseMergeAgentConfiguration:
		return "MergeAgentConfiguration"
	case PhaseVerifyReadiness:
		return "VerifyReadiness"
	case PhaseCommitActiveRelease:
		return "CommitActiveRelease"
	default:
		return "Unknown"
	}
}

// State is the durable state of one installation operation.
type State uint8

const (
	// StateUnknown is the invalid zero value of State.
	StateUnknown State = iota
	// StateRunning means the current phase may execute.
	StateRunning
	// StateRebootPending means a one-use continuation is recorded but unverified.
	StateRebootPending
	// StateResumeVerified means the continuation verified and may resume once.
	StateResumeVerified
	// StateFailedRecoverable means retry may resume the first unverified phase.
	StateFailedRecoverable
	// StatePausedForAdministrator means device policy or authority must change first.
	StatePausedForAdministrator
	// StateCancelled means the user declined or cancelled this operation.
	StateCancelled
	// StateUnsupportedHost means the host cannot execute the certified plan.
	StateUnsupportedHost
	// StateRuntimeConflict means the discovered runtime cannot be changed safely.
	StateRuntimeConflict
	// StateReady means all ordered phases have verified evidence.
	StateReady
)

// Valid reports whether s is a durable operation state.
func (s State) Valid() bool {
	return s >= StateRunning && s <= StateReady
}

// Terminal reports whether no same-plan transition may leave this state.
func (s State) Terminal() bool {
	switch s {
	case StateCancelled, StateUnsupportedHost, StateRuntimeConflict, StateReady:
		return true
	case StateUnknown, StateRunning, StateRebootPending, StateResumeVerified,
		StateFailedRecoverable, StatePausedForAdministrator:
		return false
	default:
		return false
	}
}

func (s State) String() string {
	switch s {
	case StateUnknown:
		return "Unknown"
	case StateRunning:
		return "Running"
	case StateRebootPending:
		return "RebootPending"
	case StateResumeVerified:
		return "ResumeVerified"
	case StateFailedRecoverable:
		return "FailedRecoverable"
	case StatePausedForAdministrator:
		return "PausedForAdministrator"
	case StateCancelled:
		return "Cancelled"
	case StateUnsupportedHost:
		return "UnsupportedHost"
	case StateRuntimeConflict:
		return "RuntimeConflict"
	case StateReady:
		return "Ready"
	default:
		return "Unknown"
	}
}
