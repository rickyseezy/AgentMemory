package runtimeinstall

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Phase is one ordered runtime provisioning transition.
type Phase uint8

const (
	// PhaseUnknown is the invalid or terminal cursor.
	PhaseUnknown Phase = iota
	// PhaseDetectHost records read-only host capability facts.
	PhaseDetectHost
	// PhaseDetectRuntime records explicitly addressed runtime facts.
	PhaseDetectRuntime
	// PhasePlanRuntime binds the exact certified mutation plan.
	PhasePlanRuntime
	// PhaseAwaitRuntimeConsent obtains plan-bound user consent.
	PhaseAwaitRuntimeConsent
	// PhaseAcquireRuntime acquires or identifies the exact runtime artifact.
	PhaseAcquireRuntime
	// PhaseVerifyRuntimeArtifact proves artifact and native publisher trust.
	PhaseVerifyRuntimeArtifact
	// PhaseInstallPrerequisites performs closed prerequisite operations.
	PhaseInstallPrerequisites
	// PhaseInstallRuntime invokes the verified platform installer.
	PhaseInstallRuntime
	// PhaseAwaitThirdPartyTerms binds the vendor terms receipt.
	PhaseAwaitThirdPartyTerms
	// PhaseStartRuntime starts only the explicit local endpoint.
	PhaseStartRuntime
	// PhaseVerifyRuntimeCapabilities executes the full capability probes.
	PhaseVerifyRuntimeCapabilities
)

var orderedPhases = [...]Phase{
	PhaseDetectHost,
	PhaseDetectRuntime,
	PhasePlanRuntime,
	PhaseAwaitRuntimeConsent,
	PhaseAcquireRuntime,
	PhaseVerifyRuntimeArtifact,
	PhaseInstallPrerequisites,
	PhaseInstallRuntime,
	PhaseAwaitThirdPartyTerms,
	PhaseStartRuntime,
	PhaseVerifyRuntimeCapabilities,
}

// OrderedPhases returns an immutable-by-copy phase sequence.
func OrderedPhases() []Phase {
	return append([]Phase(nil), orderedPhases[:]...)
}

func (p Phase) String() string {
	switch p {
	case PhaseDetectHost:
		return "DetectHost"
	case PhaseDetectRuntime:
		return "DetectRuntime"
	case PhasePlanRuntime:
		return "PlanRuntime"
	case PhaseAwaitRuntimeConsent:
		return "AwaitRuntimeConsent"
	case PhaseAcquireRuntime:
		return "AcquireRuntime"
	case PhaseVerifyRuntimeArtifact:
		return "VerifyRuntimeArtifact"
	case PhaseInstallPrerequisites:
		return "InstallPrerequisites"
	case PhaseInstallRuntime:
		return "InstallRuntime"
	case PhaseAwaitThirdPartyTerms:
		return "AwaitThirdPartyTerms"
	case PhaseStartRuntime:
		return "StartRuntime"
	case PhaseVerifyRuntimeCapabilities:
		return "VerifyRuntimeCapabilities"
	case PhaseUnknown:
	}
	return "Unknown"
}

func (p Phase) valid() bool {
	return p >= PhaseDetectHost && p <= PhaseVerifyRuntimeCapabilities
}

func phaseIndex(phase Phase) int {
	for index, candidate := range orderedPhases {
		if candidate == phase {
			return index
		}
	}
	return -1
}

// OperationState is the closed runtime-provisioning state vocabulary.
type OperationState uint8

const (
	// OperationStateUnknown is the invalid zero value.
	OperationStateUnknown OperationState = iota
	// OperationStateRunning executes the first unverified phase.
	OperationStateRunning
	// OperationStateRebootPending requires the exact one-use receipt.
	OperationStateRebootPending
	// OperationStateReady means every runtime phase is verified.
	OperationStateReady
	// OperationStateCancelled records an explicit user decline.
	OperationStateCancelled
	// OperationStatePausedForAdministrator records a managed-device block.
	OperationStatePausedForAdministrator
	// OperationStateUnsupportedHost records a certified incompatibility.
	OperationStateUnsupportedHost
	// OperationStateRuntimeConflict preserves incompatible external state.
	OperationStateRuntimeConflict
	// OperationStateFailedRecoverable keeps the current cursor retryable.
	OperationStateFailedRecoverable
)

func (s OperationState) String() string {
	switch s {
	case OperationStateRunning:
		return "Running"
	case OperationStateRebootPending:
		return "RebootPending"
	case OperationStateReady:
		return "Ready"
	case OperationStateCancelled:
		return "Cancelled"
	case OperationStatePausedForAdministrator:
		return "PausedForAdministrator"
	case OperationStateUnsupportedHost:
		return "UnsupportedHost"
	case OperationStateRuntimeConflict:
		return "RuntimeConflict"
	case OperationStateFailedRecoverable:
		return "FailedRecoverable"
	case OperationStateUnknown:
	}
	return "Unknown"
}

// TransitionEvidence binds one verified transition to the exact parent plan.
type TransitionEvidence struct {
	Phase          Phase
	Attempt        uint32
	PlanDigest     Hash
	InputDigest    Hash
	OutputDigest   Hash
	ArtifactDigest Hash
	Ownership      OwnershipDisposition
}

// NewTransitionEvidence rejects incomplete or phase-inconsistent evidence.
func NewTransitionEvidence(
	phase Phase,
	attempt uint32,
	planDigest Hash,
	inputDigest Hash,
	outputDigest Hash,
	artifactDigest Hash,
	ownership OwnershipDisposition,
) (TransitionEvidence, error) {
	if !phase.valid() || attempt == 0 || planDigest.IsZero() || inputDigest.IsZero() || outputDigest.IsZero() {
		return TransitionEvidence{}, errors.New("runtime transition evidence is incomplete")
	}
	if phaseIndex(phase) >= phaseIndex(PhaseVerifyRuntimeArtifact) && artifactDigest.IsZero() {
		return TransitionEvidence{}, errors.New("verified runtime artifact digest is required")
	}
	if phase == PhaseVerifyRuntimeCapabilities && ownership == OwnershipUnknown {
		return TransitionEvidence{}, errors.New("runtime ownership is required at capability verification")
	}
	return TransitionEvidence{
		Phase:          phase,
		Attempt:        attempt,
		PlanDigest:     planDigest,
		InputDigest:    inputDigest,
		OutputDigest:   outputDigest,
		ArtifactDigest: artifactDigest,
		Ownership:      ownership,
	}, nil
}

// OperationSnapshot is the persistence DTO for one runtime sub-saga.
type OperationSnapshot struct {
	SchemaVersion uint16
	OperationID   string
	PlanDigest    Hash
	State         OperationState
	CurrentPhase  Phase
	Attempt       uint32
	Version       uint64
	Evidence      []TransitionEvidence
	RebootReceipt Hash
}

// Operation owns runtime provisioning transition invariants.
type Operation struct {
	id            string
	planDigest    Hash
	state         OperationState
	currentPhase  Phase
	attempt       uint32
	version       uint64
	evidence      []TransitionEvidence
	rebootReceipt Hash
}

const operationSnapshotSchemaVersion = uint16(1)

// NewOperation starts the runtime sub-saga at DetectHost.
func NewOperation(operationID string, planDigest Hash) (*Operation, error) {
	if err := validateOperationID(operationID); err != nil {
		return nil, err
	}
	if planDigest.IsZero() {
		return nil, errors.New("runtime operation plan digest is required")
	}
	return &Operation{
		id:           operationID,
		planDigest:   planDigest,
		state:        OperationStateRunning,
		currentPhase: PhaseDetectHost,
		attempt:      1,
	}, nil
}

func validateOperationID(value string) error {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return errors.New("runtime operation identifier is invalid")
	}
	for _, character := range value {
		if !runtimeOperationIDCharacter(character) {
			return errors.New("runtime operation identifier is invalid")
		}
	}
	return nil
}

func runtimeOperationIDCharacter(character rune) bool {
	return character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9' ||
		character == '-' || character == '_' || character == '.'
}

// ID returns the parent installation operation identifier.
func (o *Operation) ID() string { return o.id }

// PlanDigest returns the immutable canonical-plan binding.
func (o *Operation) PlanDigest() Hash { return o.planDigest }

// State returns the current aggregate state.
func (o *Operation) State() OperationState { return o.state }

// CurrentPhase returns the first unverified phase or PhaseUnknown at Ready.
func (o *Operation) CurrentPhase() Phase { return o.currentPhase }

// Attempt returns the one-based attempt for CurrentPhase.
func (o *Operation) Attempt() uint32 { return o.attempt }

// Version returns the optimistic-concurrency aggregate revision.
func (o *Operation) Version() uint64 { return o.version }

// Complete advances exactly the current phase after validating its evidence.
func (o *Operation) Complete(phase Phase, evidence TransitionEvidence) error {
	if o.state != OperationStateRunning || phase != o.currentPhase {
		return fmt.Errorf("runtime phase %s is not the current running phase", phase)
	}
	if evidence.Phase != phase || evidence.Attempt != o.attempt || evidence.PlanDigest != o.planDigest {
		return errors.New("runtime transition evidence does not match the current cursor")
	}
	if _, err := NewTransitionEvidence(
		evidence.Phase,
		evidence.Attempt,
		evidence.PlanDigest,
		evidence.InputDigest,
		evidence.OutputDigest,
		evidence.ArtifactDigest,
		evidence.Ownership,
	); err != nil {
		return err
	}

	o.evidence = append(o.evidence, evidence)
	o.version++
	o.attempt = 1
	index := phaseIndex(phase)
	if index == len(orderedPhases)-1 {
		o.state = OperationStateReady
		o.currentPhase = PhaseUnknown
		return nil
	}
	o.currentPhase = orderedPhases[index+1]
	return nil
}

// RequireReboot creates a receipt-bound pause only around prerequisite or
// runtime installation, before any subsequent transition can execute.
func (o *Operation) RequireReboot(receipt Hash) error {
	if o.state != OperationStateRunning || receipt.IsZero() ||
		(o.currentPhase != PhaseInstallPrerequisites && o.currentPhase != PhaseInstallRuntime) {
		return errors.New("runtime reboot is not valid at the current phase")
	}
	o.state = OperationStateRebootPending
	o.rebootReceipt = receipt
	o.version++
	return nil
}

// Pause records a non-success outcome without advancing the first unverified
// phase. Only FailedRecoverable and PausedForAdministrator may later resume.
func (o *Operation) Pause(state OperationState) error {
	if o.state != OperationStateRunning {
		return errors.New("runtime operation is not running")
	}
	switch state {
	case OperationStateCancelled,
		OperationStatePausedForAdministrator,
		OperationStateUnsupportedHost,
		OperationStateRuntimeConflict,
		OperationStateFailedRecoverable:
	case OperationStateUnknown,
		OperationStateRunning,
		OperationStateRebootPending,
		OperationStateReady:
		return errors.New("runtime pause state is invalid")
	}
	o.state = state
	o.version++
	return nil
}

// Resume retries the first unverified phase after a recoverable or
// administrator-resolved pause.
func (o *Operation) Resume() error {
	if o.state != OperationStateFailedRecoverable && o.state != OperationStatePausedForAdministrator {
		return errors.New("runtime operation state is not resumable")
	}
	o.state = OperationStateRunning
	o.attempt++
	o.version++
	return nil
}

// ResumeAfterReboot consumes the exact receipt and retries the paused phase.
func (o *Operation) ResumeAfterReboot(receipt Hash) error {
	if o.state != OperationStateRebootPending || receipt.IsZero() || receipt != o.rebootReceipt {
		return errors.New("runtime reboot receipt is invalid")
	}
	o.rebootReceipt = Hash{}
	o.state = OperationStateRunning
	o.attempt++
	o.version++
	return nil
}

// Snapshot returns an immutable-by-copy persistence representation.
func (o *Operation) Snapshot() OperationSnapshot {
	return OperationSnapshot{
		SchemaVersion: operationSnapshotSchemaVersion,
		OperationID:   o.id,
		PlanDigest:    o.planDigest,
		State:         o.state,
		CurrentPhase:  o.currentPhase,
		Attempt:       o.attempt,
		Version:       o.version,
		Evidence:      append([]TransitionEvidence(nil), o.evidence...),
		RebootReceipt: o.rebootReceipt,
	}
}

// RestoreOperation validates the complete history instead of trusting the
// stored cursor or version fields.
func RestoreOperation(snapshot OperationSnapshot) (*Operation, error) {
	if snapshot.SchemaVersion != operationSnapshotSchemaVersion {
		return nil, errors.New("unsupported runtime operation snapshot schema")
	}
	operation, err := NewOperation(snapshot.OperationID, snapshot.PlanDigest)
	if err != nil {
		return nil, err
	}
	for _, evidence := range snapshot.Evidence {
		// Failed/reboot pauses are journal-authenticated version changes but are
		// not successful phase evidence. Restore the recorded per-phase attempt
		// before replaying its completion, then validate the final aggregate
		// version independently below.
		operation.attempt = evidence.Attempt
		if err := operation.Complete(operation.CurrentPhase(), evidence); err != nil {
			return nil, fmt.Errorf("restore runtime transition: %w", err)
		}
	}

	switch snapshot.State {
	case OperationStateRunning:
		if snapshot.RebootReceipt != (Hash{}) {
			return nil, errors.New("running runtime snapshot contains a reboot receipt")
		}
	case OperationStateRebootPending:
		if snapshot.RebootReceipt.IsZero() ||
			(operation.currentPhase != PhaseInstallPrerequisites && operation.currentPhase != PhaseInstallRuntime) {
			return nil, errors.New("runtime reboot snapshot is invalid")
		}
		operation.state = snapshot.State
		operation.rebootReceipt = snapshot.RebootReceipt
	case OperationStateReady:
		if operation.state != OperationStateReady || snapshot.RebootReceipt != (Hash{}) {
			return nil, errors.New("runtime Ready snapshot is incomplete")
		}
	case OperationStateCancelled,
		OperationStatePausedForAdministrator,
		OperationStateUnsupportedHost,
		OperationStateRuntimeConflict,
		OperationStateFailedRecoverable:
		if operation.state != OperationStateRunning || snapshot.RebootReceipt != (Hash{}) {
			return nil, errors.New("runtime paused snapshot is inconsistent")
		}
		operation.state = snapshot.State
	case OperationStateUnknown:
		return nil, errors.New("runtime snapshot state is not restorable")
	}

	minimumVersion := uint64(len(snapshot.Evidence))
	if snapshot.State != OperationStateRunning && snapshot.State != OperationStateReady {
		minimumVersion++
	}
	if snapshot.Version < minimumVersion || snapshot.Attempt == 0 ||
		(snapshot.Version == 0 && (len(snapshot.Evidence) != 0 || snapshot.Attempt != 1)) {
		return nil, errors.New("runtime snapshot version is inconsistent with history")
	}
	operation.attempt = snapshot.Attempt
	operation.version = snapshot.Version
	if operation.state != snapshot.State || operation.currentPhase != snapshot.CurrentPhase {
		return nil, errors.New("runtime snapshot cursor or version is inconsistent with history")
	}
	return operation, nil
}
