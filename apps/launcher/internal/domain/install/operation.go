package install

import "math"

// ResumeAction tells the application layer how an idempotent resume request
// was handled without exposing platform details to the domain.
type ResumeAction uint8

const (
	// ResumeActionUnknown is the invalid zero value.
	ResumeActionUnknown ResumeAction = iota
	// ResumeActionAlreadyRunning means no state change was needed.
	ResumeActionAlreadyRunning
	// ResumeActionCurrentPhase means the first unverified phase may run again.
	ResumeActionCurrentPhase
	// ResumeActionAwaitVerification means a reboot continuation must verify first.
	ResumeActionAwaitVerification
	// ResumeActionAlreadyReady means installation was already complete.
	ResumeActionAlreadyReady
)

// RebootCheckpoint binds a one-use resume receipt to the exact plan, phase, and
// attempt that requested a reboot. The receipt itself is a digest, never a
// continuation token or credential.
type RebootCheckpoint struct {
	planDigest PlanDigest
	phase      Phase
	attempt    uint32
	receipt    Digest
	nextAction SafeAction
}

// NewRebootCheckpoint validates a digest-only, plan-bound reboot continuation.
func NewRebootCheckpoint(
	plan PlanDigest,
	phase Phase,
	attempt uint32,
	receipt Digest,
	nextAction SafeAction,
) (RebootCheckpoint, error) {
	if plan.IsZero() {
		return RebootCheckpoint{}, newValidationError("plan_digest", "must not be zero")
	}
	if phase != PhaseEnsureContainerRuntime {
		return RebootCheckpoint{}, newValidationError("reboot_phase", "only EnsureContainerRuntime can request a PF-001 reboot")
	}
	if attempt == 0 {
		return RebootCheckpoint{}, newValidationError("attempt", "must be at least one")
	}
	if receipt.IsZero() {
		return RebootCheckpoint{}, newValidationError("resume_receipt_digest", "must not be zero")
	}
	if !nextAction.valid() {
		return RebootCheckpoint{}, newValidationError("next_safe_action", "is not a valid message key")
	}
	return RebootCheckpoint{
		planDigest: plan,
		phase:      phase,
		attempt:    attempt,
		receipt:    receipt,
		nextAction: nextAction,
	}, nil
}

// PlanDigest returns the plan binding captured before reboot.
func (c RebootCheckpoint) PlanDigest() PlanDigest { return c.planDigest }

// Phase returns the phase that must resume.
func (c RebootCheckpoint) Phase() Phase { return c.phase }

// Attempt returns the phase-local attempt captured before reboot.
func (c RebootCheckpoint) Attempt() uint32 { return c.attempt }

// ReceiptDigest returns the digest of the one-use continuation receipt.
func (c RebootCheckpoint) ReceiptDigest() Digest { return c.receipt }

// NextSafeAction returns the restart guidance message key.
func (c RebootCheckpoint) NextSafeAction() SafeAction { return c.nextAction }

func (c RebootCheckpoint) valid() bool {
	return !c.planDigest.IsZero() && c.phase == PhaseEnsureContainerRuntime &&
		c.attempt > 0 && !c.receipt.IsZero() && c.nextAction.valid()
}

func (c RebootCheckpoint) equal(other RebootCheckpoint) bool {
	return c.planDigest.Equal(other.planDigest) && c.phase == other.phase &&
		c.attempt == other.attempt && c.receipt.Equal(other.receipt) &&
		c.nextAction.String() == other.nextAction.String()
}

// RestoreInput is the persistence-neutral representation needed to verify and
// rehydrate an operation. RestoreOperation rejects any non-contiguous or
// contradictory evidence rather than guessing what completed.
type RestoreInput struct {
	OperationID        OperationID
	PlanDigest         PlanDigest
	AggregateVersion   uint64
	State              State
	CurrentPhase       Phase
	Attempt            uint32
	Completed          []StepEvidence
	RebootCheckpoint   *RebootCheckpoint
	CancellationIntent *CancellationRestoreInput
}

// OperationSnapshot is an immutable-by-copy view of an Operation.
type OperationSnapshot struct {
	operationID        OperationID
	planDigest         PlanDigest
	aggregateVersion   uint64
	state              State
	currentPhase       Phase
	attempt            uint32
	completed          []StepEvidence
	rebootCheckpoint   *RebootCheckpoint
	cancellationIntent *CancellationSnapshot
}

// OperationID returns the operation identity.
func (s OperationSnapshot) OperationID() OperationID { return s.operationID }

// PlanDigest returns the immutable plan binding.
func (s OperationSnapshot) PlanDigest() PlanDigest { return s.planDigest }

// AggregateVersion returns the monotonic concurrency token. It advances once
// for each successful state mutation and never advances for an idempotent
// replay or rejected transition.
func (s OperationSnapshot) AggregateVersion() uint64 { return s.aggregateVersion }

// State returns the durable operation state.
func (s OperationSnapshot) State() State { return s.state }

// CurrentPhase returns the first unverified phase, or the final phase at Ready.
func (s OperationSnapshot) CurrentPhase() Phase { return s.currentPhase }

// Attempt returns the current phase-local attempt.
func (s OperationSnapshot) Attempt() uint32 { return s.attempt }

// CompletedEvidence returns a defensive copy of the verified evidence prefix.
func (s OperationSnapshot) CompletedEvidence() []StepEvidence {
	return cloneEvidence(s.completed)
}

// RebootCheckpoint returns a copy of the continuation checkpoint when present.
func (s OperationSnapshot) RebootCheckpoint() (RebootCheckpoint, bool) {
	if s.rebootCheckpoint == nil {
		return RebootCheckpoint{}, false
	}
	return *s.rebootCheckpoint, true
}

// CancellationIntent returns immutable cancellation lifecycle evidence.
func (s OperationSnapshot) CancellationIntent() (CancellationSnapshot, bool) {
	if s.cancellationIntent == nil {
		return CancellationSnapshot{}, false
	}
	return *s.cancellationIntent, true
}

// Operation is the PF-001 installation aggregate.
type Operation struct {
	id                 OperationID
	planDigest         PlanDigest
	aggregateVersion   uint64
	state              State
	currentPhase       Phase
	attempt            uint32
	completed          []StepEvidence
	rebootCheckpoint   *RebootCheckpoint
	cancellationIntent *CancellationSnapshot
}

// NewOperation creates a running operation at VerifyHost attempt one.
func NewOperation(id OperationID, plan PlanDigest) (*Operation, error) {
	if id.IsZero() {
		return nil, newValidationError("operation_id", "must not be empty")
	}
	if plan.IsZero() {
		return nil, newValidationError("plan_digest", "must not be zero")
	}
	return &Operation{
		id:           id,
		planDigest:   plan,
		state:        StateRunning,
		currentPhase: PhaseVerifyHost,
		attempt:      1,
		completed:    make([]StepEvidence, 0, len(orderedPhases)),
	}, nil
}

// ID returns the operation identity.
func (o *Operation) ID() OperationID { return o.id }

// PlanDigest returns the operation's immutable plan binding.
func (o *Operation) PlanDigest() PlanDigest { return o.planDigest }

// VerifyPlanBinding validates an idempotent command without changing state.
// Terminal reconciliation uses it before retrying cleanup side effects.
func (o *Operation) VerifyPlanBinding(plan PlanDigest) error { return o.requirePlan(plan) }

// AggregateVersion returns the monotonic concurrency token for optimistic
// aggregate persistence.
func (o *Operation) AggregateVersion() uint64 { return o.aggregateVersion }

// State returns the current durable state.
func (o *Operation) State() State { return o.state }

// CurrentPhase returns the first unverified phase, or the final phase at Ready.
func (o *Operation) CurrentPhase() Phase { return o.currentPhase }

// Attempt returns the current phase-local attempt.
func (o *Operation) Attempt() uint32 { return o.attempt }

// CompletedEvidence returns a defensive copy of the verified evidence prefix.
func (o *Operation) CompletedEvidence() []StepEvidence {
	return cloneEvidence(o.completed)
}

// CancellationIntent returns immutable cancellation lifecycle evidence.
func (o *Operation) CancellationIntent() (CancellationSnapshot, bool) {
	if o.cancellationIntent == nil {
		return CancellationSnapshot{}, false
	}
	return *o.cancellationIntent, true
}

// FirstUnverified returns the earliest phase without verified evidence.
func (o *Operation) FirstUnverified() (Phase, bool) {
	if len(o.completed) == len(orderedPhases) {
		return PhaseUnknown, false
	}
	return orderedPhases[len(o.completed)], true
}

// Snapshot returns an immutable-by-copy persistence view of the aggregate.
func (o *Operation) Snapshot() OperationSnapshot {
	var checkpoint *RebootCheckpoint
	if o.rebootCheckpoint != nil {
		copyOfCheckpoint := *o.rebootCheckpoint
		checkpoint = &copyOfCheckpoint
	}
	var cancellation *CancellationSnapshot
	if o.cancellationIntent != nil {
		copyOfCancellation := *o.cancellationIntent
		cancellation = &copyOfCancellation
	}
	return OperationSnapshot{
		operationID:        o.id,
		planDigest:         o.planDigest,
		aggregateVersion:   o.aggregateVersion,
		state:              o.state,
		currentPhase:       o.currentPhase,
		attempt:            o.attempt,
		completed:          cloneEvidence(o.completed),
		rebootCheckpoint:   checkpoint,
		cancellationIntent: cancellation,
	}
}

// RestoreOperation verifies a durable snapshot before making it executable.
func RestoreOperation(input RestoreInput) (*Operation, error) {
	if input.OperationID.IsZero() {
		return nil, newIntegrityError("operation ID is absent")
	}
	if input.PlanDigest.IsZero() {
		return nil, newIntegrityError("plan digest is absent")
	}
	if !input.State.Valid() {
		return nil, newIntegrityError("operation state is invalid")
	}
	if input.Attempt == 0 {
		return nil, newIntegrityError("current attempt is zero")
	}
	if len(input.Completed) > len(orderedPhases) {
		return nil, newIntegrityError("evidence contains more steps than the install plan")
	}

	completed := cloneEvidence(input.Completed)
	for index, evidence := range completed {
		if !evidence.valid() {
			return nil, newIntegrityError("step evidence fingerprint or fields are invalid")
		}
		if evidence.phase != orderedPhases[index] {
			return nil, newIntegrityError("step evidence is duplicated, skipped, or out of order")
		}
		if !evidence.planDigest.Equal(input.PlanDigest) {
			return nil, newIntegrityError("step evidence is bound to another plan")
		}
	}
	if !runtimeOwnershipChainValid(completed) {
		return nil, newIntegrityError("step evidence changes the resolved runtime ownership")
	}
	if input.AggregateVersion < uint64(len(completed)) {
		return nil, newIntegrityError("aggregate version predates completed step evidence")
	}
	if input.AggregateVersion == 0 &&
		(input.State != StateRunning || input.CurrentPhase != PhaseVerifyHost || input.Attempt != 1 || len(completed) != 0) {
		return nil, newIntegrityError("zero aggregate version does not describe a pristine operation")
	}

	allVerified := len(completed) == len(orderedPhases)
	if allVerified {
		if input.State != StateReady {
			return nil, newIntegrityError("all steps are verified but state is not Ready")
		}
		if input.CurrentPhase != PhaseCommitActiveRelease {
			return nil, newIntegrityError("Ready snapshot does not retain the final phase")
		}
		if input.RebootCheckpoint != nil {
			return nil, newIntegrityError("Ready snapshot retains a reboot checkpoint")
		}
	} else {
		expected := orderedPhases[len(completed)]
		if input.CurrentPhase != expected {
			return nil, newIntegrityError("current phase is not the first unverified phase")
		}
		if input.State == StateReady {
			return nil, newIntegrityError("Ready is unreachable before every step verifies")
		}
	}

	requiresCheckpoint := input.State == StateRebootPending || input.State == StateResumeVerified
	if requiresCheckpoint {
		if input.RebootCheckpoint == nil || !input.RebootCheckpoint.valid() {
			return nil, newIntegrityError("reboot state has no valid checkpoint")
		}
		checkpoint := input.RebootCheckpoint
		if !checkpoint.planDigest.Equal(input.PlanDigest) || checkpoint.phase != input.CurrentPhase || checkpoint.attempt != input.Attempt {
			return nil, newIntegrityError("reboot checkpoint does not match the operation cursor")
		}
	} else if input.RebootCheckpoint != nil {
		return nil, newIntegrityError("non-reboot state retains a reboot checkpoint")
	}

	var checkpoint *RebootCheckpoint
	if input.RebootCheckpoint != nil {
		copyOfCheckpoint := *input.RebootCheckpoint
		checkpoint = &copyOfCheckpoint
	}
	cancellation, err := restoreCancellation(input.CancellationIntent, input.AggregateVersion, input.State)
	if err != nil {
		return nil, err
	}
	return &Operation{
		id:                 input.OperationID,
		planDigest:         input.PlanDigest,
		aggregateVersion:   input.AggregateVersion,
		state:              input.State,
		currentPhase:       input.CurrentPhase,
		attempt:            input.Attempt,
		completed:          completed,
		rebootCheckpoint:   checkpoint,
		cancellationIntent: cancellation,
	}, nil
}

// RequestCancellation appends intent to the same aggregate CAS authority used
// by phase transitions. A racing Ready transition therefore cannot coexist
// with a pending request.
func (o *Operation) RequestCancellation(plan PlanDigest) error {
	if err := o.requirePlan(plan); err != nil {
		return err
	}
	if o.cancellationIntent != nil {
		return nil
	}
	if o.state.Terminal() {
		return newTransitionError(o.state, o.currentPhase, "RequestCancellation")
	}
	if err := o.advanceVersion(); err != nil {
		return err
	}
	o.cancellationIntent = &CancellationSnapshot{requestedAtVersion: o.aggregateVersion}
	return nil
}

// AcknowledgeCancellation is legal only after StateCancelled is durable and
// cleanup has succeeded. The application persists this mutation last.
func (o *Operation) AcknowledgeCancellation(plan PlanDigest) error {
	if err := o.requirePlan(plan); err != nil {
		return err
	}
	if o.cancellationIntent == nil {
		return newIntegrityError("cancellation acknowledgement has no request")
	}
	if o.cancellationIntent.acknowledgedAtVersion != 0 {
		return nil
	}
	if o.state != StateCancelled {
		return newTransitionError(o.state, o.currentPhase, "AcknowledgeCancellation")
	}
	if err := o.advanceVersion(); err != nil {
		return err
	}
	o.cancellationIntent.acknowledgedAtVersion = o.aggregateVersion
	return nil
}

// CompleteStep appends verified evidence for the current phase. Replaying the
// identical evidence is a no-op; conflicting evidence for an already verified
// phase is an integrity violation.
func (o *Operation) CompleteStep(evidence StepEvidence) error {
	if err := o.requirePlan(evidence.planDigest); err != nil {
		return err
	}
	if !evidence.valid() {
		return newValidationError("step_evidence", "is incomplete or has an invalid fingerprint")
	}
	if o.cancellationIntent != nil && o.cancellationIntent.Status() == CancellationRequested {
		return newTransitionError(o.state, o.currentPhase, "CompleteStepWhileCancellationRequested")
	}
	for _, completed := range o.completed {
		if completed.phase != evidence.phase {
			continue
		}
		if completed.Equal(evidence) {
			return nil
		}
		return newIntegrityError("a verified phase was replayed with different evidence")
	}
	if o.state != StateRunning {
		return newTransitionError(o.state, o.currentPhase, "CompleteStep")
	}
	if evidence.phase != o.currentPhase {
		return newTransitionError(o.state, o.currentPhase, "CompleteOutOfOrderStep")
	}
	if evidence.attempt != o.attempt {
		return newIntegrityError("step evidence attempt does not match the operation cursor")
	}
	if !runtimeOwnershipMatchesHistory(o.completed, evidence) {
		return newIntegrityError("step evidence changes the resolved runtime ownership")
	}
	if err := o.advanceVersion(); err != nil {
		return err
	}

	o.completed = append(o.completed, evidence.clone())
	if next, ok := o.currentPhase.Next(); ok {
		o.currentPhase = next
		o.attempt = 1
		return nil
	}

	if len(o.completed) != len(orderedPhases) {
		return newIntegrityError("final phase cannot reach Ready with missing evidence")
	}
	o.state = StateReady
	o.rebootCheckpoint = nil
	return nil
}

// FailRecoverable pauses the current unverified phase for an automatic retry.
func (o *Operation) FailRecoverable(plan PlanDigest) error {
	if err := o.requirePlan(plan); err != nil {
		return err
	}
	if o.state == StateFailedRecoverable {
		return nil
	}
	if o.state != StateRunning {
		return newTransitionError(o.state, o.currentPhase, "FailRecoverable")
	}
	if err := o.advanceVersion(); err != nil {
		return err
	}
	o.state = StateFailedRecoverable
	return nil
}

// PauseForAdministrator pauses until device policy or authority changes.
func (o *Operation) PauseForAdministrator(plan PlanDigest) error {
	if err := o.requirePlan(plan); err != nil {
		return err
	}
	if o.state == StatePausedForAdministrator {
		return nil
	}
	if o.state != StateRunning && o.state != StateFailedRecoverable {
		return newTransitionError(o.state, o.currentPhase, "PauseForAdministrator")
	}
	if err := o.advanceVersion(); err != nil {
		return err
	}
	o.state = StatePausedForAdministrator
	return nil
}

// Cancel terminates the operation without marking it Ready.
func (o *Operation) Cancel(plan PlanDigest) error {
	return o.enterTerminal(plan, StateCancelled, "Cancel")
}

// MarkUnsupportedHost terminates an operation on an uncertified host.
func (o *Operation) MarkUnsupportedHost(plan PlanDigest) error {
	return o.enterTerminal(plan, StateUnsupportedHost, "MarkUnsupportedHost")
}

// MarkRuntimeConflict terminates a plan that cannot safely adopt or mutate the
// discovered local runtime.
func (o *Operation) MarkRuntimeConflict(plan PlanDigest) error {
	return o.enterTerminal(plan, StateRuntimeConflict, "MarkRuntimeConflict")
}

func (o *Operation) enterTerminal(plan PlanDigest, target State, operation string) error {
	if err := o.requirePlan(plan); err != nil {
		return err
	}
	if o.state == target {
		return nil
	}
	if o.state.Terminal() {
		return newTransitionError(o.state, o.currentPhase, operation)
	}
	if err := o.advanceVersion(); err != nil {
		return err
	}
	o.state = target
	o.rebootCheckpoint = nil
	return nil
}

// MarkRebootPending records an authenticated checkpoint before restart.
func (o *Operation) MarkRebootPending(plan PlanDigest, checkpoint RebootCheckpoint) error {
	if err := o.requirePlan(plan); err != nil {
		return err
	}
	if !checkpoint.valid() {
		return newValidationError("reboot_checkpoint", "is invalid")
	}
	if !checkpoint.planDigest.Equal(o.planDigest) {
		return &PlanBindingError{expected: o.planDigest, actual: checkpoint.planDigest}
	}
	if o.state == StateRebootPending {
		if o.rebootCheckpoint != nil && o.rebootCheckpoint.equal(checkpoint) {
			return nil
		}
		return newIntegrityError("reboot was replayed with a different checkpoint")
	}
	if o.state != StateRunning || o.currentPhase != PhaseEnsureContainerRuntime || checkpoint.phase != o.currentPhase || checkpoint.attempt != o.attempt {
		return newTransitionError(o.state, o.currentPhase, "MarkRebootPending")
	}
	if err := o.advanceVersion(); err != nil {
		return err
	}
	copyOfCheckpoint := checkpoint
	o.rebootCheckpoint = &copyOfCheckpoint
	o.state = StateRebootPending
	return nil
}

// VerifyResume consumes proof for the recorded continuation. A mismatched
// receipt is an integrity violation and never advances the cursor.
func (o *Operation) VerifyResume(plan PlanDigest, receipt Digest) error {
	if err := o.requirePlan(plan); err != nil {
		return err
	}
	if o.state == StateResumeVerified {
		if o.rebootCheckpoint != nil && o.rebootCheckpoint.receipt.Equal(receipt) {
			return nil
		}
		return newIntegrityError("resume verification was replayed with a different receipt")
	}
	if o.state != StateRebootPending || o.rebootCheckpoint == nil {
		return newTransitionError(o.state, o.currentPhase, "VerifyResume")
	}
	if receipt.IsZero() || !o.rebootCheckpoint.receipt.Equal(receipt) {
		return newIntegrityError("resume receipt does not match the reboot checkpoint")
	}
	if err := o.advanceVersion(); err != nil {
		return err
	}
	o.state = StateResumeVerified
	return nil
}

// Resume is idempotent. It continues exactly the first unverified phase,
// increments that phase's attempt once, and never infers completion from host
// observations. A reboot requires VerifyResume before it can continue.
func (o *Operation) Resume(plan PlanDigest) (ResumeAction, error) {
	if err := o.requirePlan(plan); err != nil {
		return ResumeActionUnknown, err
	}
	switch o.state {
	case StateRunning:
		return ResumeActionAlreadyRunning, nil
	case StateReady:
		return ResumeActionAlreadyReady, nil
	case StateRebootPending:
		return ResumeActionAwaitVerification, nil
	case StateFailedRecoverable, StatePausedForAdministrator, StateResumeVerified:
		if o.attempt == math.MaxUint32 {
			return ResumeActionUnknown, newIntegrityError("phase attempt counter overflow")
		}
		if err := o.advanceVersion(); err != nil {
			return ResumeActionUnknown, err
		}
		o.attempt++
		o.state = StateRunning
		o.rebootCheckpoint = nil
		return ResumeActionCurrentPhase, nil
	case StateUnknown, StateCancelled, StateUnsupportedHost, StateRuntimeConflict:
		return ResumeActionUnknown, newTransitionError(o.state, o.currentPhase, "Resume")
	default:
		return ResumeActionUnknown, newTransitionError(o.state, o.currentPhase, "Resume")
	}
}

func (o *Operation) advanceVersion() error {
	if o.aggregateVersion == math.MaxUint64 {
		return newIntegrityError("aggregate version counter overflow")
	}
	o.aggregateVersion++
	return nil
}

func (o *Operation) requirePlan(plan PlanDigest) error {
	if plan.IsZero() {
		return newValidationError("plan_digest", "must not be zero")
	}
	if !o.planDigest.Equal(plan) {
		return &PlanBindingError{expected: o.planDigest, actual: plan}
	}
	return nil
}

func runtimeOwnershipChainValid(completed []StepEvidence) bool {
	for index, evidence := range completed {
		if !runtimeOwnershipMatchesHistory(completed[:index], evidence) {
			return false
		}
	}
	return true
}

func runtimeOwnershipMatchesHistory(completed []StepEvidence, candidate StepEvidence) bool {
	if candidate.phase <= PhaseEnsureContainerRuntime {
		return true
	}
	for _, evidence := range completed {
		if evidence.phase == PhaseEnsureContainerRuntime {
			return evidence.runtimeOwnership == candidate.runtimeOwnership
		}
	}
	return false
}

func cloneEvidence(source []StepEvidence) []StepEvidence {
	result := make([]StepEvidence, len(source))
	for index, evidence := range source {
		result[index] = evidence.clone()
	}
	return result
}
