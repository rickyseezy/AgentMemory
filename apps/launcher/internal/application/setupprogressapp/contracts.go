// Package setupprogressapp owns the host-neutral setup progress and decision
// contract. It contains no HTTP, browser, listener, entropy, or filesystem
// capability.
package setupprogressapp

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const (
	// ContractVersion is the only setup UI protocol understood by PF-001.
	ContractVersion uint8 = 1
	// MaximumSafeInteger is JavaScript Number.MAX_SAFE_INTEGER.
	MaximumSafeInteger uint64 = 1<<53 - 1
	maximumChanges            = 16
)

// Binding selects exactly one authenticated install operation and plan.
type Binding struct {
	operationID install.OperationID
	planDigest  install.PlanDigest
}

// NewBinding constructs the immutable setup authority binding.
func NewBinding(operationID install.OperationID, planDigest install.PlanDigest) (Binding, error) {
	if operationID.IsZero() || planDigest.IsZero() {
		return Binding{}, errors.New("setup progress binding is invalid")
	}
	return Binding{operationID: operationID, planDigest: planDigest}, nil
}

// OperationID returns the exact installation operation.
func (b Binding) OperationID() install.OperationID { return b.operationID }

// PlanDigest returns the exact canonical plan binding.
func (b Binding) PlanDigest() install.PlanDigest { return b.planDigest }

// Valid reports whether the binding came from its closed constructor.
func (b Binding) Valid() bool { return !b.operationID.IsZero() && !b.planDigest.IsZero() }

// State is the closed TypeScript SetupState vocabulary.
type State string

//nolint:revive // Closed protocol constants are documented by their exported State type.
const (
	StateConnecting             State = "connecting"
	StateAwaitingConsent        State = "awaiting_consent"
	StateRunning                State = "running"
	StatePausedForAdministrator State = "paused_for_administrator"
	StateRebootRequired         State = "reboot_required"
	StateReady                  State = "ready"
	StateFailed                 State = "failed"
	StateCancelled              State = "cancelled"
)

func (s State) valid() bool {
	switch s {
	case StateConnecting, StateAwaitingConsent, StateRunning, StatePausedForAdministrator,
		StateRebootRequired, StateReady, StateFailed, StateCancelled:
		return true
	default:
		return false
	}
}

// Phase is the closed TypeScript InstallPhase vocabulary.
type Phase string

//nolint:revive // Closed protocol constants are documented by their exported Phase type.
const (
	PhaseVerifyHost              Phase = "verify_host"
	PhaseEnsureContainerRuntime  Phase = "ensure_container_runtime"
	PhaseVerifyRelease           Phase = "verify_release"
	PhaseReserveSpace            Phase = "reserve_space"
	PhaseEnsureDirectories       Phase = "ensure_directories"
	PhaseEnsureKeys              Phase = "ensure_keys"
	PhaseEnsureComposeBundle     Phase = "ensure_compose_bundle"
	PhaseEnsureNetworkAndVolumes Phase = "ensure_network_and_volumes"
	PhaseRunMigrations           Phase = "run_migrations"
	PhaseEnsureCoreAndGraph      Phase = "ensure_core_and_graph"
	PhaseBootstrapLocalBrain     Phase = "bootstrap_local_brain"
	PhaseMergeAgentConfiguration Phase = "merge_agent_configuration"
	PhaseVerifyReadiness         Phase = "verify_readiness"
	PhaseCommitActiveRelease     Phase = "commit_active_release"
)

func (p Phase) valid() bool {
	switch p {
	case PhaseVerifyHost, PhaseEnsureContainerRuntime, PhaseVerifyRelease, PhaseReserveSpace,
		PhaseEnsureDirectories, PhaseEnsureKeys, PhaseEnsureComposeBundle, PhaseEnsureNetworkAndVolumes,
		PhaseRunMigrations, PhaseEnsureCoreAndGraph, PhaseBootstrapLocalBrain,
		PhaseMergeAgentConfiguration, PhaseVerifyReadiness, PhaseCommitActiveRelease:
		return true
	default:
		return false
	}
}

// MessageKey is the closed non-diagnostic UI localization vocabulary.
type MessageKey string

//nolint:revive // Closed protocol constants are documented by their exported MessageKey type.
const (
	MessageConnecting            MessageKey = "setup.connecting"
	MessageAwaitingConsent       MessageKey = "setup.awaiting_consent"
	MessagePreparingRuntime      MessageKey = "setup.preparing_runtime"
	MessageDownloading           MessageKey = "setup.downloading"
	MessageVerifying             MessageKey = "setup.verifying"
	MessageInstallingRuntime     MessageKey = "setup.installing_runtime"
	MessageStartingBrain         MessageKey = "setup.starting_brain"
	MessageCheckingBrain         MessageKey = "setup.checking_brain"
	MessageReady                 MessageKey = "setup.ready"
	MessageCancelled             MessageKey = "setup.cancelled"
	MessageRetryableFailure      MessageKey = "setup.retryable_failure"
	MessageAdministratorRequired MessageKey = "setup.administrator_required"
	MessageRebootRequired        MessageKey = "setup.reboot_required"
)

func (m MessageKey) valid() bool {
	switch m {
	case MessageConnecting, MessageAwaitingConsent, MessagePreparingRuntime, MessageDownloading,
		MessageVerifying, MessageInstallingRuntime, MessageStartingBrain, MessageCheckingBrain,
		MessageReady, MessageCancelled, MessageRetryableFailure, MessageAdministratorRequired,
		MessageRebootRequired:
		return true
	default:
		return false
	}
}

// SafeAction is the closed next-action vocabulary.
type SafeAction string

//nolint:revive // Closed protocol constants are documented by their exported SafeAction type.
const (
	ActionNone             SafeAction = "none"
	ActionRetry            SafeAction = "retry"
	ActionCancel           SafeAction = "cancel"
	ActionOpenNativePrompt SafeAction = "open_native_prompt"
	ActionReboot           SafeAction = "reboot"
)

func (a SafeAction) valid() bool {
	return a == ActionNone || a == ActionRetry || a == ActionCancel ||
		a == ActionOpenNativePrompt || a == ActionReboot
}

// Decision is the closed command vocabulary accepted from the setup UI.
type Decision string

//nolint:revive // Closed protocol constants are documented by their exported Decision type.
const (
	DecisionAccept  Decision = "accept"
	DecisionDecline Decision = "decline"
	DecisionRetry   Decision = "retry"
	DecisionCancel  Decision = "cancel"
)

// Valid reports whether the decision is in the exact UI vocabulary.
func (d Decision) Valid() bool {
	return d == DecisionAccept || d == DecisionDecline || d == DecisionRetry || d == DecisionCancel
}

// Progress is the bounded TypeScript SetupProgress projection.
type Progress struct {
	CompletedStages uint64
	TotalStages     uint64
	DownloadedBytes uint64
	TotalBytes      uint64
}

func (p Progress) valid() bool {
	return p.TotalStages > 0 && p.TotalStages <= MaximumSafeInteger &&
		p.CompletedStages <= p.TotalStages && p.DownloadedBytes <= p.TotalBytes &&
		p.DownloadedBytes <= MaximumSafeInteger && p.TotalBytes <= MaximumSafeInteger
}

// ConsentInput is copied into the immutable safe consent projection.
type ConsentInput struct {
	TermsTitle        string
	TermsURL          string
	TermsDigest       string
	DownloadBytes     uint64
	ExpandedBytes     uint64
	RequiresElevation bool
	MayRequireReboot  bool
	Changes           []string
}

// Consent is a comparable, immutable consent summary with a fixed-capacity
// changes array so snapshots can detect equal-sequence backend contradictions.
type Consent struct {
	termsTitle        string
	termsURL          string
	termsDigest       string
	downloadBytes     uint64
	expandedBytes     uint64
	requiresElevation bool
	mayRequireReboot  bool
	changes           [maximumChanges]string
	changeCount       uint8
}

func newConsent(input ConsentInput) (Consent, error) {
	if !validBoundedText(input.TermsTitle, 120) || !validHTTPSURL(input.TermsURL) ||
		!validLowerDigest(input.TermsDigest) || input.DownloadBytes > MaximumSafeInteger ||
		input.ExpandedBytes > MaximumSafeInteger || len(input.Changes) > maximumChanges {
		return Consent{}, errors.New("setup consent is invalid")
	}
	consent := Consent{
		termsTitle: input.TermsTitle, termsURL: input.TermsURL, termsDigest: input.TermsDigest,
		downloadBytes: input.DownloadBytes, expandedBytes: input.ExpandedBytes,
		requiresElevation: input.RequiresElevation, mayRequireReboot: input.MayRequireReboot,
		// G115 is bounded by len(input.Changes) <= maximumChanges (16).
		changeCount: uint8(len(input.Changes)), //nolint:gosec
	}
	for index, change := range input.Changes {
		if !validBoundedText(change, 160) {
			return Consent{}, errors.New("setup consent change is invalid")
		}
		consent.changes[index] = change
	}
	return consent, nil
}

// SnapshotInput is the backend-owned setup projection before validation.
type SnapshotInput struct {
	Sequence    uint64
	OperationID install.OperationID
	PlanDigest  install.PlanDigest
	State       State
	Phase       Phase
	MessageKey  MessageKey
	Progress    Progress
	SafeAction  SafeAction
	Consent     *ConsentInput
}

// Snapshot is the exact immutable TypeScript SetupSnapshot authority value.
type Snapshot struct {
	sequence    uint64
	operationID install.OperationID
	planDigest  install.PlanDigest
	state       State
	phase       Phase
	messageKey  MessageKey
	progress    Progress
	safeAction  SafeAction
	consent     Consent
	hasConsent  bool
}

// NewSnapshot validates every UI and authority invariant without inventing a
// state transition or synthesizing Ready.
func NewSnapshot(input SnapshotInput) (Snapshot, error) {
	if input.Sequence == 0 || input.Sequence > MaximumSafeInteger || input.OperationID.IsZero() ||
		input.PlanDigest.IsZero() || !input.State.valid() || !input.Phase.valid() ||
		!input.MessageKey.valid() || !input.Progress.valid() || !input.SafeAction.valid() {
		return Snapshot{}, errors.New("setup snapshot is invalid")
	}
	snapshot := Snapshot{
		sequence: input.Sequence, operationID: input.OperationID, planDigest: input.PlanDigest,
		state: input.State, phase: input.Phase, messageKey: input.MessageKey,
		progress: input.Progress, safeAction: input.SafeAction,
	}
	if input.Consent != nil {
		consent, err := newConsent(*input.Consent)
		if err != nil {
			return Snapshot{}, err
		}
		snapshot.consent, snapshot.hasConsent = consent, true
	}
	if snapshot.hasConsent != (input.State == StateAwaitingConsent) {
		return Snapshot{}, errors.New("setup consent and state are inconsistent")
	}
	return snapshot, nil
}

// ContractVersion returns the exact DTO version.
func (s Snapshot) ContractVersion() uint8 { return ContractVersion }

// Sequence returns the strictly monotonic backend snapshot sequence.
func (s Snapshot) Sequence() uint64 { return s.sequence }

// OperationID returns the exact operation binding.
func (s Snapshot) OperationID() install.OperationID { return s.operationID }

// PlanDigest returns the exact plan binding.
func (s Snapshot) PlanDigest() install.PlanDigest { return s.planDigest }

// State returns the closed UI state.
func (s Snapshot) State() State { return s.state }

// Phase returns the closed install phase.
func (s Snapshot) Phase() Phase { return s.phase }

// MessageKey returns the safe localized message key.
func (s Snapshot) MessageKey() MessageKey { return s.messageKey }

// Progress returns the bounded progress projection.
func (s Snapshot) Progress() Progress { return s.progress }

// SafeAction returns the closed next-action value.
func (s Snapshot) SafeAction() SafeAction { return s.safeAction }

// Consent returns the immutable consent summary when present.
func (s Snapshot) Consent() (Consent, bool) { return s.consent, s.hasConsent }

// Terminal reports only backend-provided terminal states. It never derives or
// promotes Ready from progress counters.
func (s Snapshot) Terminal() bool {
	return s.state == StateReady || s.state == StateFailed || s.state == StateCancelled
}

// CanonicalJSON returns the exact bounded lower-camel TypeScript DTO.
func (s Snapshot) CanonicalJSON() ([]byte, error) {
	if _, err := NewSnapshot(s.input()); err != nil {
		return nil, errors.New("setup snapshot cannot be encoded")
	}
	document := snapshotDocument{
		ContractVersion: ContractVersion, Sequence: s.sequence, OperationID: s.operationID.String(),
		PlanDigest: s.planDigest.String(), State: s.state, Phase: s.phase, MessageKey: s.messageKey,
		Progress: progressDocument{
			CompletedStages: s.progress.CompletedStages, TotalStages: s.progress.TotalStages,
			DownloadedBytes: s.progress.DownloadedBytes, TotalBytes: s.progress.TotalBytes,
		},
		SafeAction: s.safeAction,
	}
	if s.hasConsent {
		changes := make([]string, int(s.consent.changeCount))
		copy(changes, s.consent.changes[:s.consent.changeCount])
		document.Consent = &consentDocument{
			TermsTitle: s.consent.termsTitle, TermsURL: s.consent.termsURL,
			TermsDigest: s.consent.termsDigest, DownloadBytes: s.consent.downloadBytes,
			ExpandedBytes: s.consent.expandedBytes, RequiresElevation: s.consent.requiresElevation,
			MayRequireReboot: s.consent.mayRequireReboot, Changes: changes,
		}
	}
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) > 64*1024 {
		return nil, errors.New("setup snapshot exceeds its canonical bound")
	}
	return encoded, nil
}

func (s Snapshot) input() SnapshotInput {
	input := SnapshotInput{
		Sequence: s.sequence, OperationID: s.operationID, PlanDigest: s.planDigest,
		State: s.state, Phase: s.phase, MessageKey: s.messageKey,
		Progress: s.progress, SafeAction: s.safeAction,
	}
	if s.hasConsent {
		changes := make([]string, int(s.consent.changeCount))
		copy(changes, s.consent.changes[:s.consent.changeCount])
		input.Consent = &ConsentInput{
			TermsTitle: s.consent.termsTitle, TermsURL: s.consent.termsURL,
			TermsDigest: s.consent.termsDigest, DownloadBytes: s.consent.downloadBytes,
			ExpandedBytes: s.consent.expandedBytes, RequiresElevation: s.consent.requiresElevation,
			MayRequireReboot: s.consent.mayRequireReboot, Changes: changes,
		}
	}
	return input
}

// DecisionCommand is the immutable value passed only to the durable authority.
type DecisionCommand struct {
	binding        Binding
	decision       Decision
	idempotencyKey string
}

func newDecisionCommand(binding Binding, decision Decision, idempotencyKey string) DecisionCommand {
	return DecisionCommand{binding: binding, decision: decision, idempotencyKey: idempotencyKey}
}

// Binding returns the exact operation and plan authority.
func (c DecisionCommand) Binding() Binding { return c.binding }

// Decision returns the closed requested transition.
func (c DecisionCommand) Decision() Decision { return c.decision }

// IdempotencyKey returns the exact lower-case RFC 4122 UUID.
func (c DecisionCommand) IdempotencyKey() string { return c.idempotencyKey }

// DecisionReceipt is minted only by the durable idempotent decision port.
type DecisionReceipt struct {
	idempotencyKey string
	decision       Decision
	snapshot       Snapshot
}

// NewDecisionReceipt creates a validated result for production adapters and
// contract doubles. It does not itself claim persistence.
func NewDecisionReceipt(
	idempotencyKey string,
	decision Decision,
	snapshot Snapshot,
) (DecisionReceipt, error) {
	if !validUUID(idempotencyKey) || !decision.Valid() {
		return DecisionReceipt{}, errors.New("setup decision receipt is invalid")
	}
	if _, err := snapshot.CanonicalJSON(); err != nil {
		return DecisionReceipt{}, errors.New("setup decision receipt snapshot is invalid")
	}
	return DecisionReceipt{idempotencyKey: idempotencyKey, decision: decision, snapshot: snapshot}, nil
}

// IdempotencyKey returns the exact durable command identity.
func (r DecisionReceipt) IdempotencyKey() string { return r.idempotencyKey }

// Decision returns the exact durable decision.
func (r DecisionReceipt) Decision() Decision { return r.decision }

// Snapshot returns the backend-authoritative post-decision projection.
func (r DecisionReceipt) Snapshot() Snapshot { return r.snapshot }

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if character < '0' || character > '9' && (character < 'a' || character > 'f') {
			return false
		}
	}
	version := value[14]
	variant := value[19]
	return version >= '1' && version <= '8' && strings.ContainsRune("89ab", rune(variant))
}

func validLowerDigest(value string) bool {
	digest, err := install.ParseDigest(value)
	return err == nil && digest.String() == value
}

func validBoundedText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validHTTPSURL(value string) bool {
	if !validBoundedText(value, 2048) || !strings.HasPrefix(value, "https://") ||
		strings.ContainsAny(value, "\\@#") || strings.Contains(value, "//") &&
		strings.Contains(strings.TrimPrefix(value, "https://"), "//") {
		return false
	}
	authorityAndPath := strings.TrimPrefix(value, "https://")
	authority, _, _ := strings.Cut(authorityAndPath, "/")
	return authority != "" && !strings.HasPrefix(authority, ".") && !strings.HasSuffix(authority, ".") &&
		strings.Contains(authority, ".")
}

type snapshotDocument struct {
	ContractVersion uint8            `json:"contractVersion"`
	Sequence        uint64           `json:"sequence"`
	OperationID     string           `json:"operationId"`
	PlanDigest      string           `json:"planDigest"`
	State           State            `json:"state"`
	Phase           Phase            `json:"phase"`
	MessageKey      MessageKey       `json:"messageKey"`
	Progress        progressDocument `json:"progress"`
	SafeAction      SafeAction       `json:"safeAction"`
	Consent         *consentDocument `json:"consent"`
}

type progressDocument struct {
	CompletedStages uint64 `json:"completedStages"`
	TotalStages     uint64 `json:"totalStages"`
	DownloadedBytes uint64 `json:"downloadedBytes"`
	TotalBytes      uint64 `json:"totalBytes"`
}

type consentDocument struct {
	TermsTitle        string   `json:"termsTitle"`
	TermsURL          string   `json:"termsUrl"`
	TermsDigest       string   `json:"termsDigest"`
	DownloadBytes     uint64   `json:"downloadBytes"`
	ExpandedBytes     uint64   `json:"expandedBytes"`
	RequiresElevation bool     `json:"requiresElevation"`
	MayRequireReboot  bool     `json:"mayRequireReboot"`
	Changes           []string `json:"changes"`
}

func equalCanonicalSnapshot(left, right Snapshot) bool {
	leftJSON, leftError := left.CanonicalJSON()
	rightJSON, rightError := right.CanonicalJSON()
	return leftError == nil && rightError == nil && bytes.Equal(leftJSON, rightJSON)
}
