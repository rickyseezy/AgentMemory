// Package installprogress projects the authenticated PF-001 operation
// aggregate into the transport-neutral setup progress contract.
package installprogress

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"strings"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
	journalport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeinstallapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/setupprogressapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const (
	decisionSchemaVersion = uint16(1)
	maximumDecisionCount  = 128
	maximumDecisionBytes  = 4 * 1024 * 1024
	maximumCASAttempts    = 8
	defaultPollInterval   = 100 * time.Millisecond
)

// OperationRepository is the authenticated aggregate query required for
// progress projection. The concrete filesystem repository implements it.
type OperationRepository interface {
	Load(context.Context, install.OperationID) (*install.Operation, error)
}

// RuntimeOperationRepository restores the authenticated PF-006 child saga.
// Its revision is folded into the public sequence so nested progress cannot be
// hidden behind an unchanged PF-001 aggregate.
type RuntimeOperationRepository interface {
	Load(context.Context, string) (*runtimeinstall.Operation, error)
}

// RuntimePlanRepository restores the immutable signed nested authority that
// PF-001 persisted before PF-006 began. Consent is projected only from it.
type RuntimePlanRepository interface {
	LoadRuntimePlan(
		context.Context,
		install.OperationID,
		install.PlanDigest,
	) (installplanapp.RuntimePlanAuthority, error)
}

// DecisionJournalProvider supplies a purpose-separated authenticated and
// rollback-anchored journal. It must not share a root or key with operation
// state or the per-agent bootstrap pointer.
type DecisionJournalProvider interface {
	JournalFor(context.Context, install.OperationID) (journalport.Journal, error)
}

// DecisionEffect applies the externally visible effect of a setup decision.
// Implementations must be exact-binding checked and idempotent because a crash
// may occur after the effect commits but before its receipt is journaled.
type DecisionEffect interface {
	ApplySetupDecision(context.Context, setupprogressapp.DecisionCommand) error
}

// Clock supplies durable receipt timestamps.
type Clock interface{ Now() time.Time }

// Authority is the sole production SnapshotAuthority and DecisionAuthority.
// It never derives Ready: Ready is projected only from the restored aggregate.
type Authority struct {
	binding      setupprogressapp.Binding
	totalBytes   uint64
	operations   OperationRepository
	runtime      RuntimeOperationRepository
	runtimePlans RuntimePlanRepository
	decisions    DecisionJournalProvider
	effects      DecisionEffect
	clock        Clock
	pollInterval time.Duration
}

// NewAuthority binds every query and mutation to one authenticated operation.
func NewAuthority(
	binding setupprogressapp.Binding,
	totalBytes uint64,
	operations OperationRepository,
	runtime RuntimeOperationRepository,
	runtimePlans RuntimePlanRepository,
	decisions DecisionJournalProvider,
	effects DecisionEffect,
	clock Clock,
) (*Authority, error) {
	if !binding.Valid() || totalBytes > setupprogressapp.MaximumSafeInteger ||
		nilCapability(operations) || nilCapability(runtime) || nilCapability(runtimePlans) ||
		nilCapability(decisions) ||
		nilCapability(effects) || nilCapability(clock) {
		return nil, setupprogressapp.ErrAuthorityIntegrity
	}
	return &Authority{
		binding: binding, totalBytes: totalBytes, operations: operations,
		runtime: runtime, runtimePlans: runtimePlans,
		decisions: decisions, effects: effects, clock: clock,
		pollInterval: defaultPollInterval,
	}, nil
}

// CurrentSnapshot restores and validates the aggregate before projecting it.
func (a *Authority) CurrentSnapshot(
	ctx context.Context,
	binding setupprogressapp.Binding,
) (setupprogressapp.Snapshot, error) {
	if err := a.validateCall(ctx, binding); err != nil {
		return setupprogressapp.Snapshot{}, err
	}
	operation, err := a.operations.Load(ctx, binding.OperationID())
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return setupprogressapp.Snapshot{}, err
		}
		if errors.Is(err, installapp.ErrOperationIntegrity) {
			return setupprogressapp.Snapshot{}, setupprogressapp.ErrAuthorityIntegrity
		}
		return setupprogressapp.Snapshot{}, errors.New("setup operation authority is unavailable")
	}
	if operation == nil || operation.ID() != binding.OperationID() ||
		!operation.PlanDigest().Equal(binding.PlanDigest()) {
		return setupprogressapp.Snapshot{}, setupprogressapp.ErrAuthorityIntegrity
	}
	return a.project(ctx, operation)
}

// WaitSnapshotAfter polls only the authenticated repository with a bounded
// timer and no background goroutine. The caller's context owns the wait.
func (a *Authority) WaitSnapshotAfter(
	ctx context.Context,
	binding setupprogressapp.Binding,
	after uint64,
) (setupprogressapp.Snapshot, error) {
	if after > setupprogressapp.MaximumSafeInteger {
		return setupprogressapp.Snapshot{}, setupprogressapp.ErrAuthorityIntegrity
	}
	for {
		snapshot, err := a.CurrentSnapshot(ctx, binding)
		if err != nil {
			return setupprogressapp.Snapshot{}, err
		}
		if snapshot.Sequence() > after {
			return snapshot, nil
		}
		timer := time.NewTimer(a.pollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return setupprogressapp.Snapshot{}, ctx.Err()
		case <-timer.C:
		}
	}
}

// ApplyDecision gives every UUID a durable immutable receipt. Competing
// writers use the anchored journal revision as their compare-and-swap token.
func (a *Authority) ApplyDecision(
	ctx context.Context,
	command setupprogressapp.DecisionCommand,
) (setupprogressapp.DecisionReceipt, error) {
	if err := a.validateCall(ctx, command.Binding()); err != nil ||
		!command.Decision().Valid() || command.IdempotencyKey() == "" {
		return setupprogressapp.DecisionReceipt{}, setupprogressapp.ErrAuthorityIntegrity
	}
	journal, err := a.decisions.JournalFor(ctx, a.binding.OperationID())
	if err != nil || nilCapability(journal) {
		return setupprogressapp.DecisionReceipt{}, errors.New("setup decision authority is unavailable")
	}
	effectApplied := false
	for attempt := 0; attempt < maximumCASAttempts; attempt++ {
		state, revision, loadErr := a.loadDecisionState(ctx, journal)
		if loadErr != nil {
			return setupprogressapp.DecisionReceipt{}, loadErr
		}
		if receipt, found, lookupErr := receiptFor(state, command); found || lookupErr != nil {
			return receipt, lookupErr
		}
		if len(state.Receipts) >= maximumDecisionCount || revision == math.MaxUint64 {
			return setupprogressapp.DecisionReceipt{}, setupprogressapp.ErrAuthorityConflict
		}
		before, currentErr := a.CurrentSnapshot(ctx, a.binding)
		if currentErr != nil {
			return setupprogressapp.DecisionReceipt{}, currentErr
		}
		needsEffect, transitionErr := validateDecisionTransition(before, command.Decision())
		if transitionErr != nil {
			return setupprogressapp.DecisionReceipt{}, transitionErr
		}
		if needsEffect && !effectApplied {
			if effectErr := a.effects.ApplySetupDecision(ctx, command); effectErr != nil {
				if errors.Is(effectErr, context.Canceled) || errors.Is(effectErr, context.DeadlineExceeded) {
					return setupprogressapp.DecisionReceipt{}, effectErr
				}
				return setupprogressapp.DecisionReceipt{}, errors.New("setup decision effect is unavailable")
			}
			effectApplied = true
		}
		after, currentErr := a.CurrentSnapshot(ctx, a.binding)
		if currentErr != nil {
			return setupprogressapp.DecisionReceipt{}, currentErr
		}
		canonical, encodeErr := after.CanonicalJSON()
		if encodeErr != nil {
			return setupprogressapp.DecisionReceipt{}, setupprogressapp.ErrAuthorityIntegrity
		}
		state.SchemaVersion = decisionSchemaVersion
		state.OperationID = a.binding.OperationID().String()
		state.PlanDigest = a.binding.PlanDigest().String()
		state.Revision = revision + 1
		state.Receipts = append(state.Receipts, decisionReceiptDocument{
			IdempotencyKey: command.IdempotencyKey(), Decision: string(command.Decision()),
			Snapshot: canonical,
		})
		payload, marshalErr := json.Marshal(state)
		capturedAt := a.clock.Now().UTC().Truncate(time.Microsecond)
		if marshalErr != nil || len(payload) == 0 || len(payload) > maximumDecisionBytes || capturedAt.IsZero() {
			return setupprogressapp.DecisionReceipt{}, setupprogressapp.ErrAuthorityIntegrity
		}
		appendErr := journal.Append(ctx, revision, journalport.Snapshot{
			OperationID: a.binding.OperationID().String(), Revision: revision + 1,
			CapturedAt: capturedAt, Payload: payload,
		})
		if errors.Is(appendErr, journalport.ErrConflict) {
			continue
		}
		if appendErr != nil {
			return setupprogressapp.DecisionReceipt{}, mapJournalError(appendErr)
		}
		if confirmErr := journal.ConfirmDurable(ctx, a.binding.OperationID().String(), revision+1); confirmErr != nil {
			return setupprogressapp.DecisionReceipt{}, mapJournalError(confirmErr)
		}
		return setupprogressapp.NewDecisionReceipt(
			command.IdempotencyKey(), command.Decision(), after,
		)
	}
	return setupprogressapp.DecisionReceipt{}, setupprogressapp.ErrAuthorityConflict
}

func (a *Authority) validateCall(ctx context.Context, binding setupprogressapp.Binding) error {
	if a == nil || ctx == nil || !a.binding.Valid() || !binding.Valid() ||
		binding.OperationID() != a.binding.OperationID() ||
		!binding.PlanDigest().Equal(a.binding.PlanDigest()) ||
		nilCapability(a.operations) || nilCapability(a.runtime) || nilCapability(a.runtimePlans) ||
		nilCapability(a.decisions) ||
		nilCapability(a.effects) || nilCapability(a.clock) || a.pollInterval <= 0 {
		return setupprogressapp.ErrAuthorityIntegrity
	}
	return ctx.Err()
}

func (a *Authority) project(
	ctx context.Context,
	operation *install.Operation,
) (setupprogressapp.Snapshot, error) {
	if operation.AggregateVersion() >= setupprogressapp.MaximumSafeInteger {
		return setupprogressapp.Snapshot{}, setupprogressapp.ErrAuthorityIntegrity
	}
	state, action := setupState(operation.State())
	phase, valid := setupPhase(operation.CurrentPhase())
	if !valid {
		return setupprogressapp.Snapshot{}, setupprogressapp.ErrAuthorityIntegrity
	}
	completed := operation.CompletedEvidence()
	downloaded := uint64(0)
	for _, evidence := range completed {
		if evidence.Phase() == install.PhaseEnsureComposeBundle {
			downloaded = a.totalBytes
			break
		}
	}
	sequence := operation.AggregateVersion() + 1
	var consent *setupprogressapp.ConsentInput
	if operation.CurrentPhase() >= install.PhaseEnsureContainerRuntime ||
		operation.State() == install.StateReady {
		child, childErr := a.runtime.Load(ctx, operation.ID().String())
		switch {
		case errors.Is(childErr, runtimeinstallapp.ErrOperationNotFound):
			if operation.CurrentPhase() > install.PhaseEnsureContainerRuntime ||
				operation.State() == install.StateReady {
				return setupprogressapp.Snapshot{}, setupprogressapp.ErrAuthorityIntegrity
			}
		case childErr != nil:
			return setupprogressapp.Snapshot{}, mapRuntimeProjectionError(childErr)
		case child == nil || child.ID() != operation.ID().String() || child.PlanDigest().IsZero() ||
			child.Version() > setupprogressapp.MaximumSafeInteger-sequence:
			return setupprogressapp.Snapshot{}, setupprogressapp.ErrAuthorityIntegrity
		default:
			sequence += child.Version()
			if operation.CurrentPhase() == install.PhaseEnsureContainerRuntime {
				state, action = setupRuntimeState(child.State())
				if child.State() == runtimeinstall.OperationStateRunning &&
					child.CurrentPhase() == runtimeinstall.PhaseAwaitRuntimeConsent {
					projected, projectionErr := a.runtimeConsent(ctx, operation, child)
					if projectionErr != nil {
						return setupprogressapp.Snapshot{}, projectionErr
					}
					state, action, consent = setupprogressapp.StateAwaitingConsent,
						setupprogressapp.ActionNone, &projected
				}
			}
		}
	}
	message := setupMessage(operation.State(), operation.CurrentPhase())
	if consent != nil {
		message = setupprogressapp.MessageAwaitingConsent
	} else if operation.CurrentPhase() == install.PhaseEnsureContainerRuntime {
		message = runtimeMessage(state)
	}
	snapshot, err := setupprogressapp.NewSnapshot(setupprogressapp.SnapshotInput{
		Sequence:    sequence,
		OperationID: operation.ID(), PlanDigest: operation.PlanDigest(),
		State: state, Phase: phase, MessageKey: message,
		Progress: setupprogressapp.Progress{
			CompletedStages: uint64(len(completed)), TotalStages: uint64(len(install.OrderedPhases())),
			DownloadedBytes: downloaded, TotalBytes: a.totalBytes,
		},
		SafeAction: action, Consent: consent,
	})
	if err != nil {
		return setupprogressapp.Snapshot{}, setupprogressapp.ErrAuthorityIntegrity
	}
	return snapshot, nil
}

func (a *Authority) runtimeConsent(
	ctx context.Context,
	parent *install.Operation,
	child *runtimeinstall.Operation,
) (setupprogressapp.ConsentInput, error) {
	authority, err := a.runtimePlans.LoadRuntimePlan(ctx, parent.ID(), parent.PlanDigest())
	if err != nil {
		return setupprogressapp.ConsentInput{}, mapRuntimeProjectionError(err)
	}
	plan := authority.Plan()
	if authority.OperationID() != parent.ID() ||
		!authority.ParentPlanDigest().Equal(parent.PlanDigest()) ||
		plan.Digest() != child.PlanDigest() || plan.TermsDigest().IsZero() ||
		plan.DownloadBytes() == 0 || plan.ExpandedBytes() < plan.DownloadBytes() ||
		plan.DownloadBytes() > setupprogressapp.MaximumSafeInteger ||
		plan.ExpandedBytes() > setupprogressapp.MaximumSafeInteger {
		return setupprogressapp.ConsentInput{}, setupprogressapp.ErrAuthorityIntegrity
	}
	change, elevation, reboot, ok := runtimeConsentChange(plan)
	if !ok {
		return setupprogressapp.ConsentInput{}, setupprogressapp.ErrAuthorityIntegrity
	}
	return setupprogressapp.ConsentInput{
		TermsTitle:  "Docker Subscription Service Agreement",
		TermsURL:    "https://www.docker.com/legal/docker-subscription-service-agreement/",
		TermsDigest: plan.TermsDigest().String(), DownloadBytes: plan.DownloadBytes(),
		ExpandedBytes: plan.ExpandedBytes(), RequiresElevation: elevation,
		MayRequireReboot: reboot, Changes: []string{change},
	}, nil
}

func runtimeConsentChange(plan runtimeinstall.Plan) (string, bool, bool, bool) {
	product := strings.ReplaceAll(plan.Product(), "_", " ")
	if product == "" || plan.Version() == "" {
		return "", false, false, false
	}
	suffix := product + " " + plan.Version()
	switch plan.Action() {
	case runtimeinstall.PlanActionAdoptCompatible:
		return "Use the compatible existing " + suffix, false, false, true
	case runtimeinstall.PlanActionStartCompatible:
		return "Start the compatible existing " + suffix, false, false, true
	case runtimeinstall.PlanActionInstallCertified:
		return "Install the certified " + suffix, true,
			plan.Platform() == runtimeinstall.PlatformWindows, true
	case runtimeinstall.PlanActionRepairManaged:
		return "Repair the AgentMemory-managed " + suffix, true,
			plan.Platform() == runtimeinstall.PlatformWindows, true
	case runtimeinstall.PlanActionUnknown, runtimeinstall.PlanActionBlock:
		return "", false, false, false
	default:
		return "", false, false, false
	}
}

func setupRuntimeState(
	state runtimeinstall.OperationState,
) (setupprogressapp.State, setupprogressapp.SafeAction) {
	switch state {
	case runtimeinstall.OperationStateRunning, runtimeinstall.OperationStateReady:
		return setupprogressapp.StateRunning, setupprogressapp.ActionCancel
	case runtimeinstall.OperationStateRebootPending:
		return setupprogressapp.StateRebootRequired, setupprogressapp.ActionReboot
	case runtimeinstall.OperationStatePausedForAdministrator:
		return setupprogressapp.StatePausedForAdministrator, setupprogressapp.ActionOpenNativePrompt
	case runtimeinstall.OperationStateFailedRecoverable:
		return setupprogressapp.StateFailed, setupprogressapp.ActionRetry
	case runtimeinstall.OperationStateCancelled:
		return setupprogressapp.StateCancelled, setupprogressapp.ActionNone
	case runtimeinstall.OperationStateUnsupportedHost, runtimeinstall.OperationStateRuntimeConflict:
		return setupprogressapp.StateFailed, setupprogressapp.ActionNone
	case runtimeinstall.OperationStateUnknown:
		return setupprogressapp.StateConnecting, setupprogressapp.ActionNone
	default:
		return setupprogressapp.StateConnecting, setupprogressapp.ActionNone
	}
}

func runtimeMessage(state setupprogressapp.State) setupprogressapp.MessageKey {
	switch state {
	case setupprogressapp.StateRebootRequired:
		return setupprogressapp.MessageRebootRequired
	case setupprogressapp.StatePausedForAdministrator:
		return setupprogressapp.MessageAdministratorRequired
	case setupprogressapp.StateFailed:
		return setupprogressapp.MessageRetryableFailure
	case setupprogressapp.StateCancelled:
		return setupprogressapp.MessageCancelled
	case setupprogressapp.StateConnecting:
		return setupprogressapp.MessageConnecting
	case setupprogressapp.StateAwaitingConsent:
		return setupprogressapp.MessageAwaitingConsent
	case setupprogressapp.StateRunning, setupprogressapp.StateReady:
		return setupprogressapp.MessagePreparingRuntime
	default:
		return setupprogressapp.MessageConnecting
	}
}

func mapRuntimeProjectionError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, runtimeinstallapp.ErrOperationIntegrity) ||
		errors.Is(err, installplanapp.ErrRuntimePlanIntegrity) ||
		errors.Is(err, installplanapp.ErrRuntimePlanConflict) {
		return setupprogressapp.ErrAuthorityIntegrity
	}
	return errors.New("runtime setup authority is unavailable")
}

func setupState(state install.State) (setupprogressapp.State, setupprogressapp.SafeAction) {
	switch state {
	case install.StateRunning, install.StateResumeVerified:
		return setupprogressapp.StateRunning, setupprogressapp.ActionCancel
	case install.StateRebootPending:
		return setupprogressapp.StateRebootRequired, setupprogressapp.ActionReboot
	case install.StateFailedRecoverable:
		return setupprogressapp.StateFailed, setupprogressapp.ActionRetry
	case install.StatePausedForAdministrator:
		return setupprogressapp.StatePausedForAdministrator, setupprogressapp.ActionOpenNativePrompt
	case install.StateCancelled:
		return setupprogressapp.StateCancelled, setupprogressapp.ActionNone
	case install.StateUnsupportedHost, install.StateRuntimeConflict:
		return setupprogressapp.StateFailed, setupprogressapp.ActionNone
	case install.StateReady:
		return setupprogressapp.StateReady, setupprogressapp.ActionNone
	case install.StateUnknown:
		return setupprogressapp.StateConnecting, setupprogressapp.ActionNone
	default:
		return setupprogressapp.StateConnecting, setupprogressapp.ActionNone
	}
}

func setupPhase(phase install.Phase) (setupprogressapp.Phase, bool) {
	phases := map[install.Phase]setupprogressapp.Phase{
		install.PhaseVerifyHost:              setupprogressapp.PhaseVerifyHost,
		install.PhaseEnsureContainerRuntime:  setupprogressapp.PhaseEnsureContainerRuntime,
		install.PhaseVerifyRelease:           setupprogressapp.PhaseVerifyRelease,
		install.PhaseReserveSpace:            setupprogressapp.PhaseReserveSpace,
		install.PhaseEnsureDirectories:       setupprogressapp.PhaseEnsureDirectories,
		install.PhaseEnsureKeys:              setupprogressapp.PhaseEnsureKeys,
		install.PhaseEnsureComposeBundle:     setupprogressapp.PhaseEnsureComposeBundle,
		install.PhaseEnsureNetworkAndVolumes: setupprogressapp.PhaseEnsureNetworkAndVolumes,
		install.PhaseRunMigrations:           setupprogressapp.PhaseRunMigrations,
		install.PhaseEnsureCoreAndGraph:      setupprogressapp.PhaseEnsureCoreAndGraph,
		install.PhaseBootstrapLocalBrain:     setupprogressapp.PhaseBootstrapLocalBrain,
		install.PhaseMergeAgentConfiguration: setupprogressapp.PhaseMergeAgentConfiguration,
		install.PhaseVerifyReadiness:         setupprogressapp.PhaseVerifyReadiness,
		install.PhaseCommitActiveRelease:     setupprogressapp.PhaseCommitActiveRelease,
	}
	result, ok := phases[phase]
	return result, ok
}

func setupMessage(state install.State, phase install.Phase) setupprogressapp.MessageKey {
	switch state {
	case install.StateRebootPending:
		return setupprogressapp.MessageRebootRequired
	case install.StateFailedRecoverable, install.StateUnsupportedHost, install.StateRuntimeConflict:
		return setupprogressapp.MessageRetryableFailure
	case install.StatePausedForAdministrator:
		return setupprogressapp.MessageAdministratorRequired
	case install.StateCancelled:
		return setupprogressapp.MessageCancelled
	case install.StateReady:
		return setupprogressapp.MessageReady
	case install.StateUnknown:
		return setupprogressapp.MessageConnecting
	case install.StateRunning, install.StateResumeVerified:
	}
	switch phase {
	case install.PhaseEnsureContainerRuntime:
		return setupprogressapp.MessagePreparingRuntime
	case install.PhaseEnsureComposeBundle:
		return setupprogressapp.MessageDownloading
	case install.PhaseVerifyHost, install.PhaseVerifyRelease, install.PhaseReserveSpace,
		install.PhaseEnsureDirectories, install.PhaseEnsureKeys:
		return setupprogressapp.MessageVerifying
	case install.PhaseEnsureNetworkAndVolumes, install.PhaseRunMigrations:
		return setupprogressapp.MessageInstallingRuntime
	case install.PhaseEnsureCoreAndGraph, install.PhaseBootstrapLocalBrain,
		install.PhaseMergeAgentConfiguration:
		return setupprogressapp.MessageStartingBrain
	case install.PhaseVerifyReadiness, install.PhaseCommitActiveRelease:
		return setupprogressapp.MessageCheckingBrain
	case install.PhaseUnknown:
		return setupprogressapp.MessageConnecting
	default:
		return setupprogressapp.MessageConnecting
	}
}

func validateDecisionTransition(snapshot setupprogressapp.Snapshot, decision setupprogressapp.Decision) (bool, error) {
	switch decision {
	case setupprogressapp.DecisionCancel:
		if snapshot.State() == setupprogressapp.StateReady {
			return false, setupprogressapp.ErrAuthorityConflict
		}
		return snapshot.State() != setupprogressapp.StateCancelled, nil
	case setupprogressapp.DecisionDecline:
		if snapshot.State() != setupprogressapp.StateAwaitingConsent {
			return false, setupprogressapp.ErrAuthorityConflict
		}
		return true, nil
	case setupprogressapp.DecisionAccept:
		if snapshot.State() != setupprogressapp.StateAwaitingConsent {
			return false, setupprogressapp.ErrAuthorityConflict
		}
		return true, nil
	case setupprogressapp.DecisionRetry:
		if snapshot.State() != setupprogressapp.StateFailed ||
			snapshot.SafeAction() != setupprogressapp.ActionRetry {
			return false, setupprogressapp.ErrAuthorityConflict
		}
		return true, nil
	default:
		return false, setupprogressapp.ErrAuthorityIntegrity
	}
}

type decisionStateDocument struct {
	SchemaVersion uint16                    `json:"schema_version"`
	Revision      uint64                    `json:"revision"`
	OperationID   string                    `json:"operation_id"`
	PlanDigest    string                    `json:"plan_digest"`
	Receipts      []decisionReceiptDocument `json:"receipts"`
}

type decisionReceiptDocument struct {
	IdempotencyKey string          `json:"idempotency_key"`
	Decision       string          `json:"decision"`
	Snapshot       json.RawMessage `json:"snapshot"`
}

func (a *Authority) loadDecisionState(
	ctx context.Context,
	journal journalport.Journal,
) (decisionStateDocument, uint64, error) {
	snapshot, err := journal.LoadLatest(ctx)
	if errors.Is(err, journalport.ErrNotFound) {
		return decisionStateDocument{Receipts: make([]decisionReceiptDocument, 0)}, 0, nil
	}
	if err != nil {
		return decisionStateDocument{}, 0, mapJournalError(err)
	}
	if snapshot.OperationID != a.binding.OperationID().String() || snapshot.Revision == 0 ||
		snapshot.CapturedAt.IsZero() || len(snapshot.Payload) == 0 || len(snapshot.Payload) > maximumDecisionBytes {
		return decisionStateDocument{}, 0, setupprogressapp.ErrAuthorityIntegrity
	}
	var state decisionStateDocument
	if decodeStrict(snapshot.Payload, &state) != nil || state.SchemaVersion != decisionSchemaVersion ||
		state.Revision != snapshot.Revision || state.OperationID != a.binding.OperationID().String() ||
		state.PlanDigest != a.binding.PlanDigest().String() || len(state.Receipts) == 0 ||
		len(state.Receipts) > maximumDecisionCount {
		return decisionStateDocument{}, 0, setupprogressapp.ErrAuthorityIntegrity
	}
	seen := make(map[string]string, len(state.Receipts))
	for _, receipt := range state.Receipts {
		if previous, duplicate := seen[receipt.IdempotencyKey]; duplicate ||
			receipt.IdempotencyKey == "" || !setupprogressapp.Decision(receipt.Decision).Valid() {
			_ = previous
			return decisionStateDocument{}, 0, setupprogressapp.ErrAuthorityIntegrity
		}
		if _, decodeErr := decodeSnapshot(receipt.Snapshot); decodeErr != nil {
			return decisionStateDocument{}, 0, setupprogressapp.ErrAuthorityIntegrity
		}
		seen[receipt.IdempotencyKey] = receipt.Decision
	}
	if err := journal.ConfirmDurable(ctx, snapshot.OperationID, snapshot.Revision); err != nil {
		return decisionStateDocument{}, 0, mapJournalError(err)
	}
	return state, snapshot.Revision, nil
}

func receiptFor(
	state decisionStateDocument,
	command setupprogressapp.DecisionCommand,
) (setupprogressapp.DecisionReceipt, bool, error) {
	for _, persisted := range state.Receipts {
		if persisted.IdempotencyKey != command.IdempotencyKey() {
			continue
		}
		if persisted.Decision != string(command.Decision()) {
			return setupprogressapp.DecisionReceipt{}, true, setupprogressapp.ErrAuthorityConflict
		}
		snapshot, err := decodeSnapshot(persisted.Snapshot)
		if err != nil {
			return setupprogressapp.DecisionReceipt{}, true, setupprogressapp.ErrAuthorityIntegrity
		}
		receipt, err := setupprogressapp.NewDecisionReceipt(
			persisted.IdempotencyKey, command.Decision(), snapshot,
		)
		if err != nil {
			return setupprogressapp.DecisionReceipt{}, true, setupprogressapp.ErrAuthorityIntegrity
		}
		return receipt, true, nil
	}
	return setupprogressapp.DecisionReceipt{}, false, nil
}

type canonicalSnapshotDocument struct {
	ContractVersion uint8                       `json:"contractVersion"`
	Sequence        uint64                      `json:"sequence"`
	OperationID     string                      `json:"operationId"`
	PlanDigest      string                      `json:"planDigest"`
	State           setupprogressapp.State      `json:"state"`
	Phase           setupprogressapp.Phase      `json:"phase"`
	MessageKey      setupprogressapp.MessageKey `json:"messageKey"`
	Progress        setupprogressapp.Progress   `json:"progress"`
	SafeAction      setupprogressapp.SafeAction `json:"safeAction"`
	Consent         *canonicalConsentDocument   `json:"consent"`
}

type canonicalConsentDocument struct {
	TermsTitle        string   `json:"termsTitle"`
	TermsURL          string   `json:"termsUrl"`
	TermsDigest       string   `json:"termsDigest"`
	DownloadBytes     uint64   `json:"downloadBytes"`
	ExpandedBytes     uint64   `json:"expandedBytes"`
	RequiresElevation bool     `json:"requiresElevation"`
	MayRequireReboot  bool     `json:"mayRequireReboot"`
	Changes           []string `json:"changes"`
}

func decodeSnapshot(raw []byte) (setupprogressapp.Snapshot, error) {
	if len(raw) == 0 || len(raw) > 64*1024 {
		return setupprogressapp.Snapshot{}, setupprogressapp.ErrAuthorityIntegrity
	}
	var document canonicalSnapshotDocument
	if err := decodeStrict(raw, &document); err != nil ||
		document.ContractVersion != setupprogressapp.ContractVersion {
		return setupprogressapp.Snapshot{}, setupprogressapp.ErrAuthorityIntegrity
	}
	operationID, err := install.NewOperationID(document.OperationID)
	if err != nil {
		return setupprogressapp.Snapshot{}, setupprogressapp.ErrAuthorityIntegrity
	}
	planDigest, err := install.ParsePlanDigest(document.PlanDigest)
	if err != nil {
		return setupprogressapp.Snapshot{}, setupprogressapp.ErrAuthorityIntegrity
	}
	input := setupprogressapp.SnapshotInput{
		Sequence: document.Sequence, OperationID: operationID, PlanDigest: planDigest,
		State: document.State, Phase: document.Phase, MessageKey: document.MessageKey,
		Progress: document.Progress, SafeAction: document.SafeAction,
	}
	if document.Consent != nil {
		input.Consent = &setupprogressapp.ConsentInput{
			TermsTitle: document.Consent.TermsTitle, TermsURL: document.Consent.TermsURL,
			TermsDigest: document.Consent.TermsDigest, DownloadBytes: document.Consent.DownloadBytes,
			ExpandedBytes:     document.Consent.ExpandedBytes,
			RequiresElevation: document.Consent.RequiresElevation,
			MayRequireReboot:  document.Consent.MayRequireReboot,
			Changes:           append([]string(nil), document.Consent.Changes...),
		}
	}
	snapshot, err := setupprogressapp.NewSnapshot(input)
	if err != nil {
		return setupprogressapp.Snapshot{}, setupprogressapp.ErrAuthorityIntegrity
	}
	canonical, err := snapshot.CanonicalJSON()
	if err != nil || !bytes.Equal(canonical, raw) {
		return setupprogressapp.Snapshot{}, setupprogressapp.ErrAuthorityIntegrity
	}
	return snapshot, nil
}

func decodeStrict(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func mapJournalError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, journalport.ErrConflict):
		return setupprogressapp.ErrAuthorityConflict
	case errors.Is(err, journalport.ErrCorrupt), errors.Is(err, journalport.ErrUnsafePermission),
		errors.Is(err, journalport.ErrInvalidSnapshot):
		return setupprogressapp.ErrAuthorityIntegrity
	default:
		return errors.New("setup decision journal is unavailable")
	}
}

func nilCapability(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid:
		return true
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128, reflect.Array,
		reflect.String, reflect.Struct, reflect.UnsafePointer:
		return false
	}
	return false
}

var (
	_ setupprogressapp.SnapshotAuthority = (*Authority)(nil)
	_ setupprogressapp.DecisionAuthority = (*Authority)(nil)
)
