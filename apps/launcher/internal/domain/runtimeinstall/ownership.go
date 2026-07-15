package runtimeinstall

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"unicode/utf8"
)

const runtimeOwnershipRecordSchemaVersion = uint16(1)

// OwnershipStatus is the closed publication state of a runtime ownership record.
type OwnershipStatus uint8

const (
	// OwnershipStatusUnknown is the invalid zero value.
	OwnershipStatusUnknown OwnershipStatus = iota
	// OwnershipStatusPrepared proves the record existed before the first runtime mutation.
	OwnershipStatusPrepared
	// OwnershipStatusFinalized proves the compatibility phase and runtime aggregate are Ready.
	OwnershipStatusFinalized
)

// RuntimeOwnershipAuthoritySnapshot is the signed catalog-to-record projection.
// It contains no credential or command authority.
type RuntimeOwnershipAuthoritySnapshot struct {
	Vendor          string
	Version         string
	Channel         string
	Endpoint        string
	Context         string
	Publisher       string
	PublisherDigest Hash
	ArtifactDigest  Hash
	Components      []string
	Settings        []string
}

// RuntimeOwnershipAuthority is immutable signed authority for the human- and
// audit-readable portion of RuntimeOwnershipRecord.
type RuntimeOwnershipAuthority struct {
	snapshot RuntimeOwnershipAuthoritySnapshot
}

// NewRuntimeOwnershipAuthority validates exact bounded, sorted authority facts.
func NewRuntimeOwnershipAuthority(snapshot RuntimeOwnershipAuthoritySnapshot) (RuntimeOwnershipAuthority, error) {
	if !validOwnershipText(snapshot.Vendor, 128) || !validOwnershipText(snapshot.Version, 128) ||
		snapshot.Channel != "stable" || !validOwnershipText(snapshot.Endpoint, 2048) ||
		!validOwnershipText(snapshot.Context, 128) || !validOwnershipText(snapshot.Publisher, 512) ||
		snapshot.PublisherDigest.IsZero() || snapshot.ArtifactDigest.IsZero() ||
		!validOwnershipList(snapshot.Components) || !validOwnershipList(snapshot.Settings) {
		return RuntimeOwnershipAuthority{}, errors.New("runtime ownership authority is invalid")
	}
	snapshot.Components = append([]string(nil), snapshot.Components...)
	snapshot.Settings = append([]string(nil), snapshot.Settings...)
	return RuntimeOwnershipAuthority{snapshot: snapshot}, nil
}

func validOwnershipText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) &&
		strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func validOwnershipList(values []string) bool {
	if len(values) == 0 || len(values) > 128 || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !validOwnershipText(value, 512) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}

// Snapshot returns an immutable-by-copy authority representation.
func (a RuntimeOwnershipAuthority) Snapshot() RuntimeOwnershipAuthoritySnapshot {
	result := a.snapshot
	result.Components = append([]string(nil), result.Components...)
	result.Settings = append([]string(nil), result.Settings...)
	return result
}

// ArtifactDigest returns the exact signed runtime artifact/package-set digest.
func (a RuntimeOwnershipAuthority) ArtifactDigest() Hash { return a.snapshot.ArtifactDigest }

func (a RuntimeOwnershipAuthority) validFor(plan Plan) bool {
	restored, err := NewRuntimeOwnershipAuthority(a.Snapshot())
	return err == nil && restored.snapshot.Vendor == plan.Product() &&
		restored.snapshot.Version == plan.Version() && restored.snapshot.Channel == plan.Channel()
}

// RuntimeMutationEvidence binds one side-effecting phase's before/after and artifact hashes.
type RuntimeMutationEvidence struct {
	Phase          Phase `json:"phase"`
	BeforeDigest   Hash  `json:"before_digest"`
	AfterDigest    Hash  `json:"after_digest"`
	ArtifactDigest Hash  `json:"artifact_digest"`
}

// RuntimeOwnershipRecordSnapshot is the strict persistence representation.
type RuntimeOwnershipRecordSnapshot struct {
	SchemaVersion             uint16                    `json:"schema_version"`
	OperationID               string                    `json:"operation_id"`
	PlanDigest                Hash                      `json:"plan_digest"`
	Revision                  uint64                    `json:"revision"`
	OperationState            OperationState            `json:"operation_state"`
	Status                    OwnershipStatus           `json:"status"`
	Disposition               OwnershipDisposition      `json:"disposition"`
	Vendor                    string                    `json:"vendor"`
	Version                   string                    `json:"version"`
	Channel                   string                    `json:"channel"`
	Endpoint                  string                    `json:"endpoint"`
	Context                   string                    `json:"context"`
	Publisher                 string                    `json:"publisher"`
	PublisherDigest           Hash                      `json:"publisher_digest"`
	ArtifactDigest            Hash                      `json:"artifact_digest"`
	Components                []string                  `json:"components"`
	Settings                  []string                  `json:"settings"`
	PreExistingStateDigest    Hash                      `json:"pre_existing_state_digest"`
	ConsentDigest             Hash                      `json:"consent_digest"`
	Mutations                 []RuntimeMutationEvidence `json:"mutations"`
	PrivilegeReceiptDigests   []Hash                    `json:"privilege_receipt_digests"`
	Continuations             []Hash                    `json:"continuations"`
	CompatibilityDigest       Hash                      `json:"compatibility_digest"`
	CompensationReceiptDigest Hash                      `json:"compensation_receipt_digest"`
	Digest                    Hash                      `json:"digest"`
}

// RuntimeOwnershipRecord is the immutable, monotonic runtime lifecycle authority.
type RuntimeOwnershipRecord struct {
	snapshot RuntimeOwnershipRecordSnapshot
}

// RuntimeOwnershipRequired reports when consent is durable and the next phase
// can acquire or mutate runtime-owned state.
func RuntimeOwnershipRequired(snapshot OperationSnapshot) bool {
	operation, err := RestoreOperation(snapshot)
	if err != nil {
		return false
	}
	if operation.State() == OperationStateReady {
		return true
	}
	if phaseIndex(operation.CurrentPhase()) >= phaseIndex(PhaseAcquireRuntime) {
		return true
	}
	for _, evidence := range snapshot.Evidence {
		if phaseIndex(evidence.Phase) >= phaseIndex(PhaseAcquireRuntime) {
			return true
		}
	}
	return false
}

// NewRuntimeOwnershipRecord derives the complete record only from a verified
// plan, authenticated aggregate history, signed platform authority, and the
// immediately preceding record used to retain consumed continuation receipts.
func NewRuntimeOwnershipRecord(
	plan Plan,
	operationSnapshot OperationSnapshot,
	authority RuntimeOwnershipAuthority,
	previous *RuntimeOwnershipRecord,
) (RuntimeOwnershipRecord, error) {
	operation, err := RestoreOperation(operationSnapshot)
	if err != nil || plan.Digest().IsZero() || !bytes.Equal(plan.CanonicalBytes(), operationPlanBytes(plan)) ||
		operation.PlanDigest() != plan.Digest() || !RuntimeOwnershipRequired(operationSnapshot) ||
		!authority.validFor(plan) {
		return RuntimeOwnershipRecord{}, errors.New("runtime ownership inputs are inconsistent")
	}
	disposition := ownershipDispositionForAction(plan.Action())
	if disposition == OwnershipUnknown {
		return RuntimeOwnershipRecord{}, errors.New("runtime ownership disposition is unavailable")
	}
	status := OwnershipStatusPrepared
	if operation.State() == OperationStateReady {
		status = OwnershipStatusFinalized
	}
	preExisting, consent, compatibility := Hash{}, Hash{}, Hash{}
	mutations := make([]RuntimeMutationEvidence, 0, 4)
	privilegeReceipts := make([]Hash, 0, 2)
	for _, evidence := range operationSnapshot.Evidence {
		switch evidence.Phase {
		case PhaseDetectRuntime:
			preExisting = evidence.OutputDigest
		case PhaseAwaitRuntimeConsent:
			consent = evidence.OutputDigest
		case PhaseAcquireRuntime, PhaseInstallPrerequisites, PhaseInstallRuntime, PhaseStartRuntime:
			mutations = append(mutations, RuntimeMutationEvidence{
				Phase: evidence.Phase, BeforeDigest: evidence.InputDigest,
				AfterDigest: evidence.OutputDigest, ArtifactDigest: evidence.ArtifactDigest,
			})
			if evidence.Phase == PhaseInstallPrerequisites || evidence.Phase == PhaseInstallRuntime {
				privilegeReceipts = append(privilegeReceipts, evidence.OutputDigest)
			}
		case PhaseVerifyRuntimeCapabilities:
			compatibility = evidence.OutputDigest
		case PhaseDetectHost, PhasePlanRuntime, PhaseVerifyRuntimeArtifact, PhaseAwaitThirdPartyTerms:
		case PhaseUnknown:
			return RuntimeOwnershipRecord{}, errors.New("runtime ownership history contains an invalid phase")
		}
	}
	if preExisting.IsZero() || consent.IsZero() || status == OwnershipStatusFinalized && compatibility.IsZero() {
		return RuntimeOwnershipRecord{}, errors.New("runtime ownership proof is incomplete")
	}
	continuations := make([]Hash, 0, 2)
	if previous != nil {
		if !ownershipAuthorityMatchesRecord(authority, *previous) ||
			previous.OperationID() != operation.ID() || previous.PlanDigest() != plan.Digest() ||
			previous.Revision() > operation.Version() || previous.Disposition() != disposition {
			return RuntimeOwnershipRecord{}, errors.New("previous runtime ownership record was substituted")
		}
		continuations = append(continuations, previous.snapshot.Continuations...)
	}
	if !operationSnapshot.RebootReceipt.IsZero() && !slices.Contains(continuations, operationSnapshot.RebootReceipt) {
		continuations = append(continuations, operationSnapshot.RebootReceipt)
	}
	authoritySnapshot := authority.Snapshot()
	snapshot := RuntimeOwnershipRecordSnapshot{
		SchemaVersion: runtimeOwnershipRecordSchemaVersion,
		OperationID:   operation.ID(), PlanDigest: plan.Digest(), Revision: operation.Version(),
		OperationState: operation.State(), Status: status, Disposition: disposition,
		Vendor: authoritySnapshot.Vendor, Version: authoritySnapshot.Version, Channel: authoritySnapshot.Channel,
		Endpoint: authoritySnapshot.Endpoint, Context: authoritySnapshot.Context,
		Publisher: authoritySnapshot.Publisher, PublisherDigest: authoritySnapshot.PublisherDigest,
		ArtifactDigest:         authoritySnapshot.ArtifactDigest,
		Components:             append([]string(nil), authoritySnapshot.Components...),
		Settings:               append([]string(nil), authoritySnapshot.Settings...),
		PreExistingStateDigest: preExisting, ConsentDigest: consent,
		Mutations: mutations, PrivilegeReceiptDigests: privilegeReceipts,
		Continuations: continuations, CompatibilityDigest: compatibility,
		CompensationReceiptDigest: operationSnapshot.CompensationReceipt,
	}
	snapshot.Digest = ownershipRecordDigest(snapshot)
	record, err := RestoreRuntimeOwnershipRecord(snapshot)
	if err != nil {
		return RuntimeOwnershipRecord{}, err
	}
	if previous != nil && record.Revision() > previous.Revision() && !record.CanFollow(*previous) {
		return RuntimeOwnershipRecord{}, errors.New("runtime ownership record regressed")
	}
	return record, nil
}

func operationPlanBytes(plan Plan) []byte {
	canonical := plan.CanonicalBytes()
	decoded, err := DecodePlanV1(canonical)
	if err != nil || decoded.Digest() != plan.Digest() {
		return nil
	}
	return decoded.CanonicalBytes()
}

func ownershipDispositionForAction(action PlanAction) OwnershipDisposition {
	switch action {
	case PlanActionAdoptCompatible, PlanActionStartCompatible:
		return OwnershipReusedExternal
	case PlanActionInstallCertified, PlanActionRepairManaged:
		return OwnershipProvisionedByAgentMemory
	case PlanActionBlock, PlanActionUnknown:
		return OwnershipUnknown
	}
	return OwnershipUnknown
}

func ownershipAuthorityMatchesRecord(authority RuntimeOwnershipAuthority, record RuntimeOwnershipRecord) bool {
	a := authority.snapshot
	r := record.snapshot
	return a.Vendor == r.Vendor && a.Version == r.Version && a.Channel == r.Channel &&
		a.Endpoint == r.Endpoint && a.Context == r.Context && a.Publisher == r.Publisher &&
		a.PublisherDigest == r.PublisherDigest && a.ArtifactDigest == r.ArtifactDigest &&
		slices.Equal(a.Components, r.Components) && slices.Equal(a.Settings, r.Settings)
}

// RestoreRuntimeOwnershipRecord rejects malformed, contradictory, or digest-substituted state.
func RestoreRuntimeOwnershipRecord(snapshot RuntimeOwnershipRecordSnapshot) (RuntimeOwnershipRecord, error) {
	if err := validateRuntimeOwnershipRecordSnapshot(snapshot); err != nil {
		return RuntimeOwnershipRecord{}, err
	}
	snapshot.Components = append([]string(nil), snapshot.Components...)
	snapshot.Settings = append([]string(nil), snapshot.Settings...)
	snapshot.Mutations = append([]RuntimeMutationEvidence(nil), snapshot.Mutations...)
	snapshot.PrivilegeReceiptDigests = append([]Hash(nil), snapshot.PrivilegeReceiptDigests...)
	snapshot.Continuations = append([]Hash(nil), snapshot.Continuations...)
	return RuntimeOwnershipRecord{snapshot: snapshot}, nil
}

func validateRuntimeOwnershipRecordSnapshot(snapshot RuntimeOwnershipRecordSnapshot) error {
	switch {
	case snapshot.SchemaVersion != runtimeOwnershipRecordSchemaVersion:
		return errors.New("runtime ownership record schema is invalid")
	case validateOperationID(snapshot.OperationID) != nil || snapshot.PlanDigest.IsZero() || snapshot.Revision == 0:
		return errors.New("runtime ownership record identity is invalid")
	case !validOwnershipOperationState(snapshot.OperationState) ||
		(snapshot.Status != OwnershipStatusPrepared && snapshot.Status != OwnershipStatusFinalized) ||
		(snapshot.Disposition != OwnershipReusedExternal && snapshot.Disposition != OwnershipProvisionedByAgentMemory):
		return errors.New("runtime ownership record state is invalid")
	case !validOwnershipText(snapshot.Vendor, 128) || !validOwnershipText(snapshot.Version, 128) ||
		snapshot.Channel != "stable" || !validOwnershipText(snapshot.Endpoint, 2048) ||
		!validOwnershipText(snapshot.Context, 128) || !validOwnershipText(snapshot.Publisher, 512) ||
		snapshot.PublisherDigest.IsZero() || snapshot.ArtifactDigest.IsZero():
		return errors.New("runtime ownership record authority is invalid")
	case !validOwnershipList(snapshot.Components) || !validOwnershipList(snapshot.Settings):
		return errors.New("runtime ownership record inventory is invalid")
	case snapshot.PreExistingStateDigest.IsZero() || snapshot.ConsentDigest.IsZero() ||
		!validMutationEvidence(snapshot.Mutations) || !validHashList(snapshot.PrivilegeReceiptDigests, 2) ||
		!validHashList(snapshot.Continuations, 8):
		return errors.New("runtime ownership record evidence is invalid")
	case (snapshot.Status == OwnershipStatusFinalized) != (snapshot.OperationState == OperationStateReady) ||
		snapshot.Status == OwnershipStatusFinalized && snapshot.CompatibilityDigest.IsZero() ||
		snapshot.Status == OwnershipStatusPrepared && !snapshot.CompatibilityDigest.IsZero():
		return errors.New("runtime ownership record finalization is invalid")
	case !snapshot.CompensationReceiptDigest.IsZero() && snapshot.OperationState != OperationStateCancelled:
		return errors.New("runtime ownership compensation receipt is invalid")
	case ownershipRecordDigest(snapshot) != snapshot.Digest:
		return errors.New("runtime ownership record digest is invalid")
	}
	return nil
}

func validOwnershipOperationState(state OperationState) bool {
	return state == OperationStateRunning || state == OperationStateRebootPending ||
		state == OperationStateReady || state == OperationStateFailedRecoverable ||
		state == OperationStatePausedForAdministrator || state == OperationStateCancelled ||
		state == OperationStateUnsupportedHost || state == OperationStateRuntimeConflict
}

func validMutationEvidence(values []RuntimeMutationEvidence) bool {
	if len(values) > 4 {
		return false
	}
	lastIndex := -1
	for _, value := range values {
		index := phaseIndex(value.Phase)
		if index <= lastIndex || !runtimeMutationPhase(value.Phase) ||
			value.BeforeDigest.IsZero() || value.AfterDigest.IsZero() ||
			value.Phase >= PhaseVerifyRuntimeArtifact && value.ArtifactDigest.IsZero() {
			return false
		}
		lastIndex = index
	}
	return true
}

func runtimeMutationPhase(phase Phase) bool {
	return phase == PhaseAcquireRuntime || phase == PhaseInstallPrerequisites ||
		phase == PhaseInstallRuntime || phase == PhaseStartRuntime
}

func validHashList(values []Hash, maximum int) bool {
	if len(values) > maximum {
		return false
	}
	seen := make(map[Hash]struct{}, len(values))
	for _, value := range values {
		if value.IsZero() {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func ownershipRecordDigest(snapshot RuntimeOwnershipRecordSnapshot) Hash {
	snapshot.Digest = Hash{}
	if len(snapshot.Mutations) == 0 {
		snapshot.Mutations = nil
	}
	if len(snapshot.PrivilegeReceiptDigests) == 0 {
		snapshot.PrivilegeReceiptDigests = nil
	}
	if len(snapshot.Continuations) == 0 {
		snapshot.Continuations = nil
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return Hash{}
	}
	return Sum(encoded)
}

// CanFollow proves strict monotonicity and immutable authority across repository revisions.
func (r RuntimeOwnershipRecord) CanFollow(previous RuntimeOwnershipRecord) bool {
	return r.Revision() > previous.Revision() && r.OperationID() == previous.OperationID() &&
		r.PlanDigest() == previous.PlanDigest() && r.Disposition() == previous.Disposition() &&
		ownershipRecordAuthorityEqual(r, previous) &&
		prefixMutationEvidence(previous.snapshot.Mutations, r.snapshot.Mutations) &&
		prefixHashes(previous.snapshot.PrivilegeReceiptDigests, r.snapshot.PrivilegeReceiptDigests) &&
		prefixHashes(previous.snapshot.Continuations, r.snapshot.Continuations) &&
		(previous.snapshot.CompensationReceiptDigest.IsZero() ||
			r.snapshot.CompensationReceiptDigest == previous.snapshot.CompensationReceiptDigest) &&
		(previous.Status() != OwnershipStatusFinalized || r.Status() == OwnershipStatusFinalized)
}

func ownershipRecordAuthorityEqual(left, right RuntimeOwnershipRecord) bool {
	l, r := left.snapshot, right.snapshot
	return l.Vendor == r.Vendor && l.Version == r.Version && l.Channel == r.Channel &&
		l.Endpoint == r.Endpoint && l.Context == r.Context && l.Publisher == r.Publisher &&
		l.PublisherDigest == r.PublisherDigest && l.ArtifactDigest == r.ArtifactDigest &&
		slices.Equal(l.Components, r.Components) && slices.Equal(l.Settings, r.Settings) &&
		l.PreExistingStateDigest == r.PreExistingStateDigest && l.ConsentDigest == r.ConsentDigest
}

func prefixMutationEvidence(prefix, values []RuntimeMutationEvidence) bool {
	return len(prefix) <= len(values) && slices.Equal(prefix, values[:len(prefix)])
}

func prefixHashes(prefix, values []Hash) bool {
	return len(prefix) <= len(values) && slices.Equal(prefix, values[:len(prefix)])
}

// Snapshot returns an immutable-by-copy persistence representation.
func (r RuntimeOwnershipRecord) Snapshot() RuntimeOwnershipRecordSnapshot {
	result := r.snapshot
	result.Components = append([]string(nil), result.Components...)
	result.Settings = append([]string(nil), result.Settings...)
	result.Mutations = append([]RuntimeMutationEvidence(nil), result.Mutations...)
	result.PrivilegeReceiptDigests = append([]Hash(nil), result.PrivilegeReceiptDigests...)
	result.Continuations = append([]Hash(nil), result.Continuations...)
	return result
}

// OperationID returns the parent runtime installation operation.
func (r RuntimeOwnershipRecord) OperationID() string { return r.snapshot.OperationID }

// PlanDigest returns the exact runtime plan binding.
func (r RuntimeOwnershipRecord) PlanDigest() Hash { return r.snapshot.PlanDigest }

// Revision returns the source runtime aggregate version.
func (r RuntimeOwnershipRecord) Revision() uint64 { return r.snapshot.Revision }

// OperationState returns the authenticated runtime aggregate state.
func (r RuntimeOwnershipRecord) OperationState() OperationState { return r.snapshot.OperationState }

// Status returns Prepared or Finalized.
func (r RuntimeOwnershipRecord) Status() OwnershipStatus { return r.snapshot.Status }

// Disposition reports external reuse or AgentMemory provisioning.
func (r RuntimeOwnershipRecord) Disposition() OwnershipDisposition { return r.snapshot.Disposition }

// Vendor returns the exact signed runtime product.
func (r RuntimeOwnershipRecord) Vendor() string { return r.snapshot.Vendor }

// Version returns the exact signed runtime version.
func (r RuntimeOwnershipRecord) Version() string { return r.snapshot.Version }

// Channel returns the signed stable channel.
func (r RuntimeOwnershipRecord) Channel() string { return r.snapshot.Channel }

// Endpoint returns the explicit local endpoint without changing global context.
func (r RuntimeOwnershipRecord) Endpoint() string { return r.snapshot.Endpoint }

// Context returns the closed endpoint/context selection policy.
func (r RuntimeOwnershipRecord) Context() string { return r.snapshot.Context }

// Publisher returns the native publisher identity.
func (r RuntimeOwnershipRecord) Publisher() string { return r.snapshot.Publisher }

// ArtifactDigest returns the exact runtime artifact/package-set digest.
func (r RuntimeOwnershipRecord) ArtifactDigest() Hash { return r.snapshot.ArtifactDigest }

// Components returns exact signed component identities and versions.
func (r RuntimeOwnershipRecord) Components() []string {
	return append([]string(nil), r.snapshot.Components...)
}

// Settings returns exact signed settings/components whose ownership may change.
func (r RuntimeOwnershipRecord) Settings() []string {
	return append([]string(nil), r.snapshot.Settings...)
}

// PreExistingStateDigest returns the before-mutation runtime inventory hash.
func (r RuntimeOwnershipRecord) PreExistingStateDigest() Hash {
	return r.snapshot.PreExistingStateDigest
}

// ConsentDigest returns the exact authenticated plan/terms decision hash.
func (r RuntimeOwnershipRecord) ConsentDigest() Hash { return r.snapshot.ConsentDigest }

// Mutations returns ordered before/after phase evidence.
func (r RuntimeOwnershipRecord) Mutations() []RuntimeMutationEvidence {
	return append([]RuntimeMutationEvidence(nil), r.snapshot.Mutations...)
}

// PrivilegeReceiptDigests returns prerequisite/installer receipt aggregates.
func (r RuntimeOwnershipRecord) PrivilegeReceiptDigests() []Hash {
	return append([]Hash(nil), r.snapshot.PrivilegeReceiptDigests...)
}

// Continuations returns every registered reboot receipt, including consumed receipts.
func (r RuntimeOwnershipRecord) Continuations() []Hash {
	return append([]Hash(nil), r.snapshot.Continuations...)
}

// CompatibilityDigest returns the last complete active-capability proof.
func (r RuntimeOwnershipRecord) CompatibilityDigest() Hash {
	return r.snapshot.CompatibilityDigest
}

// CompensationReceiptDigest returns the exact owned-cleanup receipt after a
// cancelled runtime operation has settled.
func (r RuntimeOwnershipRecord) CompensationReceiptDigest() Hash {
	return r.snapshot.CompensationReceiptDigest
}

// Digest returns the canonical record digest protected by the repository journal.
func (r RuntimeOwnershipRecord) Digest() Hash { return r.snapshot.Digest }
