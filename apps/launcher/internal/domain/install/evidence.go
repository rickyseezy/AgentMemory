package install

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxFactNameSize         = 64
	maxFactValueSize        = 512
	maxEvidenceFacts        = 128
	maxBoundarySize         = 128
	maxTransparentFactToken = 31
)

// RuntimeOwnership is the runtime disposition observed after a phase.
type RuntimeOwnership uint8

const (
	// RuntimeOwnershipUnknown is the invalid zero value.
	RuntimeOwnershipUnknown RuntimeOwnership = iota
	// RuntimeOwnershipUndetermined means runtime discovery has not resolved ownership yet.
	RuntimeOwnershipUndetermined
	// RuntimeOwnershipReusedExternal means AgentMemory adopted a compatible existing runtime.
	RuntimeOwnershipReusedExternal
	// RuntimeOwnershipProvisionedByAgentMemory means AgentMemory installed the runtime.
	RuntimeOwnershipProvisionedByAgentMemory
	// RuntimeOwnershipNotApplicable means the phase has no runtime ownership observation.
	RuntimeOwnershipNotApplicable
)

// Valid reports whether o is a persistable runtime ownership disposition.
func (o RuntimeOwnership) Valid() bool {
	return o >= RuntimeOwnershipUndetermined && o <= RuntimeOwnershipNotApplicable
}

// Resolved reports whether runtime discovery established exactly who owns the
// compatible container runtime. Only these dispositions may cross the runtime
// phase boundary.
func (o RuntimeOwnership) Resolved() bool {
	return o == RuntimeOwnershipReusedExternal || o == RuntimeOwnershipProvisionedByAgentMemory
}

// ValidForPhase applies the PF-001 ownership proof policy. Host verification
// starts without an ownership conclusion; runtime provisioning resolves it;
// every subsequent phase must carry a resolved disposition.
func (o RuntimeOwnership) ValidForPhase(phase Phase) bool {
	switch {
	case phase == PhaseVerifyHost:
		return o == RuntimeOwnershipUndetermined
	case phase >= PhaseEnsureContainerRuntime && phase <= PhaseCommitActiveRelease:
		return o.Resolved()
	default:
		return false
	}
}

func (o RuntimeOwnership) String() string {
	switch o {
	case RuntimeOwnershipUnknown:
		return "unknown"
	case RuntimeOwnershipUndetermined:
		return "undetermined"
	case RuntimeOwnershipReusedExternal:
		return "reused_external"
	case RuntimeOwnershipProvisionedByAgentMemory:
		return "provisioned_by_agentmemory"
	case RuntimeOwnershipNotApplicable:
		return "not_applicable"
	default:
		return "unknown"
	}
}

// CompensationBoundary names the highest safe compensation operation. Like a
// SafeAction, it is a closed message/operation key rather than executable text.
type CompensationBoundary struct {
	key string
}

// NewCompensationBoundary validates a closed compensation operation key.
func NewCompensationBoundary(key string) (CompensationBoundary, error) {
	if key == "" || len(key) > maxBoundarySize || key != strings.TrimSpace(key) {
		return CompensationBoundary{}, newValidationError("compensation_boundary", "must be a non-empty operation key within 128 bytes")
	}
	for _, character := range key {
		if !isActionCharacter(character) {
			return CompensationBoundary{}, newValidationError("compensation_boundary", "must contain only lowercase operation-key characters")
		}
	}
	return CompensationBoundary{key: key}, nil
}

func (b CompensationBoundary) String() string { return b.key }

func (b CompensationBoundary) valid() bool {
	if b.key == "" || len(b.key) > maxBoundarySize {
		return false
	}
	for _, character := range b.key {
		if !isActionCharacter(character) {
			return false
		}
	}
	return true
}

// NonSecretFact is a deliberately small, explicitly non-secret output fact.
// Its constructor applies a conservative display-safe scalar policy in
// addition to rejecting sensitive-looking names. Opaque material and common
// credential representations must use a purpose-built secret or digest type.
type NonSecretFact struct {
	name  string
	value string
}

// NewNonSecretFact validates evidence that application policy classified as
// non-secret. Both the key and value fail closed on credential-like material.
func NewNonSecretFact(name, value string) (NonSecretFact, error) {
	if name == "" || len(name) > maxFactNameSize || name != strings.TrimSpace(name) {
		return NonSecretFact{}, newValidationError("fact_name", "must be a non-empty key within 64 bytes")
	}
	for _, character := range name {
		if !isActionCharacter(character) {
			return NonSecretFact{}, newValidationError("fact_name", "must contain only lowercase key characters")
		}
	}
	if sensitiveFactName(name) {
		return NonSecretFact{}, newValidationError("fact_name", "sensitive facts cannot be installation evidence")
	}
	if !safeFactValue(value) {
		return NonSecretFact{}, newValidationError(
			"fact_value",
			"must be a non-empty, bounded, display-safe scalar without credential-like or opaque material",
		)
	}
	return NonSecretFact{name: name, value: value}, nil
}

// Name returns the stable fact key.
func (f NonSecretFact) Name() string { return f.name }

// Value returns the bounded, non-secret fact value.
func (f NonSecretFact) Value() string { return f.value }

func sensitiveFactName(name string) bool {
	for _, fragment := range [...]string{"secret", "password", "passwd", "credential", "token", "private_key", "api_key"} {
		if strings.Contains(name, fragment) {
			return true
		}
	}
	return false
}

func safeFactValue(value string) bool {
	if value == "" || len(value) > maxFactValueSize || !utf8.ValidString(value) || value != strings.TrimSpace(value) {
		return false
	}

	lowerValue := strings.ToLower(value)
	for _, fragment := range [...]string{
		"authorization", "bearer ", "basic ", "password", "passwd", "secret",
		"credential", "private key", "private_key", "api key", "api_key", "apikey",
		"access key", "access_key", "client secret", "client_secret", "token",
		"-----begin", "ghp_", "github_pat_", "glpat-", "sk-", "xoxb-", "xoxp-",
		"akia", "ya29.",
	} {
		if strings.Contains(lowerValue, fragment) {
			return false
		}
	}

	for _, character := range value {
		if unicode.IsControl(character) || !safeFactCharacter(character) {
			return false
		}
	}
	return !looksLikeJWT(value) && !containsOpaqueFactToken(value)
}

func safeFactCharacter(character rune) bool {
	if unicode.IsLetter(character) || unicode.IsNumber(character) {
		return true
	}
	switch character {
	case ' ', '.', '_', '-', '/', '\\', ':', '+', '(', ')', '[', ']', ',':
		return true
	default:
		return false
	}
}

func looksLikeJWT(value string) bool {
	segments := strings.Split(value, ".")
	if len(segments) != 3 || !strings.HasPrefix(segments[0], "eyJ") {
		return false
	}
	for _, segment := range segments {
		if segment == "" {
			return false
		}
		for _, character := range segment {
			if !isOpaqueFactCharacter(character) {
				return false
			}
		}
	}
	return true
}

func containsOpaqueFactToken(value string) bool {
	length := 0
	containsLetter := false
	containsNumber := false
	flush := func() bool {
		opaque := length > maxTransparentFactToken && containsLetter && containsNumber
		length = 0
		containsLetter = false
		containsNumber = false
		return opaque
	}

	for _, character := range value {
		if !isOpaqueFactCharacter(character) {
			if flush() {
				return true
			}
			continue
		}
		length++
		containsLetter = containsLetter || unicode.IsLetter(character)
		containsNumber = containsNumber || unicode.IsNumber(character)
	}
	return flush()
}

func isOpaqueFactCharacter(character rune) bool {
	return character <= unicode.MaxASCII &&
		(unicode.IsLetter(character) || unicode.IsNumber(character) ||
			character == '_' || character == '-' || character == '+')
}

// PhaseRequiresVerifiedArtifact reports whether completion proof must bind an
// independently verified executable or release artifact digest.
func PhaseRequiresVerifiedArtifact(phase Phase) bool {
	return phase == PhaseEnsureContainerRuntime || phase == PhaseVerifyRelease ||
		phase == PhaseEnsureComposeBundle
}

// StepEvidenceInput is consumed by NewStepEvidence. Slice data is copied and
// normalized; later mutations of this input cannot change the evidence.
type StepEvidenceInput struct {
	Phase                  Phase
	Attempt                uint32
	PlanDigest             PlanDigest
	InputDigest            Digest
	OutputDigest           Digest
	VerifiedArtifactDigest Digest
	Facts                  []NonSecretFact
	RuntimeOwnership       RuntimeOwnership
	CompensationBoundary   CompensationBoundary
	NextSafeAction         SafeAction
}

// StepEvidence is immutable proof that one phase completed and was verified.
type StepEvidence struct {
	phase                  Phase
	attempt                uint32
	planDigest             PlanDigest
	inputDigest            Digest
	outputDigest           Digest
	verifiedArtifactDigest Digest
	facts                  []NonSecretFact
	runtimeOwnership       RuntimeOwnership
	compensationBoundary   CompensationBoundary
	nextSafeAction         SafeAction
	fingerprint            Digest
}

// NewStepEvidence validates, copies, orders, and fingerprints verified phase
// evidence. The artifact digest may be zero when the phase has no artifact.
func NewStepEvidence(input StepEvidenceInput) (StepEvidence, error) {
	if !input.Phase.Valid() {
		return StepEvidence{}, newValidationError("phase", "is not a PF-001 phase")
	}
	if input.Attempt == 0 {
		return StepEvidence{}, newValidationError("attempt", "must be at least one")
	}
	if input.PlanDigest.IsZero() {
		return StepEvidence{}, newValidationError("plan_digest", "must not be zero")
	}
	if input.InputDigest.IsZero() || input.OutputDigest.IsZero() {
		return StepEvidence{}, newValidationError("evidence_digest", "input and output digests are required")
	}
	if !input.RuntimeOwnership.ValidForPhase(input.Phase) {
		return StepEvidence{}, newValidationError("runtime_ownership", "does not satisfy the phase proof policy")
	}
	if PhaseRequiresVerifiedArtifact(input.Phase) && input.VerifiedArtifactDigest.IsZero() {
		return StepEvidence{}, newValidationError("verified_artifact_digest", "is required for this phase")
	}
	if !input.CompensationBoundary.valid() {
		return StepEvidence{}, newValidationError("compensation_boundary", "is not a valid operation key")
	}
	if !input.NextSafeAction.valid() {
		return StepEvidence{}, newValidationError("next_safe_action", "is not a valid message key")
	}
	if len(input.Facts) > maxEvidenceFacts {
		return StepEvidence{}, newValidationError("facts", "must not contain more than 128 entries")
	}

	facts := append([]NonSecretFact(nil), input.Facts...)
	sort.Slice(facts, func(left, right int) bool {
		if facts[left].name == facts[right].name {
			return facts[left].value < facts[right].value
		}
		return facts[left].name < facts[right].name
	})
	for index, fact := range facts {
		validated, err := NewNonSecretFact(fact.name, fact.value)
		if err != nil {
			return StepEvidence{}, err
		}
		facts[index] = validated
		if index > 0 && facts[index-1].name == fact.name {
			return StepEvidence{}, newValidationError("facts", "fact names must be unique")
		}
	}

	evidence := StepEvidence{
		phase:                  input.Phase,
		attempt:                input.Attempt,
		planDigest:             input.PlanDigest,
		inputDigest:            input.InputDigest,
		outputDigest:           input.OutputDigest,
		verifiedArtifactDigest: input.VerifiedArtifactDigest,
		facts:                  facts,
		runtimeOwnership:       input.RuntimeOwnership,
		compensationBoundary:   input.CompensationBoundary,
		nextSafeAction:         input.NextSafeAction,
	}
	evidence.fingerprint = evidence.calculateFingerprint()
	return evidence, nil
}

// Phase returns the verified phase.
func (e StepEvidence) Phase() Phase { return e.phase }

// Attempt returns the phase-local attempt that produced this evidence.
func (e StepEvidence) Attempt() uint32 { return e.attempt }

// PlanDigest returns the immutable plan binding.
func (e StepEvidence) PlanDigest() PlanDigest { return e.planDigest }

// InputDigest returns the digest of canonical step inputs.
func (e StepEvidence) InputDigest() Digest { return e.inputDigest }

// OutputDigest returns the digest of verified step outputs.
func (e StepEvidence) OutputDigest() Digest { return e.outputDigest }

// VerifiedArtifactDigest returns the verified artifact digest when applicable,
// or the zero Digest for a phase that consumes no artifact.
func (e StepEvidence) VerifiedArtifactDigest() Digest { return e.verifiedArtifactDigest }

// RuntimeOwnership returns the runtime disposition observed by the step.
func (e StepEvidence) RuntimeOwnership() RuntimeOwnership { return e.runtimeOwnership }

// CompensationBoundary returns the highest compensation operation proved safe.
func (e StepEvidence) CompensationBoundary() CompensationBoundary {
	return e.compensationBoundary
}

// NextSafeAction returns the localized message key for the next safe action.
func (e StepEvidence) NextSafeAction() SafeAction { return e.nextSafeAction }

// Fingerprint returns the deterministic digest of all evidence fields.
func (e StepEvidence) Fingerprint() Digest { return e.fingerprint }

// Facts returns a defensive copy of the ordered non-secret facts.
func (e StepEvidence) Facts() []NonSecretFact {
	return append([]NonSecretFact(nil), e.facts...)
}

// Equal compares deterministic evidence fingerprints.
func (e StepEvidence) Equal(other StepEvidence) bool {
	return !e.fingerprint.IsZero() && e.fingerprint.Equal(other.fingerprint)
}

func (e StepEvidence) valid() bool {
	if !e.phase.Valid() || e.attempt == 0 || e.planDigest.IsZero() ||
		e.inputDigest.IsZero() || e.outputDigest.IsZero() ||
		!e.runtimeOwnership.ValidForPhase(e.phase) ||
		(PhaseRequiresVerifiedArtifact(e.phase) && e.verifiedArtifactDigest.IsZero()) ||
		!e.compensationBoundary.valid() || !e.nextSafeAction.valid() {
		return false
	}
	if len(e.facts) > maxEvidenceFacts {
		return false
	}
	if !evidenceFactsValid(e.facts) {
		return false
	}
	return !e.fingerprint.IsZero() && e.fingerprint.Equal(e.calculateFingerprint())
}

func evidenceFactsValid(facts []NonSecretFact) bool {
	for index, fact := range facts {
		if _, err := NewNonSecretFact(fact.name, fact.value); err != nil {
			return false
		}
		if index > 0 && facts[index-1].name >= fact.name {
			return false
		}
	}
	return true
}

func (e StepEvidence) clone() StepEvidence {
	e.facts = append([]NonSecretFact(nil), e.facts...)
	return e
}

func (e StepEvidence) calculateFingerprint() Digest {
	hash := sha256.New()
	writeUint32(hash, uint32(e.phase))
	writeUint32(hash, e.attempt)
	writeString(hash, e.planDigest.String())
	writeString(hash, e.inputDigest.String())
	writeString(hash, e.outputDigest.String())
	writeString(hash, e.verifiedArtifactDigest.String())
	writeString(hash, e.runtimeOwnership.String())
	writeString(hash, e.compensationBoundary.String())
	writeString(hash, e.nextSafeAction.String())
	for _, fact := range e.facts {
		writeString(hash, fact.name)
		writeString(hash, fact.value)
	}

	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return Digest{value: result}
}

type hashWriter interface {
	Write([]byte) (int, error)
}

func writeUint32(writer hashWriter, value uint32) {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	_, _ = writer.Write(encoded[:])
}

func writeString(writer hashWriter, value string) {
	// Each value is represented by a fixed-width digest. This preserves field
	// boundaries without a platform-sized integer conversion in signed evidence.
	digest := sha256.Sum256([]byte(value))
	_, _ = writer.Write(digest[:])
}
