package readiness

import (
	"encoding/binary"
	"sort"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const defaultMaximumEvidenceAge = 5 * time.Minute

// FailureCode is a stable fail-closed readiness reason.
type FailureCode string

const (
	// FailureInvalidInput rejects malformed gate or result state.
	FailureInvalidInput FailureCode = "invalid_input"
	// FailureMissingProbe reports an absent required check.
	FailureMissingProbe FailureCode = "missing_probe"
	// FailureDuplicateProbe reports ambiguous duplicate evidence.
	FailureDuplicateProbe FailureCode = "duplicate_probe"
	// FailureProbeFailed reports a valid negative probe result.
	FailureProbeFailed FailureCode = "probe_failed"
	// FailureBindingMismatch reports cross-operation/release evidence.
	FailureBindingMismatch FailureCode = "binding_mismatch"
	// FailureStaleEvidence reports expired or future-dated evidence.
	FailureStaleEvidence FailureCode = "stale_evidence"
)

// Failure contains no raw database, path, provider, or Docker diagnostic.
type Failure struct {
	Probe Probe
	Code  FailureCode
}

// GateInput binds all probe evidence to exactly one installation plan and
// signed release/data generation.
type GateInput struct {
	OperationID    install.OperationID
	PlanDigest     install.PlanDigest
	ReleaseID      string
	GenerationID   string
	ManifestDigest install.Digest
	ComposeDigest  install.Digest
	EvaluatedAt    time.Time
	Results        []Result
}

// Receipt is the sole domain proof that may authorize CommitActiveRelease.
type Receipt struct {
	operationID    install.OperationID
	planDigest     install.PlanDigest
	releaseID      string
	generationID   string
	manifestDigest install.Digest
	composeDigest  install.Digest
	evaluatedAt    time.Time
	results        []Result
	digest         install.Digest
}

// Gate evaluates the complete closed set without accepting partial success.
type Gate struct{ maximumEvidenceAge time.Duration }

// NewGate constructs the normative installation-time freshness policy.
func NewGate() Gate { return Gate{maximumEvidenceAge: defaultMaximumEvidenceAge} }

// Evaluate returns a receipt only when every required probe passes exactly
// once with fresh evidence bound to the same operation, plan, release, and
// generation. Failures are deterministic and privacy-safe.
func (g Gate) Evaluate(input GateInput) (Receipt, []Failure) {
	evaluatedAt := input.EvaluatedAt.UTC().Truncate(time.Microsecond)
	if input.OperationID.IsZero() || input.PlanDigest.IsZero() || !validBinding(input.ReleaseID) ||
		!validUUIDv7(input.GenerationID) || input.ManifestDigest.IsZero() || input.ComposeDigest.IsZero() ||
		input.EvaluatedAt.IsZero() || g.maximumEvidenceAge <= 0 {
		return Receipt{}, []Failure{{Probe: ProbeUnknown, Code: FailureInvalidInput}}
	}

	byProbe := make(map[Probe]Result, len(input.Results))
	failures := make([]Failure, 0)
	for _, result := range input.Results {
		if !result.probe.Valid() || result.status == StatusUnknown || result.observedAt.IsZero() {
			failures = append(failures, Failure{Probe: result.probe, Code: FailureInvalidInput})
			continue
		}
		if _, duplicate := byProbe[result.probe]; duplicate {
			failures = append(failures, Failure{Probe: result.probe, Code: FailureDuplicateProbe})
			continue
		}
		byProbe[result.probe] = result
		if result.operationID != input.OperationID || !result.planDigest.Equal(input.PlanDigest) ||
			result.releaseID != input.ReleaseID || result.generationID != input.GenerationID ||
			!result.manifestDigest.Equal(input.ManifestDigest) || !result.composeDigest.Equal(input.ComposeDigest) {
			failures = append(failures, Failure{Probe: result.probe, Code: FailureBindingMismatch})
		}
		if result.status != StatusPassed {
			failures = append(failures, Failure{Probe: result.probe, Code: FailureProbeFailed})
		}
		if result.observedAt.After(evaluatedAt) || evaluatedAt.Sub(result.observedAt) > g.maximumEvidenceAge {
			failures = append(failures, Failure{Probe: result.probe, Code: FailureStaleEvidence})
		}
	}
	for _, required := range RequiredProbes() {
		if _, exists := byProbe[required]; !exists {
			failures = append(failures, Failure{Probe: required, Code: FailureMissingProbe})
		}
	}
	if len(failures) != 0 {
		sortFailures(failures)
		return Receipt{}, failures
	}

	ordered := make([]Result, 0, len(byProbe))
	for _, probe := range RequiredProbes() {
		ordered = append(ordered, byProbe[probe])
	}
	receipt := Receipt{
		operationID:    input.OperationID,
		planDigest:     input.PlanDigest,
		releaseID:      input.ReleaseID,
		generationID:   input.GenerationID,
		manifestDigest: input.ManifestDigest,
		composeDigest:  input.ComposeDigest,
		evaluatedAt:    evaluatedAt,
		results:        ordered,
	}
	receipt.digest = install.DigestBytes(receipt.canonicalBytes())
	return receipt, nil
}

func sortFailures(failures []Failure) {
	sort.Slice(failures, func(left int, right int) bool {
		if failures[left].Probe != failures[right].Probe {
			return failures[left].Probe < failures[right].Probe
		}
		return failures[left].Code < failures[right].Code
	})
}

func (r Receipt) canonicalBytes() []byte {
	output := make([]byte, 0, 1024)
	output = appendField(output, "agentmemory.readiness-receipt.v1")
	output = appendField(output, r.operationID.String())
	output = appendField(output, r.planDigest.String())
	output = appendField(output, r.releaseID)
	output = appendField(output, r.generationID)
	output = appendField(output, r.manifestDigest.String())
	output = appendField(output, r.composeDigest.String())
	output = appendUint64(output, uint64(r.evaluatedAt.UnixMicro()))
	for _, result := range r.results {
		output = appendUint64(output, uint64(result.probe))
		output = appendField(output, result.evidenceDigest.String())
		output = appendUint64(output, uint64(result.observedAt.UnixMicro()))
	}
	return output
}

func appendField(output []byte, value string) []byte {
	output = appendUint64(output, uint64(len(value)))
	return append(output, value...)
}

func appendUint64(output []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(output, encoded[:]...)
}

// OperationID returns the installation operation binding.
func (r Receipt) OperationID() install.OperationID { return r.operationID }

// PlanDigest returns the installation plan binding.
func (r Receipt) PlanDigest() install.PlanDigest { return r.planDigest }

// ReleaseID returns the signed release identity.
func (r Receipt) ReleaseID() string { return r.releaseID }

// GenerationID returns the activated data-generation identity.
func (r Receipt) GenerationID() string { return r.generationID }

// ManifestDigest returns the verified release-manifest binding.
func (r Receipt) ManifestDigest() install.Digest { return r.manifestDigest }

// ComposeDigest returns the exact normalized Compose binding.
func (r Receipt) ComposeDigest() install.Digest { return r.composeDigest }

// EvaluatedAt returns the gate decision time.
func (r Receipt) EvaluatedAt() time.Time { return r.evaluatedAt }

// Digest returns the complete deterministic receipt binding.
func (r Receipt) Digest() install.Digest { return r.digest }

// Results returns a caller-owned copy in normative order.
func (r Receipt) Results() []Result { return append([]Result(nil), r.results...) }

// IsZero reports whether the value is not a valid successful receipt.
func (r Receipt) IsZero() bool { return r.digest.IsZero() }
