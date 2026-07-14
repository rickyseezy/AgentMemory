package readiness

import (
	"errors"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const receiptRecordSchemaVersion = uint16(1)

// ResultRecord is the explicit versioned persistence DTO for one probe proof.
type ResultRecord struct {
	Probe          string
	Status         string
	OperationID    string
	PlanDigest     string
	ReleaseID      string
	GenerationID   string
	ManifestDigest string
	ComposeDigest  string
	EvidenceDigest string
	ObservedAt     string
}

// ReceiptRecord is the complete persistence DTO for one successful gate.
type ReceiptRecord struct {
	SchemaVersion  uint16
	OperationID    string
	PlanDigest     string
	ReleaseID      string
	GenerationID   string
	ManifestDigest string
	ComposeDigest  string
	EvaluatedAt    string
	Results        []ResultRecord
	ReceiptDigest  string
}

// Record returns a caller-owned persistence value in normative probe order.
func (r Receipt) Record() ReceiptRecord {
	results := make([]ResultRecord, 0, len(r.results))
	for _, result := range r.results {
		results = append(results, ResultRecord{
			Probe:          result.probe.String(),
			Status:         statusString(result.status),
			OperationID:    result.operationID.String(),
			PlanDigest:     result.planDigest.String(),
			ReleaseID:      result.releaseID,
			GenerationID:   result.generationID,
			ManifestDigest: result.manifestDigest.String(),
			ComposeDigest:  result.composeDigest.String(),
			EvidenceDigest: result.evidenceDigest.String(),
			ObservedAt:     result.observedAt.Format(time.RFC3339Nano),
		})
	}
	return ReceiptRecord{
		SchemaVersion:  receiptRecordSchemaVersion,
		OperationID:    r.operationID.String(),
		PlanDigest:     r.planDigest.String(),
		ReleaseID:      r.releaseID,
		GenerationID:   r.generationID,
		ManifestDigest: r.manifestDigest.String(),
		ComposeDigest:  r.composeDigest.String(),
		EvaluatedAt:    r.evaluatedAt.Format(time.RFC3339Nano),
		Results:        results,
		ReceiptDigest:  r.digest.String(),
	}
}

// RestoreReceipt reconstructs only a complete, fresh-at-evaluation,
// all-passing receipt whose deterministic digest exactly matches the record.
func RestoreReceipt(record ReceiptRecord) (Receipt, error) {
	if record.SchemaVersion != receiptRecordSchemaVersion {
		return Receipt{}, errors.New("readiness receipt schema is unsupported")
	}
	operationID, operationError := install.NewOperationID(record.OperationID)
	planDigest, planError := install.ParsePlanDigest(record.PlanDigest)
	manifestDigest, manifestError := install.ParseDigest(record.ManifestDigest)
	composeDigest, composeError := install.ParseDigest(record.ComposeDigest)
	receiptDigest, receiptError := install.ParseDigest(record.ReceiptDigest)
	evaluatedAt, evaluatedError := parseCanonicalTime(record.EvaluatedAt)
	if operationError != nil || planError != nil || manifestError != nil || composeError != nil ||
		receiptError != nil || evaluatedError != nil {
		return Receipt{}, errors.New("readiness receipt record is invalid")
	}

	results := make([]Result, 0, len(record.Results))
	for _, persisted := range record.Results {
		probe, probeError := parseProbe(persisted.Probe)
		status, statusError := parseStatus(persisted.Status)
		resultOperation, resultOperationError := install.NewOperationID(persisted.OperationID)
		resultPlan, resultPlanError := install.ParsePlanDigest(persisted.PlanDigest)
		resultManifest, resultManifestError := install.ParseDigest(persisted.ManifestDigest)
		resultCompose, resultComposeError := install.ParseDigest(persisted.ComposeDigest)
		evidence, evidenceError := install.ParseDigest(persisted.EvidenceDigest)
		observedAt, observedError := parseCanonicalTime(persisted.ObservedAt)
		if probeError != nil || statusError != nil || resultOperationError != nil || resultPlanError != nil ||
			resultManifestError != nil || resultComposeError != nil || evidenceError != nil || observedError != nil {
			return Receipt{}, errors.New("readiness probe record is invalid")
		}
		result, resultError := NewResult(ResultInput{
			Probe:          probe,
			Status:         status,
			OperationID:    resultOperation,
			PlanDigest:     resultPlan,
			ReleaseID:      persisted.ReleaseID,
			GenerationID:   persisted.GenerationID,
			ManifestDigest: resultManifest,
			ComposeDigest:  resultCompose,
			EvidenceDigest: evidence,
			ObservedAt:     observedAt,
		})
		if resultError != nil {
			return Receipt{}, errors.New("readiness probe record violates policy")
		}
		results = append(results, result)
	}

	restored, failures := NewGate().Evaluate(GateInput{
		OperationID:    operationID,
		PlanDigest:     planDigest,
		ReleaseID:      record.ReleaseID,
		GenerationID:   record.GenerationID,
		ManifestDigest: manifestDigest,
		ComposeDigest:  composeDigest,
		EvaluatedAt:    evaluatedAt,
		Results:        results,
	})
	if len(failures) != 0 || !restored.digest.Equal(receiptDigest) {
		return Receipt{}, errors.New("readiness receipt integrity violation")
	}
	return restored, nil
}

func statusString(status Status) string {
	if status == StatusPassed {
		return "passed"
	}
	if status == StatusFailed {
		return "failed"
	}
	return "unknown"
}

func parseStatus(value string) (Status, error) {
	if value == "passed" {
		return StatusPassed, nil
	}
	if value == "failed" {
		return StatusFailed, nil
	}
	return StatusUnknown, errors.New("readiness status is invalid")
}

func parseProbe(value string) (Probe, error) {
	for _, probe := range RequiredProbes() {
		if probe.String() == value {
			return probe, nil
		}
	}
	return ProbeUnknown, errors.New("readiness probe is invalid")
}

func parseCanonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.IsZero() {
		return time.Time{}, errors.New("readiness time is invalid")
	}
	canonical := parsed.UTC().Truncate(time.Microsecond)
	if value != canonical.Format(time.RFC3339Nano) {
		return time.Time{}, errors.New("readiness time is not canonical")
	}
	return canonical, nil
}
