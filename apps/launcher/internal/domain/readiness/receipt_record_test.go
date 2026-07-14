package readiness

import (
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001ReadinessReceiptRecordRoundTripsWithoutLosingBindings(t *testing.T) {
	t.Parallel()

	input := validGateInput(t)
	receipt, failures := NewGate().Evaluate(input)
	if len(failures) != 0 {
		t.Fatalf("failures = %v", failures)
	}
	record := receipt.Record()
	restored, err := RestoreReceipt(record)
	if err != nil {
		t.Fatal(err)
	}
	if !restored.Digest().Equal(receipt.Digest()) || restored.OperationID() != receipt.OperationID() ||
		!restored.PlanDigest().Equal(receipt.PlanDigest()) || restored.ReleaseID() != receipt.ReleaseID() ||
		restored.GenerationID() != receipt.GenerationID() || !restored.ManifestDigest().Equal(receipt.ManifestDigest()) ||
		!restored.ComposeDigest().Equal(receipt.ComposeDigest()) || restored.EvaluatedAt() != receipt.EvaluatedAt() ||
		len(restored.Results()) != len(receipt.Results()) {
		t.Fatalf("restored = %+v", restored)
	}
	record.Results[0].EvidenceDigest = install.DigestBytes([]byte("mutated")).String()
	if restored.Results()[0].EvidenceDigest().Equal(install.DigestBytes([]byte("mutated"))) {
		t.Fatal("Receipt record/result aliases restored domain state")
	}
}

func TestPF001ReadinessReceiptRestoreRejectsTamperUnknownAndPartialRecords(t *testing.T) {
	t.Parallel()

	receipt, failures := NewGate().Evaluate(validGateInput(t))
	if len(failures) != 0 {
		t.Fatal(failures)
	}
	valid := receipt.Record()
	tests := []struct {
		name   string
		mutate func(*ReceiptRecord)
	}{
		{name: "zero", mutate: func(value *ReceiptRecord) { *value = ReceiptRecord{} }},
		{name: "schema", mutate: func(value *ReceiptRecord) { value.SchemaVersion++ }},
		{name: "operation", mutate: func(value *ReceiptRecord) { value.OperationID = "bad/id" }},
		{name: "plan", mutate: func(value *ReceiptRecord) { value.PlanDigest = "bad" }},
		{name: "release", mutate: func(value *ReceiptRecord) { value.ReleaseID = "INVALID" }},
		{name: "generation", mutate: func(value *ReceiptRecord) { value.GenerationID = "invalid" }},
		{name: "manifest", mutate: func(value *ReceiptRecord) { value.ManifestDigest = "bad" }},
		{name: "compose", mutate: func(value *ReceiptRecord) { value.ComposeDigest = "bad" }},
		{name: "time", mutate: func(value *ReceiptRecord) { value.EvaluatedAt = "tomorrow" }},
		{name: "receipt digest", mutate: func(value *ReceiptRecord) { value.ReceiptDigest = install.DigestBytes([]byte("other")).String() }},
		{name: "missing probe", mutate: func(value *ReceiptRecord) { value.Results = value.Results[1:] }},
		{name: "duplicate probe", mutate: func(value *ReceiptRecord) { value.Results[1] = value.Results[0] }},
		{name: "failed probe", mutate: func(value *ReceiptRecord) { value.Results[0].Status = "failed" }},
		{name: "unknown probe", mutate: func(value *ReceiptRecord) { value.Results[0].Probe = "future_probe" }},
		{name: "cross release", mutate: func(value *ReceiptRecord) { value.Results[0].ReleaseID = "other" }},
		{name: "evidence", mutate: func(value *ReceiptRecord) { value.Results[0].EvidenceDigest = "bad" }},
		{name: "observation time", mutate: func(value *ReceiptRecord) { value.Results[0].ObservedAt = "bad" }},
		{name: "future observation", mutate: func(value *ReceiptRecord) {
			value.Results[0].ObservedAt = receipt.EvaluatedAt().Add(time.Microsecond).Format(time.RFC3339Nano)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			record := cloneReceiptRecord(valid)
			test.mutate(&record)
			if _, err := RestoreReceipt(record); err == nil {
				t.Fatal("RestoreReceipt() accepted invalid state")
			}
		})
	}
}

func cloneReceiptRecord(input ReceiptRecord) ReceiptRecord {
	input.Results = append([]ResultRecord(nil), input.Results...)
	return input
}
