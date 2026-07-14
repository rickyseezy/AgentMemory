package setupprogressapp

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001SetupSnapshotMatchesExactTypeScriptDTO(t *testing.T) {
	t.Parallel()
	binding := testBinding(t)
	snapshot := testSnapshot(t, binding, 1, StateAwaitingConsent)
	encoded, err := snapshot.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"contractVersion":1,"sequence":1,"operationId":"operation-1","planDigest":"` +
		strings.Repeat("a", 64) +
		`","state":"awaiting_consent","phase":"ensure_container_runtime","messageKey":"setup.awaiting_consent","progress":{"completedStages":1,"totalStages":14,"downloadedBytes":0,"totalBytes":1024},"safeAction":"cancel","consent":{"termsTitle":"Docker Subscription Service Agreement","termsUrl":"https://www.docker.com/legal/docker-subscription-service-agreement/","termsDigest":"` +
		strings.Repeat("b", 64) +
		`","downloadBytes":1024,"expandedBytes":4096,"requiresElevation":false,"mayRequireReboot":false,"changes":["Install the verified local runtime"]}}`
	if !bytes.Equal(encoded, []byte(want)) {
		t.Fatalf("CanonicalJSON()=%s", encoded)
	}
	if snapshot.ContractVersion() != 1 || snapshot.OperationID() != binding.OperationID() ||
		snapshot.PlanDigest() != binding.PlanDigest() || snapshot.Terminal() {
		t.Fatal("snapshot getters are inconsistent")
	}
}

func TestPF001SetupSnapshotConstructorRejectsEveryInvalidInvariant(t *testing.T) {
	t.Parallel()
	binding := testBinding(t)
	valid := SnapshotInput{
		Sequence: 1, OperationID: binding.OperationID(), PlanDigest: binding.PlanDigest(),
		State: StateAwaitingConsent, Phase: PhaseEnsureContainerRuntime,
		MessageKey: MessageAwaitingConsent,
		Progress:   Progress{CompletedStages: 1, TotalStages: 14, TotalBytes: 1024},
		SafeAction: ActionCancel, Consent: testConsentInput(),
	}
	tests := []struct {
		name   string
		mutate func(*SnapshotInput)
	}{
		{name: "zero sequence", mutate: func(input *SnapshotInput) { input.Sequence = 0 }},
		{name: "unsafe integer", mutate: func(input *SnapshotInput) { input.Sequence = MaximumSafeInteger + 1 }},
		{name: "operation", mutate: func(input *SnapshotInput) { input.OperationID = install.OperationID{} }},
		{name: "plan", mutate: func(input *SnapshotInput) { input.PlanDigest = install.PlanDigest{} }},
		{name: "state", mutate: func(input *SnapshotInput) { input.State = "invented" }},
		{name: "phase", mutate: func(input *SnapshotInput) { input.Phase = "invented" }},
		{name: "message", mutate: func(input *SnapshotInput) { input.MessageKey = "raw diagnostic /secret" }},
		{name: "action", mutate: func(input *SnapshotInput) { input.SafeAction = "shell" }},
		{name: "stage total", mutate: func(input *SnapshotInput) { input.Progress.TotalStages = 0 }},
		{name: "stage overflow", mutate: func(input *SnapshotInput) { input.Progress.CompletedStages = 15 }},
		{name: "byte overflow", mutate: func(input *SnapshotInput) { input.Progress.DownloadedBytes = 2048 }},
		{name: "consent outside consent state", mutate: func(input *SnapshotInput) { input.State = StateRunning }},
		{name: "missing consent", mutate: func(input *SnapshotInput) { input.Consent = nil }},
		{name: "unsafe terms URL", mutate: func(input *SnapshotInput) { input.Consent.TermsURL = "http://example.test" }},
		{name: "raw terms control", mutate: func(input *SnapshotInput) { input.Consent.TermsTitle = "secret\npath" }},
		{name: "terms digest", mutate: func(input *SnapshotInput) { input.Consent.TermsDigest = strings.Repeat("0", 64) }},
		{name: "too many changes", mutate: func(input *SnapshotInput) { input.Consent.Changes = make([]string, 17) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := valid
			consent := *valid.Consent
			consent.Changes = append([]string(nil), valid.Consent.Changes...)
			input.Consent = &consent
			test.mutate(&input)
			if _, err := NewSnapshot(input); err == nil {
				t.Fatal("invalid snapshot accepted")
			}
		})
	}
}

func TestPF001SetupClosedVocabulariesAndDecisionReceipt(t *testing.T) {
	t.Parallel()
	for _, decision := range []Decision{DecisionAccept, DecisionDecline, DecisionRetry, DecisionCancel} {
		if !decision.Valid() {
			t.Fatalf("decision %q is invalid", decision)
		}
	}
	if Decision("approve").Valid() {
		t.Fatal("open decision vocabulary")
	}
	binding := testBinding(t)
	snapshot := testSnapshot(t, binding, 2, StateRunning)
	key := "018f47ab-9a77-7df0-8f4c-3e934c0a7d41"
	receipt, err := NewDecisionReceipt(key, DecisionAccept, snapshot)
	if err != nil || receipt.IdempotencyKey() != key || receipt.Decision() != DecisionAccept ||
		receipt.Snapshot() != snapshot {
		t.Fatalf("receipt=%+v error=%v", receipt, err)
	}
	if _, err := NewDecisionReceipt("bad", DecisionAccept, snapshot); err == nil {
		t.Fatal("invalid idempotency receipt accepted")
	}
}
