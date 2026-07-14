package resourceinventory

import (
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
)

func TestPF001ResourceInventoryDigestIsDeterministicAndStateSensitive(t *testing.T) {
	t.Parallel()

	inventory := newInventory(t)
	emptyDigest, err := inventory.Digest()
	if err != nil || emptyDigest.IsZero() {
		t.Fatalf("empty Digest() = %v, %v", emptyDigest, err)
	}
	spec := mustPlan(t)[0]
	_, _ = inventory.Begin(spec, "install-1")
	pendingDigest, err := inventory.Digest()
	if err != nil || pendingDigest.Equal(emptyDigest) {
		t.Fatalf("pending Digest() = %v, %v", pendingDigest, err)
	}
	_, _ = inventory.Record(spec, "install-1", observedFor(t, spec))
	recordedDigest, err := inventory.Digest()
	if err != nil || recordedDigest.Equal(pendingDigest) {
		t.Fatalf("recorded Digest() = %v, %v", recordedDigest, err)
	}

	snapshot := inventory.Snapshot()
	restored, err := Restore(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	restoredDigest, err := restored.Digest()
	if err != nil || !restoredDigest.Equal(recordedDigest) {
		t.Fatalf("restored Digest() = %v, %v", restoredDigest, err)
	}
	snapshotDigest, err := DigestSnapshot(snapshot)
	if err != nil || !snapshotDigest.Equal(recordedDigest) {
		t.Fatalf("DigestSnapshot() = %v, %v", snapshotDigest, err)
	}

	snapshot.Entries[0].Labels[composeplan.LabelRelease] = "other"
	changed, err := DigestSnapshot(snapshot)
	if err != nil || changed.Equal(recordedDigest) {
		t.Fatalf("changed DigestSnapshot() = %v, %v", changed, err)
	}
	snapshot.Entries[0].Labels[composeplan.LabelManaged] = "false"
	if _, err := DigestSnapshot(snapshot); err == nil {
		t.Fatal("DigestSnapshot() accepted invalid managed label")
	}
}

func TestPF001ResourceInventoryDigestDoesNotDependOnMapIteration(t *testing.T) {
	t.Parallel()

	inventory := newInventory(t)
	for _, spec := range mustPlan(t) {
		_, _ = inventory.Begin(spec, "install-1")
		_, _ = inventory.Record(spec, "install-1", observedFor(t, spec))
	}
	first, err := inventory.Digest()
	if err != nil {
		t.Fatal(err)
	}
	snapshot := inventory.Snapshot()
	for index := range snapshot.Entries {
		labels := snapshot.Entries[index].Labels
		reversed := make(map[string]string, len(labels))
		keys := []string{
			composeplan.LabelPurpose,
			composeplan.LabelManaged,
			composeplan.LabelGeneration,
			composeplan.LabelRelease,
			composeplan.LabelInstallation,
		}
		for _, key := range keys {
			reversed[key] = labels[key]
		}
		snapshot.Entries[index].Labels = reversed
	}
	second, err := DigestSnapshot(snapshot)
	if err != nil || !second.Equal(first) {
		t.Fatalf("reordered digest = %v, %v; want %v", second, err, first)
	}
}
