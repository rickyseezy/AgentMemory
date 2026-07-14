package artifactacquisition

import (
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001AcquisitionPlanCalculatesExactSignedHeadroom(t *testing.T) {
	t.Parallel()
	plan := testPlan(t)
	if plan.Totals().DownloadBytes() != 6 || plan.Totals().ExpandedBytes() != 6 ||
		plan.Totals().RollbackHeadroomBytes() != 20 || plan.Totals().SafetyHeadroomBytes() != 30 ||
		plan.Totals().RequiredBytes() != 62 {
		t.Fatalf("totals=%+v", plan.Totals())
	}
	artifact := plan.Artifacts()[0]
	if artifact.ID() != "core" || artifact.Size() != 6 || artifact.ExpandedBytes() != 6 ||
		!artifact.ExpandedDigest().Equal(releaseinventory.DigestBytes([]byte("abcdef"))) ||
		artifact.TargetKind() != releaseinventory.ExpandedTargetComposeBundle ||
		artifact.TargetStorageID() != "compose/compose.yaml" || artifact.TargetAuthorityDigest().IsZero() ||
		artifact.ContentKey() != "sha256/"+artifact.Digest().Hex()[:2]+"/"+artifact.Digest().Hex() ||
		!artifact.SourceAuthorized("https://releases.agentmemory.dev/artifacts/core.bin") ||
		artifact.SourceAuthorized("https://releases.agentmemory.dev/artifacts/core.bin/extra") {
		t.Fatalf("artifact=%+v", artifact)
	}
	if _, exists := plan.Artifact("missing"); exists {
		t.Fatal("found unknown artifact")
	}
	reservationID, err := plan.ReservationID("install-1")
	if err != nil || !strings.HasPrefix(reservationID, "r-") || len(reservationID) != 66 {
		t.Fatalf("reservation ID=(%q,%v)", reservationID, err)
	}
}

func TestPF001AcquisitionPlanRejectsUnsignedMismatchOverflowAndMutableSources(t *testing.T) {
	t.Parallel()
	base := testPlanInput()
	mutations := []func(*PlanInput){
		func(input *PlanInput) { input.PlanDigest = releaseinventory.Digest{} },
		func(input *PlanInput) { input.Totals.DownloadBytes++ },
		func(input *PlanInput) { input.Totals.ExpandedBytes++ },
		func(input *PlanInput) { input.Totals.RequiredBytes++ },
		func(input *PlanInput) { input.Totals.RollbackHeadroomBytes = 0 },
		func(input *PlanInput) { input.Artifacts[0].ID = "bad id" },
		func(input *PlanInput) { input.Artifacts[0].Size = 0 },
		func(input *PlanInput) { input.Artifacts[0].ExpandedDigest = releaseinventory.Digest{} },
		func(input *PlanInput) {
			input.Artifacts[0].ExpandedBytes = 0
			input.Totals.ExpandedBytes = 0
			input.Totals.RequiredBytes -= 6
		},
		func(input *PlanInput) { input.Artifacts[0].Chunks[1].Offset++ },
		func(input *PlanInput) { input.Artifacts[0].Chunks[1].Size-- },
		func(input *PlanInput) { input.Artifacts[0].Sources[0] = "http://releases.agentmemory.dev/core" },
		func(input *PlanInput) { input.Artifacts[0].Sources[0] += "?latest=true" },
		func(input *PlanInput) {
			input.Artifacts[0].Sources = append(input.Artifacts[0].Sources, input.Artifacts[0].Sources[0])
		},
		func(input *PlanInput) { input.Artifacts = append(input.Artifacts, input.Artifacts[0]) },
		func(input *PlanInput) { input.Artifacts[0].ExpandedBytes = math.MaxUint64 },
	}
	for index, mutate := range mutations {
		candidate := clonePlanInput(base)
		mutate(&candidate)
		if _, err := NewPlan(candidate); !errors.Is(err, ErrInvalidPlan) {
			t.Fatalf("mutation %d error=%v", index, err)
		}
	}
}

func TestPF001ChunkVerificationIsExact(t *testing.T) {
	t.Parallel()
	chunk := testPlan(t).Artifacts()[0].Chunks()[0]
	if chunk.Index() != 0 || chunk.Offset() != 0 || chunk.Size() != 3 || chunk.End() != 2 ||
		!chunk.Digest().Equal(releaseinventory.DigestBytes([]byte("abc"))) || !chunk.VerifyBytes([]byte("abc")) ||
		chunk.VerifyBytes([]byte("abd")) || chunk.VerifyBytes([]byte("abcx")) {
		t.Fatalf("chunk=%+v", chunk)
	}
}

func TestPF001AcquisitionAggregateRequiresReservationAndExactOwnership(t *testing.T) {
	t.Parallel()
	plan := testPlan(t)
	aggregate, err := NewAggregate("install-1", plan)
	if err != nil {
		t.Fatal(err)
	}
	artifact := plan.Artifacts()[0]
	if _, err := aggregate.BeginArtifact(artifact); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("begin before reserve error=%v", err)
	}
	reservationID, _ := plan.ReservationID("install-1")
	proof, _ := NewReservationProof(reservationID, plan.Totals().DownloadBytes(), "localfs-1")
	_, _ = aggregate.RequestReservation()
	changed, err := aggregate.RecordReservation(proof)
	if err != nil || !changed || aggregate.Version() != 2 || !aggregate.Reserved() {
		t.Fatalf("reserve=(%v,%v) version=%d", changed, err, aggregate.Version())
	}
	changed, err = aggregate.RecordReservation(proof)
	if err != nil || changed || aggregate.Version() != 2 {
		t.Fatalf("replay reserve=(%v,%v)", changed, err)
	}
	changed, err = aggregate.BeginArtifact(artifact)
	if err != nil || !changed || aggregate.Version() != 3 {
		t.Fatalf("begin=(%v,%v)", changed, err)
	}
	authorization, err := aggregate.AuthorizePartial(artifact)
	if err != nil || !authorization.Valid() || authorization.ArtifactID() != artifact.ID() ||
		authorization.Digest() != artifact.Digest() || authorization.Size() != artifact.Size() ||
		authorization.ContentKey() != artifact.ContentKey() || !strings.HasPrefix(authorization.PartialID(), "p-") {
		t.Fatalf("authorization=%+v err=%v", authorization, err)
	}
}

func TestPF001AggregateRevalidatesChunksAndCompletesOnlyExactFinal(t *testing.T) {
	t.Parallel()
	plan, aggregate, artifact := reservedAggregate(t)
	chunks := artifact.Chunks()
	for _, chunk := range chunks {
		if aggregate.ChunkVerified(artifact, chunk) {
			t.Fatal("new chunk already verified")
		}
		changed, err := aggregate.MarkChunkVerified(artifact, chunk, chunk.Digest())
		if err != nil || !changed || !aggregate.ChunkVerified(artifact, chunk) {
			t.Fatalf("mark=(%v,%v)", changed, err)
		}
	}
	proof, _ := NewFinalProof(artifact.Digest(), artifact.Size(), artifact.ContentKey())
	changed, err := aggregate.CompleteArtifact(artifact, proof)
	if err != nil || !changed || !aggregate.ArtifactCompleted(artifact) {
		t.Fatalf("complete=(%v,%v)", changed, err)
	}
	changed, err = aggregate.CompleteArtifact(artifact, proof)
	if err != nil || changed {
		t.Fatalf("replay complete=(%v,%v)", changed, err)
	}
	if _, err := NewFinalProof(artifact.Digest(), artifact.Size(), "wrong"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("wrong final error=%v", err)
	}
	_ = plan
}

func TestPF001AggregateInvalidatesRetainedChunkBeforeReplacement(t *testing.T) {
	t.Parallel()
	_, aggregate, artifact := reservedAggregate(t)
	chunk := artifact.Chunks()[0]
	_, _ = aggregate.MarkChunkVerified(artifact, chunk, chunk.Digest())
	changed, err := aggregate.InvalidateChunk(artifact, chunk)
	if err != nil || !changed || aggregate.ChunkVerified(artifact, chunk) {
		t.Fatalf("invalidate=(%v,%v)", changed, err)
	}
	changed, err = aggregate.InvalidateChunk(artifact, chunk)
	if err != nil || changed {
		t.Fatalf("replay invalidate=(%v,%v)", changed, err)
	}
	if _, err := aggregate.MarkChunkVerified(artifact, chunk, releaseinventory.DigestBytes([]byte("wrong"))); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("wrong digest error=%v", err)
	}
}

func TestPF001AggregateResetsOnlyExactOwnedInvalidPartialAndRetainsCapacity(t *testing.T) {
	t.Parallel()
	_, aggregate, artifact := reservedAggregate(t)
	authorization, _ := aggregate.AuthorizePartial(artifact)
	chunk := artifact.Chunks()[0]
	_, _ = aggregate.MarkChunkVerified(artifact, chunk, chunk.Digest())
	before := aggregate.Version()
	if err := aggregate.ResetInvalidPartial(authorization); err != nil || aggregate.Version() != before+1 {
		t.Fatalf("reset error=%v version=%d", err, aggregate.Version())
	}
	if _, err := aggregate.AuthorizePartial(artifact); err != nil || !aggregate.ReservationConsumed(artifact) || aggregate.ChunkVerified(artifact, chunk) {
		t.Fatalf("reset ownership/capacity error=%v", err)
	}
	if err := aggregate.ResetInvalidPartial(PartialAuthorization{}); !errors.Is(err, ErrUnauthorizedPartial) {
		t.Fatalf("unowned reset error=%v", err)
	}
}

func TestPF001AggregateSnapshotRoundTripAndTamperRejection(t *testing.T) {
	t.Parallel()
	plan, aggregate, artifact := reservedAggregate(t)
	chunk := artifact.Chunks()[0]
	_, _ = aggregate.MarkChunkVerified(artifact, chunk, chunk.Digest())
	snapshot := aggregate.Snapshot()
	restored, err := Restore(plan, snapshot)
	if err != nil || !reflect.DeepEqual(snapshot, restored.Snapshot()) {
		t.Fatalf("roundtrip err=%v\n got=%+v\nwant=%+v", err, restored.Snapshot(), snapshot)
	}
	mutations := []func(*Snapshot){
		func(value *Snapshot) { value.SchemaVersion++ },
		func(value *Snapshot) { value.PlanDigest = strings.Repeat("a", 64) },
		func(value *Snapshot) { value.ReservedBytes++ },
		func(value *Snapshot) { value.Version = 0 },
		func(value *Snapshot) { value.Progress[0].ArtifactID = "other" },
		func(value *Snapshot) { value.Progress[0].ArtifactDigest = strings.Repeat("b", 64) },
		func(value *Snapshot) { value.Progress[0].PartialID = "p-other" },
		func(value *Snapshot) { value.Progress[0].VerifiedChunks = []uint32{99} },
		func(value *Snapshot) { value.Progress[0].VerifiedChunks = []uint32{1} },
		func(value *Snapshot) { value.Progress = append(value.Progress, value.Progress[0]) },
	}
	for index, mutate := range mutations {
		candidate := cloneSnapshot(snapshot)
		mutate(&candidate)
		if _, err := Restore(plan, candidate); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("mutation %d error=%v", index, err)
		}
	}
}

func TestPF001ArtifactAggregateEvidenceIsCanonicalAndTransitionBound(t *testing.T) {
	t.Parallel()
	plan := testPlan(t)
	aggregate, err := NewAggregate("install-1", plan)
	if err != nil {
		t.Fatal(err)
	}
	pristine := aggregate.EvidenceDigest()
	if pristine.IsZero() || !pristine.Equal(aggregate.EvidenceDigest()) {
		t.Fatal("pristine aggregate evidence is absent or unstable")
	}
	id, _ := plan.ReservationID("install-1")
	proof, _ := NewReservationProof(id, plan.Totals().DownloadBytes(), "localfs-1")
	_, _ = aggregate.RequestReservation()
	_, _ = aggregate.RecordReservation(proof)
	reserved := aggregate.EvidenceDigest()
	if reserved.Equal(pristine) {
		t.Fatal("reservation transition did not change aggregate evidence")
	}
	restored, err := Restore(plan, aggregate.Snapshot())
	if err != nil || !restored.EvidenceDigest().Equal(reserved) {
		t.Fatalf("restored evidence mismatch: %v", err)
	}
}

func TestPF001ArtifactDomainValueAndFailureBoundaries(t *testing.T) {
	t.Parallel()
	plan := testPlan(t)
	if plan.Digest().IsZero() || len(plan.Artifacts()[0].Sources()) != 2 {
		t.Fatal("signed plan accessors lost data")
	}
	if _, err := plan.ReservationID("bad id"); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("invalid reservation operation error=%v", err)
	}
	if _, err := NewAggregate("bad id", plan); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("invalid aggregate operation error=%v", err)
	}
	if _, err := NewAggregate("install-1", Plan{}); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("empty aggregate plan error=%v", err)
	}

	id, _ := plan.ReservationID("install-1")
	proof, err := NewReservationProof(id, plan.Totals().DownloadBytes(), "localfs-1")
	if err != nil || proof.ID() != id || proof.Bytes() != plan.Totals().DownloadBytes() || proof.FilesystemID() != "localfs-1" {
		t.Fatalf("reservation proof=%+v err=%v", proof, err)
	}
	for _, input := range []struct {
		id string
		b  uint64
		fs string
	}{{"", 1, "fs"}, {id, 0, "fs"}, {id, maximumSafeBytes + 1, "fs"}, {id, 1, "bad fs"}} {
		if _, err := NewReservationProof(input.id, input.b, input.fs); !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("invalid proof accepted: %+v", input)
		}
	}

	artifact := plan.Artifacts()[0]
	final, _ := NewFinalProof(artifact.Digest(), artifact.Size(), artifact.ContentKey())
	if final.Digest() != artifact.Digest() || final.Size() != artifact.Size() || final.ContentKey() != artifact.ContentKey() {
		t.Fatal("final proof accessors lost data")
	}
	if contentKeyFor(releaseinventory.Digest{}) != "" {
		t.Fatal("zero digest produced a content key")
	}
	if value, err := checkedAdd(1, 2); err != nil || value != 3 {
		t.Fatalf("checked add=(%d,%v)", value, err)
	}
	if _, err := checkedAdd(maximumSafeBytes, 1); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("overflow error=%v", err)
	}

	aggregate, _ := NewAggregate("install-1", plan)
	_, _ = aggregate.RequestReservation()
	if aggregate.OperationID() != "install-1" {
		t.Fatal("operation identity lost")
	}
	_, _ = aggregate.RecordReservation(proof)
	if observed, exists := aggregate.Reservation(); !exists || observed != proof {
		t.Fatalf("Reservation()=(%+v,%t)", observed, exists)
	}
	changed, err := aggregate.BeginArtifact(artifact)
	if err != nil || !changed {
		t.Fatalf("first begin=(%t,%v)", changed, err)
	}
	changed, err = aggregate.BeginArtifact(artifact)
	if err != nil || changed {
		t.Fatalf("replayed begin=(%t,%v)", changed, err)
	}
	chunks := artifact.Chunks()
	if _, err := aggregate.MarkChunkVerified(artifact, chunks[1], chunks[1].Digest()); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("out-of-order chunk error=%v", err)
	}
	changed, _ = aggregate.MarkChunkVerified(artifact, chunks[0], chunks[0].Digest())
	if !changed {
		t.Fatal("first chunk was not recorded")
	}
	changed, err = aggregate.MarkChunkVerified(artifact, chunks[0], chunks[0].Digest())
	if err != nil || changed {
		t.Fatalf("replayed chunk=(%t,%v)", changed, err)
	}
}

func TestPF001ArtifactSourceGrammarFailsClosed(t *testing.T) {
	t.Parallel()
	valid := []string{"bundle://release/core.bin", "https://release.example/core.bin"}
	invalid := []string{
		"", "bundle://", "bundle://../core", "bundle:///absolute", "bundle://release//core",
		"http://release.example/core", "https://release.example", "https://release.example/",
		"https://UPPER.example/core", "https://bad..example/core", "https://release.example/core?latest",
	}
	for _, source := range valid {
		if !validSource(source) {
			t.Fatalf("valid source rejected: %q", source)
		}
	}
	for _, source := range invalid {
		if validSource(source) {
			t.Fatalf("invalid source accepted: %q", source)
		}
	}
	for _, path := range []string{"", ".", "../core", "release\\core", "release//core", "release/./core", "release/core:"} {
		if validPath(path) {
			t.Fatalf("invalid path accepted: %q", path)
		}
	}
	for _, identifier := range []string{"", " bad", "bad id", strings.Repeat("a", 129)} {
		if validIdentifier(identifier) {
			t.Fatalf("invalid identifier accepted: %q", identifier)
		}
	}
}

func testPlan(t *testing.T) Plan {
	t.Helper()
	plan, err := NewPlan(testPlanInput())
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func testPlanInput() PlanInput {
	digest := releaseinventory.DigestBytes([]byte("abcdef"))
	target, _ := releaseinventory.NewReleaseExpandedTarget(digest, 6, releaseinventory.ReleaseExpandedTargetInput{
		Kind: releaseinventory.ExpandedTargetComposeBundle, StorageID: "compose/compose.yaml", Digest: digest, Bytes: 6,
	})
	return PlanInput{
		PlanDigest: releaseinventory.DigestBytes([]byte("signed-plan")),
		Artifacts: []ArtifactInput{{
			ID: "core", Digest: digest, Size: 6, ExpandedBytes: 6, ExpandedDigest: digest,
			TargetKind: target.Kind(), TargetStorageID: target.StorageID(), TargetAuthorityDigest: target.AuthorityDigest(),
			Sources: []string{"bundle://release/core.bin", "https://releases.agentmemory.dev/artifacts/core.bin"},
			Chunks: []ChunkInput{
				{Offset: 0, Size: 3, Digest: releaseinventory.DigestBytes([]byte("abc"))},
				{Offset: 3, Size: 3, Digest: releaseinventory.DigestBytes([]byte("def"))},
			},
		}},
		Totals: TotalsInput{DownloadBytes: 6, ExpandedBytes: 6, RollbackHeadroomBytes: 20, SafetyHeadroomBytes: 30, RequiredBytes: 62},
	}
}

func clonePlanInput(input PlanInput) PlanInput {
	copyOfInput := input
	copyOfInput.Artifacts = append([]ArtifactInput(nil), input.Artifacts...)
	for index := range copyOfInput.Artifacts {
		copyOfInput.Artifacts[index].Sources = append([]string(nil), input.Artifacts[index].Sources...)
		copyOfInput.Artifacts[index].Chunks = append([]ChunkInput(nil), input.Artifacts[index].Chunks...)
	}
	return copyOfInput
}

func reservedAggregate(t *testing.T) (Plan, *Aggregate, Artifact) {
	t.Helper()
	plan := testPlan(t)
	aggregate, _ := NewAggregate("install-1", plan)
	id, _ := plan.ReservationID("install-1")
	proof, _ := NewReservationProof(id, plan.Totals().DownloadBytes(), "localfs-1")
	_, _ = aggregate.RequestReservation()
	_, _ = aggregate.RecordReservation(proof)
	artifact := plan.Artifacts()[0]
	_, _ = aggregate.BeginArtifact(artifact)
	authorization, _ := aggregate.AuthorizeConsumption(artifact)
	consumption, _ := NewConsumptionProof(
		authorization.ReservationID(), authorization.PartialID(), authorization.Bytes(), authorization.FilesystemID(),
	)
	_, _ = aggregate.RecordConsumption(authorization, consumption)
	return plan, aggregate, artifact
}

func cloneSnapshot(snapshot Snapshot) Snapshot {
	copyOfSnapshot := snapshot
	copyOfSnapshot.Progress = append([]ProgressSnapshot(nil), snapshot.Progress...)
	for index := range copyOfSnapshot.Progress {
		copyOfSnapshot.Progress[index].VerifiedChunks = append([]uint32(nil), snapshot.Progress[index].VerifiedChunks...)
	}
	return copyOfSnapshot
}
