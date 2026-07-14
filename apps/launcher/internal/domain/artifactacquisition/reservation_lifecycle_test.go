package artifactacquisition

import (
	"errors"
	"testing"
)

func TestPF001RecordedReservationRevalidationTracksEveryCrashRecoverableLayout(t *testing.T) {
	t.Parallel()
	plan := testPlan(t)
	aggregate, _ := NewAggregate("reservation-revalidation", plan)
	reservationID, _ := plan.ReservationID("reservation-revalidation")
	proof, _ := NewReservationProof(reservationID, plan.Totals().DownloadBytes(), "localfs-1")
	_, _ = aggregate.RequestReservation()
	_, _ = aggregate.RecordReservation(proof)
	artifact := plan.Artifacts()[0]
	authorization, err := aggregate.AuthorizeReservationRevalidation()
	if err != nil || !authorization.Valid() || !aggregate.ReservationActive() ||
		authorization.Reservation() != proof ||
		len(authorization.Expectations()) != 1 || authorization.Expectations()[0].Stage() != ReservationStageSlot {
		t.Fatalf("AuthorizeReservationRevalidation()=(%+v,%v)", authorization, err)
	}
	_, _ = aggregate.BeginArtifact(artifact)
	authorization, err = aggregate.AuthorizeReservationRevalidation()
	if err != nil || authorization.Expectations()[0].Stage() != ReservationStageTransferPending {
		t.Fatalf("transfer-pending revalidation=(%+v,%v)", authorization, err)
	}
	consume, _ := aggregate.AuthorizeConsumption(artifact)
	consumed, _ := NewConsumptionProof(consume.ReservationID(), consume.PartialID(), consume.Bytes(), consume.FilesystemID())
	_, _ = aggregate.RecordConsumption(consume, consumed)
	authorization, err = aggregate.AuthorizeReservationRevalidation()
	if err != nil || authorization.Expectations()[0].Stage() != ReservationStageFinalizePending {
		t.Fatalf("finalize-pending revalidation=(%+v,%v)", authorization, err)
	}
	for _, chunk := range artifact.Chunks() {
		_, _ = aggregate.MarkChunkVerified(artifact, chunk, chunk.Digest())
	}
	final, _ := NewFinalProof(artifact.Digest(), artifact.Size(), artifact.ContentKey())
	_, _ = aggregate.CompleteArtifact(artifact, final)
	authorization, err = aggregate.AuthorizeReservationRevalidation()
	if err != nil || authorization.Expectations()[0].Stage() != ReservationStageFinal {
		t.Fatalf("final revalidation=(%+v,%v)", authorization, err)
	}
	copyOfExpectations := authorization.Expectations()
	copyOfExpectations[0] = ReservationExpectation{}
	if !authorization.Expectations()[0].Valid() || (ReservationRevalidationAuthorization{}).Valid() ||
		(ReservationExpectation{}).Valid() {
		t.Fatal("revalidation authorization exposed mutable or zero-valid expectations")
	}
	_, _ = aggregate.RequestReservationRelease(ReleaseReasonCancelled)
	if aggregate.ReservationActive() {
		t.Fatal("pending release reported active reservation")
	}
	if _, err := aggregate.AuthorizeReservationRevalidation(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("revalidation during release error=%v", err)
	}
}

func TestPF001ReservationConsumptionAndReleaseAreJournalAuthorizedAndReplaySafe(t *testing.T) {
	t.Parallel()
	plan := testPlan(t)
	aggregate, err := NewAggregate("install-1", plan)
	if err != nil {
		t.Fatal(err)
	}
	allocations := aggregate.ReservationAllocations()
	if len(allocations) != 1 || allocations[0].Bytes() != plan.Artifacts()[0].Size() ||
		allocations[0].PartialID() == "" || allocations[0].SlotID() == "" {
		t.Fatalf("allocations=%+v", allocations)
	}

	reservationID, _ := plan.ReservationID("install-1")
	reservation, _ := NewReservationProof(reservationID, plan.Totals().DownloadBytes(), "localfs-1")
	_, _ = aggregate.RequestReservation()
	_, _ = aggregate.RecordReservation(reservation)
	artifact := plan.Artifacts()[0]
	_, _ = aggregate.BeginArtifact(artifact)
	authorization, err := aggregate.AuthorizeConsumption(artifact)
	if err != nil || authorization.ReservationID() != reservationID || authorization.PartialID() != allocations[0].PartialID() {
		t.Fatalf("AuthorizeConsumption()=(%+v,%v)", authorization, err)
	}
	proof, err := NewConsumptionProof(
		authorization.ReservationID(), authorization.PartialID(), authorization.Bytes(), authorization.FilesystemID(),
	)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := aggregate.RecordConsumption(authorization, proof)
	if err != nil || !changed || !aggregate.ReservationConsumed(artifact) {
		t.Fatalf("RecordConsumption()=(%t,%v)", changed, err)
	}
	changed, err = aggregate.RecordConsumption(authorization, proof)
	if err != nil || changed {
		t.Fatalf("replayed RecordConsumption()=(%t,%v)", changed, err)
	}

	for _, chunk := range artifact.Chunks() {
		_, _ = aggregate.MarkChunkVerified(artifact, chunk, chunk.Digest())
	}
	final, _ := NewFinalProof(artifact.Digest(), artifact.Size(), artifact.ContentKey())
	_, _ = aggregate.CompleteArtifact(artifact, final)
	changed, err = aggregate.RequestReservationRelease(ReleaseReasonCompleted)
	if err != nil || !changed || !aggregate.ReservationReleasePending() {
		t.Fatalf("RequestReservationRelease()=(%t,%v)", changed, err)
	}
	release, err := aggregate.AuthorizeRelease()
	if err != nil || release.Reason() != ReleaseReasonCompleted || len(release.Allocations()) != 1 {
		t.Fatalf("AuthorizeRelease()=(%+v,%v)", release, err)
	}
	changed, err = aggregate.RecordReleased(release)
	if err != nil || !changed || !aggregate.ReservationReleased() {
		t.Fatalf("RecordReleased()=(%t,%v)", changed, err)
	}
	changed, err = aggregate.RecordReleased(release)
	if err != nil || changed {
		t.Fatalf("replayed RecordReleased()=(%t,%v)", changed, err)
	}

	restored, err := Restore(plan, aggregate.Snapshot())
	if err != nil || !restored.ReservationReleased() || restored.ReservationReleaseReason() != ReleaseReasonCompleted {
		t.Fatalf("Restore()=(%+v,%v)", restored, err)
	}
}

func TestPF001ReservationReleaseRejectsUnauthenticatedOrPrematureTransitions(t *testing.T) {
	t.Parallel()
	plan, aggregate, artifact := reservedAggregate(t)
	if _, err := aggregate.RequestReservationRelease(ReleaseReasonCompleted); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("premature complete release error=%v", err)
	}
	if _, err := aggregate.RequestReservationRelease(ReleaseReason("unknown")); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("unknown release reason error=%v", err)
	}
	if _, err := aggregate.RequestReservationRelease(ReleaseReasonCancelled); err != nil {
		t.Fatalf("cancel release error=%v", err)
	}
	if _, err := aggregate.AuthorizeConsumption(artifact); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("consumption after release intent error=%v", err)
	}
	if _, err := Restore(plan, func() Snapshot {
		snapshot := aggregate.Snapshot()
		snapshot.ReleaseReason = string(ReleaseReasonCompleted)
		return snapshot
	}()); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("contradictory release restore error=%v", err)
	}
}

func TestPF001ReservationLifecycleValueObjectsAndInvalidTransitionsFailClosed(t *testing.T) {
	t.Parallel()
	plan := testPlan(t)
	aggregate, _ := NewAggregate("install-values", plan)
	changed, err := aggregate.RequestReservation()
	if err != nil || !changed || !aggregate.ReservationRequested() || aggregate.Reserved() {
		t.Fatalf("RequestReservation()=(%t,%v)", changed, err)
	}
	changed, err = aggregate.RequestReservation()
	if err != nil || changed {
		t.Fatalf("replayed RequestReservation()=(%t,%v)", changed, err)
	}
	authorization, err := aggregate.AuthorizeReservation()
	allocations := authorization.Allocations()
	if err != nil || !authorization.Valid() || authorization.ReservationID() == "" ||
		!authorization.PlanDigest().Equal(plan.Digest()) || authorization.RequiredBytes() != plan.Totals().DownloadBytes() ||
		len(allocations) != 1 || allocations[0].ReservationID() != authorization.ReservationID() ||
		allocations[0].ArtifactID() != plan.Artifacts()[0].ID() || !allocations[0].Valid() {
		t.Fatalf("authorization=%+v allocations=%+v err=%v", authorization, allocations, err)
	}
	allocations[0] = ReservationAllocation{}
	if !authorization.Allocations()[0].Valid() {
		t.Fatal("reservation authorization exposed mutable allocations")
	}
	if (ReservationAuthorization{}).Valid() || (ReservationAllocation{}).Valid() {
		t.Fatal("zero reservation authority accepted")
	}

	proof, _ := NewReservationProof(authorization.ReservationID(), authorization.RequiredBytes(), "localfs-values")
	_, _ = aggregate.RecordReservation(proof)
	if _, err := aggregate.AuthorizeReservation(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("committed reservation reauthorization error=%v", err)
	}
	artifact := plan.Artifacts()[0]
	_, _ = aggregate.BeginArtifact(artifact)
	consume, _ := aggregate.AuthorizeConsumption(artifact)
	consumedProof, _ := NewConsumptionProof(
		consume.ReservationID(), consume.PartialID(), consume.Bytes(), consume.FilesystemID(),
	)
	if consumedProof.ReservationID() != consume.ReservationID() || consumedProof.PartialID() != consume.PartialID() ||
		consumedProof.Bytes() != consume.Bytes() || consumedProof.FilesystemID() != consume.FilesystemID() {
		t.Fatal("consumption proof accessors lost fields")
	}
	if _, err := NewConsumptionProof("", "", 0, ""); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("invalid consumption proof error=%v", err)
	}
	_, _ = aggregate.RecordConsumption(consume, consumedProof)
	if _, err := aggregate.RequestReservationRelease(ReleaseReasonRollback); err != nil {
		t.Fatal(err)
	}
	release, err := aggregate.AuthorizeRelease()
	if err != nil || !release.Valid() || !release.Committed() || release.Reservation() != proof {
		t.Fatalf("release=%+v err=%v", release, err)
	}
	copyOfAllocations := release.Allocations()
	copyOfAllocations[0] = ReservationAllocation{}
	if !release.Allocations()[0].Valid() || (ReleaseAuthorization{}).Valid() {
		t.Fatal("release authorization validity/copy changed")
	}
	if _, err := aggregate.RecordReleased(ReleaseAuthorization{}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("unrelated release proof error=%v", err)
	}
}

func TestPF001AllocatingReservationSnapshotRoundTripsAndCanBeCancelled(t *testing.T) {
	t.Parallel()
	plan := testPlan(t)
	aggregate, _ := NewAggregate("install-allocating", plan)
	_, _ = aggregate.RequestReservation()
	restored, err := Restore(plan, aggregate.Snapshot())
	if err != nil || !restored.ReservationRequested() || restored.Reserved() {
		t.Fatalf("allocating Restore()=(%+v,%v)", restored, err)
	}
	_, _ = restored.RequestReservationRelease(ReleaseReasonCancelled)
	release, err := restored.AuthorizeRelease()
	if err != nil || release.Committed() || release.Reason() != ReleaseReasonCancelled {
		t.Fatalf("allocating release=(%+v,%v)", release, err)
	}
	_, _ = restored.RecordReleased(release)
	if _, err := Restore(plan, restored.Snapshot()); err != nil {
		t.Fatalf("released allocating Restore() error=%v", err)
	}
}
