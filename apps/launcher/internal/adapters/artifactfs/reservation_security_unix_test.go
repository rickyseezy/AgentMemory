//go:build darwin || linux

package artifactfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
)

func TestPF001ReservationSlotsConsumeCapacityWithoutTransientFreeSpace(t *testing.T) {
	t.Parallel()
	root := resolvedTempDir(t)
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	plan := fsPlan(t, []string{"bundle://release/core.bin"})
	aggregate, artifact, partial := fsReservationAggregate(t, store, "slot-consume", plan)
	request := fsReservationRequest(t, "slot-consume", plan)
	if _, err := store.Reserve(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	authorization, err := aggregate.AuthorizeConsumption(artifact)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate all remaining free space being consumed after reservation. The
	// slot-to-partial rename and in-place writes must still succeed.
	store.available = func(*os.File) (uint64, error) { return 0, nil }
	proof, err := store.Consume(context.Background(), authorization)
	if err != nil || proof.Bytes() != artifact.Size() {
		t.Fatalf("Consume()=(%+v,%v)", proof, err)
	}
	_, _ = aggregate.RecordConsumption(authorization, proof)
	if _, err := store.Consume(context.Background(), authorization); err != nil {
		t.Fatalf("crash replay Consume() error=%v", err)
	}
	if err := store.WriteChunk(context.Background(), partial, artifact.Chunks()[0], []byte("abc")); err != nil {
		t.Fatalf("reserved in-place WriteChunk() error=%v", err)
	}
	if err := store.ResetInvalidPartial(context.Background(), partial); err != nil {
		t.Fatalf("zero-space ResetInvalidPartial() error=%v", err)
	}
	for index, chunk := range artifact.Chunks() {
		value := [][]byte{[]byte("abc"), []byte("def")}[index]
		if err := store.WriteChunk(context.Background(), partial, chunk, value); err != nil {
			t.Fatalf("retry WriteChunk(%d) error=%v", index, err)
		}
		_, _ = aggregate.MarkChunkVerified(artifact, chunk, chunk.Digest())
	}
	if _, err := store.Finalize(context.Background(), partial, artifact); err != nil {
		t.Fatalf("zero-space retry Finalize() error=%v", err)
	}
}

func TestPF001ReservationReleaseIsIdempotentAfterCrashAndPreservesUnrelatedFiles(t *testing.T) {
	t.Parallel()
	root := resolvedTempDir(t)
	store, _ := NewStore(root)
	plan := fsPlan(t, []string{"bundle://release/core.bin"})
	aggregate, artifact, _ := fsReservationAggregate(t, store, "release-crash", plan)
	request := fsReservationRequest(t, "release-crash", plan)
	_, _ = store.Reserve(context.Background(), request)
	consume, _ := aggregate.AuthorizeConsumption(artifact)
	_, _ = store.Consume(context.Background(), consume)
	for _, chunk := range artifact.Chunks() {
		_, _ = aggregate.MarkChunkVerified(artifact, chunk, chunk.Digest())
	}
	// Cancellation/rollback may occur before completion and is authorized in
	// the durable aggregate before filesystem deletion.
	_, _ = aggregate.RequestReservationRelease(artifactacquisition.ReleaseReasonCancelled)
	release, _ := aggregate.AuthorizeRelease()
	unrelated := filepath.Join(root, ".reservations", "keep")
	if err := os.WriteFile(unrelated, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Release(context.Background(), release); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash before RecordReleased; replay must be harmless.
	if err := store.Release(context.Background(), release); err != nil {
		t.Fatalf("replayed Release() error=%v", err)
	}
	if value, err := os.ReadFile(unrelated); err != nil || string(value) != "keep" { // #nosec G304 -- test-owned path.
		t.Fatalf("unrelated value=%q err=%v", value, err)
	}
}

func TestPF001ArtifactFSRejectsPrecreatedAndSwappedHardLinks(t *testing.T) {
	t.Parallel()
	root := resolvedTempDir(t)
	store, _ := NewStore(root)
	plan := fsPlan(t, []string{"bundle://release/core.bin"})
	aggregate, artifact, authorization := fsReservationAggregate(t, store, "hard-link", plan)
	if _, err := store.Reserve(context.Background(), fsReservationRequest(t, "hard-link", plan)); err != nil {
		t.Fatal(err)
	}
	consumption, _ := aggregate.AuthorizeConsumption(artifact)
	partialPath := filepath.Join(root, ".partials", authorization.PartialID()+".part")
	unrelated := filepath.Join(root, "unrelated")
	if err := os.WriteFile(unrelated, []byte("abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(unrelated, partialPath); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Consume(context.Background(), consumption); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("precreated hard-link consume error=%v", err)
	}
	if err := store.WriteChunk(context.Background(), authorization, artifact.Chunks()[0], []byte("abc")); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("precreated hard-link write error=%v", err)
	}
	if value, _ := os.ReadFile(unrelated); string(value) != "abcdef" { // #nosec G304 -- test-owned path.
		t.Fatalf("unrelated hard-link target mutated: %q", value)
	}
	if err := os.Remove(partialPath); err != nil {
		t.Fatal(err)
	}
	proof, err := store.Consume(context.Background(), consumption)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = aggregate.RecordConsumption(consumption, proof)
	if err := store.WriteChunk(context.Background(), authorization, artifact.Chunks()[0], []byte("abc")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(partialPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(unrelated, partialPath); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteChunk(context.Background(), authorization, artifact.Chunks()[1], []byte("def")); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("swapped hard-link write error=%v", err)
	}

	finalDirectory, _, err := store.finalLocation(artifact.ContentKey(), true)
	if err != nil {
		t.Fatal(err)
	}
	_ = finalDirectory.Close()
	finalPath := filepath.Join(root, filepath.FromSlash(artifact.ContentKey()))
	if err := os.Link(unrelated, finalPath); err != nil {
		t.Fatal(err)
	}
	if _, err := store.InspectFinal(context.Background(), artifact); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("precreated CAS hard link error=%v", err)
	}
}

func TestPF001ArtifactConstructorsRejectIntermediateSymlinksAndStoreDescriptorsSurviveRootSwap(t *testing.T) {
	t.Parallel()
	base := resolvedTempDir(t)
	realParent := filepath.Join(base, "real")
	storeRoot := filepath.Join(realParent, "store")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(storeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	intermediate := filepath.Join(base, "intermediate")
	if err := os.Symlink(realParent, intermediate); err == nil {
		throughLink := filepath.Join(intermediate, "store")
		if _, err := NewStore(throughLink); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
			t.Fatalf("intermediate store symlink error=%v", err)
		}
		if _, err := NewBundleFetcher(throughLink); !errors.Is(err, artifactapp.ErrFetchIntegrity) {
			t.Fatalf("intermediate bundle symlink error=%v", err)
		}
	}

	store, err := NewStore(storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	plan := fsPlan(t, []string{"bundle://release/core.bin"})
	aggregate, artifact, partial := fsReservationAggregate(t, store, "root-swap", plan)
	if _, err := store.Reserve(context.Background(), fsReservationRequest(t, "root-swap", plan)); err != nil {
		t.Fatal(err)
	}
	consume, _ := aggregate.AuthorizeConsumption(artifact)
	if _, err := store.Consume(context.Background(), consume); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(realParent, "store-moved")
	if err := os.Rename(storeRoot, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(storeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	for index, chunk := range artifact.Chunks() {
		value := [][]byte{[]byte("abc"), []byte("def")}[index]
		if err := store.WriteChunk(context.Background(), partial, chunk, value); err != nil {
			t.Fatalf("descriptor-root WriteChunk(%d) error=%v", index, err)
		}
		if digest, err := store.VerifyChunk(context.Background(), partial, chunk); err != nil || !digest.Equal(chunk.Digest()) {
			t.Fatalf("descriptor-root VerifyChunk(%d)=(%s,%v)", index, digest.Hex(), err)
		}
	}
	if _, err := store.Finalize(context.Background(), partial, artifact); err != nil {
		t.Fatalf("descriptor-root Finalize() error=%v", err)
	}
	if _, err := store.InspectFinal(context.Background(), artifact); err != nil {
		t.Fatalf("descriptor-root InspectFinal() error=%v", err)
	}
	if entries, err := os.ReadDir(storeRoot); err != nil || len(entries) != 0 {
		t.Fatalf("replacement root was touched: entries=%v err=%v", entries, err)
	}
	if _, err := os.Lstat(filepath.Join(moved, filepath.FromSlash(artifact.ContentKey()))); err != nil {
		t.Fatalf("descriptor-root CAS not published under original root: %v", err)
	}

	// A reservation begun after the pathname swap is also confined to the
	// retained original directory object.
	second := fsReservationRequest(t, "root-swap-after", plan)
	secondProof, err := store.Reserve(context.Background(), second)
	if err != nil {
		t.Fatalf("descriptor-root Reserve() error=%v", err)
	}
	if _, err := os.Lstat(filepath.Join(moved, ".reservations", second.Allocations[0].SlotID()+".slot")); err != nil {
		t.Fatalf("descriptor-root reservation not in original root: %v", err)
	}
	if entries, err := os.ReadDir(storeRoot); err != nil || len(entries) != 0 {
		t.Fatalf("replacement root touched after reserve: entries=%v err=%v", entries, err)
	}

	restarted, err := NewStore(storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.filesystemID == store.filesystemID {
		t.Fatalf("replacement root reused durable identity %q", restarted.filesystemID)
	}
	restored, _ := artifactacquisition.NewAggregate("root-swap-after", plan)
	_, _ = restored.RequestReservation()
	_, _ = restored.RecordReservation(secondProof)
	restartArtifact := plan.Artifacts()[0]
	_, _ = restored.BeginArtifact(restartArtifact)
	restartAuthorization, _ := restored.AuthorizeConsumption(restartArtifact)
	if _, err := restarted.Consume(context.Background(), restartAuthorization); !errors.Is(err, artifactapp.ErrReservationOperation) {
		t.Fatalf("replacement-root restart consume error=%v", err)
	}
	if err := restarted.Close(); err != nil || restarted.Close() != nil {
		t.Fatalf("idempotent restarted Close() error=%v", err)
	}
	if _, err := restarted.Reserve(context.Background(), second); !errors.Is(err, artifactapp.ErrReservationOperation) {
		t.Fatalf("closed store reserve error=%v", err)
	}
}

func TestPF001StoreIdentitySurvivesMountIDChangeAndRejectsMarkerReplacement(t *testing.T) {
	t.Parallel()
	root := resolvedTempDir(t)
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	first, err := boundFilesystemIdentity("transient-mount-a", store.rootDirectory, store.identityValue)
	second, secondError := boundFilesystemIdentity("transient-mount-b", store.rootDirectory, store.identityValue)
	if err != nil || secondError != nil || first != second || first != store.filesystemID {
		t.Fatalf("stable identity first/second/store/errors=%q/%q/%q/%v/%v", first, second, store.filesystemID, err, secondError)
	}
	original := store.filesystemID
	if err := os.Remove(filepath.Join(root, storeIdentityLeaf)); err != nil {
		t.Fatal(err)
	}
	if store.valid() {
		t.Fatal("store remained valid after persistent identity removal")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restarted.Close() }()
	if restarted.filesystemID == original {
		t.Fatalf("replacement marker reused identity %q", original)
	}
}

func TestPF001StoreIdentityPublicationIsConcurrentAndNeverPartiallyVisible(t *testing.T) {
	root := resolvedTempDir(t)
	const workers = 32
	start := make(chan struct{})
	results := make(chan *Store, workers)
	errorsSeen := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			store, err := NewStore(root)
			if err != nil {
				errorsSeen <- err
				return
			}
			results <- store
		}()
	}
	close(start)
	group.Wait()
	close(results)
	close(errorsSeen)
	for err := range errorsSeen {
		t.Fatalf("concurrent NewStore() error=%v", err)
	}
	var identity string
	count := 0
	for store := range results {
		count++
		if identity == "" {
			identity = store.filesystemID
		}
		if store.filesystemID != identity || !store.valid() {
			t.Fatalf("concurrent identity=%q want=%q valid=%t", store.filesystemID, identity, store.valid())
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if count != workers {
		t.Fatalf("opened stores=%d want=%d", count, workers)
	}
	info, err := os.Lstat(filepath.Join(root, storeIdentityLeaf))
	if err != nil || info.Size() != 32 || info.Mode().Perm() != 0o600 {
		t.Fatalf("published identity info=%+v error=%v", info, err)
	}
}

func TestPF001ReservationRevalidationProvesEveryCrashLayoutAndNeverRepairs(t *testing.T) {
	t.Parallel()
	root := resolvedTempDir(t)
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	enableReservationMechanicsForTest(t, store)
	defer func() { _ = store.Close() }()
	operationID := "physical-revalidation"
	plan := fsPlan(t, []string{"bundle://release/core.bin"})
	request := fsReservationRequest(t, operationID, plan)
	proof, err := store.Reserve(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	aggregate, _ := artifactacquisition.NewAggregate(operationID, plan)
	_, _ = aggregate.RequestReservation()
	_, _ = aggregate.RecordReservation(proof)

	revalidate := func(wantError bool) {
		t.Helper()
		authorization, authorizationError := aggregate.AuthorizeReservationRevalidation()
		if authorizationError != nil {
			t.Fatal(authorizationError)
		}
		observed, observedError := store.Revalidate(context.Background(), authorization)
		if wantError {
			if observedError == nil {
				t.Fatalf("Revalidate() unexpectedly succeeded with proof=%+v", observed)
			}
			return
		}
		if observedError != nil || observed != proof {
			t.Fatalf("Revalidate()=(%+v,%v) want=%+v", observed, observedError, proof)
		}
	}
	revalidate(false)
	slot := filepath.Join(root, ".reservations", request.Allocations[0].SlotID()+".slot")
	if err := os.Remove(slot); err != nil {
		t.Fatal(err)
	}
	revalidate(true)
	if _, err := store.Reserve(context.Background(), request); err != nil {
		t.Fatal(err)
	}

	artifact := plan.Artifacts()[0]
	_, _ = aggregate.BeginArtifact(artifact)
	revalidate(false)
	consume, _ := aggregate.AuthorizeConsumption(artifact)
	consumption, err := store.Consume(context.Background(), consume)
	if err != nil {
		t.Fatal(err)
	}
	// Crash after the no-replace move but before the aggregate records it.
	revalidate(false)
	_, _ = aggregate.RecordConsumption(consume, consumption)
	revalidate(false)
	partial, _ := aggregate.AuthorizePartial(artifact)
	for index, chunk := range artifact.Chunks() {
		value := [][]byte{[]byte("abc"), []byte("def")}[index]
		if err := store.WriteChunk(context.Background(), partial, chunk, value); err != nil {
			t.Fatal(err)
		}
		_, _ = aggregate.MarkChunkVerified(artifact, chunk, chunk.Digest())
	}
	final, err := store.Finalize(context.Background(), partial, artifact)
	if err != nil {
		t.Fatal(err)
	}
	// Crash after final publication but before aggregate completion.
	revalidate(false)
	_, _ = aggregate.CompleteArtifact(artifact, final)
	revalidate(false)
	if err := os.Remove(filepath.Join(root, filepath.FromSlash(artifact.ContentKey()))); err != nil {
		t.Fatal(err)
	}
	revalidate(true)
}

func TestPF001FinalizeReopensAndRejectsPublishedCASReplacement(t *testing.T) {
	t.Parallel()
	for _, attack := range []string{"replacement", "hard-link", "prefix-swap"} {
		t.Run(attack, func(t *testing.T) {
			root := resolvedTempDir(t)
			store, err := NewStore(root)
			if err != nil {
				t.Fatal(err)
			}
			aggregate, artifact, authorization := fsConsumedArtifact(t, store, "post-publish-"+attack)
			for index, chunk := range artifact.Chunks() {
				value := [][]byte{[]byte("abc"), []byte("def")}[index]
				if err := store.WriteChunk(context.Background(), authorization, chunk, value); err != nil {
					t.Fatal(err)
				}
				_, _ = aggregate.MarkChunkVerified(artifact, chunk, chunk.Digest())
			}
			finalPath := filepath.Join(root, filepath.FromSlash(artifact.ContentKey()))
			var hookError error
			store.afterPublish = func() {
				if attack == "prefix-swap" {
					prefix := filepath.Dir(finalPath)
					hookError = os.Rename(prefix, prefix+".displaced")
					if hookError == nil {
						hookError = os.Mkdir(prefix, 0o700)
					}
					return
				}
				displaced := finalPath + ".displaced"
				if hookError = os.Rename(finalPath, displaced); hookError != nil {
					return
				}
				if attack == "hard-link" {
					hookError = os.Link(displaced, finalPath)
					return
				}
				hookError = os.WriteFile(finalPath, []byte("abcdeg"), 0o600)
			}
			proof, err := store.Finalize(context.Background(), authorization, artifact)
			if hookError != nil {
				t.Fatal(hookError)
			}
			if !proof.Digest().IsZero() || !errors.Is(err, artifactapp.ErrStoreIntegrity) {
				t.Fatalf("post-publication %s proof=%+v error=%v", attack, proof, err)
			}
		})
	}
}

func TestPF001BundleFetcherDescriptorsSurviveRootSwapAndCloseIdempotently(t *testing.T) {
	t.Parallel()
	base := resolvedTempDir(t)
	root := filepath.Join(base, "bundle")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "release"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "release", "core.bin"), []byte("abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	fetcher, err := NewBundleFetcher(root)
	if err != nil {
		t.Fatal(err)
	}
	artifact := fsPlan(t, []string{"bundle://release/core.bin"}).Artifacts()[0]
	moved := filepath.Join(base, "bundle-moved")
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "release"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "release", "core.bin"), []byte("abcdeg"), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := fetcher.Fetch(context.Background(), artifact, artifact.Sources()[0], artifact.Chunks()[1])
	if err != nil || string(value) != "def" {
		t.Fatalf("descriptor-root bundle value=%q error=%v", value, err)
	}
	if err := fetcher.Close(); err != nil || fetcher.Close() != nil {
		t.Fatalf("idempotent bundle Close() error=%v", err)
	}
	if _, err := fetcher.Fetch(context.Background(), artifact, artifact.Sources()[0], artifact.Chunks()[0]); !errors.Is(err, artifactapp.ErrFetchIntegrity) {
		t.Fatalf("closed bundle fetch error=%v", err)
	}
}

func TestPF001ReservationReplaysNativeAllocatedSlotAfterInterruptedJournalCommit(t *testing.T) {
	t.Parallel()
	root := resolvedTempDir(t)
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if !store.reservationSafe {
		t.Skip("host filesystem cannot prove durable native allocation")
	}
	plan := fsPlan(t, []string{"bundle://release/core.bin"})
	request := fsReservationRequest(t, "false-allocation-proof", plan)
	allocation := request.Allocations[0]
	path := filepath.Join(root, ".reservations", allocation.SlotID()+".slot")
	if err := os.WriteFile(path, make([]byte, allocation.Bytes()), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	allocated, blocksVisible := allocatedFileBytes(info)
	if err != nil || !blocksVisible || allocated < allocation.Bytes() {
		t.Fatalf("fixture is not allocated-looking: info=%+v allocated=%d error=%v", info, allocated, err)
	}
	proof, err := store.Reserve(context.Background(), request)
	if err != nil || proof.ID() != request.ReservationID || proof.Bytes() != request.RequiredBytes {
		t.Fatalf("interrupted allocation replay proof=%+v error=%v", proof, err)
	}
}

func TestPF001InterruptedReservationAllocationReplaysOrCancelsFromJournalIntent(t *testing.T) {
	t.Parallel()
	root := resolvedTempDir(t)
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	enableReservationMechanicsForTest(t, store)
	plan := fsPlan(t, []string{"bundle://release/core.bin"})
	request := fsReservationRequest(t, "power-loss", plan)
	slotPath := filepath.Join(root, ".reservations", request.Allocations[0].SlotID()+".slot")
	if err := os.WriteFile(slotPath, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	const shortReservationBytes = uint64(5)
	missing := request.DownloadBytes - shortReservationBytes
	store.available = func(*os.File) (uint64, error) { return missing, nil }
	if _, err := store.Reserve(context.Background(), request); err != nil {
		t.Fatalf("power-loss replay Reserve() error=%v", err)
	}
	info, statError := os.Lstat(slotPath)
	slotSize, sizeValid := nonNegativeInt64(infoSize(info, statError))
	if statError != nil || !sizeValid || slotSize != request.DownloadBytes {
		t.Fatalf("replayed slot info=%+v err=%v", info, statError)
	}

	cancelRoot := resolvedTempDir(t)
	cancelStore, _ := NewStore(cancelRoot)
	cancelRequest := fsReservationRequest(t, "power-cancel", plan)
	cancelSlot := filepath.Join(cancelRoot, ".reservations", cancelRequest.Allocations[0].SlotID()+".slot")
	if err := os.WriteFile(cancelSlot, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(cancelRoot, ".reservations", "unrelated")
	if err := os.WriteFile(unrelated, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	aggregate, _ := artifactacquisition.NewAggregate("power-cancel", plan)
	_, _ = aggregate.RequestReservation()
	_, _ = aggregate.RequestReservationRelease(artifactacquisition.ReleaseReasonCancelled)
	release, err := aggregate.AuthorizeRelease()
	if err != nil || release.Committed() {
		t.Fatalf("allocating release=(%+v,%v)", release, err)
	}
	if err := cancelStore.Release(context.Background(), release); err != nil {
		t.Fatalf("allocating cancel Release() error=%v", err)
	}
	for _, path := range []string{cancelSlot} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("owned interrupted allocation remains: %s: %v", path, err)
		}
	}
	if value, err := os.ReadFile(unrelated); err != nil || string(value) != "keep" { // #nosec G304 -- test-owned path.
		t.Fatalf("unrelated value=%q err=%v", value, err)
	}
}

func fsReservationRequest(t *testing.T, operationID string, plan artifactacquisition.Plan) artifactapp.ReservationRequest {
	t.Helper()
	aggregate, err := artifactacquisition.NewAggregate(operationID, plan)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := plan.ReservationID(operationID)
	_, _ = aggregate.RequestReservation()
	authorization, err := aggregate.AuthorizeReservation()
	if err != nil {
		t.Fatal(err)
	}
	totals := plan.Totals()
	return artifactapp.ReservationRequest{
		Authorization: authorization,
		ReservationID: id, PlanDigest: plan.Digest(), RequiredBytes: totals.DownloadBytes(),
		DownloadBytes: totals.DownloadBytes(),
		Allocations:   aggregate.ReservationAllocations(),
	}
}

func fsReservationAggregate(
	t *testing.T,
	store *Store,
	operationID string,
	plan artifactacquisition.Plan,
) (*artifactacquisition.Aggregate, artifactacquisition.Artifact, artifactacquisition.PartialAuthorization) {
	t.Helper()
	enableReservationMechanicsForTest(t, store)
	aggregate, _ := artifactacquisition.NewAggregate(operationID, plan)
	id, _ := plan.ReservationID(operationID)
	proof, _ := artifactacquisition.NewReservationProof(id, plan.Totals().DownloadBytes(), store.filesystemID)
	_, _ = aggregate.RequestReservation()
	_, _ = aggregate.RecordReservation(proof)
	artifact := plan.Artifacts()[0]
	_, _ = aggregate.BeginArtifact(artifact)
	partial, err := aggregate.AuthorizePartial(artifact)
	if err != nil {
		t.Fatal(err)
	}
	return aggregate, artifact, partial
}

func enableReservationMechanicsForTest(t *testing.T, store *Store) {
	t.Helper()
	if store == nil {
		t.Fatal("test store is nil")
	}
	// Exercise reservation mechanics independently of host pool attestation.
	// Production has no caller-controlled bypass for APFS/Btrfs rejection.
	store.reservationSafe = true
}
