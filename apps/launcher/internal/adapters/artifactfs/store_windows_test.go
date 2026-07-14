//go:build windows

package artifactfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"golang.org/x/sys/windows"
)

func TestPF001WindowsArtifactStoreReservesResumesAndPublishesExactCAS(t *testing.T) {
	t.Parallel()
	root := resolvedTempDir(t)
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if !store.reservationSafe || !store.valid() {
		t.Fatal("Windows store did not retain its NTFS/ReFS reservation authority")
	}
	plan := fsPlan(t, []string{"bundle://release/core.bin"})
	request := fsReservationRequest(t, "windows-complete", plan)
	reserved, err := store.Reserve(context.Background(), request)
	if err != nil || reserved.ID() != request.ReservationID || reserved.Bytes() != plan.Totals().DownloadBytes() ||
		reserved.FilesystemID() != store.filesystemID {
		t.Fatalf("Reserve()=%+v,%v", reserved, err)
	}
	if replay, replayError := store.Reserve(context.Background(), request); replayError != nil || replay != reserved {
		t.Fatalf("Reserve replay=%+v,%v", replay, replayError)
	}
	aggregate, artifact, partial := fsReservationAggregate(t, store, "windows-complete", plan)
	revalidation, err := aggregate.AuthorizeReservationRevalidation()
	if err != nil {
		t.Fatal(err)
	}
	if proof, proofError := store.Revalidate(context.Background(), revalidation); proofError != nil || proof != reserved {
		t.Fatalf("Revalidate(slot)=%+v,%v", proof, proofError)
	}
	consume, err := aggregate.AuthorizeConsumption(artifact)
	if err != nil {
		t.Fatal(err)
	}
	consumed, err := store.Consume(context.Background(), consume)
	if err != nil || consumed.Bytes() != artifact.Size() || consumed.FilesystemID() != store.filesystemID {
		t.Fatalf("Consume()=%+v,%v", consumed, err)
	}
	if replay, replayError := store.Consume(context.Background(), consume); replayError != nil || replay != consumed {
		t.Fatalf("Consume replay=%+v,%v", replay, replayError)
	}
	if _, err := aggregate.RecordConsumption(consume, consumed); err != nil {
		t.Fatal(err)
	}
	for index, chunk := range artifact.Chunks() {
		value := [][]byte{[]byte("abc"), []byte("def")}[index]
		if err := store.WriteChunk(context.Background(), partial, chunk, value); err != nil {
			t.Fatalf("WriteChunk(%d)=%v", index, err)
		}
		observed, err := store.VerifyChunk(context.Background(), partial, chunk)
		if err != nil || !observed.Equal(chunk.Digest()) {
			t.Fatalf("VerifyChunk(%d)=%s,%v", index, observed.Hex(), err)
		}
		if _, err := aggregate.MarkChunkVerified(artifact, chunk, observed); err != nil {
			t.Fatal(err)
		}
	}
	revalidation, err = aggregate.AuthorizeReservationRevalidation()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Revalidate(context.Background(), revalidation); err != nil {
		t.Fatalf("Revalidate(partial)=%v", err)
	}
	final, err := store.Finalize(context.Background(), partial, artifact)
	if err != nil || final.ContentKey() != artifact.ContentKey() || final.Size() != artifact.Size() ||
		!final.Digest().Equal(artifact.Digest()) {
		t.Fatalf("Finalize()=%+v,%v", final, err)
	}
	if inspected, inspectError := store.InspectFinal(context.Background(), artifact); inspectError != nil || inspected != final {
		t.Fatalf("InspectFinal()=%+v,%v", inspected, inspectError)
	}
	finalPath := filepath.Join(root, filepath.FromSlash(artifact.ContentKey()))
	file, _, err := windowssecurity.OpenVerified(context.Background(), finalPath, false, false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	allocated, proven := allocatedFileBytesDescriptor(file, mustWindowsFileInfo(t, file))
	if !proven || allocated < artifact.Size() || !windowsSafeRegularFile(file) {
		t.Fatalf("published allocation=%d proven=%t", allocated, proven)
	}
}

func TestPF001WindowsArtifactStoreConstructionRetainsEveryNativeAuthority(t *testing.T) {
	t.Parallel()
	root := resolvedTempDir(t)
	directory, err := openSecureDirectory(root)
	if err != nil {
		t.Fatalf("open protected store root: %v", err)
	}
	defer func() { _ = directory.Close() }()
	local, filesystemID, err := localFilesystemDescriptor(directory)
	if err != nil || !local || filesystemID == "" {
		t.Fatalf("attest local filesystem: local=%t id=%q error=%v", local, filesystemID, err)
	}
	if _, err := reservationFilesystemSafeDescriptor(directory); err != nil {
		t.Fatalf("attest reservation filesystem: %v", err)
	}
	identity, identityValue, err := openStoreIdentity(directory)
	if err != nil {
		t.Fatalf("open durable store identity: %v", err)
	}
	defer identity.close()
	if _, err := boundFilesystemIdentity(filesystemID, directory, identityValue); err != nil {
		t.Fatalf("bind store filesystem identity: %v", err)
	}
	for _, leaf := range []string{".partials", ".reservations", "sha256"} {
		child, err := openSecureChildDirectoryAt(directory, leaf, true)
		if err != nil {
			t.Fatalf("open protected child %q: %v", leaf, err)
		}
		if !secureChildDirectoryIdentity(directory, leaf, child) {
			_ = child.Close()
			t.Fatalf("protected child %q lost identity", leaf)
		}
		if err := child.Close(); err != nil {
			t.Fatalf("close protected child %q: %v", leaf, err)
		}
	}
}

func TestPF001WindowsArtifactStoreReleaseIsExactDurableAndIdempotent(t *testing.T) {
	t.Parallel()
	root := resolvedTempDir(t)
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	plan := fsPlan(t, []string{"bundle://release/core.bin"})
	request := fsReservationRequest(t, "windows-release", plan)
	if _, err := store.Reserve(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	aggregate, artifact, _ := fsReservationAggregate(t, store, "windows-release", plan)
	consume, _ := aggregate.AuthorizeConsumption(artifact)
	proof, err := store.Consume(context.Background(), consume)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = aggregate.RecordConsumption(consume, proof)
	if _, err := aggregate.RequestReservationRelease(artifactacquisition.ReleaseReasonCancelled); err != nil {
		t.Fatal(err)
	}
	release, err := aggregate.AuthorizeRelease()
	if err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(root, ".reservations", "unrelated")
	writeWindowsPrivateTestFile(t, unrelated, []byte("keep"))
	if err := store.Release(context.Background(), release); err != nil {
		t.Fatal(err)
	}
	if err := store.Release(context.Background(), release); err != nil {
		t.Fatalf("Release replay=%v", err)
	}
	if value, err := os.ReadFile(unrelated); err != nil || string(value) != "keep" { // #nosec G304 -- test-owned path.
		t.Fatalf("unrelated=%q,%v", value, err)
	}
}

func TestPF001WindowsArtifactStoreRejectsHardLinksAlternateStreamsAndForeignDACLs(t *testing.T) {
	t.Parallel()
	root := resolvedTempDir(t)
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	plan := fsPlan(t, []string{"bundle://release/core.bin"})
	request := fsReservationRequest(t, "windows-links", plan)
	allocation := request.Allocations[0]
	unrelated := filepath.Join(root, "unrelated.bin")
	writeWindowsPrivateTestFile(t, unrelated, []byte("abcdef"))
	slot := filepath.Join(root, ".reservations", allocation.SlotID()+".slot")
	if err := os.Link(unrelated, slot); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reserve(context.Background(), request); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("hard-link reservation error=%v", err)
	}
	if err := os.Remove(slot); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reserve(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	stream := slot + ":foreign"
	if err := os.WriteFile(stream, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reserve(context.Background(), request); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("alternate-stream reservation error=%v", err)
	}
	unsafeRoot := filepath.Join(root, "inherited-root")
	if err := os.Mkdir(unsafeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(unsafeRoot); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("foreign/inherited DACL root error=%v", err)
	}
}

func TestPF001WindowsBundleFetcherRequiresProtectedStableExactObjects(t *testing.T) {
	t.Parallel()
	root := resolvedTempDir(t)
	release := filepath.Join(root, "release")
	makeSecureTestDirectory(t, release)
	path := filepath.Join(release, "core.bin")
	writeWindowsPrivateTestFile(t, path, []byte("abcdef"))
	fetcher, err := NewBundleFetcher(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fetcher.Close() })
	artifact := fsPlan(t, []string{"bundle://release/core.bin"}).Artifacts()[0]
	for index, chunk := range artifact.Chunks() {
		value, err := fetcher.Fetch(context.Background(), artifact, artifact.Sources()[0], chunk)
		if err != nil || string(value) != []string{"abc", "def"}[index] {
			t.Fatalf("Fetch(%d)=%q,%v", index, value, err)
		}
	}
	if err := os.WriteFile(path+":foreign", []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fetcher.Fetch(context.Background(), artifact, artifact.Sources()[0], artifact.Chunks()[0]); !errors.Is(err, artifactapp.ErrFetchIntegrity) {
		t.Fatalf("ADS Fetch error=%v", err)
	}
}

func TestPF001WindowsPhysicalAllocationIsMeasuredAndReplaySafe(t *testing.T) {
	t.Parallel()
	root := resolvedTempDir(t)
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	opened, created, err := openSecureLeafAt(store.reservationRoot, "manual.reserve", true)
	if err != nil || !created {
		t.Fatalf("open reservation=%t,%v", created, err)
	}
	defer opened.close()
	const bytes = uint64(8193)
	if err := allocatePhysical(context.Background(), opened.file, bytes); err != nil {
		t.Fatal(err)
	}
	if !physicallyAllocated(opened.file, bytes) {
		t.Fatal("Windows allocation was not physically proven")
	}
	allocated, proven := allocatedFileBytesDescriptor(opened.file, mustWindowsFileInfo(t, opened.file))
	if !proven || allocated < bytes {
		t.Fatalf("allocation=%d proven=%t", allocated, proven)
	}
	if err := allocatePhysical(context.Background(), opened.file, bytes); err != nil {
		t.Fatalf("allocation replay=%v", err)
	}
	if err := removeOpenSecureFile(opened); err != nil {
		t.Fatal(err)
	}
}

func TestPF001WindowsVolumeAndPathPoliciesFailClosed(t *testing.T) {
	t.Parallel()
	required := uint32(windows.FILE_PERSISTENT_ACLS | windows.FILE_UNICODE_ON_DISK | windows.FILE_NAMED_STREAMS)
	for _, filesystem := range []string{"NTFS", "ReFS"} {
		if !windowsSupportedVolume(windowsVolumeDescriptor{
			root: `C:\`, filesystem: filesystem, serial: 1, flags: required,
		}) {
			t.Fatalf("supported %s volume rejected", filesystem)
		}
	}
	for _, descriptor := range []windowsVolumeDescriptor{
		{root: `C:\`, filesystem: "FAT32", serial: 1, flags: required},
		{root: `C:\`, filesystem: "NTFS", serial: 0, flags: required},
		{root: `C:\`, filesystem: "NTFS", serial: 1, flags: required | windows.FILE_VOLUME_IS_COMPRESSED},
		{root: `C:\`, filesystem: "ReFS", serial: 1, flags: required | windows.FILE_READ_ONLY_VOLUME},
	} {
		if windowsSupportedVolume(descriptor) {
			t.Fatalf("unsafe volume accepted: %+v", descriptor)
		}
	}
	for _, leaf := range []string{"", ".", "..", "CON", "aux.txt", "LPT9.log", "name.", "name ", "a:b", `a\b`, "a/b"} {
		if safeLeaf(leaf) {
			t.Fatalf("unsafe Windows leaf accepted: %q", leaf)
		}
	}
	if !safeLeaf("sha256-file.reserve") {
		t.Fatal("safe Windows leaf rejected")
	}
	if _, err := NewStore(`\\server\share\cas`); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("UNC store error=%v", err)
	}
	if _, err := NewStore(`C:\cas:stream`); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("ADS store error=%v", err)
	}
}

func TestPF001WindowsStoreLifecycleAndAuthorityBoundariesFailClosed(t *testing.T) {
	t.Parallel()
	root := resolvedTempDir(t)
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	plan := fsPlan(t, []string{"bundle://release/core.bin"})
	request := fsReservationRequest(t, "windows-boundaries", plan)
	var nilContext context.Context
	if _, err := store.Reserve(nilContext, request); !errors.Is(err, artifactapp.ErrReservationOperation) {
		t.Fatalf("nil Reserve error=%v", err)
	}
	if _, err := store.Revalidate(context.Background(), artifactacquisition.ReservationRevalidationAuthorization{}); !errors.Is(err, artifactapp.ErrReservationOperation) {
		t.Fatalf("invalid Revalidate error=%v", err)
	}
	if _, err := store.Consume(context.Background(), artifactacquisition.ConsumptionAuthorization{}); !errors.Is(err, artifactapp.ErrReservationOperation) {
		t.Fatalf("invalid Consume error=%v", err)
	}
	if err := store.Release(context.Background(), artifactacquisition.ReleaseAuthorization{}); !errors.Is(err, artifactapp.ErrReservationOperation) {
		t.Fatalf("invalid Release error=%v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close replay=%v", err)
	}
	if _, err := store.Reserve(context.Background(), request); !errors.Is(err, artifactapp.ErrReservationOperation) {
		t.Fatalf("closed Reserve error=%v", err)
	}
	var absent *Store
	if err := absent.Close(); err != nil {
		t.Fatalf("nil Close=%v", err)
	}
}

func TestPF001WindowsFilesystemHelpersRetainProtectedHandleSemantics(t *testing.T) {
	t.Parallel()
	root := resolvedTempDir(t)
	if err := errors.Join(secureDirectory(root), ensureDirectory(root), syncDirectory(root)); err != nil {
		t.Fatalf("protected directory helpers failed: %v", err)
	}
	info, err := os.Stat(root)
	if err != nil || !safeDirectoryInfo(info) || safeDirectoryInfo(nil) {
		t.Fatalf("safeDirectoryInfo()=%v,%v", info, err)
	}
	identity, err := captureDirectoryIdentity(root)
	if err != nil || identity == "" || !directoryIdentityMatches(root, identity) ||
		directoryIdentityMatches(root, "") || directoryIdentityMatches(filepath.Join(root, "missing"), identity) {
		t.Fatalf("protected directory identity=%q,%v", identity, err)
	}
	local, filesystemID, err := localFilesystem(root)
	if err != nil || !local || filesystemID == "" {
		t.Fatalf("localFilesystem()=%t,%q,%v", local, filesystemID, err)
	}
	if !isNotDirectoryError(windows.ERROR_DIRECTORY) || isNotDirectoryError(nil) {
		t.Fatal("Windows not-directory classification is not fail closed")
	}

	exactPath := filepath.Join(root, "exact.bin")
	exact, err := openSecureFile(exactPath, true)
	if err != nil {
		t.Fatal(err)
	}
	if written, writeErr := exact.Write([]byte("ok")); writeErr != nil || written != 2 || durableSync(exact) != nil {
		_ = exact.Close()
		t.Fatalf("write exact helper file=%d,%v", written, writeErr)
	}
	if err := exact.Close(); err != nil {
		t.Fatal(err)
	}
	if err := removeSecureLeaf(root, "exact.bin", 3); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("wrong-size exact removal=%v", err)
	}
	if err := removeSecureLeaf(root, "exact.bin", 2); err != nil {
		t.Fatal(err)
	}

	bounded, created, err := openSecureLeaf(root, "bounded.bin", true)
	if err != nil || !created {
		t.Fatalf("open bounded helper file=%t,%v", created, err)
	}
	if written, writeErr := bounded.file.Write([]byte("ok")); writeErr != nil || written != 2 ||
		durableSync(bounded.file) != nil {
		bounded.close()
		t.Fatalf("write bounded helper file=%d,%v", written, writeErr)
	}
	bounded.close()
	if err := removeSecureLeafAtMost(root, "bounded.bin", 1); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("undersized bounded removal=%v", err)
	}
	if err := removeSecureLeafAtMost(root, "bounded.bin", 2); err != nil {
		t.Fatal(err)
	}
}

func fsPlan(t *testing.T, sources []string) artifactacquisition.Plan {
	t.Helper()
	digest := releaseinventory.DigestBytes([]byte("abcdef"))
	target, err := releaseinventory.NewReleaseExpandedTarget(digest, 6, releaseinventory.ReleaseExpandedTargetInput{
		Kind: releaseinventory.ExpandedTargetComposeBundle, StorageID: "compose/compose.yaml", Digest: digest, Bytes: 6,
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := artifactacquisition.NewPlan(artifactacquisition.PlanInput{
		PlanDigest: releaseinventory.DigestBytes([]byte("plan")),
		Artifacts: []artifactacquisition.ArtifactInput{{
			ID: "core", Digest: digest, Size: 6, ExpandedBytes: 6, ExpandedDigest: digest,
			TargetKind: target.Kind(), TargetStorageID: target.StorageID(), TargetAuthorityDigest: target.AuthorityDigest(),
			Sources: sources,
			Chunks: []artifactacquisition.ChunkInput{
				{Offset: 0, Size: 3, Digest: releaseinventory.DigestBytes([]byte("abc"))},
				{Offset: 3, Size: 3, Digest: releaseinventory.DigestBytes([]byte("def"))},
			},
		}},
		Totals: artifactacquisition.TotalsInput{
			DownloadBytes: 6, ExpandedBytes: 6, RollbackHeadroomBytes: 20, SafetyHeadroomBytes: 30, RequiredBytes: 62,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
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
	return artifactapp.ReservationRequest{
		Authorization: authorization, ReservationID: id, PlanDigest: plan.Digest(),
		RequiredBytes: plan.Totals().DownloadBytes(), DownloadBytes: plan.Totals().DownloadBytes(),
		Allocations: aggregate.ReservationAllocations(),
	}
}

func fsReservationAggregate(
	t *testing.T,
	store *Store,
	operationID string,
	plan artifactacquisition.Plan,
) (*artifactacquisition.Aggregate, artifactacquisition.Artifact, artifactacquisition.PartialAuthorization) {
	t.Helper()
	aggregate, err := artifactacquisition.NewAggregate(operationID, plan)
	if err != nil {
		t.Fatal(err)
	}
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

func writeWindowsPrivateTestFile(t *testing.T, path string, value []byte) {
	t.Helper()
	file, err := windowssecurity.CreatePrivateFile(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	count, writeError := file.Write(value)
	flushError := windowssecurity.Flush(file)
	closeError := file.Close()
	if writeError != nil || count != len(value) || flushError != nil || closeError != nil {
		t.Fatalf("write private Windows fixture=%d,%v,%v,%v", count, writeError, flushError, closeError)
	}
}

func mustWindowsFileInfo(t *testing.T, file *os.File) os.FileInfo {
	t.Helper()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestPF001WindowsSafeTokenPolicyRemainsExact(t *testing.T) {
	t.Parallel()
	if safeToken("r-short", "r-") || !safeToken("r-"+strings.Repeat("a", 64), "r-") {
		t.Fatal("safe token policy changed")
	}
}
