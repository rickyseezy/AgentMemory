//go:build darwin || linux

package artifactfs

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001ArtifactFSReservesExactLocalBytesDurablyAndIdempotently(t *testing.T) {
	t.Parallel()
	root := resolvedTempDir(t)
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	enableReservationMechanicsForTest(t, store)
	plan := fsPlan(t, []string{"bundle://release/core.bin"})
	request := fsReservationRequest(t, "install-1", plan)
	id := request.ReservationID
	totals := plan.Totals()
	proof, err := store.Reserve(context.Background(), request)
	if err != nil || proof.ID() != id || proof.Bytes() != totals.DownloadBytes() || !strings.HasPrefix(proof.FilesystemID(), "fs-") {
		t.Fatalf("Reserve()=(%+v,%v)", proof, err)
	}
	slotPath := filepath.Join(root, ".reservations", request.Allocations[0].SlotID()+".slot")
	info, err := os.Lstat(slotPath)
	observedSize, sizeValid := nonNegativeInt64(infoSize(info, err))
	if err != nil || !sizeValid || observedSize != totals.DownloadBytes() {
		t.Fatalf("slot info=%+v err=%v", info, err)
	}
	replayed, err := store.Reserve(context.Background(), request)
	if err != nil || replayed != proof {
		t.Fatalf("replay=(%+v,%v)", replayed, err)
	}
	request.RequiredBytes++
	if _, err := store.Reserve(context.Background(), request); !errors.Is(err, artifactapp.ErrReservationOperation) {
		t.Fatalf("contradictory reservation error=%v", err)
	}
}

func TestPF001ArtifactFSCancelledReservationRemovesOnlyOwnedPartial(t *testing.T) {
	t.Parallel()
	root := resolvedTempDir(t)
	store, _ := NewStore(root)
	enableReservationMechanicsForTest(t, store)
	plan := fsPlan(t, []string{"bundle://release/core.bin"})
	request := fsReservationRequest(t, "cancel-1", plan)
	id := request.ReservationID
	unrelated := filepath.Join(root, ".reservations", "unrelated")
	if err := os.WriteFile(unrelated, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := store.Reserve(ctx, request)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, artifactapp.ErrReservationOperation) {
		t.Fatalf("cancellation error=%v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, ".reservations", id+".reserve")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned cancelled reservation remains: %v", err)
	}
	if value, err := os.ReadFile(unrelated); err != nil || string(value) != "keep" { // #nosec G304 -- test-owned temporary path.
		t.Fatalf("unrelated value=%q err=%v", value, err)
	}
}

func TestPF001ArtifactFSWritesVerifiesAndAtomicallyPublishesCAS(t *testing.T) {
	t.Parallel()
	root := resolvedTempDir(t)
	store, _ := NewStore(root)
	aggregate, artifact, authorization := fsConsumedArtifact(t, store, "install-1")
	values := [][]byte{[]byte("abc"), []byte("def")}
	for index, chunk := range artifact.Chunks() {
		if err := store.WriteChunk(context.Background(), authorization, chunk, values[index]); err != nil {
			t.Fatal(err)
		}
		digest, err := store.VerifyChunk(context.Background(), authorization, chunk)
		if err != nil || !digest.Equal(chunk.Digest()) {
			t.Fatalf("VerifyChunk()=(%s,%v)", digest.Hex(), err)
		}
		_, _ = aggregate.MarkChunkVerified(artifact, chunk, digest)
	}
	proof, err := store.Finalize(context.Background(), authorization, artifact)
	if err != nil || proof.Digest() != artifact.Digest() || proof.Size() != artifact.Size() || proof.ContentKey() != artifact.ContentKey() {
		t.Fatalf("Finalize()=(%+v,%v)", proof, err)
	}
	inspected, err := store.InspectFinal(context.Background(), artifact)
	if err != nil || inspected != proof {
		t.Fatalf("InspectFinal()=(%+v,%v)", inspected, err)
	}
	if _, err := os.Lstat(filepath.Join(root, ".partials", authorization.PartialID()+".part")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial remains: %v", err)
	}
	final := filepath.Join(root, filepath.FromSlash(artifact.ContentKey()))
	info, err := os.Lstat(final)
	observedSize, sizeValid := nonNegativeInt64(infoSize(info, err))
	if err != nil || !sizeValid || info.Mode().Perm() != 0o600 || observedSize != artifact.Size() {
		t.Fatalf("final info=%+v err=%v", info, err)
	}

	// A second operation never overwrites the existing exact CAS object.
	aggregate2, artifact2, authorization2 := fsConsumedArtifact(t, store, "install-2")
	for index, chunk := range artifact2.Chunks() {
		_ = store.WriteChunk(context.Background(), authorization2, chunk, values[index])
		_, _ = aggregate2.MarkChunkVerified(artifact2, chunk, chunk.Digest())
	}
	if proof2, err := store.Finalize(context.Background(), authorization2, artifact2); err != nil || proof2 != proof {
		t.Fatalf("deduplicated finalize=(%+v,%v)", proof2, err)
	}
}

func TestPF001ArtifactFSCorruptionFailsClosedAndOwnedRemovalPreservesUnrelated(t *testing.T) {
	t.Parallel()
	root := resolvedTempDir(t)
	store, _ := NewStore(root)
	_, artifact, authorization := fsConsumedArtifact(t, store, "install-corrupt")
	chunk := artifact.Chunks()[0]
	if err := store.WriteChunk(context.Background(), authorization, chunk, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	partialPath := filepath.Join(root, ".partials", authorization.PartialID()+".part")
	file, _ := os.OpenFile(partialPath, os.O_WRONLY, 0) // #nosec G304 -- test-owned temporary path.
	_, _ = file.WriteAt([]byte("X"), 1)
	_ = file.Close()
	beforeReset, err := os.ReadFile(partialPath) // #nosec G304 -- test-owned temporary path.
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Finalize(context.Background(), authorization, artifact); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("corrupt finalize error=%v", err)
	}
	unrelated := filepath.Join(root, ".partials", "unrelated")
	_ = os.WriteFile(unrelated, []byte("keep"), 0o600)
	if err := store.ResetInvalidPartial(context.Background(), authorization); err != nil {
		t.Fatal(err)
	}
	info, statError := os.Lstat(partialPath)
	observedSize, sizeValid := nonNegativeInt64(infoSize(info, statError))
	if statError != nil || !sizeValid || observedSize != authorization.Size() {
		t.Fatalf("reset owned partial info=%+v err=%v", info, statError)
	}
	afterReset, err := os.ReadFile(partialPath) // #nosec G304 -- test-owned temporary path.
	if err != nil || string(afterReset) != string(beforeReset) {
		t.Fatalf("ResetInvalidPartial rewrote retained extents: before=%x after=%x error=%v", beforeReset, afterReset, err)
	}
	if value, err := os.ReadFile(unrelated); err != nil || string(value) != "keep" { // #nosec G304 -- test-owned temporary path.
		t.Fatalf("unrelated value=%q err=%v", value, err)
	}
}

func TestPF001ArtifactFSOfflineBundleReadsExactVerifiedRanges(t *testing.T) {
	t.Parallel()
	root := resolvedTempDir(t)
	if err := os.MkdirAll(filepath.Join(root, "release"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "release", "core.bin")
	if err := os.WriteFile(path, []byte("abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	fetcher, err := NewBundleFetcher(root)
	if err != nil {
		t.Fatal(err)
	}
	artifact := fsPlan(t, []string{"bundle://release/core.bin"}).Artifacts()[0]
	for index, chunk := range artifact.Chunks() {
		value, err := fetcher.Fetch(context.Background(), artifact, artifact.Sources()[0], chunk)
		if err != nil || string(value) != []string{"abc", "def"}[index] {
			t.Fatalf("Fetch(%d)=(%q,%v)", index, value, err)
		}
	}
	if _, err := fetcher.Fetch(context.Background(), artifact, "bundle://release/other", artifact.Chunks()[0]); !errors.Is(err, artifactapp.ErrFetchIntegrity) {
		t.Fatalf("unauthorized bundle error=%v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "other"), path); err == nil {
		if _, err := fetcher.Fetch(context.Background(), artifact, artifact.Sources()[0], artifact.Chunks()[0]); !errors.Is(err, artifactapp.ErrFetchIntegrity) {
			t.Fatalf("symlink bundle error=%v", err)
		}
	}
}

func TestPF001OfflineBundleStreamsExactReleaseResourcesFromRetainedAuthority(t *testing.T) {
	t.Parallel()
	base := resolvedTempDir(t)
	root := filepath.Join(base, "bundle")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "release"), 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte(`{"bomFormat":"CycloneDX"}`)
	path := filepath.Join(root, "release", "core.cdx.json")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	fetcher, err := NewBundleFetcher(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fetcher.Close() })
	resource, err := releaseinventory.NewResource(releaseinventory.ResourceInput{
		ID: "core-cyclonedx", Kind: releaseinventory.ResourceKindCycloneDXSBOM,
		Purpose:   releaseinventory.ResourcePurposeCycloneDXSBOM,
		MediaType: releaseinventory.MediaTypeCycloneDX, Digest: releaseinventory.DigestBytes(content),
		Size: uint64(len(content)), SourceRef: "bundle://release/core.cdx.json",
		SourceAllowlist:   []string{"bundle://release/core.cdx.json"},
		SubjectResourceID: "core-image", SubjectDigest: releaseinventory.DigestBytes([]byte("subject")),
	})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := fetcher.OpenResource(context.Background(), resource)
	if err != nil {
		t.Fatal(err)
	}
	value, err := io.ReadAll(reader)
	if err != nil || string(value) != string(content) {
		t.Fatalf("resource bytes=%q error=%v", value, err)
	}
	if err := reader.Close(); err != nil || reader.Close() != nil {
		t.Fatalf("resource close error=%v", err)
	}

	for _, input := range []struct {
		name   string
		ctx    context.Context
		source string
		size   uint64
		want   error
	}{
		{name: "nil context", source: resource.SourceRef(), size: resource.Size(), want: artifactapp.ErrFetchIntegrity},
		{name: "mutable transport", ctx: context.Background(), source: "https://example.com/core.cdx.json", size: resource.Size(), want: artifactapp.ErrFetchIntegrity},
		{name: "empty path", ctx: context.Background(), source: "bundle://", size: resource.Size(), want: artifactapp.ErrFetchIntegrity},
		{name: "absolute path", ctx: context.Background(), source: "bundle:///release/core.cdx.json", size: resource.Size(), want: artifactapp.ErrFetchIntegrity},
		{name: "zero size", ctx: context.Background(), source: resource.SourceRef(), want: artifactapp.ErrFetchIntegrity},
		{name: "wrong size", ctx: context.Background(), source: resource.SourceRef(), size: resource.Size() + 1, want: artifactapp.ErrFetchIntegrity},
		{name: "missing", ctx: context.Background(), source: "bundle://release/missing.json", size: resource.Size(), want: artifactapp.ErrFetchUnavailable},
	} {
		t.Run(input.name, func(t *testing.T) {
			opened, openError := fetcher.openExactResource(input.ctx, input.source, input.size)
			if opened != nil || !errors.Is(openError, input.want) {
				t.Fatalf("open=%v error=%v, want %v", opened, openError, input.want)
			}
		})
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if reader, err := fetcher.openExactResource(cancelled, resource.SourceRef(), resource.Size()); reader != nil || !errors.Is(err, artifactapp.ErrFetchIntegrity) {
		t.Fatalf("cancelled open=%v error=%v", reader, err)
	}
	var absent *bundleResourceReader
	if _, err := absent.Read(nil); !errors.Is(err, artifactapp.ErrFetchIntegrity) {
		t.Fatalf("nil reader read error=%v", err)
	}
	if err := absent.Close(); !errors.Is(err, artifactapp.ErrFetchIntegrity) {
		t.Fatalf("nil reader close error=%v", err)
	}
}

func TestPF001ArtifactFSRejectsUnsafeRootsAndArguments(t *testing.T) {
	t.Parallel()
	if _, err := NewStore("relative"); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("relative root error=%v", err)
	}
	root := resolvedTempDir(t)
	if err := os.Chmod(root, 0o755); err != nil { // #nosec G302 -- intentionally creates an unsafe test directory.
		t.Fatal(err)
	}
	if _, err := NewStore(root); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("unsafe permission error=%v", err)
	}
	if _, err := NewBundleFetcher(root); !errors.Is(err, artifactapp.ErrFetchIntegrity) {
		t.Fatalf("unsafe bundle permission error=%v", err)
	}
	if safeToken("r-short", "r-") || !safeToken("r-"+strings.Repeat("a", 64), "r-") {
		t.Fatal("safe token validation changed")
	}
}

func TestPF001ArtifactFSFailsClosedAtStoreAndBundleBoundaries(t *testing.T) {
	t.Parallel()
	if _, err := NewBundleFetcher("relative"); !errors.Is(err, artifactapp.ErrFetchIntegrity) {
		t.Fatalf("relative bundle root error=%v", err)
	}

	root := resolvedTempDir(t)
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	_, artifact, authorization := fsOwnedArtifact(t, "boundary-1")
	chunk := artifact.Chunks()[0]
	if _, err := store.InspectFinal(context.Background(), artifact); !errors.Is(err, artifactapp.ErrArtifactNotFound) {
		t.Fatalf("missing final error=%v", err)
	}
	if _, err := store.VerifyChunk(context.Background(), authorization, chunk); !errors.Is(err, artifactapp.ErrArtifactNotFound) {
		t.Fatalf("missing chunk error=%v", err)
	}
	if _, err := store.Finalize(context.Background(), authorization, artifact); !errors.Is(err, artifactapp.ErrArtifactNotFound) {
		t.Fatalf("missing partial error=%v", err)
	}
	if err := store.WriteChunk(context.Background(), authorization, chunk, []byte("bad")); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("unverified bytes error=%v", err)
	}
	if err := store.ResetInvalidPartial(context.Background(), authorization); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("missing reset error=%v", err)
	}
	var absentAuthorization artifactacquisition.PartialAuthorization
	if err := store.WriteChunk(context.Background(), absentAuthorization, chunk, []byte("abc")); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("unminted authorization error=%v", err)
	}
	if _, _, err := finalParts("sha256/not-a-key"); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("invalid CAS key error=%v", err)
	}

	bundle, err := NewBundleFetcher(root)
	if err != nil {
		t.Fatal(err)
	}
	source := artifact.Sources()[0]
	if _, err := bundle.Fetch(context.Background(), artifact, source, chunk); !errors.Is(err, artifactapp.ErrFetchUnavailable) {
		t.Fatalf("missing bundle error=%v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "release"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "release", "core.bin")
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.Fetch(context.Background(), artifact, source, chunk); !errors.Is(err, artifactapp.ErrFetchIntegrity) {
		t.Fatalf("wrong bundle size error=%v", err)
	}
	if err := os.WriteFile(path, []byte("abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := bundle.Fetch(cancelled, artifact, source, chunk); !errors.Is(err, context.Canceled) || !errors.Is(err, artifactapp.ErrFetchUnavailable) {
		t.Fatalf("cancelled bundle error=%v", err)
	}

	for _, test := range []struct {
		err       error
		integrity bool
		want      error
	}{
		{artifactapp.ErrArtifactNotFound, false, artifactapp.ErrArtifactNotFound},
		{artifactapp.ErrStoreIntegrity, false, artifactapp.ErrStoreIntegrity},
		{artifactapp.ErrStoreOperation, true, artifactapp.ErrStoreOperation},
		{errors.New("raw"), true, artifactapp.ErrStoreIntegrity},
		{errors.New("raw"), false, artifactapp.ErrStoreOperation},
	} {
		if observed := sanitizeStoreError(test.err, test.integrity); !errors.Is(observed, test.want) {
			t.Fatalf("sanitizeStoreError(%v,%t)=%v want=%v", test.err, test.integrity, observed, test.want)
		}
	}

	notDirectory := filepath.Join(root, "not-directory")
	if err := os.WriteFile(notDirectory, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureDirectory(notDirectory); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("file accepted as directory: %v", err)
	}
	if _, err := openSecureFile(filepath.Join(root, "missing"), false); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing secure file error=%v", err)
	}
	if err := syncDirectory(filepath.Join(root, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing directory sync error=%v", err)
	}
}

func TestPF001ArtifactFSRejectsUnsafeStoreObjectsAndInterruptedIO(t *testing.T) {
	t.Parallel()
	root := resolvedTempDir(t)
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	aggregate, artifact, authorization := fsConsumedArtifact(t, store, "unsafe-objects")
	chunks := artifact.Chunks()
	if digest, err := store.VerifyChunk(context.Background(), authorization, chunks[1]); err != nil || digest.Equal(chunks[1].Digest()) {
		t.Fatalf("unwritten reserved range digest=%s error=%v", digest.Hex(), err)
	}
	if err := store.WriteChunk(context.Background(), authorization, chunks[0], []byte("abc")); err != nil {
		t.Fatal(err)
	}
	var absentContext context.Context
	if _, err := store.VerifyChunk(absentContext, authorization, chunks[0]); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("nil chunk verification context error=%v", err)
	}
	if err := store.WriteChunk(absentContext, authorization, chunks[1], []byte("def")); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("nil chunk write context error=%v", err)
	}
	if digest, err := store.VerifyChunk(context.Background(), authorization, chunks[1]); err != nil || digest.Equal(chunks[1].Digest()) {
		t.Fatalf("unwritten second range digest=%s error=%v", digest.Hex(), err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.VerifyChunk(cancelled, authorization, chunks[0]); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled verify error=%v", err)
	}
	if err := store.WriteChunk(cancelled, authorization, chunks[1], []byte("def")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled write error=%v", err)
	}
	partial := filepath.Join(root, ".partials", authorization.PartialID()+".part")
	if err := os.Chmod(partial, 0o644); err != nil { // #nosec G302 -- intentionally creates an unsafe fixture to prove rejection.
		t.Fatal(err)
	}
	if _, err := store.VerifyChunk(context.Background(), authorization, chunks[0]); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("unsafe partial error=%v", err)
	}
	if err := store.ResetInvalidPartial(context.Background(), authorization); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("unsafe removal error=%v", err)
	}
	if err := os.Chmod(partial, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.ResetInvalidPartial(context.Background(), authorization); err != nil {
		t.Fatal(err)
	}
	if err := store.ResetInvalidPartial(context.Background(), authorization); err != nil {
		t.Fatalf("replayed reset error=%v", err)
	}
	var absent artifactacquisition.PartialAuthorization
	if err := store.ResetInvalidPartial(context.Background(), absent); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("unminted removal error=%v", err)
	}

	// Recreate an oversized owned partial; a valid range write must fail closed.
	if err := os.WriteFile(partial, []byte("abcdefx"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteChunk(context.Background(), authorization, chunks[0], []byte("abc")); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("oversized partial error=%v", err)
	}
	_ = os.Remove(partial)

	otherPlan := fsPlanForBytes(t, "other", []byte("ghijkl"))
	other := otherPlan.Artifacts()[0]
	if _, err := store.Finalize(context.Background(), authorization, other); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("cross-artifact finalize error=%v", err)
	}
	_ = aggregate
}

func TestPF001ArtifactFSDetectsCorruptExistingCASAndBundleObjects(t *testing.T) {
	t.Parallel()
	root := resolvedTempDir(t)
	store, _ := NewStore(root)
	aggregate, artifact, authorization := fsConsumedArtifact(t, store, "publish-1")
	for index, chunk := range artifact.Chunks() {
		value := [][]byte{[]byte("abc"), []byte("def")}[index]
		_ = store.WriteChunk(context.Background(), authorization, chunk, value)
		_, _ = aggregate.MarkChunkVerified(artifact, chunk, chunk.Digest())
	}
	if _, err := store.Finalize(context.Background(), authorization, artifact); err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(root, filepath.FromSlash(artifact.ContentKey()))
	file, err := os.OpenFile(final, os.O_WRONLY, 0) // #nosec G304 -- test-owned temporary path.
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.WriteAt([]byte("X"), 0)
	_ = file.Close()
	if _, err := store.InspectFinal(context.Background(), artifact); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("corrupt final error=%v", err)
	}

	aggregate2, artifact2, authorization2 := fsConsumedArtifact(t, store, "publish-2")
	for index, chunk := range artifact2.Chunks() {
		value := [][]byte{[]byte("abc"), []byte("def")}[index]
		_ = store.WriteChunk(context.Background(), authorization2, chunk, value)
		_, _ = aggregate2.MarkChunkVerified(artifact2, chunk, chunk.Digest())
	}
	if _, err := store.Finalize(context.Background(), authorization2, artifact2); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("corrupt existing CAS accepted: %v", err)
	}

	bundleRoot := resolvedTempDir(t)
	if err := os.Mkdir(filepath.Join(bundleRoot, "release"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(bundleRoot, "release", "core.bin")
	if err := os.WriteFile(path, []byte("abcdeg"), 0o600); err != nil {
		t.Fatal(err)
	}
	bundle, _ := NewBundleFetcher(bundleRoot)
	bundleArtifact := fsPlan(t, []string{"bundle://release/core.bin"}).Artifacts()[0]
	if _, err := bundle.Fetch(context.Background(), bundleArtifact, bundleArtifact.Sources()[0], bundleArtifact.Chunks()[1]); !errors.Is(err, artifactapp.ErrFetchIntegrity) {
		t.Fatalf("corrupt bundle chunk error=%v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.Fetch(context.Background(), bundleArtifact, bundleArtifact.Sources()[0], bundleArtifact.Chunks()[0]); !errors.Is(err, artifactapp.ErrFetchIntegrity) {
		t.Fatalf("bundle directory error=%v", err)
	}
}

func TestPF001ArtifactFSConstructorAndConversionGuardsFailClosed(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(resolvedTempDir(t), "missing")
	if _, err := NewStore(missing); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("missing root error=%v", err)
	}
	if _, err := NewBundleFetcher(missing); !errors.Is(err, artifactapp.ErrFetchIntegrity) {
		t.Fatalf("missing bundle root error=%v", err)
	}
	if _, _, err := localFilesystem(missing); err == nil {
		t.Fatal("missing filesystem unexpectedly classified")
	}
	if _, err := availableBytes(missing); err == nil {
		t.Fatal("missing filesystem capacity unexpectedly read")
	}
	controlled := resolvedTempDir(t)
	if _, identity, err := localFilesystem(controlled); err != nil || identity == "" {
		t.Fatalf("controlled filesystem classification=%q,%v", identity, err)
	}
	if available, err := availableBytes(controlled); err != nil || available == 0 {
		t.Fatalf("controlled filesystem capacity=%d,%v", available, err)
	}
	root := resolvedTempDir(t)
	if err := os.WriteFile(filepath.Join(root, ".partials"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(root); !errors.Is(err, artifactapp.ErrStoreOperation) {
		t.Fatalf("blocked store directory error=%v", err)
	}
	if safeFileInfo(nil, 0) {
		t.Fatal("nil file information accepted")
	}
	if _, valid := allocatedFileBytes(nil); valid {
		t.Fatal("nil allocation information accepted")
	}
	if _, valid := allocatedFileBytes(allocationFileInfo{value: &syscall.Stat_t{Blocks: -1}}); valid {
		t.Fatal("negative allocation count accepted")
	}
	if _, valid := allocatedFileBytes(allocationFileInfo{value: &syscall.Stat_t{Blocks: int64(^uint64(0)/512 + 1)}}); valid {
		t.Fatal("overflowing allocation count accepted")
	}
	if value, valid := nonNegativeInt64(-1); valid || value != 0 {
		t.Fatalf("negative conversion=(%d,%t)", value, valid)
	}
	if _, valid := uint64ToInt64(^uint64(0)); valid {
		t.Fatal("overflowing int64 conversion accepted")
	}
	if _, valid := uint64ToInt(^uint64(0)); valid {
		t.Fatal("overflowing int conversion accepted")
	}
	if value := infoSize(nil, errors.New("stat")); value != -1 {
		t.Fatalf("failed stat size=%d", value)
	}
	if safeToken("r-"+strings.Repeat("g", 64), "r-") {
		t.Fatal("non-hex reservation token accepted")
	}
}

func TestPF001ArtifactFSReservationAndFinalizeFailureBoundaries(t *testing.T) {
	t.Parallel()
	root := resolvedTempDir(t)
	store, _ := NewStore(root)
	plan := fsPlan(t, []string{"bundle://release/core.bin"})
	id, _ := plan.ReservationID("capacity")
	request := artifactapp.ReservationRequest{
		ReservationID: id, PlanDigest: plan.Digest(), RequiredBytes: uint64(1 << 53), DownloadBytes: uint64(1 << 53),
	}
	var absent context.Context
	if _, err := store.Reserve(absent, request); !errors.Is(err, artifactapp.ErrReservationOperation) {
		t.Fatalf("nil reservation context error=%v", err)
	}
	if _, err := store.Reserve(context.Background(), request); !errors.Is(err, artifactapp.ErrReservationOperation) {
		t.Fatalf("impossible reservation error=%v", err)
	}
	request.RequiredBytes, request.DownloadBytes = 1, 0
	if _, err := store.Reserve(context.Background(), request); !errors.Is(err, artifactapp.ErrReservationOperation) {
		t.Fatalf("contradictory totals error=%v", err)
	}
	reservationPath := filepath.Join(root, ".reservations", id+".reserve")
	if err := os.WriteFile(reservationPath, []byte("wrong"), 0o600); err != nil {
		t.Fatal(err)
	}
	request.RequiredBytes, request.DownloadBytes = 1, 1
	if _, err := store.Reserve(context.Background(), request); !errors.Is(err, artifactapp.ErrReservationOperation) {
		t.Fatalf("unsafe retained reservation error=%v", err)
	}

	aggregate, artifact, authorization := fsConsumedArtifact(t, store, "finalize-guards")
	for index, chunk := range artifact.Chunks() {
		value := [][]byte{[]byte("abc"), []byte("def")}[index]
		_ = store.WriteChunk(context.Background(), authorization, chunk, value)
		_, _ = aggregate.MarkChunkVerified(artifact, chunk, chunk.Digest())
	}
	if _, err := store.Finalize(absent, authorization, artifact); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("nil finalize context error=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Finalize(cancelled, authorization, artifact); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled finalize error=%v", err)
	}
	prefix := filepath.Join(root, "sha256", artifact.Digest().Hex()[:2])
	if err := os.WriteFile(prefix, []byte("blocked"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Finalize(context.Background(), authorization, artifact); !errors.Is(err, artifactapp.ErrStoreOperation) {
		t.Fatalf("blocked CAS directory error=%v", err)
	}
	if _, err := store.InspectFinal(absent, artifact); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("nil inspect context error=%v", err)
	}
	if _, err := store.InspectFinal(context.Background(), artifact); !errors.Is(err, artifactapp.ErrStoreIntegrity) {
		t.Fatalf("blocked final directory error=%v", err)
	}
	newDirectory := filepath.Join(root, "new-directory")
	if err := ensureDirectory(newDirectory); err != nil {
		t.Fatalf("create secure directory error=%v", err)
	}
	if err := secureDirectory(filepath.Join(root, "missing-directory")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing secure directory error=%v", err)
	}
	target := filepath.Join(root, "target")
	link := filepath.Join(root, "link")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err == nil {
		if file, err := openSecureFile(link, false); err == nil {
			_ = file.Close()
			t.Fatal("symlink opened as secure file")
		}
	}

	bundleRoot := resolvedTempDir(t)
	bundle, _ := NewBundleFetcher(bundleRoot)
	bundleArtifact := fsPlan(t, []string{"bundle://release/core.bin"}).Artifacts()[0]
	if _, err := bundle.Fetch(absent, bundleArtifact, bundleArtifact.Sources()[0], bundleArtifact.Chunks()[0]); !errors.Is(err, artifactapp.ErrFetchIntegrity) {
		t.Fatalf("nil bundle context error=%v", err)
	}
}

func fsOwnedArtifact(t *testing.T, operationID string) (*artifactacquisition.Aggregate, artifactacquisition.Artifact, artifactacquisition.PartialAuthorization) {
	t.Helper()
	plan := fsPlan(t, []string{"bundle://release/core.bin"})
	aggregate, _ := artifactacquisition.NewAggregate(operationID, plan)
	id, _ := plan.ReservationID(operationID)
	proof, _ := artifactacquisition.NewReservationProof(id, plan.Totals().DownloadBytes(), "localfs-1")
	_, _ = aggregate.RequestReservation()
	_, _ = aggregate.RecordReservation(proof)
	artifact := plan.Artifacts()[0]
	_, _ = aggregate.BeginArtifact(artifact)
	authorization, err := aggregate.AuthorizePartial(artifact)
	if err != nil {
		t.Fatal(err)
	}
	return aggregate, artifact, authorization
}

func fsConsumedArtifact(
	t *testing.T,
	store *Store,
	operationID string,
) (*artifactacquisition.Aggregate, artifactacquisition.Artifact, artifactacquisition.PartialAuthorization) {
	t.Helper()
	plan := fsPlan(t, []string{"bundle://release/core.bin"})
	aggregate, artifact, partial := fsReservationAggregate(t, store, operationID, plan)
	request := fsReservationRequest(t, operationID, plan)
	if _, err := store.Reserve(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	authorization, err := aggregate.AuthorizeConsumption(artifact)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := store.Consume(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aggregate.RecordConsumption(authorization, proof); err != nil {
		t.Fatal(err)
	}
	return aggregate, artifact, partial
}

func fsPlan(t *testing.T, sources []string) artifactacquisition.Plan {
	t.Helper()
	digest := releaseinventory.DigestBytes([]byte("abcdef"))
	target, targetErr := releaseinventory.NewReleaseExpandedTarget(digest, 6, releaseinventory.ReleaseExpandedTargetInput{
		Kind: releaseinventory.ExpandedTargetComposeBundle, StorageID: "compose/compose.yaml", Digest: digest, Bytes: 6,
	})
	if targetErr != nil {
		t.Fatal(targetErr)
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
		Totals: artifactacquisition.TotalsInput{DownloadBytes: 6, ExpandedBytes: 6, RollbackHeadroomBytes: 20, SafetyHeadroomBytes: 30, RequiredBytes: 62},
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func fsPlanForBytes(t *testing.T, id string, value []byte) artifactacquisition.Plan {
	t.Helper()
	plan, err := artifactacquisition.NewPlan(artifactacquisition.PlanInput{
		PlanDigest: releaseinventory.DigestBytes([]byte("other-plan")),
		Artifacts: []artifactacquisition.ArtifactInput{{
			ID: id, Digest: releaseinventory.DigestBytes(value), Size: uint64(len(value)),
			Sources: []string{"bundle://release/other.bin"},
			Chunks:  []artifactacquisition.ChunkInput{{Offset: 0, Size: uint64(len(value)), Digest: releaseinventory.DigestBytes(value)}},
		}},
		Totals: artifactacquisition.TotalsInput{DownloadBytes: uint64(len(value)), RollbackHeadroomBytes: 1, SafetyHeadroomBytes: 1, RequiredBytes: uint64(len(value)) + 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func resolvedTempDir(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil { // #nosec G302 -- directory owner-only mode is required.
		t.Fatal(err)
	}
	return root
}

type allocationFileInfo struct {
	os.FileInfo
	value any
}

func (i allocationFileInfo) Sys() any { return i.value }
