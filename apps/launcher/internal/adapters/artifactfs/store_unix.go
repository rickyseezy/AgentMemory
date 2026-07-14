//go:build darwin || linux || windows

package artifactfs

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func newStore(root string) (*Store, error) {
	return newStoreWithReservationAttestor(root, reservationFilesystemSafeDescriptor)
}

// newStoreWithReservationAttestor is an unexported constructor seam used by
// package tests to exercise lease mechanics on CI filesystems that production
// correctly rejects (notably APFS). Production always calls newStore above.
func newStoreWithReservationAttestor(root string, attest func(*os.File) (bool, error)) (*Store, error) {
	if attest == nil {
		return nil, artifactapp.ErrStoreIntegrity
	}
	rootDirectory, err := openSecureDirectory(root)
	if err != nil {
		return nil, artifactapp.ErrStoreIntegrity
	}
	closeOnFailure := true
	defer func() {
		if closeOnFailure {
			_ = rootDirectory.Close()
		}
	}()
	local, filesystemID, err := localFilesystemDescriptor(rootDirectory)
	if err != nil || !local || filesystemID == "" {
		return nil, artifactapp.ErrStoreIntegrity
	}
	reservationSafe, err := attest(rootDirectory)
	if err != nil {
		return nil, artifactapp.ErrStoreIntegrity
	}
	identity, identityValue, err := openStoreIdentity(rootDirectory)
	if err != nil {
		return nil, artifactapp.ErrStoreIntegrity
	}
	defer func() {
		if closeOnFailure {
			identity.close()
		}
	}()
	filesystemID, err = boundFilesystemIdentity(filesystemID, rootDirectory, identityValue)
	if err != nil {
		return nil, artifactapp.ErrStoreIntegrity
	}
	partialRoot, err := openSecureChildDirectoryAt(rootDirectory, ".partials", true)
	if err != nil {
		return nil, artifactapp.ErrStoreOperation
	}
	defer func() {
		if closeOnFailure {
			_ = partialRoot.Close()
		}
	}()
	reservationRoot, err := openSecureChildDirectoryAt(rootDirectory, ".reservations", true)
	if err != nil {
		return nil, artifactapp.ErrStoreOperation
	}
	defer func() {
		if closeOnFailure {
			_ = reservationRoot.Close()
		}
	}()
	casRoot, err := openSecureChildDirectoryAt(rootDirectory, "sha256", true)
	if err != nil {
		return nil, artifactapp.ErrStoreOperation
	}
	defer func() {
		if closeOnFailure {
			_ = casRoot.Close()
		}
	}()
	if durableSync(rootDirectory) != nil {
		return nil, artifactapp.ErrStoreOperation
	}
	store := &Store{
		filesystemID: filesystemID, identityFile: identity.file, identityDir: identity.directory,
		identityValue: identityValue, rootDirectory: rootDirectory,
		partialRoot: partialRoot, reservationRoot: reservationRoot, casRoot: casRoot,
		available: availableBytesDescriptor, reservationSafe: reservationSafe,
	}
	if !store.valid() {
		return nil, artifactapp.ErrStoreIntegrity
	}
	closeOnFailure = false
	return store, nil
}

func (s *Store) valid() bool {
	return s != nil && safeDirectoryDescriptor(s.rootDirectory) && validStoreIdentity(&secureFile{
		file: s.identityFile, directory: s.identityDir, leaf: storeIdentityLeaf,
	}, s.identityValue) &&
		secureChildDirectoryIdentity(s.rootDirectory, ".partials", s.partialRoot) &&
		secureChildDirectoryIdentity(s.rootDirectory, ".reservations", s.reservationRoot) &&
		secureChildDirectoryIdentity(s.rootDirectory, "sha256", s.casRoot)
}

// Reserve uses a reviewed native physical-allocation primitive for one
// headroom file and one artifact-sized slot per signed artifact. The slot is
// later renamed into the partial, so acquisition consumes the same allocated
// extents without a second download-capacity allocation.
func (s *Store) Reserve(ctx context.Context, request artifactapp.ReservationRequest) (artifactacquisition.ReservationProof, error) {
	if !s.beginOperation() {
		return artifactacquisition.ReservationProof{}, artifactapp.ErrReservationOperation
	}
	defer s.endOperation()
	if ctx == nil || !s.reservationSafe {
		return artifactacquisition.ReservationProof{}, errors.Join(artifactapp.ErrReservationOperation, artifactapp.ErrReservationUnsupported)
	}
	if !safeToken(request.ReservationID, "r-") || request.PlanDigest.IsZero() || request.RequiredBytes == 0 ||
		request.DownloadBytes != request.RequiredBytes || s.available == nil || !validAllocations(request) ||
		!request.Authorization.Valid() || request.Authorization.ReservationID() != request.ReservationID ||
		!request.Authorization.PlanDigest().Equal(request.PlanDigest) || request.Authorization.RequiredBytes() != request.RequiredBytes ||
		!sameAllocations(request.Authorization.Allocations(), request.Allocations) {
		return artifactacquisition.ReservationProof{}, artifactapp.ErrReservationOperation
	}
	targets := make([]reservationTarget, 0, len(request.Allocations))
	for _, allocation := range request.Allocations {
		targets = append(targets, reservationTarget{leaf: allocation.SlotID() + ".slot", bytes: allocation.Bytes()})
	}
	missing, err := s.missingReservationBytes(targets)
	if errors.Is(err, artifactapp.ErrStoreIntegrity) {
		return artifactacquisition.ReservationProof{}, artifactapp.ErrStoreIntegrity
	}
	if err != nil {
		return artifactacquisition.ReservationProof{}, artifactapp.ErrReservationOperation
	}
	available, err := s.available(s.rootDirectory)
	if err != nil || available < missing {
		return artifactacquisition.ReservationProof{}, artifactapp.ErrReservationOperation
	}
	for _, target := range targets {
		if err := s.allocateReservationTarget(ctx, target); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return artifactacquisition.ReservationProof{}, errors.Join(artifactapp.ErrReservationOperation, err)
			}
			if errors.Is(err, artifactapp.ErrReservationUnsupported) {
				return artifactacquisition.ReservationProof{}, errors.Join(artifactapp.ErrReservationOperation, artifactapp.ErrReservationUnsupported)
			}
			if errors.Is(err, artifactapp.ErrStoreIntegrity) {
				return artifactacquisition.ReservationProof{}, artifactapp.ErrStoreIntegrity
			}
			return artifactacquisition.ReservationProof{}, artifactapp.ErrReservationOperation
		}
	}
	return artifactacquisition.NewReservationProof(request.ReservationID, request.RequiredBytes, s.filesystemID)
}

// Revalidate proves the exact crash-recoverable physical layout without
// creating, extending, moving, or repairing any object. A missing headroom
// file or impossible slot/partial/final combination therefore fails closed on
// every resumed acquisition.
func (s *Store) Revalidate(
	ctx context.Context,
	authorization artifactacquisition.ReservationRevalidationAuthorization,
) (artifactacquisition.ReservationProof, error) {
	if !s.beginOperation() {
		return artifactacquisition.ReservationProof{}, artifactapp.ErrStoreIntegrity
	}
	defer s.endOperation()
	proof := authorization.Reservation()
	if ctx == nil || !authorization.Valid() || proof.FilesystemID() != s.filesystemID ||
		!safeToken(proof.ID(), "r-") {
		return artifactacquisition.ReservationProof{}, artifactapp.ErrReservationOperation
	}
	for _, expectation := range authorization.Expectations() {
		if err := ctx.Err(); err != nil {
			return artifactacquisition.ReservationProof{}, errors.Join(artifactapp.ErrReservationOperation, err)
		}
		allocation := expectation.Allocation()
		slot, slotError := physicalReservationLeaf(s.reservationRoot, allocation.SlotID()+".slot", allocation.Bytes())
		partial, partialError := physicalReservationLeaf(s.partialRoot, allocation.PartialID()+".part", allocation.Bytes())
		final := false
		var finalError error
		if expectation.Stage() == artifactacquisition.ReservationStageFinalizePending ||
			expectation.Stage() == artifactacquisition.ReservationStageFinal {
			final, finalError = s.physicalFinal(expectation.Artifact())
		}
		if slotError != nil || partialError != nil || finalError != nil {
			return artifactacquisition.ReservationProof{}, artifactapp.ErrStoreIntegrity
		}
		valid := false
		switch expectation.Stage() {
		case artifactacquisition.ReservationStageSlot:
			valid = slot && !partial
		case artifactacquisition.ReservationStageTransferPending:
			valid = slot != partial
		case artifactacquisition.ReservationStageFinalizePending:
			valid = !slot && (partial || final)
		case artifactacquisition.ReservationStageFinal:
			valid = !slot && final
		}
		if !valid {
			return artifactacquisition.ReservationProof{}, artifactapp.ErrReservationOperation
		}
	}
	return proof, nil
}

func physicalReservationLeaf(directory *os.File, leaf string, size uint64) (bool, error) {
	opened, _, err := openSecureLeafAt(directory, leaf, false)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer opened.close()
	if opened.verifyExactSize(size) != nil || !physicallyAllocated(opened.file, size) {
		return false, artifactapp.ErrStoreIntegrity
	}
	return true, nil
}

func (s *Store) physicalFinal(artifact artifactacquisition.Artifact) (bool, error) {
	directory, leaf, err := s.finalLocation(artifact.ContentKey(), false)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, artifactapp.ErrArtifactNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = directory.Close() }()
	opened, _, err := openSecureLeafAt(directory, leaf, false)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer opened.close()
	if opened.verifyExactSize(artifact.Size()) != nil || !physicallyAllocated(opened.file, artifact.Size()) {
		return false, artifactapp.ErrStoreIntegrity
	}
	return true, nil
}

// Consume atomically moves one already allocated slot into its aggregate-owned
// partial name. The no-replace rename preserves capacity and rejects path swaps.
func (s *Store) Consume(
	ctx context.Context,
	authorization artifactacquisition.ConsumptionAuthorization,
) (artifactacquisition.ConsumptionProof, error) {
	if !s.beginOperation() {
		return artifactacquisition.ConsumptionProof{}, artifactapp.ErrStoreIntegrity
	}
	defer s.endOperation()
	if ctx == nil || !authorization.Valid() || authorization.FilesystemID() != s.filesystemID ||
		!safeToken(authorization.ReservationID(), "r-") || !safeToken(authorization.SlotID(), "s-") ||
		!safeToken(authorization.PartialID(), "p-") {
		return artifactacquisition.ConsumptionProof{}, artifactapp.ErrReservationOperation
	}
	if err := ctx.Err(); err != nil {
		return artifactacquisition.ConsumptionProof{}, errors.Join(artifactapp.ErrReservationOperation, err)
	}
	partialLeaf := authorization.PartialID() + ".part"
	slotLeaf := authorization.SlotID() + ".slot"
	partial, _, partialError := openSecureLeafAt(s.partialRoot, partialLeaf, false)
	if partialError == nil {
		defer partial.close()
		if err := partial.verifyExactSize(authorization.Bytes()); err != nil ||
			!physicallyAllocated(partial.file, authorization.Bytes()) {
			return artifactacquisition.ConsumptionProof{}, artifactapp.ErrStoreIntegrity
		}
		if slot, _, err := openSecureLeafAt(s.reservationRoot, slotLeaf, false); err == nil {
			slot.close()
			return artifactacquisition.ConsumptionProof{}, artifactapp.ErrStoreIntegrity
		} else if !errors.Is(err, os.ErrNotExist) {
			return artifactacquisition.ConsumptionProof{}, artifactapp.ErrStoreIntegrity
		}
		return artifactacquisition.NewConsumptionProof(
			authorization.ReservationID(), authorization.PartialID(), authorization.Bytes(), s.filesystemID,
		)
	}
	if !errors.Is(partialError, os.ErrNotExist) {
		return artifactacquisition.ConsumptionProof{}, artifactapp.ErrStoreIntegrity
	}
	slot, _, err := openSecureLeafAt(s.reservationRoot, slotLeaf, false)
	if errors.Is(err, os.ErrNotExist) {
		return artifactacquisition.ConsumptionProof{}, artifactapp.ErrReservationOperation
	}
	if err != nil {
		return artifactacquisition.ConsumptionProof{}, artifactapp.ErrStoreIntegrity
	}
	defer slot.close()
	if err := slot.verifyExactSize(authorization.Bytes()); err != nil || !physicallyAllocated(slot.file, authorization.Bytes()) {
		return artifactacquisition.ConsumptionProof{}, artifactapp.ErrStoreIntegrity
	}
	partialDirectory, err := duplicateSecureDirectory(s.partialRoot)
	if err != nil {
		return artifactacquisition.ConsumptionProof{}, artifactapp.ErrStoreIntegrity
	}
	defer func() { _ = partialDirectory.Close() }()
	if err := slot.verifyExactSize(authorization.Bytes()); err != nil {
		return artifactacquisition.ConsumptionProof{}, artifactapp.ErrStoreIntegrity
	}
	if err := renameSecureNoReplace(slot, partialDirectory, partialLeaf); err != nil {
		return artifactacquisition.ConsumptionProof{}, sanitizeStoreError(err, true)
	}
	if durableSync(slot.directory) != nil || durableSync(partialDirectory) != nil {
		return artifactacquisition.ConsumptionProof{}, artifactapp.ErrStoreOperation
	}
	consumed, _, err := openSecureLeafAt(s.partialRoot, partialLeaf, false)
	if err != nil {
		return artifactacquisition.ConsumptionProof{}, artifactapp.ErrStoreIntegrity
	}
	defer consumed.close()
	if err := consumed.verifyExactSize(authorization.Bytes()); err != nil || !physicallyAllocated(consumed.file, authorization.Bytes()) {
		return artifactacquisition.ConsumptionProof{}, artifactapp.ErrStoreIntegrity
	}
	return artifactacquisition.NewConsumptionProof(
		authorization.ReservationID(), authorization.PartialID(), authorization.Bytes(), s.filesystemID,
	)
}

// Release removes only identities present in a journal-backed authorization.
// Missing owned files are an idempotent crash replay; unsafe objects fail closed.
func (s *Store) Release(ctx context.Context, authorization artifactacquisition.ReleaseAuthorization) error {
	if !s.beginOperation() {
		return artifactapp.ErrStoreIntegrity
	}
	defer s.endOperation()
	proof := authorization.Reservation()
	if ctx == nil || !authorization.Valid() || (proof.FilesystemID() != "" && proof.FilesystemID() != s.filesystemID) ||
		!safeToken(proof.ID(), "r-") {
		return artifactapp.ErrReservationOperation
	}
	var download uint64
	for _, allocation := range authorization.Allocations() {
		if err := ctx.Err(); err != nil {
			return errors.Join(artifactapp.ErrReservationOperation, err)
		}
		if !safeToken(allocation.SlotID(), "s-") || !safeToken(allocation.PartialID(), "p-") ||
			^uint64(0)-download < allocation.Bytes() {
			return artifactapp.ErrReservationOperation
		}
		download += allocation.Bytes()
		remove := removeSecureLeafAt
		if !authorization.Committed() {
			remove = removeSecureLeafAtMostAt
		}
		if err := remove(s.reservationRoot, allocation.SlotID()+".slot", allocation.Bytes()); err != nil {
			return sanitizeStoreError(err, true)
		}
		if err := remove(s.partialRoot, allocation.PartialID()+".part", allocation.Bytes()); err != nil {
			return sanitizeStoreError(err, true)
		}
	}
	if download != proof.Bytes() {
		return artifactapp.ErrReservationOperation
	}
	return nil
}

// InspectFinal verifies exact final size, final SHA-256, and all chunk digests.
func (s *Store) InspectFinal(ctx context.Context, artifact artifactacquisition.Artifact) (artifactacquisition.FinalProof, error) {
	if !s.beginOperation() {
		return artifactacquisition.FinalProof{}, artifactapp.ErrStoreIntegrity
	}
	defer s.endOperation()
	return s.inspectFinal(ctx, artifact)
}

func (s *Store) inspectFinal(ctx context.Context, artifact artifactacquisition.Artifact) (artifactacquisition.FinalProof, error) {
	if ctx == nil {
		return artifactacquisition.FinalProof{}, artifactapp.ErrStoreIntegrity
	}
	prefix, _, err := finalParts(artifact.ContentKey())
	if err != nil {
		return artifactacquisition.FinalProof{}, artifactapp.ErrStoreIntegrity
	}
	directory, leaf, err := s.finalLocation(artifact.ContentKey(), false)
	if err != nil {
		return artifactacquisition.FinalProof{}, err
	}
	defer func() { _ = directory.Close() }()
	file, _, err := openSecureLeafAt(directory, leaf, false)
	if errors.Is(err, os.ErrNotExist) {
		return artifactacquisition.FinalProof{}, artifactapp.ErrArtifactNotFound
	}
	if err != nil {
		return artifactacquisition.FinalProof{}, artifactapp.ErrStoreIntegrity
	}
	defer file.close()
	if err := verifyFile(ctx, file, artifact); err != nil {
		return artifactacquisition.FinalProof{}, err
	}
	if !secureChildDirectoryIdentity(s.casRoot, prefix, directory) || file.verifyExactSize(artifact.Size()) != nil {
		return artifactacquisition.FinalProof{}, artifactapp.ErrStoreIntegrity
	}
	return artifactacquisition.NewFinalProof(artifact.Digest(), artifact.Size(), artifact.ContentKey())
}

// VerifyChunk hashes one exact retained range.
func (s *Store) VerifyChunk(
	ctx context.Context,
	authorization artifactacquisition.PartialAuthorization,
	chunk artifactacquisition.Chunk,
) (releaseinventory.Digest, error) {
	if !s.beginOperation() {
		return releaseinventory.Digest{}, artifactapp.ErrStoreIntegrity
	}
	defer s.endOperation()
	leaf, err := partialLeaf(authorization)
	if err != nil {
		return releaseinventory.Digest{}, err
	}
	file, _, err := openSecureLeafAt(s.partialRoot, leaf, false)
	if errors.Is(err, os.ErrNotExist) {
		return releaseinventory.Digest{}, artifactapp.ErrArtifactNotFound
	}
	if err != nil {
		return releaseinventory.Digest{}, artifactapp.ErrStoreIntegrity
	}
	defer file.close()
	if ctx == nil || chunk.Offset()+chunk.Size() > authorization.Size() {
		return releaseinventory.Digest{}, artifactapp.ErrStoreIntegrity
	}
	chunkSize, sizeValid := uint64ToInt(chunk.Size())
	chunkOffset, offsetValid := uint64ToInt64(chunk.Offset())
	if !sizeValid || !offsetValid {
		return releaseinventory.Digest{}, artifactapp.ErrStoreIntegrity
	}
	value := make([]byte, chunkSize)
	if err := file.verifyPathIdentity(); err != nil {
		return releaseinventory.Digest{}, artifactapp.ErrStoreIntegrity
	}
	count, readError := file.file.ReadAt(value, chunkOffset)
	if readError != nil && !errors.Is(readError, io.EOF) || count != chunkSize {
		return releaseinventory.Digest{}, artifactapp.ErrArtifactNotFound
	}
	if err := ctx.Err(); err != nil {
		return releaseinventory.Digest{}, errors.Join(artifactapp.ErrStoreOperation, err)
	}
	if err := file.verifyExactSize(authorization.Size()); err != nil || !physicallyAllocated(file.file, authorization.Size()) {
		return releaseinventory.Digest{}, artifactapp.ErrStoreIntegrity
	}
	return releaseinventory.DigestBytes(value), nil
}

// WriteChunk double-checks signed bytes, writes one exact range, and fsyncs it.
func (s *Store) WriteChunk(
	ctx context.Context,
	authorization artifactacquisition.PartialAuthorization,
	chunk artifactacquisition.Chunk,
	value []byte,
) error {
	if !s.beginOperation() {
		return artifactapp.ErrStoreIntegrity
	}
	defer s.endOperation()
	leaf, err := partialLeaf(authorization)
	if err != nil || ctx == nil || chunk.Offset()+chunk.Size() > authorization.Size() || !chunk.VerifyBytes(value) {
		return artifactapp.ErrStoreIntegrity
	}
	file, _, err := openSecureLeafAt(s.partialRoot, leaf, false)
	if err != nil {
		return sanitizeStoreError(err, false)
	}
	defer file.close()
	if err := ctx.Err(); err != nil {
		return errors.Join(artifactapp.ErrStoreOperation, err)
	}
	chunkOffset, offsetValid := uint64ToInt64(chunk.Offset())
	if !offsetValid {
		return artifactapp.ErrStoreIntegrity
	}
	info, statError := file.file.Stat()
	currentSize, sizeValid := nonNegativeInt64(infoSize(info, statError))
	if statError != nil || !sizeValid || currentSize != authorization.Size() || file.verifyExactSize(currentSize) != nil ||
		!physicallyAllocated(file.file, authorization.Size()) {
		return artifactapp.ErrStoreIntegrity
	}
	count, err := file.file.WriteAt(value, chunkOffset)
	if err != nil || count != len(value) || durableSync(file.file) != nil {
		return artifactapp.ErrStoreOperation
	}
	info, err = file.file.Stat()
	fileSize, sizeValid := nonNegativeInt64(infoSize(info, err))
	if err != nil || !sizeValid || fileSize != authorization.Size() || file.verifyExactSize(fileSize) != nil ||
		!physicallyAllocated(file.file, authorization.Size()) {
		return artifactapp.ErrStoreIntegrity
	}
	return nil
}

// Finalize verifies the complete partial, fsyncs it, publishes with an atomic
// no-replace rename, then reopens and fully verifies the published CAS path
// before returning any FinalProof.
func (s *Store) Finalize(
	ctx context.Context,
	authorization artifactacquisition.PartialAuthorization,
	artifact artifactacquisition.Artifact,
) (artifactacquisition.FinalProof, error) {
	if !s.beginOperation() {
		return artifactacquisition.FinalProof{}, artifactapp.ErrStoreIntegrity
	}
	defer s.endOperation()
	if ctx == nil || !authorization.Valid() || authorization.Digest() != artifact.Digest() || authorization.Size() != artifact.Size() ||
		authorization.ContentKey() != artifact.ContentKey() {
		return artifactacquisition.FinalProof{}, artifactapp.ErrStoreIntegrity
	}
	finalPrefix, _, err := finalParts(artifact.ContentKey())
	if err != nil {
		return artifactacquisition.FinalProof{}, artifactapp.ErrStoreIntegrity
	}
	partialName, err := partialLeaf(authorization)
	if err != nil {
		return artifactacquisition.FinalProof{}, err
	}
	partial, _, err := openSecureLeafAt(s.partialRoot, partialName, false)
	if errors.Is(err, os.ErrNotExist) {
		return artifactacquisition.FinalProof{}, artifactapp.ErrArtifactNotFound
	}
	if err != nil {
		return artifactacquisition.FinalProof{}, artifactapp.ErrStoreIntegrity
	}
	if err := verifyFile(ctx, partial, artifact); err != nil {
		partial.close()
		return artifactacquisition.FinalProof{}, err
	}
	if err := durableSync(partial.file); err != nil || partial.verifyExactSize(artifact.Size()) != nil ||
		!physicallyAllocated(partial.file, artifact.Size()) {
		partial.close()
		return artifactacquisition.FinalProof{}, artifactapp.ErrStoreOperation
	}
	finalDirectory, finalName, err := s.finalLocation(artifact.ContentKey(), true)
	if err != nil {
		partial.close()
		return artifactacquisition.FinalProof{}, err
	}
	defer func() { _ = finalDirectory.Close() }()
	if err := partial.verifyExactSize(artifact.Size()); err != nil {
		partial.close()
		return artifactacquisition.FinalProof{}, artifactapp.ErrStoreIntegrity
	}
	if err := renameSecureNoReplace(partial, finalDirectory, finalName); err != nil {
		if !errors.Is(err, os.ErrExist) {
			partial.close()
			return artifactacquisition.FinalProof{}, artifactapp.ErrStoreOperation
		}
		partial.close()
		proof, inspectError := s.inspectFinal(ctx, artifact)
		if inspectError != nil {
			return artifactacquisition.FinalProof{}, artifactapp.ErrStoreIntegrity
		}
		if removeError := removeSecureLeafAt(s.partialRoot, partialName, artifact.Size()); removeError != nil {
			return artifactacquisition.FinalProof{}, artifactapp.ErrStoreOperation
		}
		return proof, nil
	}
	partial.close()
	if err := durableSync(finalDirectory); err != nil || durableSync(s.partialRoot) != nil {
		return artifactacquisition.FinalProof{}, artifactapp.ErrStoreOperation
	}
	if s.afterPublish != nil {
		s.afterPublish()
	}
	published, _, err := openSecureLeafAt(finalDirectory, finalName, false)
	if err != nil {
		return artifactacquisition.FinalProof{}, artifactapp.ErrStoreIntegrity
	}
	defer published.close()
	if err := verifyFile(ctx, published, artifact); err != nil || published.verifyExactSize(artifact.Size()) != nil ||
		!secureChildDirectoryIdentity(s.casRoot, finalPrefix, finalDirectory) {
		return artifactacquisition.FinalProof{}, artifactapp.ErrStoreIntegrity
	}
	return artifactacquisition.NewFinalProof(artifact.Digest(), artifact.Size(), artifact.ContentKey())
}

// ResetInvalidPartial re-establishes ownership, exact size, and native physical
// allocation proof without rewriting valid extents. The aggregate clears
// chunk evidence and the retry overwrites every signed chunk.
func (s *Store) ResetInvalidPartial(ctx context.Context, authorization artifactacquisition.PartialAuthorization) error {
	if !s.beginOperation() {
		return artifactapp.ErrStoreIntegrity
	}
	defer s.endOperation()
	leaf, err := partialLeaf(authorization)
	if err != nil || ctx == nil {
		return artifactapp.ErrStoreIntegrity
	}
	opened, _, err := openSecureLeafAt(s.partialRoot, leaf, false)
	if errors.Is(err, os.ErrNotExist) {
		return artifactapp.ErrStoreIntegrity
	}
	if err != nil {
		return artifactapp.ErrStoreIntegrity
	}
	defer opened.close()
	if opened.verifyExactSize(authorization.Size()) != nil || !physicallyAllocated(opened.file, authorization.Size()) {
		return artifactapp.ErrStoreIntegrity
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(artifactapp.ErrStoreOperation, err)
	}
	if durableSync(opened.file) != nil || opened.verifyExactSize(authorization.Size()) != nil ||
		!physicallyAllocated(opened.file, authorization.Size()) {
		return artifactapp.ErrStoreOperation
	}
	return nil
}

func partialLeaf(authorization artifactacquisition.PartialAuthorization) (string, error) {
	if !authorization.Valid() || !safeToken(authorization.PartialID(), "p-") {
		return "", artifactapp.ErrStoreIntegrity
	}
	return authorization.PartialID() + ".part", nil
}

func finalParts(contentKey string) (string, string, error) {
	parts := strings.Split(contentKey, "/")
	if len(parts) != 3 || parts[0] != "sha256" || len(parts[1]) != 2 || len(parts[2]) != 64 || !strings.HasPrefix(parts[2], parts[1]) {
		return "", "", artifactapp.ErrStoreIntegrity
	}
	return parts[1], parts[2], nil
}

func (s *Store) finalLocation(contentKey string, create bool) (*os.File, string, error) {
	prefix, leaf, err := finalParts(contentKey)
	if err != nil || !s.valid() {
		return nil, "", artifactapp.ErrStoreIntegrity
	}
	directory, err := openSecureChildDirectoryAt(s.casRoot, prefix, create)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", artifactapp.ErrArtifactNotFound
	}
	if err != nil {
		if create {
			return nil, "", artifactapp.ErrStoreOperation
		}
		return nil, "", artifactapp.ErrStoreIntegrity
	}
	if create && durableSync(s.casRoot) != nil {
		_ = directory.Close()
		return nil, "", artifactapp.ErrStoreOperation
	}
	return directory, leaf, nil
}

func secureDirectory(path string) error {
	directory, err := openSecureDirectory(path)
	if err != nil {
		return err
	}
	return directory.Close()
}

func ensureDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := secureDirectory(path); err != nil {
		if isNotDirectoryError(err) {
			return artifactapp.ErrStoreIntegrity
		}
		return err
	}
	return nil
}

func openSecureFile(path string, create bool) (*os.File, error) {
	opened, _, err := openSecureLeaf(filepath.Dir(path), filepath.Base(path), create)
	if err != nil {
		return nil, err
	}
	_ = opened.directory.Close()
	return opened.file, nil
}

func verifyFile(ctx context.Context, file *secureFile, artifact artifactacquisition.Artifact) error {
	if err := file.verifyExactSize(artifact.Size()); err != nil {
		return artifactapp.ErrStoreIntegrity
	}
	finalHasher := sha256.New()
	for _, chunk := range artifact.Chunks() {
		if err := ctx.Err(); err != nil {
			return errors.Join(artifactapp.ErrStoreOperation, err)
		}
		chunkSize, sizeValid := uint64ToInt(chunk.Size())
		chunkOffset, offsetValid := uint64ToInt64(chunk.Offset())
		if !sizeValid || !offsetValid {
			return artifactapp.ErrStoreIntegrity
		}
		value := make([]byte, chunkSize)
		if err := file.verifyExactSize(artifact.Size()); err != nil {
			return artifactapp.ErrStoreIntegrity
		}
		count, readError := file.file.ReadAt(value, chunkOffset)
		if readError != nil && !errors.Is(readError, io.EOF) || count != chunkSize || !chunk.VerifyBytes(value) {
			return artifactapp.ErrStoreIntegrity
		}
		_, _ = finalHasher.Write(value)
	}
	var observed releaseinventory.Digest
	copy(observed[:], finalHasher.Sum(nil))
	if !observed.Equal(artifact.Digest()) {
		return artifactapp.ErrStoreIntegrity
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := openSecureDirectory(path)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return durableSync(directory)
}

type reservationTarget struct {
	leaf  string
	bytes uint64
}

func validAllocations(request artifactapp.ReservationRequest) bool {
	if len(request.Allocations) == 0 || len(request.Allocations) > 4096 {
		return false
	}
	seenSlots := make(map[string]struct{}, len(request.Allocations))
	seenPartials := make(map[string]struct{}, len(request.Allocations))
	var total uint64
	for _, allocation := range request.Allocations {
		if !allocation.Valid() || allocation.ReservationID() != request.ReservationID ||
			!safeToken(allocation.SlotID(), "s-") || !safeToken(allocation.PartialID(), "p-") ||
			^uint64(0)-total < allocation.Bytes() {
			return false
		}
		if _, exists := seenSlots[allocation.SlotID()]; exists {
			return false
		}
		if _, exists := seenPartials[allocation.PartialID()]; exists {
			return false
		}
		seenSlots[allocation.SlotID()] = struct{}{}
		seenPartials[allocation.PartialID()] = struct{}{}
		total += allocation.Bytes()
	}
	return total == request.DownloadBytes && request.RequiredBytes == request.DownloadBytes
}

func sameAllocations(left, right []artifactacquisition.ReservationAllocation) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].ReservationID() != right[index].ReservationID() || left[index].SlotID() != right[index].SlotID() ||
			left[index].PartialID() != right[index].PartialID() || left[index].ArtifactID() != right[index].ArtifactID() ||
			left[index].Bytes() != right[index].Bytes() {
			return false
		}
	}
	return true
}

func (s *Store) missingReservationBytes(targets []reservationTarget) (uint64, error) {
	var missing uint64
	for _, target := range targets {
		if target.bytes == 0 || !safeLeaf(target.leaf) {
			return 0, artifactapp.ErrReservationOperation
		}
		opened, _, err := openSecureLeafAt(s.reservationRoot, target.leaf, false)
		if errors.Is(err, os.ErrNotExist) {
			if ^uint64(0)-missing < target.bytes {
				return 0, artifactapp.ErrReservationOperation
			}
			missing += target.bytes
			continue
		}
		if err != nil {
			return 0, artifactapp.ErrStoreIntegrity
		}
		info, statError := opened.file.Stat()
		observed, sizeValid := nonNegativeInt64(infoSize(info, statError))
		if statError != nil || !sizeValid || observed > target.bytes || opened.verifyPathIdentity() != nil {
			opened.close()
			return 0, artifactapp.ErrStoreIntegrity
		}
		opened.close()
		if ^uint64(0)-missing < target.bytes-observed {
			return 0, artifactapp.ErrReservationOperation
		}
		missing += target.bytes - observed
	}
	return missing, nil
}

func (s *Store) allocateReservationTarget(
	ctx context.Context,
	target reservationTarget,
) error {
	opened, created, err := openSecureLeafAt(s.reservationRoot, target.leaf, true)
	if err != nil {
		return err
	}
	defer opened.close()
	removeOnFailure := created
	defer func() {
		if removeOnFailure {
			_ = removeOpenSecureFile(opened)
		}
	}()
	info, err := opened.file.Stat()
	written, valid := nonNegativeInt64(infoSize(info, err))
	if err != nil || !valid || written > target.bytes || opened.verifyPathIdentity() != nil {
		return artifactapp.ErrStoreIntegrity
	}
	if written == target.bytes {
		if !physicallyAllocated(opened.file, target.bytes) {
			return artifactapp.ErrStoreIntegrity
		}
		removeOnFailure = false
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := allocatePhysical(ctx, opened.file, target.bytes); err != nil {
		return err
	}
	if opened.verifyExactSize(target.bytes) != nil ||
		!physicallyAllocated(opened.file, target.bytes) ||
		opened.syncDirectory() != nil {
		return artifactapp.ErrStoreOperation
	}
	removeOnFailure = false
	return nil
}

var (
	_ artifactapp.Store           = (*Store)(nil)
	_ artifactapp.ReservationPort = (*Store)(nil)
)
