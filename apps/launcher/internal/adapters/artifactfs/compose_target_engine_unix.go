//go:build darwin || linux || windows

package artifactfs

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

// ComposeBundleTargetEngine publishes the signed raw Compose bytes from CAS
// by atomically renaming the exact HostRelease reservation into place. The
// final target therefore consumes the already reserved extents and source and
// target digest/length remain byte-for-byte identical.
type ComposeBundleTargetEngine struct {
	store    *Store
	capacity *HostReleaseCapacity
}

// NewComposeBundleTargetEngine binds the verified CAS and HostRelease lease adapter.
func NewComposeBundleTargetEngine(
	store *Store,
	capacity *HostReleaseCapacity,
) (*ComposeBundleTargetEngine, error) {
	if store == nil || !store.valid() || capacity == nil {
		return nil, artifactapp.ErrExpandedTargetUnsupported
	}
	return &ComposeBundleTargetEngine{store: store, capacity: capacity}, nil
}

// MaterializeExpandedTarget writes verified CAS bytes into the reserved file
// and atomically moves that same inode to the signed release-relative path.
func (e *ComposeBundleTargetEngine) MaterializeExpandedTarget(
	ctx context.Context,
	authority artifactacquisition.ExpandedTargetAuthority,
) (artifactacquisition.ExpandedTargetObservation, error) {
	if err := e.begin(ctx, authority); err != nil {
		return artifactacquisition.ExpandedTargetObservation{}, err
	}
	defer e.end()
	lease := authority.ConsumeAuthorization().Lease()
	source, err := e.openSource(ctx, lease)
	if err != nil {
		return artifactacquisition.ExpandedTargetObservation{}, err
	}
	defer source.close()
	if target, targetErr := openComposeTarget(lease); targetErr == nil {
		defer target.close()
		allocated, verifyErr := verifyTargetFile(ctx, target, lease.Bytes(), lease.ExpectedTargetDigest())
		if verifyErr != nil {
			return artifactacquisition.ExpandedTargetObservation{}, verifyErr
		}
		if reservation, reservationErr := findHostReleaseReservation(lease); reservationErr == nil {
			reservation.close()
			return artifactacquisition.ExpandedTargetObservation{}, artifactapp.ErrExpandedTargetOperation
		} else if !errors.Is(reservationErr, os.ErrNotExist) {
			return artifactacquisition.ExpandedTargetObservation{}, artifactapp.ErrExpandedTargetOperation
		}
		return composeTargetObservation(authority, lease.Owner(), lease.Bytes(), allocated, false, true)
	} else if !errors.Is(targetErr, os.ErrNotExist) && !errors.Is(targetErr, artifactapp.ErrArtifactNotFound) {
		return artifactacquisition.ExpandedTargetObservation{}, artifactapp.ErrExpandedTargetOperation
	}

	reservation, err := findHostReleaseReservation(lease)
	if err != nil {
		return artifactacquisition.ExpandedTargetObservation{}, artifactapp.ErrExpandedTargetOperation
	}
	defer reservation.close()
	receipt, err := hostReleaseReservationReceipt(lease, reservation)
	if err != nil || receipt.Token() != authority.ConsumeAuthorization().ReceiptToken() ||
		receipt.AllocatedBytes() != authority.ConsumeAuthorization().ReceiptAllocatedBytes() {
		return artifactacquisition.ExpandedTargetObservation{}, artifactapp.ErrExpandedTargetOperation
	}
	if err := copyExactComposeSource(ctx, source, reservation, lease); err != nil {
		return artifactacquisition.ExpandedTargetObservation{}, err
	}
	targetDirectory, targetLeaf, err := composeTargetLocation(lease, true)
	if err != nil {
		return artifactacquisition.ExpandedTargetObservation{}, artifactapp.ErrExpandedTargetOperation
	}
	defer func() { _ = targetDirectory.Close() }()
	if err := renameSecureNoReplace(reservation, targetDirectory, targetLeaf); err != nil {
		return artifactacquisition.ExpandedTargetObservation{}, artifactapp.ErrExpandedTargetOperation
	}
	if durableSync(reservation.directory) != nil || durableSync(targetDirectory) != nil {
		return artifactacquisition.ExpandedTargetObservation{}, artifactapp.ErrExpandedTargetOperation
	}
	published, err := openSecureReadLeafAt(targetDirectory, targetLeaf)
	if err != nil {
		return artifactacquisition.ExpandedTargetObservation{}, artifactapp.ErrExpandedTargetOperation
	}
	defer published.close()
	allocated, err := verifyTargetFile(ctx, published, lease.Bytes(), lease.ExpectedTargetDigest())
	if err != nil || allocated != receipt.AllocatedBytes() {
		return artifactacquisition.ExpandedTargetObservation{}, artifactapp.ErrExpandedTargetOperation
	}
	return composeTargetObservation(authority, lease.Owner(), lease.Bytes(), allocated, false, true)
}

// InspectExpandedTarget returns exact read-only reservation and target state.
func (e *ComposeBundleTargetEngine) InspectExpandedTarget(
	ctx context.Context,
	authority artifactacquisition.ExpandedTargetAuthority,
	snapshot artifactacquisition.ExpandedTargetSnapshot,
) (artifactacquisition.ExpandedTargetObservation, error) {
	if err := e.begin(ctx, authority); err != nil {
		return artifactacquisition.ExpandedTargetObservation{}, err
	}
	defer e.end()
	lease := authority.ConsumeAuthorization().Lease()
	source, err := e.openSource(ctx, lease)
	if err != nil {
		return artifactacquisition.ExpandedTargetObservation{}, err
	}
	source.close()
	reservationPresent := false
	if reservation, reservationErr := findHostReleaseReservation(lease); reservationErr == nil {
		receipt, receiptErr := hostReleaseReservationReceipt(lease, reservation)
		reservation.close()
		if receiptErr != nil || receipt.Token() != authority.ConsumeAuthorization().ReceiptToken() ||
			receipt.AllocatedBytes() != authority.ConsumeAuthorization().ReceiptAllocatedBytes() {
			return artifactacquisition.ExpandedTargetObservation{}, artifactapp.ErrExpandedTargetOperation
		}
		reservationPresent = true
	} else if !errors.Is(reservationErr, os.ErrNotExist) {
		return artifactacquisition.ExpandedTargetObservation{}, artifactapp.ErrExpandedTargetOperation
	}
	owner := snapshot.CurrentOwner
	if artifactacquisition.ExpandedTargetState(snapshot.State) == artifactacquisition.ExpandedTargetTransferPending {
		owner = snapshot.NewOwner
	}
	target, targetErr := openComposeTarget(lease)
	if errors.Is(targetErr, os.ErrNotExist) || errors.Is(targetErr, artifactapp.ErrArtifactNotFound) {
		return composeTargetObservation(authority, owner, 0, 0, reservationPresent, false)
	}
	if targetErr != nil {
		return artifactacquisition.ExpandedTargetObservation{}, artifactapp.ErrExpandedTargetOperation
	}
	defer target.close()
	allocated, err := verifyTargetFile(ctx, target, lease.Bytes(), lease.ExpectedTargetDigest())
	if err != nil {
		return artifactacquisition.ExpandedTargetObservation{}, err
	}
	return composeTargetObservation(authority, owner, lease.Bytes(), allocated, reservationPresent, true)
}

// TransferExpandedTarget records no ambient filesystem ownership. The exact
// release path is generation-pinned; journal ownership changes only after the
// immutable target is reverified.
func (e *ComposeBundleTargetEngine) TransferExpandedTarget(
	ctx context.Context,
	authority artifactacquisition.ExpandedTargetAuthority,
	_ artifactacquisition.ExpandedTargetSnapshot,
	newOwner string,
) (artifactacquisition.ExpandedTargetObservation, error) {
	if err := e.begin(ctx, authority); err != nil {
		return artifactacquisition.ExpandedTargetObservation{}, err
	}
	defer e.end()
	lease := authority.ConsumeAuthorization().Lease()
	target, err := openComposeTarget(lease)
	if err != nil {
		return artifactacquisition.ExpandedTargetObservation{}, artifactapp.ErrExpandedTargetOperation
	}
	defer target.close()
	allocated, err := verifyTargetFile(ctx, target, lease.Bytes(), lease.ExpectedTargetDigest())
	if err != nil {
		return artifactacquisition.ExpandedTargetObservation{}, err
	}
	if reservation, reservationErr := findHostReleaseReservation(lease); reservationErr == nil {
		reservation.close()
		return artifactacquisition.ExpandedTargetObservation{}, artifactapp.ErrExpandedTargetOperation
	} else if !errors.Is(reservationErr, os.ErrNotExist) {
		return artifactacquisition.ExpandedTargetObservation{}, artifactapp.ErrExpandedTargetOperation
	}
	return composeTargetObservation(authority, newOwner, lease.Bytes(), allocated, false, true)
}

// RetireExpandedTarget deletes only a byte-exact signed target and/or exact
// reservation, then proves both names absent. Drift is never repaired.
func (e *ComposeBundleTargetEngine) RetireExpandedTarget(
	ctx context.Context,
	authority artifactacquisition.ExpandedTargetAuthority,
	snapshot artifactacquisition.ExpandedTargetSnapshot,
	authorization artifactacquisition.CapacityReleaseAuthorization,
) (artifactacquisition.ExpandedTargetObservation, error) {
	if !authorization.Valid() || authorization.Lease().ID() != authority.ConsumeAuthorization().Lease().ID() {
		return artifactacquisition.ExpandedTargetObservation{}, artifactapp.ErrExpandedTargetOperation
	}
	if err := e.begin(ctx, authority); err != nil {
		return artifactacquisition.ExpandedTargetObservation{}, err
	}
	defer e.end()
	lease := authority.ConsumeAuthorization().Lease()
	if target, targetErr := openComposeTarget(lease); targetErr == nil {
		if _, verifyErr := verifyTargetFile(ctx, target, lease.Bytes(), lease.ExpectedTargetDigest()); verifyErr != nil ||
			removeOpenSecureFile(target) != nil {
			target.close()
			return artifactacquisition.ExpandedTargetObservation{}, artifactapp.ErrExpandedTargetOperation
		}
		target.close()
	} else if !errors.Is(targetErr, os.ErrNotExist) && !errors.Is(targetErr, artifactapp.ErrArtifactNotFound) {
		return artifactacquisition.ExpandedTargetObservation{}, artifactapp.ErrExpandedTargetOperation
	}
	if reservation, reservationErr := findHostReleaseReservation(lease); reservationErr == nil {
		receipt, receiptErr := hostReleaseReservationReceipt(lease, reservation)
		if receiptErr != nil || receipt.Token() != authority.ConsumeAuthorization().ReceiptToken() ||
			receipt.AllocatedBytes() != authority.ConsumeAuthorization().ReceiptAllocatedBytes() ||
			removeOpenSecureFile(reservation) != nil {
			reservation.close()
			return artifactacquisition.ExpandedTargetObservation{}, artifactapp.ErrExpandedTargetOperation
		}
		reservation.close()
	} else if !errors.Is(reservationErr, os.ErrNotExist) {
		return artifactacquisition.ExpandedTargetObservation{}, artifactapp.ErrExpandedTargetOperation
	}
	if target, targetErr := openComposeTarget(lease); targetErr == nil {
		target.close()
		return artifactacquisition.ExpandedTargetObservation{}, artifactapp.ErrExpandedTargetOperation
	} else if !errors.Is(targetErr, os.ErrNotExist) && !errors.Is(targetErr, artifactapp.ErrArtifactNotFound) {
		return artifactacquisition.ExpandedTargetObservation{}, artifactapp.ErrExpandedTargetOperation
	}
	owner := snapshot.CurrentOwner
	if owner == "" {
		owner = lease.Owner()
	}
	return composeTargetObservation(authority, owner, snapshot.MeasuredBytes, snapshot.AllocatedBytes, false, false)
}

func (e *ComposeBundleTargetEngine) begin(
	ctx context.Context,
	authority artifactacquisition.ExpandedTargetAuthority,
) error {
	if e == nil || e.store == nil || e.capacity == nil || ctx == nil || ctx.Err() != nil || !authority.Valid() ||
		authority.ConsumeAuthorization().Lease().TargetKind() != releaseinventory.ExpandedTargetComposeBundle {
		return artifactapp.ErrExpandedTargetUnsupported
	}
	e.capacity.mu.Lock()
	if !e.store.beginOperation() {
		e.capacity.mu.Unlock()
		return artifactapp.ErrExpandedTargetOperation
	}
	return nil
}

func (e *ComposeBundleTargetEngine) end() {
	e.store.endOperation()
	e.capacity.mu.Unlock()
}

func (e *ComposeBundleTargetEngine) openSource(
	ctx context.Context,
	lease artifactacquisition.CapacityLease,
) (*secureFile, error) {
	hexDigest := lease.SourceDigest().Hex()
	directory, leaf, err := e.store.finalLocation("sha256/"+hexDigest[:2]+"/"+hexDigest, false)
	if err != nil {
		return nil, artifactapp.ErrExpandedTargetOperation
	}
	defer func() { _ = directory.Close() }()
	source, err := openSecureReadLeafAt(directory, leaf)
	if err != nil {
		return nil, artifactapp.ErrExpandedTargetOperation
	}
	if _, err := verifyTargetFile(ctx, source, lease.SourceBytes(), lease.SourceDigest()); err != nil {
		source.close()
		return nil, err
	}
	return source, nil
}

func composeTargetLocation(
	lease artifactacquisition.CapacityLease,
	create bool,
) (*os.File, string, error) {
	parts := strings.Split(lease.TargetStorageID(), "/")
	if !validHostReleaseLease(lease) || len(parts) < 2 {
		return nil, "", artifactapp.ErrExpandedTargetUnsupported
	}
	directory, err := openSecureDirectory(lease.TargetRoot())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, "", os.ErrNotExist
		}
		return nil, "", artifactapp.ErrExpandedTargetOperation
	}
	for _, component := range parts[:len(parts)-1] {
		next, childErr := openSecureChildDirectoryAt(directory, component, create)
		_ = directory.Close()
		if childErr != nil {
			if errors.Is(childErr, os.ErrNotExist) {
				return nil, "", os.ErrNotExist
			}
			return nil, "", artifactapp.ErrExpandedTargetOperation
		}
		directory = next
	}
	return directory, parts[len(parts)-1], nil
}

func openComposeTarget(lease artifactacquisition.CapacityLease) (*secureFile, error) {
	directory, leaf, err := composeTargetLocation(lease, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = directory.Close() }()
	target, err := openSecureReadLeafAt(directory, leaf)
	if errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	return target, err
}

func copyExactComposeSource(
	ctx context.Context,
	source *secureFile,
	destination *secureFile,
	lease artifactacquisition.CapacityLease,
) error {
	expectedBytes, valid := uint64ToInt64(lease.SourceBytes())
	if ctx == nil || source == nil || destination == nil || !valid || source.verifyExactSize(lease.SourceBytes()) != nil ||
		destination.verifyExactSize(lease.Bytes()) != nil || lease.SourceBytes() != lease.Bytes() {
		return artifactapp.ErrExpandedTargetOperation
	}
	if _, err := source.file.Seek(0, io.SeekStart); err != nil {
		return artifactapp.ErrExpandedTargetOperation
	}
	if _, err := destination.file.Seek(0, io.SeekStart); err != nil {
		return artifactapp.ErrExpandedTargetOperation
	}
	written, err := io.CopyBuffer(destination.file, io.LimitReader(source.file, expectedBytes), make([]byte, 64*1024))
	if err != nil || written != expectedBytes || ctx.Err() != nil || durableSync(destination.file) != nil {
		return artifactapp.ErrExpandedTargetOperation
	}
	if _, err := verifyTargetFile(ctx, destination, lease.Bytes(), lease.ExpectedTargetDigest()); err != nil {
		return err
	}
	return nil
}

func verifyTargetFile(
	ctx context.Context,
	file *secureFile,
	bytes uint64,
	expected releaseinventory.Digest,
) (uint64, error) {
	expectedBytes, valid := uint64ToInt64(bytes)
	if ctx == nil || file == nil || expected.IsZero() || !valid || file.verifyExactSize(bytes) != nil {
		return 0, artifactapp.ErrExpandedTargetOperation
	}
	if _, err := file.file.Seek(0, io.SeekStart); err != nil {
		return 0, artifactapp.ErrExpandedTargetOperation
	}
	hasher := sha256.New()
	read, err := io.CopyBuffer(hasher, io.LimitReader(file.file, expectedBytes), make([]byte, 64*1024))
	if err != nil || read != expectedBytes || ctx.Err() != nil {
		return 0, artifactapp.ErrExpandedTargetOperation
	}
	var observed releaseinventory.Digest
	copy(observed[:], hasher.Sum(nil))
	info, statErr := file.file.Stat()
	allocated, proven := allocatedFileBytesDescriptor(file.file, info)
	if statErr != nil || !observed.Equal(expected) || !proven || allocated == 0 {
		return 0, artifactapp.ErrExpandedTargetOperation
	}
	return allocated, nil
}

func composeTargetObservation(
	authority artifactacquisition.ExpandedTargetAuthority,
	owner string,
	logical uint64,
	allocated uint64,
	reservationPresent bool,
	targetPresent bool,
) (artifactacquisition.ExpandedTargetObservation, error) {
	lease := authority.ConsumeAuthorization().Lease()
	return artifactacquisition.NewExpandedTargetObservation(artifactacquisition.ExpandedTargetObservationInput{
		LeaseID: lease.ID(), ReceiptToken: authority.ConsumeAuthorization().ReceiptToken(), PlanDigest: lease.PlanDigest(),
		PoolID: lease.Pool().ID(), PoolKind: lease.Pool().Kind(), SourceDigest: lease.SourceDigest(), SourceBytes: lease.SourceBytes(),
		TargetDigest: lease.ExpectedTargetDigest(), ReservedBytes: lease.Bytes(),
		ReservedAllocatedBytes: authority.ConsumeAuthorization().ReceiptAllocatedBytes(), TargetKind: authority.TargetKind(),
		TargetStorageID: authority.TargetStorageID(), TargetRoot: lease.TargetRoot(), TargetAuthorityDigest: authority.Digest(),
		Owner: owner, MeasuredBytes: logical, AllocatedBytes: allocated,
		ReservationPresent: reservationPresent, TargetPresent: targetPresent,
	})
}

var _ artifactapp.ExpandedTargetEngine = (*ComposeBundleTargetEngine)(nil)
