//go:build darwin || linux || windows

package artifactfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

const hostReleaseReservationDirectory = ".agentmemory-release-capacity"

// HostReleaseCapacity reserves physical bytes on the exact filesystem that
// backs a parent-plan release directory. It never redirects release bytes to
// Docker storage or the CAS filesystem.
type HostReleaseCapacity struct {
	mu sync.Mutex
}

// NewHostReleaseCapacity constructs the local host release lease adapter.
func NewHostReleaseCapacity() *HostReleaseCapacity { return &HostReleaseCapacity{} }

// ReserveLease creates or revalidates a deterministic owner-only physical file
// before any target directory write. The nearest secure existing ancestor is
// used when the release directory has not been created yet.
func (a *HostReleaseCapacity) ReserveLease(
	ctx context.Context,
	lease artifactacquisition.CapacityLease,
) (artifactacquisition.LeaseReceipt, error) {
	if a == nil || ctx == nil || ctx.Err() != nil || !validHostReleaseLease(lease) {
		return artifactacquisition.LeaseReceipt{}, artifactapp.ErrReservationUnsupported
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if reservation, err := findHostReleaseReservation(lease); err == nil {
		defer reservation.close()
		return hostReleaseReservationReceipt(lease, reservation)
	} else if !errors.Is(err, os.ErrNotExist) {
		return artifactacquisition.LeaseReceipt{}, artifactapp.ErrReservationOperation
	}
	anchor, err := openNearestSecureAncestor(lease.TargetRoot())
	if err != nil {
		return artifactacquisition.LeaseReceipt{}, artifactapp.ErrReservationUnsupported
	}
	defer func() { _ = anchor.Close() }()
	pool, err := attestHostReleasePool(lease.TargetRoot())
	if err != nil || pool != lease.Pool() {
		return artifactacquisition.LeaseReceipt{}, artifactapp.ErrReservationUnsupported
	}
	available, err := availableBytesDescriptor(anchor)
	if err != nil || available < lease.Bytes() {
		return artifactacquisition.LeaseReceipt{}, artifactapp.ErrReservationOperation
	}
	directory, err := openSecureChildDirectoryAt(anchor, hostReleaseReservationDirectory, true)
	if err != nil {
		return artifactacquisition.LeaseReceipt{}, artifactapp.ErrReservationOperation
	}
	defer func() { _ = directory.Close() }()
	reservation, created, err := openSecureLeafAt(directory, hostReleaseReservationLeaf(lease), true)
	if err != nil {
		return artifactacquisition.LeaseReceipt{}, artifactapp.ErrReservationOperation
	}
	defer reservation.close()
	removeOnFailure := created
	defer func() {
		if removeOnFailure {
			_ = removeOpenSecureFile(reservation)
		}
	}()
	if err := ctx.Err(); err != nil || allocatePhysical(ctx, reservation.file, lease.Bytes()) != nil ||
		reservation.syncDirectory() != nil {
		return artifactacquisition.LeaseReceipt{}, artifactapp.ErrReservationOperation
	}
	receipt, err := hostReleaseReservationReceipt(lease, reservation)
	if err != nil {
		return artifactacquisition.LeaseReceipt{}, err
	}
	removeOnFailure = false
	return receipt, nil
}

// RevalidateLease proves the exact reservation file and allocated blocks
// without creating, extending, moving, or repairing any path.
func (a *HostReleaseCapacity) RevalidateLease(
	ctx context.Context,
	lease artifactacquisition.CapacityLease,
) (artifactacquisition.LeaseReceipt, error) {
	if a == nil || ctx == nil || ctx.Err() != nil || !validHostReleaseLease(lease) {
		return artifactacquisition.LeaseReceipt{}, artifactapp.ErrReservationUnsupported
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	reservation, err := findHostReleaseReservation(lease)
	if err != nil {
		return artifactacquisition.LeaseReceipt{}, artifactapp.ErrReservationOperation
	}
	defer reservation.close()
	return hostReleaseReservationReceipt(lease, reservation)
}

// TransferLease is intentionally not a host-filesystem metadata mutation.
// Expanded target ownership is journaled and handled by ExpandedTargets.
func (a *HostReleaseCapacity) TransferLease(
	context.Context,
	artifactacquisition.CapacityLease,
	string,
) (artifactacquisition.CapacityMutationProof, error) {
	return artifactacquisition.CapacityMutationProof{}, artifactapp.ErrReservationUnsupported
}

// ReleaseCapacity removes only an exact untouched reservation. Consumed target
// retirement is handled by the target engine using the expanded journal.
func (a *HostReleaseCapacity) ReleaseCapacity(
	ctx context.Context,
	authorization artifactacquisition.CapacityReleaseAuthorization,
) (artifactacquisition.LeaseReceipt, error) {
	if a == nil || ctx == nil || ctx.Err() != nil || !authorization.Valid() ||
		!validHostReleaseLease(authorization.Lease()) || !hostReleaseReservationState(authorization.FromState()) {
		return artifactacquisition.LeaseReceipt{}, artifactapp.ErrReservationUnsupported
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	lease := authorization.Lease()
	token := hostReleaseReservationToken(lease)
	if authorization.ReceiptToken() != "" && authorization.ReceiptToken() != token {
		return artifactacquisition.LeaseReceipt{}, artifactapp.ErrReservationOperation
	}
	allocated := lease.Bytes()
	reservation, err := findHostReleaseReservation(lease)
	switch {
	case err == nil:
		receipt, receiptErr := hostReleaseReservationReceipt(lease, reservation)
		if receiptErr != nil || authorization.ReceiptAllocatedBytes() != 0 &&
			receipt.AllocatedBytes() != authorization.ReceiptAllocatedBytes() {
			reservation.close()
			return artifactacquisition.LeaseReceipt{}, artifactapp.ErrReservationOperation
		}
		allocated = receipt.AllocatedBytes()
		if removeOpenSecureFile(reservation) != nil {
			reservation.close()
			return artifactacquisition.LeaseReceipt{}, artifactapp.ErrReservationOperation
		}
		reservation.close()
	case !errors.Is(err, os.ErrNotExist):
		return artifactacquisition.LeaseReceipt{}, artifactapp.ErrReservationOperation
	case authorization.ReceiptAllocatedBytes() != 0:
		allocated = authorization.ReceiptAllocatedBytes()
	}
	return artifactacquisition.NewMeasuredLeaseReceipt(
		lease.ID(), lease.Pool(), lease.Bytes(), allocated, token, false,
	)
}

func validHostReleaseLease(lease artifactacquisition.CapacityLease) bool {
	if !lease.Valid() || lease.Purpose() != artifactacquisition.LeaseExpanded ||
		lease.Pool().Kind() != artifactapp.CapacityHostRelease ||
		lease.TargetKind() != releaseinventory.ExpandedTargetComposeBundle ||
		lease.TargetRoot() == "" || !filepath.IsAbs(lease.TargetRoot()) || filepath.Clean(lease.TargetRoot()) != lease.TargetRoot() {
		return false
	}
	pool, err := attestHostReleasePool(lease.TargetRoot())
	return err == nil && pool == lease.Pool()
}

func hostReleaseReservationState(state artifactacquisition.LeaseState) bool {
	return state == artifactacquisition.LeaseReservePending || state == artifactacquisition.LeaseReserved ||
		state == artifactacquisition.LeaseConsumePending
}

func hostReleaseReservationLeaf(lease artifactacquisition.CapacityLease) string {
	return lease.ID() + ".reserve"
}

func hostReleaseReservationToken(lease artifactacquisition.CapacityLease) string {
	digest := releaseinventory.DigestBytes([]byte(strings.Join([]string{
		"agentmemory-host-release-reservation-v1", lease.ID(), lease.PlanDigest().Hex(),
		lease.Pool().ID(), lease.TargetRoot(), lease.TargetStorageID(),
	}, "\x00")))
	return "r-" + digest.Hex()
}

func hostReleaseReservationReceipt(
	lease artifactacquisition.CapacityLease,
	reservation *secureFile,
) (artifactacquisition.LeaseReceipt, error) {
	if reservation == nil || reservation.verifyExactSize(lease.Bytes()) != nil ||
		!physicallyAllocated(reservation.file, lease.Bytes()) {
		return artifactacquisition.LeaseReceipt{}, artifactapp.ErrReservationOperation
	}
	info, err := reservation.file.Stat()
	allocated, proven := allocatedFileBytesDescriptor(reservation.file, info)
	if err != nil || !proven || allocated < lease.Bytes() {
		return artifactacquisition.LeaseReceipt{}, artifactapp.ErrReservationOperation
	}
	return artifactacquisition.NewMeasuredLeaseReceipt(
		lease.ID(), lease.Pool(), lease.Bytes(), allocated, hostReleaseReservationToken(lease), true,
	)
}

func findHostReleaseReservation(lease artifactacquisition.CapacityLease) (*secureFile, error) {
	if !validHostReleaseLease(lease) {
		return nil, artifactapp.ErrReservationUnsupported
	}
	leaf := hostReleaseReservationLeaf(lease)
	secureAncestorSeen := false
	for candidate := lease.TargetRoot(); ; candidate = filepath.Dir(candidate) {
		info, err := os.Lstat(candidate)
		switch {
		case err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0:
			parent, openErr := openSecureDirectory(candidate)
			if openErr != nil {
				if secureAncestorSeen {
					return nil, os.ErrNotExist
				}
				return nil, openErr
			}
			secureAncestorSeen = true
			directory, directoryErr := openSecureChildDirectoryAt(parent, hostReleaseReservationDirectory, false)
			_ = parent.Close()
			if directoryErr == nil {
				reservation, _, reservationErr := openSecureLeafAt(directory, leaf, false)
				_ = directory.Close()
				if reservationErr == nil {
					return reservation, nil
				}
				if !errors.Is(reservationErr, os.ErrNotExist) {
					return nil, reservationErr
				}
			} else if !errors.Is(directoryErr, os.ErrNotExist) {
				return nil, directoryErr
			}
		case err == nil:
			return nil, artifactapp.ErrStoreIntegrity
		case !errors.Is(err, os.ErrNotExist):
			return nil, err
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			return nil, os.ErrNotExist
		}
	}
}

var _ artifactapp.CapacityLeasePort = (*HostReleaseCapacity)(nil)
