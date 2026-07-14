//go:build linux

package capacityhelper

import (
	"context"
	"errors"
	"io"
	"os"
	"sort"
	"time"

	"golang.org/x/sys/unix"
)

const (
	metadataName          = "lease.json"
	metadataTemporaryName = ".lease.json.next"
	reservationName       = "reserved.bin"
	rootLockMaximumWait   = 30 * time.Second
	rootLockRetryInterval = 10 * time.Millisecond
)

// LinuxStore uses only the fixed /capacity mount and Linux descriptor APIs.
// It never accepts a caller-supplied path.
type LinuxStore struct {
	root string
}

// NewLinuxStore constructs the production fixed-mount physical store.
func NewLinuxStore() *LinuxStore { return &LinuxStore{root: MountTarget} }

func newLinuxStoreAt(root string) *LinuxStore { return &LinuxStore{root: root} }

// Reserve writes pending metadata before allocation, uses fallocate, fsyncs
// file and directory state, and proves exact length plus non-sparse blocks.
func (s *LinuxStore) Reserve(ctx context.Context, request Request) (Observation, error) {
	if !request.Valid() || request.Operation() != OperationReserve {
		return Observation{}, errors.New("capacity reservation request is invalid")
	}
	return s.withLockedRoot(ctx, func(rootFD int) (Observation, error) {
		if err := recoverMetadata(rootFD, request); err != nil {
			return Observation{}, err
		}
		metadata, present, err := readMetadata(rootFD)
		if err != nil {
			return Observation{}, err
		}
		if !present {
			if err := requireEntries(rootFD); err != nil {
				return Observation{}, err
			}
			metadata, err = NewMetadata(request, request.Owner(), MetadataReservePending)
			if err != nil || writeMetadata(rootFD, metadata) != nil {
				return Observation{}, errors.New("write pending capacity metadata")
			}
		} else if !metadata.MatchesImmutable(request) || metadata.Owner != request.Owner() ||
			(metadata.State != string(MetadataReservePending) && metadata.State != string(MetadataReserved)) {
			return Observation{}, errors.New("capacity reservation metadata mismatch")
		}

		file, err := openReservation(rootFD, true)
		if err != nil {
			return Observation{}, err
		}
		defer func() { _ = file.Close() }()
		before, err := availableBytes(rootFD)
		if err != nil {
			return Observation{}, err
		}
		_, allocatedBefore, err := measureReservation(file)
		if err != nil {
			return Observation{}, err
		}
		needed := uint64(0)
		if allocatedBefore < request.Bytes() {
			needed = request.Bytes() - allocatedBefore
		}
		if before < needed {
			return Observation{}, errors.New("insufficient physical capacity")
		}
		allocationLength, err := fallocateLength(request.Bytes())
		if err != nil {
			return Observation{}, err
		}
		if err := unix.Fallocate(int(file.Fd()), 0, 0, allocationLength); err != nil {
			return Observation{}, errors.New("physical capacity allocation failed")
		}
		if err := file.Sync(); err != nil {
			return Observation{}, errors.New("sync physical capacity allocation")
		}
		fileSize, allocated, err := verifyExactReservation(file, request.Bytes())
		if err != nil {
			return Observation{}, err
		}
		if metadata.State != string(MetadataReserved) {
			metadata, err = NewMetadata(request, request.Owner(), MetadataReserved)
			if err != nil || writeMetadata(rootFD, metadata) != nil {
				return Observation{}, errors.New("commit capacity metadata")
			}
		}
		if err := requireEntries(rootFD, metadataName, reservationName); err != nil {
			return Observation{}, err
		}
		after, err := availableBytes(rootFD)
		if err != nil {
			return Observation{}, err
		}
		return observation(metadata, fileSize, allocated, after), nil
	})
}

// Inspect revalidates exact canonical metadata, ownership, file size,
// allocated blocks, and statfs state without repairing untrusted drift.
func (s *LinuxStore) Inspect(ctx context.Context, request Request) (Observation, error) {
	if !request.Valid() || request.Operation() != OperationInspect {
		return Observation{}, errors.New("capacity inspection request is invalid")
	}
	return s.withLockedRoot(ctx, func(rootFD int) (Observation, error) {
		if err := recoverMetadata(rootFD, request); err != nil {
			return Observation{}, err
		}
		metadata, present, err := readMetadata(rootFD)
		if err != nil || !present || !metadata.MatchesImmutable(request) ||
			metadata.Owner != request.Owner() || metadata.State != string(MetadataReserved) {
			return Observation{}, errors.New("capacity metadata cannot be revalidated")
		}
		if err := requireEntries(rootFD, metadataName, reservationName); err != nil {
			return Observation{}, err
		}
		file, err := openReservation(rootFD, false)
		if err != nil {
			return Observation{}, err
		}
		defer func() { _ = file.Close() }()
		fileSize, allocated, err := verifyExactReservation(file, request.Bytes())
		if err != nil {
			return Observation{}, err
		}
		available, err := availableBytes(rootFD)
		if err != nil {
			return Observation{}, err
		}
		return observation(metadata, fileSize, allocated, available), nil
	})
}

// Transfer changes only the exact metadata owner after revalidating the whole
// physical reservation. Replay accepts only the same target owner.
func (s *LinuxStore) Transfer(ctx context.Context, request Request) (Observation, error) {
	if !request.Valid() || request.Operation() != OperationTransfer {
		return Observation{}, errors.New("capacity transfer request is invalid")
	}
	return s.withLockedRoot(ctx, func(rootFD int) (Observation, error) {
		if err := recoverMetadata(rootFD, request); err != nil {
			return Observation{}, err
		}
		metadata, present, err := readMetadata(rootFD)
		if err != nil || !present || !metadata.MatchesImmutable(request) {
			return Observation{}, errors.New("capacity transfer metadata is invalid")
		}
		switch MetadataState(metadata.State) {
		case MetadataReserved:
			if metadata.Owner != request.Owner() {
				return Observation{}, errors.New("capacity transfer owner mismatch")
			}
			metadata, err = NewMetadata(request, request.NewOwner(), MetadataTransferred)
			if err != nil || writeMetadata(rootFD, metadata) != nil {
				return Observation{}, errors.New("commit capacity owner transfer")
			}
		case MetadataTransferred:
			if metadata.Owner != request.NewOwner() {
				return Observation{}, errors.New("capacity transfer replay owner mismatch")
			}
		case MetadataReservePending:
			return Observation{}, errors.New("pending reservation cannot be transferred")
		default:
			return Observation{}, errors.New("unknown capacity metadata state")
		}
		if err := requireEntries(rootFD, metadataName, reservationName); err != nil {
			return Observation{}, err
		}
		file, err := openReservation(rootFD, false)
		if err != nil {
			return Observation{}, err
		}
		defer func() { _ = file.Close() }()
		fileSize, allocated, err := verifyExactReservation(file, request.Bytes())
		if err != nil {
			return Observation{}, err
		}
		available, err := availableBytes(rootFD)
		if err != nil {
			return Observation{}, err
		}
		return observation(metadata, fileSize, allocated, available), nil
	})
}

// ActivateProjection consumes a fully proved reservation into an empty
// generation-pinned volume. The capacity files are removed in a replay-safe
// order and the directory is synced after each unlink so the secret projector
// can require an exact empty output mount.
func (s *LinuxStore) ActivateProjection(ctx context.Context, request Request) (Observation, error) {
	if !request.Valid() || request.Operation() != OperationActivateProjection {
		return Observation{}, errors.New("capacity projection activation request is invalid")
	}
	return s.withLockedRoot(ctx, func(rootFD int) (Observation, error) {
		if err := recoverMetadata(rootFD, request); err != nil {
			return Observation{}, err
		}
		metadata, present, err := readMetadata(rootFD)
		if err != nil {
			return Observation{}, err
		}
		if present {
			if !metadata.MatchesImmutable(request) || metadata.Owner != request.Owner() ||
				metadata.State != string(MetadataReserved) {
				return Observation{}, errors.New("capacity projection metadata is invalid")
			}
			reservationPresent, presenceError := entryPresent(rootFD, reservationName)
			if presenceError != nil {
				return Observation{}, presenceError
			}
			if reservationPresent {
				if err := requireEntries(rootFD, metadataName, reservationName); err != nil {
					return Observation{}, err
				}
				file, openError := openReservation(rootFD, false)
				if openError != nil {
					return Observation{}, openError
				}
				_, _, verifyError := verifyExactReservation(file, request.Bytes())
				closeError := file.Close()
				if verifyError != nil || closeError != nil {
					return Observation{}, errors.New("capacity projection reservation is invalid")
				}
				if err := unix.Unlinkat(rootFD, reservationName, 0); err != nil || unix.Fsync(rootFD) != nil {
					return Observation{}, errors.New("consume capacity projection reservation")
				}
			} else if err := requireEntries(rootFD, metadataName); err != nil {
				// This is the only accepted interrupted state: reserved.bin was
				// durably removed but its authenticating metadata remains.
				return Observation{}, err
			}
			if err := unix.Unlinkat(rootFD, metadataName, 0); err != nil || unix.Fsync(rootFD) != nil {
				return Observation{}, errors.New("consume capacity projection metadata")
			}
		} else if err := requireEntries(rootFD); err != nil {
			// An empty directory is the completed replay state. Any projected
			// or foreign entry fails closed at this pre-projection boundary.
			return Observation{}, err
		}
		if err := requireEntries(rootFD); err != nil {
			return Observation{}, err
		}
		activated, err := NewMetadata(request, request.NewOwner(), MetadataTransferred)
		if err != nil {
			return Observation{}, err
		}
		available, err := availableBytes(rootFD)
		if err != nil {
			return Observation{}, err
		}
		return Observation{
			AvailableBytes: available, Metadata: activated,
			Owner: request.NewOwner(), State: "projection-ready",
		}, nil
	})
}

// DeleteProof proves the exact authorized owner/state and physical contents.
// Docker performs the later non-force volume removal after this mount exits.
func (s *LinuxStore) DeleteProof(ctx context.Context, request Request) (Observation, error) {
	if !request.Valid() || request.Operation() != OperationDeleteProof {
		return Observation{}, errors.New("capacity delete request is invalid")
	}
	return s.withLockedRoot(ctx, func(rootFD int) (Observation, error) {
		if err := recoverMetadata(rootFD, request); err != nil {
			return Observation{}, err
		}
		metadata, present, err := readMetadata(rootFD)
		if err != nil {
			return Observation{}, err
		}
		if !present {
			if request.PriorState() != PriorReservePending || requireEntries(rootFD) != nil {
				return Observation{}, errors.New("missing capacity metadata is not authorized")
			}
			metadata, err = NewMetadata(request, request.Owner(), MetadataReservePending)
			if err != nil || writeMetadata(rootFD, metadata) != nil {
				return Observation{}, errors.New("anchor empty pending capacity volume")
			}
		}
		if !metadata.MatchesImmutable(request) || !deleteOwnerAndStateAllowed(request, metadata) {
			return Observation{}, errors.New("capacity delete authority does not match metadata")
		}

		fileSize, allocated := uint64(0), uint64(0)
		reservationPresent, err := entryPresent(rootFD, reservationName)
		if err != nil {
			return Observation{}, err
		}
		if reservationPresent {
			file, openError := openReservation(rootFD, false)
			if openError != nil {
				return Observation{}, openError
			}
			defer func() { _ = file.Close() }()
			if metadata.State == string(MetadataReservePending) && request.PriorState() == PriorReservePending {
				fileSize, allocated, err = measureReservation(file)
				if err != nil || fileSize > request.Bytes() || allocated > request.Bytes()+4096 {
					return Observation{}, errors.New("interrupted reservation layout is invalid")
				}
			} else {
				fileSize, allocated, err = verifyExactReservation(file, request.Bytes())
				if err != nil {
					return Observation{}, err
				}
			}
		} else if metadata.State != string(MetadataReservePending) || request.PriorState() != PriorReservePending {
			return Observation{}, errors.New("authorized reservation bytes are missing")
		}
		expectedEntries := []string{metadataName}
		if reservationPresent {
			expectedEntries = append(expectedEntries, reservationName)
		}
		if err := requireEntries(rootFD, expectedEntries...); err != nil {
			return Observation{}, err
		}
		available, err := availableBytes(rootFD)
		if err != nil {
			return Observation{}, err
		}
		result := observation(metadata, fileSize, allocated, available)
		result.State = "delete-approved"
		return result, nil
	})
}

func (s *LinuxStore) withLockedRoot(
	ctx context.Context,
	operation func(int) (Observation, error),
) (Observation, error) {
	if s == nil || s.root == "" || ctx == nil || operation == nil {
		return Observation{}, errors.New("capacity store is invalid")
	}
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	rootFD, err := unix.Open(s.root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return Observation{}, errors.New("open fixed capacity volume")
	}
	defer func() { _ = unix.Close(rootFD) }()
	if err := validateRootDirectory(rootFD); err != nil {
		return Observation{}, err
	}
	if err := acquireRootLock(ctx, rootFD); err != nil {
		return Observation{}, errors.Join(errors.New("lock capacity volume"), err)
	}
	defer unix.Flock(rootFD, unix.LOCK_UN) //nolint:errcheck // Unlock cannot change the completed durable result.
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	result, err := operation(rootFD)
	if err != nil {
		return Observation{}, err
	}
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	return result, nil
}

func validateRootDirectory(rootFD int) error {
	var stat unix.Stat_t
	effectiveUID, effectiveGID := os.Geteuid(), os.Getegid()
	if effectiveUID < 0 || effectiveGID < 0 {
		return errors.New("capacity process identity is invalid")
	}
	// G115 is guarded by the kernel UID/GID domains and explicit non-negative check.
	expectedUID := uint32(effectiveUID) //nolint:gosec
	expectedGID := uint32(effectiveGID) //nolint:gosec
	if err := unix.Fstat(rootFD, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		stat.Mode&0o022 != 0 || stat.Uid != expectedUID || stat.Gid != expectedGID {
		return errors.New("capacity volume identity or permissions are unsafe")
	}
	return nil
}

func acquireRootLock(ctx context.Context, rootFD int) error {
	lockContext, cancel := context.WithTimeout(ctx, rootLockMaximumWait)
	defer cancel()
	for {
		err := unix.Flock(rootFD, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return errors.New("acquire capacity volume lock")
		}
		timer := time.NewTimer(rootLockRetryInterval)
		select {
		case <-lockContext.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return lockContext.Err()
		case <-timer.C:
		}
	}
}

func recoverMetadata(rootFD int, request Request) error {
	temporaryPresent, err := entryPresent(rootFD, metadataTemporaryName)
	if err != nil || !temporaryPresent {
		return err
	}
	temporary, err := readMetadataNamed(rootFD, metadataTemporaryName)
	if err != nil || !temporary.MatchesImmutable(request) {
		return errors.New("capacity metadata temporary file is invalid")
	}
	current, currentPresent, err := readMetadata(rootFD)
	if err != nil {
		return err
	}
	if currentPresent {
		if !current.MatchesImmutable(request) || metadataRank(temporary) < metadataRank(current) {
			return errors.New("capacity metadata journal regresses state")
		}
	}
	if !recoveryOwnerAllowed(request, temporary) {
		return errors.New("capacity metadata journal owner is invalid")
	}
	if err := unix.Renameat(rootFD, metadataTemporaryName, rootFD, metadataName); err != nil || unix.Fsync(rootFD) != nil {
		return errors.New("recover capacity metadata journal")
	}
	return nil
}

func recoveryOwnerAllowed(request Request, metadata Metadata) bool {
	switch MetadataState(metadata.State) {
	case MetadataReservePending, MetadataReserved:
		return metadata.Owner == request.Owner()
	case MetadataTransferred:
		return metadata.Owner == request.NewOwner() || metadata.Owner == request.AlternateOwner() ||
			metadata.Owner == request.Owner() && request.PriorState() == PriorTransferred
	default:
		return false
	}
}

func metadataRank(metadata Metadata) uint8 {
	switch MetadataState(metadata.State) {
	case MetadataReservePending:
		return 1
	case MetadataReserved:
		return 2
	case MetadataTransferred:
		return 3
	default:
		return 0
	}
}

func writeMetadata(rootFD int, metadata Metadata) error {
	canonical, err := CanonicalMetadata(metadata)
	if err != nil {
		return err
	}
	fd, err := unix.Openat(rootFD, metadataTemporaryName,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return errors.New("create capacity metadata journal")
	}
	file := os.NewFile(uintptr(fd), metadataTemporaryName)
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("open capacity metadata journal")
	}
	writeErr := writeAll(file, canonical)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("durably write capacity metadata journal")
	}
	if err := unix.Renameat(rootFD, metadataTemporaryName, rootFD, metadataName); err != nil {
		return errors.New("publish capacity metadata")
	}
	if err := unix.Fsync(rootFD); err != nil {
		return errors.New("sync capacity volume directory")
	}
	return nil
}

func readMetadata(rootFD int) (Metadata, bool, error) {
	present, err := entryPresent(rootFD, metadataName)
	if err != nil || !present {
		return Metadata{}, false, err
	}
	metadata, err := readMetadataNamed(rootFD, metadataName)
	return metadata, true, err
}

func readMetadataNamed(rootFD int, name string) (Metadata, error) {
	fd, err := unix.Openat(rootFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return Metadata{}, errors.New("open capacity metadata")
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return Metadata{}, errors.New("wrap capacity metadata descriptor")
	}
	defer func() { _ = file.Close() }()
	if err := validateRegularFile(fd, 0o600); err != nil {
		return Metadata{}, err
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(data) > 4096 {
		return Metadata{}, errors.New("read bounded capacity metadata")
	}
	return ParseMetadata(data)
}

func openReservation(rootFD int, create bool) (*os.File, error) {
	flags := unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if create {
		flags |= unix.O_CREAT
	}
	fd, err := unix.Openat(rootFD, reservationName, flags, 0o600)
	if err != nil {
		return nil, errors.New("open physical capacity reservation")
	}
	if err := validateRegularFile(fd, 0o600); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	file := os.NewFile(uintptr(fd), reservationName)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("wrap physical capacity descriptor")
	}
	return file, nil
}

func validateRegularFile(fd int, permissions uint32) error {
	var stat unix.Stat_t
	effectiveUID, effectiveGID := os.Geteuid(), os.Getegid()
	if effectiveUID < 0 || effectiveGID < 0 {
		return errors.New("capacity process identity is invalid")
	}
	// G115 is guarded by the kernel UID/GID domains and explicit non-negative check.
	expectedUID := uint32(effectiveUID) //nolint:gosec
	expectedGID := uint32(effectiveGID) //nolint:gosec
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Mode&0o777 != permissions || stat.Nlink != 1 || stat.Uid != expectedUID ||
		stat.Gid != expectedGID {
		return errors.New("capacity file identity or permissions are unsafe")
	}
	return nil
}

func verifyExactReservation(file *os.File, expected uint64) (uint64, uint64, error) {
	fileSize, allocated, err := measureReservation(file)
	if err != nil || fileSize != expected || allocated < expected {
		return 0, 0, errors.New("capacity file is sparse or has the wrong length")
	}
	return fileSize, allocated, nil
}

func measureReservation(file *os.File) (uint64, uint64, error) {
	var stat unix.Stat_t
	if file == nil || unix.Fstat(int(file.Fd()), &stat) != nil || stat.Size < 0 || stat.Blocks < 0 {
		return 0, 0, errors.New("measure physical capacity reservation")
	}
	blocks := uint64(stat.Blocks)
	if blocks > maximumSafeBytes/512 {
		return 0, 0, errors.New("physical allocation exceeds safe bound")
	}
	allocated := blocks * 512
	if uint64(stat.Size) > maximumSafeBytes || allocated > maximumSafeBytes {
		return 0, 0, errors.New("physical allocation exceeds safe bound")
	}
	return uint64(stat.Size), allocated, nil
}

func availableBytes(rootFD int) (uint64, error) {
	var stat unix.Statfs_t
	if err := unix.Fstatfs(rootFD, &stat); err != nil || stat.Bsize <= 0 {
		return 0, errors.New("measure capacity filesystem availability")
	}
	blockSize := uint64(stat.Bsize)
	availableBlocks := stat.Bavail
	if availableBlocks > maximumSafeBytes/blockSize {
		return maximumSafeBytes, nil
	}
	return availableBlocks * blockSize, nil
}

func requireEntries(rootFD int, expected ...string) error {
	actual, err := directoryEntries(rootFD, len(expected))
	if err != nil {
		return err
	}
	sort.Strings(expected)
	if len(actual) != len(expected) {
		return errors.New("capacity volume contains an unknown entry")
	}
	for index := range actual {
		if actual[index] != expected[index] {
			return errors.New("capacity volume contains an unknown entry")
		}
	}
	return nil
}

func directoryEntries(rootFD int, maximum int) ([]string, error) {
	if maximum < 0 || maximum > 3 {
		return nil, errors.New("capacity directory entry bound is invalid")
	}
	duplicate, err := unix.Openat(rootFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("duplicate capacity directory descriptor")
	}
	directory := os.NewFile(uintptr(duplicate), MountTarget)
	if directory == nil {
		_ = unix.Close(duplicate)
		return nil, errors.New("wrap capacity directory descriptor")
	}
	defer func() { _ = directory.Close() }()
	names, err := directory.Readdirnames(maximum + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, errors.New("enumerate capacity volume")
	}
	if len(names) > maximum {
		return nil, errors.New("capacity volume contains an unknown entry")
	}
	sort.Strings(names)
	return names, nil
}

func entryPresent(rootFD int, name string) (bool, error) {
	var stat unix.Stat_t
	err := unix.Fstatat(rootFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("inspect capacity volume entry")
	}
	return true, nil
}

func writeAll(file *os.File, data []byte) error {
	for len(data) > 0 {
		written, err := file.Write(data)
		if err != nil || written <= 0 {
			return errors.New("write capacity metadata")
		}
		data = data[written:]
	}
	return nil
}

func deleteOwnerAndStateAllowed(request Request, metadata Metadata) bool {
	switch request.PriorState() {
	case PriorReservePending:
		return metadata.Owner == request.Owner() &&
			(metadata.State == string(MetadataReservePending) || metadata.State == string(MetadataReserved))
	case PriorReserved:
		return metadata.Owner == request.Owner() && metadata.State == string(MetadataReserved)
	case PriorTransferPending:
		return metadata.Owner == request.Owner() && metadata.State == string(MetadataReserved) ||
			request.AlternateOwner() != "" && metadata.Owner == request.AlternateOwner() &&
				metadata.State == string(MetadataTransferred)
	case PriorTransferred:
		return request.AlternateOwner() != "" && metadata.Owner == request.AlternateOwner() &&
			metadata.State == string(MetadataTransferred)
	default:
		return false
	}
}

func observation(metadata Metadata, fileSize, allocated, available uint64) Observation {
	return Observation{
		AllocatedBlockBytes: allocated, AvailableBytes: available, FileSizeBytes: fileSize,
		Metadata: metadata, Owner: metadata.Owner, State: metadata.State,
	}
}

func fallocateLength(value uint64) (int64, error) {
	if value == 0 || value > maximumSafeBytes {
		return 0, errors.New("capacity allocation length is invalid")
	}
	return int64(value), nil
}

var _ Store = (*LinuxStore)(nil)
