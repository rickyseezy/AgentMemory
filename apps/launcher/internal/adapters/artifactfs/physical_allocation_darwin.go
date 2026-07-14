//go:build darwin

package artifactfs

import (
	"context"
	"os"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"golang.org/x/sys/unix"
)

func physicalAllocationAttribute() string { return "com.agentmemory.physical-allocation" }

func allocatePhysical(ctx context.Context, file *os.File, size uint64) error {
	length, valid := uint64ToInt64(size)
	if ctx == nil || ctx.Err() != nil || file == nil || !valid || size == 0 {
		return artifactapp.ErrReservationOperation
	}
	if physicallyAllocated(file, size) {
		return nil
	}
	// An interrupted or unmarked allocation is rebuilt from zero. This avoids
	// treating APFS compressed/CoW st_blocks as evidence that F_ALLOCATEALL ran.
	if err := file.Truncate(0); err != nil || writePhysicalAllocationMarker(file, size) != nil {
		return artifactapp.ErrReservationOperation
	}
	store := unix.Fstore_t{
		Flags: unix.F_ALLOCATEALL, Posmode: unix.F_PEOFPOSMODE, Offset: 0, Length: length,
	}
	if err := unix.FcntlFstore(file.Fd(), unix.F_PREALLOCATE, &store); err != nil || store.Bytesalloc < length {
		return artifactapp.ErrReservationOperation
	}
	if err := file.Truncate(length); err != nil || durableSync(file) != nil || !physicallyAllocated(file, size) {
		return artifactapp.ErrReservationOperation
	}
	return nil
}

func platformAllocationInvariant(file *os.File) bool {
	if file == nil {
		return false
	}
	var stat unix.Statfs_t
	if unix.Fstatfs(int(file.Fd()), &stat) != nil {
		return false
	}
	var name []byte
	for _, character := range stat.Fstypename {
		if character == 0 {
			break
		}
		name = append(name, character)
	}
	return string(name) == "apfs" || string(name) == "hfs"
}
