//go:build darwin || linux

package artifactfs

import (
	"encoding/binary"
	"os"

	"golang.org/x/sys/unix"
)

const allocationMarkerVersion = "agentmemory-physical-allocation-v1"

func physicalAllocationMarker(size uint64) []byte {
	marker := make([]byte, len(allocationMarkerVersion)+8)
	copy(marker, allocationMarkerVersion)
	binary.BigEndian.PutUint64(marker[len(allocationMarkerVersion):], size)
	return marker
}

func writePhysicalAllocationMarker(file *os.File, size uint64) error {
	return unix.Fsetxattr(int(file.Fd()), physicalAllocationAttribute(), physicalAllocationMarker(size), 0)
}

func validPhysicalAllocationMarker(file *os.File, size uint64) bool {
	expected := physicalAllocationMarker(size)
	observed := make([]byte, len(expected))
	count, err := unix.Fgetxattr(int(file.Fd()), physicalAllocationAttribute(), observed)
	return err == nil && count == len(expected) && string(observed) == string(expected)
}

func physicallyAllocated(file *os.File, expected uint64) bool {
	info, err := file.Stat()
	allocated, proven := allocatedFileBytesDescriptor(file, info)
	return err == nil && safeFileInfo(info, expected) && proven && allocated >= expected &&
		validPhysicalAllocationMarker(file, expected) && platformAllocationInvariant(file)
}
